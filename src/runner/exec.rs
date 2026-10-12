//! Execute a step list on this host, recording what each step did.

use std::path::Path;

use plugin_toolkit::prelude::*;

use super::api;
use super::health::ServiceState;
use super::host::{self, LocalHost};
use super::layout::managed_root;
use super::plan::{AccountRecord, RunnerState, Scope, Step};
use super::release;
use crate::Config;

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct StepOutcome {
    pub target: String,
    pub action: String,
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

pub struct Executor<'a> {
    pub host: &'a LocalHost,
    /// Needed only by register/deregister steps.
    pub gitea: Option<&'a Config>,
}

/// Write `contents` to a fresh temp file beside `path`, fsync it, and rename
/// over `path`, so a reader (launchd, a running runner) never sees a partial
/// file and a crash never leaves one. `create_new` refuses to reuse a temp
/// path someone else planted.
pub(crate) fn write_atomic(path: &Path, contents: &[u8], mode: u32) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("{} has no parent", path.display()))?;
    std::fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    let file_name = path
        .file_name()
        .ok_or_else(|| anyhow!("{} has no file name", path.display()))?;
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or_default();
    let tmp = parent.join(format!(
        ".{}.orca-new.{}.{nonce}",
        file_name.to_string_lossy(),
        std::process::id()
    ));
    let result = (|| -> Result<()> {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(&tmp)
            .with_context(|| format!("create {}", tmp.display()))?;
        f.write_all(contents)
            .with_context(|| format!("write {}", tmp.display()))?;
        // `mode` above is filtered by the umask; set it exactly.
        f.set_permissions(std::fs::Permissions::from_mode(mode))
            .with_context(|| format!("chmod {}", tmp.display()))?;
        f.sync_all()
            .with_context(|| format!("fsync {}", tmp.display()))?;
        std::fs::rename(&tmp, path).with_context(|| format!("rename onto {}", path.display()))?;
        if let Ok(dir) = std::fs::File::open(parent) {
            dir.sync_all().ok();
        }
        Ok(())
    })();
    if result.is_err() {
        std::fs::remove_file(&tmp).ok();
    }
    result
}

fn create_dir_mode(path: &Path, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::create_dir_all(path).with_context(|| format!("create {}", path.display()))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .with_context(|| format!("chmod {}", path.display()))
}

pub(crate) fn chown(path: &Path, uid: Option<u32>, gid: u32, recursive: bool) -> Result<()> {
    std::os::unix::fs::lchown(path, uid, Some(gid))
        .with_context(|| format!("chown {}", path.display()))?;
    if recursive && std::fs::symlink_metadata(path)?.is_dir() {
        for entry in std::fs::read_dir(path)? {
            chown(&entry?.path(), uid, gid, true)?;
        }
    }
    Ok(())
}

fn scrub(text: &str, secret: &str) -> String {
    if secret.is_empty() {
        text.to_string()
    } else {
        text.replace(secret, "<redacted>")
    }
}

/// `act_runner register` argv. Takes no token: it travels only in
/// `GITEA_RUNNER_REGISTRATION_TOKEN`, so it is never visible in `ps`.
fn register_argv(
    binary: &Path,
    instance_url: &str,
    name: &str,
    labels: &[String],
    config: &Path,
) -> Vec<String> {
    vec![
        binary.display().to_string(),
        "register".into(),
        "--no-interactive".into(),
        "--instance".into(),
        instance_url.to_string(),
        "--name".into(),
        name.to_string(),
        "--labels".into(),
        labels.join(","),
        "--config".into(),
        config.display().to_string(),
    ]
}

/// A 404 proves the runner is gone only under the scope it was registered
/// in; under a caller-supplied scope it may be the wrong collection.
fn deregister_outcome(
    existed: bool,
    scope_known: bool,
    scope: &super::plan::Scope,
    runner_id: i64,
) -> Result<Option<String>> {
    match (existed, scope_known) {
        (true, _) => Ok(None),
        (false, true) => Ok(Some("already absent in Gitea".to_string())),
        (false, false) => bail!(
            "runner {runner_id} not found under scope '{}', and the scope it was registered in is not recorded",
            scope.label()
        ),
    }
}

const SET_DISABLED_SECS: u64 = if cfg!(test) { 1 } else { 60 };
const STOP_GRACE: std::time::Duration =
    std::time::Duration::from_secs(if cfg!(test) { 0 } else { 30 });
const STOP_POLL: std::time::Duration = std::time::Duration::from_secs(1);

const POLL: std::time::Duration = if cfg!(test) {
    std::time::Duration::from_millis(10)
} else {
    std::time::Duration::from_secs(10)
};

impl Executor<'_> {
    /// Poll Gitea's view of `runner_id` until `done` holds or `timeout_secs`
    /// passes. Transient API errors are retried until the deadline.
    async fn poll_runner(
        &self,
        runner_id: i64,
        timeout_secs: u64,
        what: &str,
        done: impl Fn(&super::health::GiteaRunnerView) -> bool,
    ) -> Result<Option<String>> {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);
        loop {
            let last = match api::runner_by_id(self.gitea()?, runner_id).await {
                Ok(Some(view)) if done(&view) => {
                    return Ok(Some(format!("runner {runner_id} {what} ({})", view.status)));
                }
                Ok(Some(view)) => format!("status {}", view.status),
                Ok(None) => bail!("Gitea has no runner with id {runner_id}"),
                Err(e) if api::is_transient(&e) => format!("last error: {e:#}"),
                Err(e) => return Err(e),
            };
            if std::time::Instant::now() >= deadline {
                bail!("runner {runner_id} not {what} after {timeout_secs}s ({last})");
            }
            tokio::time::sleep(POLL).await;
        }
    }

    /// Set the `disabled` flag, retrying transient API errors for up to
    /// [`SET_DISABLED_SECS`].
    async fn set_disabled(&self, scope: &Scope, runner_id: i64, disabled: bool) -> Result<()> {
        let deadline =
            std::time::Instant::now() + std::time::Duration::from_secs(SET_DISABLED_SECS);
        loop {
            match api::set_disabled(self.gitea()?, scope, runner_id, disabled).await {
                Err(e) if api::is_transient(&e) && std::time::Instant::now() < deadline => {
                    tokio::time::sleep(POLL).await;
                }
                r => return r,
            }
        }
    }

    fn gitea(&self) -> Result<&Config> {
        self.gitea
            .ok_or_else(|| anyhow!("this step needs a Gitea endpoint (pass `endpoint`)"))
    }

    async fn step(&self, step: &Step) -> Result<Option<String>> {
        match step {
            Step::CreateDir { path, mode } => {
                create_dir_mode(path, *mode)?;
                Ok(None)
            }
            Step::InstallBinary { artifact, dest } => {
                let bytes = release::download(artifact)?;
                write_atomic(dest, &bytes, 0o755)?;
                Ok(Some(format!(
                    "installed {} from {} (sha256 {} verified)",
                    artifact.version, artifact.host, artifact.sha256
                )))
            }
            Step::CheckMajor { binary, major } => {
                let found =
                    self.host.binary_version(binary).await.ok_or_else(|| {
                        anyhow!("could not read the version of {}", binary.display())
                    })?;
                if release::major(&found) != Some(*major) {
                    bail!(
                        "installed runner is {found}, target major is {major}; pass allow_major_upgrade to cross a major version"
                    );
                }
                Ok(Some(format!("installed {found}")))
            }
            Step::Chmod { path, mode } => {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(path, std::fs::Permissions::from_mode(*mode))
                    .with_context(|| format!("chmod {}", path.display()))?;
                Ok(None)
            }
            Step::Chown {
                path,
                user,
                group,
                recursive,
            } => {
                let (gid, _) = host::lookup_group(group)?
                    .ok_or_else(|| anyhow!("group '{group}' does not exist"))?;
                let uid = match user {
                    Some(u) => Some(
                        host::lookup_user(u)?
                            .ok_or_else(|| anyhow!("user '{u}' does not exist"))?
                            .0,
                    ),
                    None => None,
                };
                chown(path, uid, gid, *recursive)?;
                Ok(None)
            }
            Step::RecordState {
                path,
                state,
                runner_file,
            } => {
                let mut state = state.clone();
                if runner_file.is_some() {
                    // The account flags on disk are the reconciled ones; the
                    // planned flags may overstate what exists.
                    let disk = RunnerState::read(path).ok_or_else(|| {
                        anyhow!(
                            "no readable state record at {} to update after register",
                            path.display()
                        )
                    })?;
                    state.created_account = disk.created_account;
                    state.added_docker_group = disk.added_docker_group;
                }
                if let Some(rf) = runner_file {
                    state.runner_id = Some(
                        host::read_registration(rf)
                            .ok_or_else(|| {
                                anyhow!("no registration at {} after register", rf.display())
                            })?
                            .id,
                    );
                }
                write_atomic(path, state.to_json().as_bytes(), 0o600)?;
                Ok(state.runner_id.map(|id| format!("gitea runner id {id}")))
            }
            Step::WriteFile {
                path,
                contents,
                mode,
                ..
            } => {
                write_atomic(path, contents.as_bytes(), *mode)?;
                Ok(None)
            }
            Step::ReconcileAccount { path, user } => {
                let mut state = RunnerState::read(path)
                    .ok_or_else(|| anyhow!("no readable state record at {}", path.display()))?;
                let record = AccountRecord::from_state(Some(&state)).observed_locally(
                    user,
                    &host::read_local_db(Path::new(host::ETC_PASSWD))?,
                    &host::read_local_db(Path::new(host::ETC_GROUP))?,
                );
                state.created_account = record.created;
                state.added_docker_group = record.added_docker_group;
                write_atomic(path, state.to_json().as_bytes(), 0o600)?;
                Ok(Some(format!(
                    "created account {}, added docker group {}",
                    record.created, record.added_docker_group
                )))
            }
            Step::Register {
                binary,
                config,
                dir,
                name,
                labels,
                instance_url,
                scope,
            } => {
                let token = api::registration_token(self.gitea()?, scope).await?;
                let argv = register_argv(binary, instance_url, name, labels, config);
                let out = self
                    .host
                    .run_with_env(
                        &argv,
                        Some(dir),
                        &[("GITEA_RUNNER_REGISTRATION_TOKEN", token.as_str())],
                    )
                    .await?;
                if !out.ok {
                    bail!(
                        "act_runner register exited {:?}: {}",
                        out.code,
                        scrub(&format!("{} {}", out.stderr, out.stdout), &token).trim()
                    );
                }
                Ok(Some(format!("registered {name} ({})", scope.label())))
            }
            Step::Run {
                argv,
                tolerate_failure,
            } => {
                let out = self.host.run(argv, None).await?;
                if out.ok {
                    return Ok(None);
                }
                let why = format!(
                    "exit {:?}: {}",
                    out.code,
                    if out.stderr.is_empty() {
                        &out.stdout
                    } else {
                        &out.stderr
                    }
                );
                if *tolerate_failure {
                    Ok(Some(format!("tolerated {why}")))
                } else {
                    bail!("{why}")
                }
            }
            Step::Deregister {
                runner_id,
                scope,
                scope_known,
            } => {
                let existed = api::deregister(self.gitea()?, scope, *runner_id).await?;
                deregister_outcome(existed, *scope_known, scope, *runner_id)
            }
            Step::WaitIdle {
                runner_id,
                timeout_secs,
            } => {
                self.poll_runner(*runner_id, *timeout_secs, "idle", |v| !v.busy)
                    .await
            }
            Step::VerifyOnline {
                runner_id,
                timeout_secs,
            } => {
                self.poll_runner(*runner_id, *timeout_secs, "online", |v| v.online)
                    .await
            }
            Step::WaitOffline {
                runner_id,
                timeout_secs,
            } => {
                self.poll_runner(*runner_id, *timeout_secs, "offline", |v| !v.online)
                    .await
            }
            Step::SetDisabled {
                runner_id,
                scope,
                disabled,
            } => {
                self.set_disabled(scope, *runner_id, *disabled).await?;
                Ok(None)
            }
            Step::VerifyStopped { layout } => {
                // systemd reports `deactivating` while the stop is in flight; an
                // Unknown state gets the same grace before failing.
                let deadline = std::time::Instant::now() + STOP_GRACE;
                loop {
                    match self.host.service_state(layout).await.0 {
                        state @ (ServiceState::Running | ServiceState::Unknown) => {
                            if std::time::Instant::now() >= deadline {
                                bail!("{} is still {state:?} after stopping it", layout.service)
                            }
                            tokio::time::sleep(STOP_POLL).await;
                        }
                        state => return Ok(Some(format!("{state:?}"))),
                    }
                }
            }
            Step::InstallRegistration {
                src,
                dest,
                runner_id,
            } => {
                let bytes = host::read_regular_nofollow(src)?;
                let found = host::parse_registration(&bytes)
                    .ok_or_else(|| anyhow!("no readable registration at {}", src.display()))?;
                if found.id != *runner_id {
                    bail!(
                        "{} now holds runner id {}, planned {runner_id}",
                        src.display(),
                        found.id
                    );
                }
                write_atomic(dest, &bytes, 0o600)?;
                Ok(Some(format!("gitea runner id {runner_id}")))
            }
            Step::Remove { path, recursive } => {
                let result = if *recursive {
                    // Recursive removal is confined to the managed root so a bad
                    // layout can never take out anything else on the host.
                    let root = managed_root(self.host.init, &self.host.home);
                    if !path.starts_with(&root) || path == &root {
                        bail!(
                            "refusing to remove {} (outside {})",
                            path.display(),
                            root.display()
                        );
                    }
                    std::fs::remove_dir_all(path)
                } else {
                    std::fs::remove_file(path)
                };
                match result {
                    Ok(()) => Ok(None),
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                        Ok(Some("already absent".to_string()))
                    }
                    Err(e) => Err(anyhow!("remove {}: {e}", path.display())),
                }
            }
        }
    }

    /// Run `steps` in order, stopping at the first failure. Returns every
    /// outcome so far plus the error, if one stopped the run.
    /// A failure while this run holds the runner disabled re-enables it, so a
    /// failed drain never strands a runner that takes no jobs.
    pub async fn run(&self, steps: &[Step]) -> (Vec<StepOutcome>, Option<anyhow::Error>) {
        let mut outcomes = Vec::new();
        let mut held: Option<(i64, &Scope)> = None;
        for step in steps {
            let change = step.to_change();
            match self.step(step).await {
                Ok(detail) => {
                    if let Step::SetDisabled {
                        runner_id,
                        scope,
                        disabled,
                    } = step
                    {
                        held = disabled.then_some((*runner_id, scope));
                    }
                    outcomes.push(StepOutcome {
                        target: change.target,
                        action: change.action,
                        ok: true,
                        detail,
                    })
                }
                Err(mut e) => {
                    // A disable that ran out of transient retries may still have
                    // landed in Gitea (lost reply).
                    if let Step::SetDisabled {
                        runner_id,
                        scope,
                        disabled: true,
                    } = step
                        && e.chain()
                            .any(|c| c.downcast_ref::<crate::runner::api::Transient>().is_some())
                    {
                        held = Some((*runner_id, scope));
                    }
                    if let Some((runner_id, scope)) = held {
                        e = match self.set_disabled(scope, runner_id, false).await {
                            Ok(()) => e.context(format!("runner {runner_id} re-enabled in Gitea")),
                            Err(re) => e.context(format!(
                                "runner {runner_id} is still DISABLED in Gitea; re-enabling failed: {re:#}"
                            )),
                        };
                    }
                    outcomes.push(StepOutcome {
                        target: change.target,
                        action: change.action,
                        ok: false,
                        detail: Some(format!("{e:#}")),
                    });
                    return (outcomes, Some(e));
                }
            }
        }
        (outcomes, None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runner::layout::Init;
    use std::path::PathBuf;

    fn scratch(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("gitea-exec-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn atomic_write_sets_mode_and_leaves_no_temp() {
        use std::os::unix::fs::PermissionsExt;
        let d = scratch("write");
        let p = d.join("nested/unit");
        write_atomic(&p, b"x", 0o755).unwrap();
        assert_eq!(std::fs::read(&p).unwrap(), b"x");
        assert_eq!(
            std::fs::metadata(&p).unwrap().permissions().mode() & 0o777,
            0o755
        );
        assert_eq!(std::fs::read_dir(d.join("nested")).unwrap().count(), 1);
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn atomic_write_replaces_and_never_reuses_a_planted_temp() {
        let d = scratch("planted");
        let p = d.join("cfg");
        std::fs::write(&p, b"old").unwrap();
        write_atomic(&p, b"new", 0o600).unwrap();
        write_atomic(&p, b"newer", 0o600).unwrap();
        assert_eq!(std::fs::read(&p).unwrap(), b"newer");
        assert_eq!(std::fs::read_dir(&d).unwrap().count(), 1);
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn create_dir_is_private() {
        use std::os::unix::fs::PermissionsExt;
        let d = scratch("mode").join("r1");
        create_dir_mode(&d, 0o700).unwrap();
        assert_eq!(
            std::fs::metadata(&d).unwrap().permissions().mode() & 0o777,
            0o700
        );
        std::fs::remove_dir_all(d.parent().unwrap()).unwrap();
    }

    #[test]
    fn a_404_is_only_success_under_the_recorded_scope() {
        use crate::runner::plan::Scope;
        assert!(
            deregister_outcome(true, false, &Scope::Instance, 1)
                .unwrap()
                .is_none()
        );
        assert!(
            deregister_outcome(false, true, &Scope::Instance, 1)
                .unwrap()
                .is_some()
        );
        let err = deregister_outcome(false, false, &Scope::Org("x".into()), 1).unwrap_err();
        assert!(err.to_string().contains("not recorded"), "{err}");
    }

    #[test]
    fn register_argv_never_carries_the_token() {
        let token = "s3cr3t-registration-token";
        let argv = register_argv(
            Path::new("/r/act_runner"),
            "https://gitea.test",
            "r1",
            &["macos:host".to_string()],
            Path::new("/r/config.yaml"),
        );
        assert!(argv.iter().all(|a| !a.contains(token)));
        assert!(!argv.iter().any(|a| a.starts_with("--token")));
        assert_eq!(argv[1], "register");
    }

    #[test]
    fn scrub_redacts_the_token() {
        assert_eq!(scrub("bad token abc123", "abc123"), "bad token <redacted>");
    }

    #[tokio::test]
    async fn reconcile_account_keeps_only_locally_visible_changes() {
        let home = scratch("reconcile");
        let host = LocalHost {
            init: Init::Launchd,
            home: home.clone(),
            uid: 501,
        };
        let exec = Executor {
            host: &host,
            gitea: None,
        };
        let path = home.join(".orca/r1.json");
        let state = RunnerState {
            scope: "instance".into(),
            version: "4.1.0".into(),
            runner_id: Some(9),
            created_account: true,
            added_docker_group: true,
            pending_stale: Vec::new(),
        };
        write_atomic(&path, state.to_json().as_bytes(), 0o600).unwrap();
        let (_, err) = exec
            .run(&[Step::ReconcileAccount {
                path: path.clone(),
                user: "no-such-orca-test-user".into(),
            }])
            .await;
        let after = RunnerState::read(&path).unwrap();
        std::fs::remove_dir_all(&home).ok();
        assert!(err.is_none(), "{err:?}");
        assert!(!after.created_account && !after.added_docker_group);
        assert_eq!(after.runner_id, Some(9));
    }

    #[tokio::test]
    async fn post_registration_record_keeps_the_reconciled_account_flags() {
        let home = scratch("rerecord");
        let host = LocalHost {
            init: Init::Launchd,
            home: home.clone(),
            uid: 501,
        };
        let exec = Executor {
            host: &host,
            gitea: None,
        };
        let path = home.join(".orca/r1.json");
        let runner_file = home.join(".runner");
        std::fs::write(&runner_file, r#"{"id":77,"name":"r1","labels":[]}"#).unwrap();
        let planned = RunnerState {
            scope: "instance".into(),
            version: "4.1.0".into(),
            runner_id: None,
            created_account: true,
            added_docker_group: true,
            pending_stale: Vec::new(),
        };
        let (_, err) = exec
            .run(&[
                Step::RecordState {
                    path: path.clone(),
                    state: planned.clone(),
                    runner_file: None,
                },
                Step::ReconcileAccount {
                    path: path.clone(),
                    user: "no-such-orca-test-user".into(),
                },
                Step::RecordState {
                    path: path.clone(),
                    state: planned,
                    runner_file: Some(runner_file),
                },
            ])
            .await;
        let after = RunnerState::read(&path).unwrap();
        std::fs::remove_dir_all(&home).ok();
        assert!(err.is_none(), "{err:?}");
        assert_eq!(after.runner_id, Some(77));
        assert!(!after.created_account && !after.added_docker_group);
    }

    #[tokio::test]
    async fn post_registration_record_needs_the_earlier_record() {
        let home = scratch("norecord");
        let host = LocalHost {
            init: Init::Launchd,
            home: home.clone(),
            uid: 501,
        };
        let exec = Executor {
            host: &host,
            gitea: None,
        };
        let runner_file = home.join(".runner");
        std::fs::write(&runner_file, r#"{"id":77,"name":"r1","labels":[]}"#).unwrap();
        let path = home.join(".orca/r1.json");
        let (_, err) = exec
            .run(&[Step::RecordState {
                path: path.clone(),
                state: RunnerState {
                    scope: "instance".into(),
                    version: "4.1.0".into(),
                    runner_id: None,
                    created_account: true,
                    added_docker_group: true,
                    pending_stale: Vec::new(),
                },
                runner_file: Some(runner_file),
            }])
            .await;
        let written = path.exists();
        std::fs::remove_dir_all(&home).ok();
        let err = err.expect("must refuse to fall back to the planned flags");
        assert!(
            format!("{err:#}").contains("no readable state record"),
            "{err:#}"
        );
        assert!(!written);
    }

    #[tokio::test]
    async fn recursive_remove_is_confined_to_the_managed_root() {
        let home = scratch("home");
        let host = LocalHost {
            init: Init::Launchd,
            home: home.clone(),
            uid: 501,
        };
        let exec = Executor {
            host: &host,
            gitea: None,
        };
        let outside = home.join("precious");
        std::fs::create_dir_all(&outside).unwrap();
        let (out, err) = exec
            .run(&[Step::Remove {
                path: outside.clone(),
                recursive: true,
            }])
            .await;
        assert!(err.is_some() && !out[0].ok);
        assert!(outside.exists());

        let inside = managed_root(Init::Launchd, &home).join("r1");
        std::fs::create_dir_all(inside.join("work")).unwrap();
        let (out, err) = exec
            .run(&[
                Step::Remove {
                    path: inside.clone(),
                    recursive: true,
                },
                Step::Remove {
                    path: inside.clone(),
                    recursive: true,
                },
            ])
            .await;
        assert!(err.is_none(), "{err:?}");
        assert!(!inside.exists());
        assert_eq!(out[1].detail.as_deref(), Some("already absent"));
        std::fs::remove_dir_all(&home).unwrap();
    }

    #[tokio::test]
    async fn a_failed_step_stops_the_run_and_tolerated_ones_do_not() {
        let home = scratch("run");
        let host = LocalHost {
            init: Init::Launchd,
            home: home.clone(),
            uid: 501,
        };
        let exec = Executor {
            host: &host,
            gitea: None,
        };
        let steps = vec![
            Step::Run {
                argv: vec!["false".into()],
                tolerate_failure: true,
            },
            Step::Run {
                argv: vec!["false".into()],
                tolerate_failure: false,
            },
            Step::Run {
                argv: vec!["true".into()],
                tolerate_failure: false,
            },
        ];
        let (out, err) = exec.run(&steps).await;
        assert_eq!(out.len(), 2);
        assert!(out[0].ok && out[0].detail.as_deref().unwrap().starts_with("tolerated"));
        assert!(!out[1].ok);
        assert!(err.is_some());
        std::fs::remove_dir_all(&home).unwrap();
    }

    fn test_host(home: &Path) -> LocalHost {
        LocalHost {
            init: Init::Launchd,
            home: home.to_path_buf(),
            uid: 501,
        }
    }

    /// Run `steps` against canned Gitea replies, served in order (the last
    /// repeats). Returns the run's error and how many requests were made.
    fn run_against(replies: Vec<(u16, String)>, steps: Vec<Step>) -> (Option<String>, usize) {
        let served = std::sync::Arc::new(std::sync::Mutex::new(0usize));
        let count = served.clone();
        let mut err = None;
        plugin_toolkit::capsink::with_cap_sink(
            Box::new(move |_c: &str, _json: &str| {
                let mut n = count.lock().unwrap();
                let (status, body) = &replies[(*n).min(replies.len() - 1)];
                *n += 1;
                Ok(plugin_toolkit::serde_json::json!({
                    "status": status,
                    "headers": [],
                    "body": body.as_bytes().to_vec(),
                })
                .to_string())
            }),
            || {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap();
                rt.block_on(async {
                    let host = test_host(&std::env::temp_dir());
                    let cfg = Config::new("https://gitea.test/api/v1", "k");
                    let exec = Executor {
                        host: &host,
                        gitea: Some(&cfg),
                    };
                    err = exec.run(&steps).await.1.map(|e| format!("{e:#}"));
                });
            },
        );
        let n = *served.lock().unwrap();
        (err, n)
    }

    fn runners(status: &str, busy: bool) -> (u16, String) {
        (
            200,
            format!(
                r#"{{"runners":[{{"id":7,"name":"r1","status":"{status}","busy":{busy}}}],"total_count":1}}"#
            ),
        )
    }

    #[test]
    fn poll_fails_at_the_deadline() {
        let (err, _) = run_against(
            vec![runners("active", true)],
            vec![Step::WaitIdle {
                runner_id: 7,
                timeout_secs: 0,
            }],
        );
        let err = err.expect("a busy runner must time out");
        assert!(err.contains("not idle after 0s"), "{err}");
    }

    #[test]
    fn poll_retries_transient_errors_until_the_deadline() {
        let (err, n) = run_against(
            vec![
                (503, String::new()),
                (502, String::new()),
                runners("online", false),
            ],
            vec![Step::VerifyOnline {
                runner_id: 7,
                timeout_secs: 30,
            }],
        );
        assert!(err.is_none(), "{err:?}");
        assert_eq!(n, 3);
    }

    #[test]
    fn poll_stops_on_a_permanent_error() {
        let (err, n) = run_against(
            vec![(403, String::new())],
            vec![Step::VerifyOnline {
                runner_id: 7,
                timeout_secs: 30,
            }],
        );
        assert!(err.expect("403 is not retried").contains("admin scope"));
        assert_eq!(n, 1);
    }

    #[test]
    fn a_source_still_online_is_not_taken_as_the_adopted_runner() {
        let (err, _) = run_against(
            vec![runners("online", false)],
            vec![
                Step::WaitOffline {
                    runner_id: 7,
                    timeout_secs: 0,
                },
                Step::VerifyOnline {
                    runner_id: 7,
                    timeout_secs: 0,
                },
            ],
        );
        let err = err.expect("a stale online status must not pass the gate");
        assert!(err.contains("not offline"), "{err}");
    }

    fn disable(disabled: bool) -> Step {
        Step::SetDisabled {
            runner_id: 7,
            scope: Scope::Instance,
            disabled,
        }
    }

    fn patched() -> (u16, String) {
        (200, r#"{"id":7,"name":"r1"}"#.to_string())
    }

    #[test]
    fn a_failed_drain_re_enables_the_runner() {
        let (err, n) = run_against(
            vec![patched(), runners("active", true), patched()],
            vec![
                disable(true),
                Step::WaitIdle {
                    runner_id: 7,
                    timeout_secs: 0,
                },
            ],
        );
        let err = err.expect("a busy runner must time out");
        assert!(err.contains("re-enabled in Gitea"), "{err}");
        assert_eq!(n, 3);
    }

    #[test]
    fn a_failed_re_enable_says_the_runner_is_still_disabled() {
        let (err, _) = run_against(
            vec![patched(), runners("active", true), (403, String::new())],
            vec![
                disable(true),
                Step::WaitIdle {
                    runner_id: 7,
                    timeout_secs: 0,
                },
            ],
        );
        assert!(err.unwrap().contains("still DISABLED"));
    }

    #[test]
    fn set_disabled_retries_transient_errors() {
        let (err, n) = run_against(
            vec![(503, String::new()), (502, String::new()), patched()],
            vec![disable(true)],
        );
        assert!(err.is_none(), "{err:?}");
        assert_eq!(n, 3);
    }

    #[test]
    fn set_disabled_on_an_old_gitea_names_the_version() {
        let (err, n) = run_against(vec![(405, String::new())], vec![disable(true)]);
        assert!(err.unwrap().contains("needs >=1.26"));
        assert_eq!(n, 1);
    }

    async fn install_registration(src: &Path, dest: &Path, runner_id: i64) -> Option<String> {
        let home = src.parent().unwrap().to_path_buf();
        let host = test_host(&home);
        let exec = Executor {
            host: &host,
            gitea: None,
        };
        exec.run(&[Step::InstallRegistration {
            src: src.to_path_buf(),
            dest: dest.to_path_buf(),
            runner_id,
        }])
        .await
        .1
        .map(|e| format!("{e:#}"))
    }

    #[tokio::test]
    async fn install_registration_copies_the_checked_bytes_privately() {
        use std::os::unix::fs::MetadataExt;
        let d = scratch("reg-ok");
        let src = d.join("moved.runner");
        let dest = d.join("r1/.runner");
        let body = br#"{"id":7,"name":"r1","token":"SECRET","labels":[]}"#;
        std::fs::write(&src, body).unwrap();
        let err = install_registration(&src, &dest, 7).await;
        let meta = std::fs::metadata(&dest).unwrap();
        let copied = std::fs::read(&dest).unwrap();
        std::fs::remove_dir_all(&d).ok();
        assert!(err.is_none(), "{err:?}");
        assert_eq!(copied, body);
        assert_eq!(meta.mode() & 0o777, 0o600);
        assert_eq!(meta.uid(), unsafe { libc::geteuid() });
    }

    #[tokio::test]
    async fn install_registration_refuses_another_runner_id() {
        let d = scratch("reg-id");
        let src = d.join("moved.runner");
        let dest = d.join("r1/.runner");
        std::fs::write(&src, r#"{"id":8,"name":"r1"}"#).unwrap();
        let err = install_registration(&src, &dest, 7).await;
        let written = dest.exists();
        std::fs::remove_dir_all(&d).ok();
        assert!(err.unwrap().contains("holds runner id 8, planned 7"));
        assert!(!written);
    }

    #[tokio::test]
    async fn install_registration_refuses_a_symlink_or_non_regular_source() {
        let d = scratch("reg-link");
        let real = d.join("real.runner");
        std::fs::write(&real, r#"{"id":7,"name":"r1"}"#).unwrap();
        let link = d.join("link.runner");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let dir = d.join("dir.runner");
        std::fs::create_dir(&dir).unwrap();
        let fifo = d.join("fifo.runner");
        let c = std::ffi::CString::new(fifo.to_str().unwrap()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        let dest = d.join("r1/.runner");
        let via_link = install_registration(&link, &dest, 7).await;
        let via_dir = install_registration(&dir, &dest, 7).await;
        let via_fifo = install_registration(&fifo, &dest, 7).await;
        let written = dest.exists();
        std::fs::remove_dir_all(&d).ok();
        assert!(via_link.unwrap().contains("symlinks refused"));
        assert!(via_dir.unwrap().contains("not a regular file"));
        assert!(via_fifo.unwrap().contains("not a regular file"));
        assert!(!written);
    }
}
