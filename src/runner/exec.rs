//! Execute a step list on this host, recording what each step did.

use std::path::Path;

use plugin_toolkit::prelude::*;

use super::api;
use super::host::{self, LocalHost};
use super::layout::managed_root;
use super::plan::{AccountRecord, RunnerState, Step};
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
fn write_atomic(path: &Path, contents: &[u8], mode: u32) -> Result<()> {
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

fn chown(path: &Path, uid: Option<u32>, gid: u32, recursive: bool) -> Result<()> {
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

impl Executor<'_> {
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
    pub async fn run(&self, steps: &[Step]) -> (Vec<StepOutcome>, Option<anyhow::Error>) {
        let mut outcomes = Vec::new();
        for step in steps {
            let change = step.to_change();
            match self.step(step).await {
                Ok(detail) => outcomes.push(StepOutcome {
                    target: change.target,
                    action: change.action,
                    ok: true,
                    detail,
                }),
                Err(e) => {
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
}
