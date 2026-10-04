//! Ordered steps for every mutating runner verb.
//!
//! A verb builds its step list once; a dry run renders it as the plan and an
//! execute runs exactly that list. The plan an operator approves is therefore
//! the work that happens, not a separate description of it.

use std::path::{Path, PathBuf};

use plugin_toolkit::contract::plan::PlannedChange;
use plugin_toolkit::prelude::*;

use super::health::{Finding, Remedy, ServiceState};
use super::host::{local_group_lists, local_user_exists};
use super::layout::{Init, Layout};
use super::release::Artifact;

/// Who a runner serves, which picks the Gitea endpoints that mint its
/// registration token and delete it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Scope {
    Instance,
    Org(String),
    Repo(String, String),
}

/// Gitea's owner/repo name charset. `.` and `..` are refused outright: they
/// are valid characters but, as whole segments, path traversal.
fn validate_segment(kind: &str, s: &str) -> Result<()> {
    let ok = !s.is_empty()
        && s.len() <= 100
        && s != "."
        && s != ".."
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'));
    if !ok {
        bail!("invalid {kind} name '{s}' in scope: use [A-Za-z0-9._-], not '.' or '..'");
    }
    Ok(())
}

/// Percent-encode one URL path segment (everything but RFC 3986 unreserved).
pub fn encode_segment(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

impl std::str::FromStr for Scope {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self> {
        let s = s.trim();
        if s.is_empty() || s == "instance" {
            return Ok(Scope::Instance);
        }
        if let Some(org) = s.strip_prefix("org:") {
            validate_segment("org", org)?;
            return Ok(Scope::Org(org.to_string()));
        }
        if let Some((owner, repo)) = s.strip_prefix("repo:").and_then(|r| r.split_once('/')) {
            validate_segment("owner", owner)?;
            validate_segment("repo", repo)?;
            return Ok(Scope::Repo(owner.to_string(), repo.to_string()));
        }
        bail!("invalid scope '{s}' (expected instance | org:<org> | repo:<owner>/<repo>)")
    }
}

impl Scope {
    /// API path (under `/api/v1`) of this scope's runner collection.
    pub fn runners_path(&self) -> String {
        match self {
            Scope::Instance => "/admin/actions/runners".to_string(),
            Scope::Org(o) => format!("/orgs/{}/actions/runners", encode_segment(o)),
            Scope::Repo(o, r) => format!(
                "/repos/{}/{}/actions/runners",
                encode_segment(o),
                encode_segment(r)
            ),
        }
    }

    pub fn label(&self) -> String {
        match self {
            Scope::Instance => "instance".to_string(),
            Scope::Org(o) => format!("org:{o}"),
            Scope::Repo(o, r) => format!("repo:{o}/{r}"),
        }
    }
}

/// What the plugin records about a managed install, root-owned and outside
/// the runner's reach. Deregistration uses the recorded scope and runner id,
/// never the runner-writable `.runner`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunnerState {
    pub scope: String,
    pub version: String,
    #[serde(default)]
    pub runner_id: Option<i64>,
    /// Whether this plugin created the service account. Only an account it
    /// created is removed on uninstall.
    #[serde(default)]
    pub created_account: bool,
    /// Whether this plugin added an existing account to the `docker` group.
    /// Revoked on uninstall; a created account takes its grant with it.
    #[serde(default)]
    pub added_docker_group: bool,
}

impl RunnerState {
    pub fn to_json(&self) -> String {
        plugin_toolkit::serde_json::to_string_pretty(self).unwrap_or_default()
    }

    pub fn read(path: &Path) -> Option<RunnerState> {
        let text = std::fs::read_to_string(path).ok()?;
        plugin_toolkit::serde_json::from_str(&text).ok()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    CreateDir {
        path: PathBuf,
        mode: u32,
    },
    /// Download the pinned artifact, verify its sha256, then atomically
    /// replace `dest`.
    InstallBinary {
        artifact: Artifact,
        dest: PathBuf,
    },
    /// Refuse to continue unless the installed binary's major version equals
    /// `major`. Runs the binary's `--version`, so it only ever runs on execute.
    CheckMajor {
        binary: PathBuf,
        major: u64,
    },
    WriteFile {
        path: PathBuf,
        contents: String,
        mode: u32,
        what: String,
    },
    Chmod {
        path: PathBuf,
        mode: u32,
    },
    /// Set ownership. `user: None` keeps the current owner (root) and only
    /// sets the group, which is how the runner gets read access to the
    /// install directory without being able to write it.
    Chown {
        path: PathBuf,
        user: Option<String>,
        group: String,
        recursive: bool,
    },
    /// Write the root-owned state record. With `runner_file`, the Gitea
    /// runner id is read from it at execute time, immediately after
    /// registration and before the runner account can touch it, and the
    /// account flags are kept from the record already on disk, which
    /// `ReconcileAccount` may have corrected.
    RecordState {
        path: PathBuf,
        state: RunnerState,
        runner_file: Option<PathBuf>,
    },
    /// Rewrite the state record's account flags from what the local account
    /// databases show now, right after the account steps.
    ReconcileAccount {
        path: PathBuf,
        user: String,
    },
    /// `act_runner register` with a registration token minted at run time and
    /// passed in the environment, so it appears in neither the plan nor `ps`.
    Register {
        binary: PathBuf,
        config: PathBuf,
        dir: PathBuf,
        name: String,
        labels: Vec<String>,
        instance_url: String,
        scope: Scope,
    },
    Run {
        argv: Vec<String>,
        /// Unload/stop of something already gone must not fail the verb.
        tolerate_failure: bool,
    },
    Deregister {
        runner_id: i64,
        scope: Scope,
        /// True when `scope` is the one recorded at install. Only then is a
        /// 404 proof the runner is gone; under a guessed scope it may just
        /// mean the wrong collection was asked.
        scope_known: bool,
    },
    Remove {
        path: PathBuf,
        recursive: bool,
    },
}

fn run(argv: &[&str], tolerate_failure: bool) -> Step {
    Step::Run {
        argv: argv.iter().map(|s| s.to_string()).collect(),
        tolerate_failure,
    }
}

impl Step {
    pub fn to_change(&self) -> PlannedChange {
        match self {
            Step::CreateDir { path, mode } => {
                PlannedChange::new(path.display().to_string(), "create-dir")
                    .with_detail(format!("mode {mode:o}"))
            }
            Step::InstallBinary { artifact: a, dest } => {
                PlannedChange::new(dest.display().to_string(), "install-binary").with_detail(
                    format!(
                        "runner {} from {} (host {}), sha256 {} pinned in the plugin, replaced atomically",
                        a.version, a.url, a.host, a.sha256
                    ),
                )
            }
            Step::CheckMajor { binary, major } => {
                PlannedChange::new(binary.display().to_string(), "check-major")
                    .with_detail(format!("refuse unless the installed major version is {major}"))
            }
            Step::WriteFile {
                path, mode, what, ..
            } => PlannedChange::new(path.display().to_string(), "write")
                .with_detail(format!("{what} (mode {mode:o})")),
            Step::Chmod { path, mode } => {
                PlannedChange::new(path.display().to_string(), "chmod")
                    .with_detail(format!("{mode:o}"))
            }
            Step::Chown {
                path,
                user,
                group,
                recursive,
            } => PlannedChange::new(path.display().to_string(), "chown").with_detail(format!(
                "{}:{group}{}",
                user.as_deref().unwrap_or("(owner unchanged)"),
                if *recursive { " recursively" } else { "" }
            )),
            Step::RecordState {
                state, runner_file, ..
            } => PlannedChange::new("orca runner state".to_string(), "record").with_detail(
                format!(
                    "scope {}, version {}, runner id {}, {} (root-owned, mode 600)",
                    state.scope,
                    state.version,
                    match (runner_file, state.runner_id) {
                        (Some(_), _) => "read from the fresh registration".to_string(),
                        (None, Some(id)) => id.to_string(),
                        (None, None) => "none yet".to_string(),
                    },
                    match runner_file {
                        Some(_) => "account flags kept from the record on disk".to_string(),
                        None => format!(
                            "created account {}, added docker group {}",
                            state.created_account, state.added_docker_group
                        ),
                    },
                ),
            ),
            Step::ReconcileAccount { user, .. } => {
                PlannedChange::new("orca runner state".to_string(), "reconcile-account")
                    .with_detail(format!(
                        "keep only the changes to {user} that /etc/passwd and /etc/group show"
                    ))
            }
            Step::Register {
                name,
                labels,
                instance_url,
                scope,
                ..
            } => PlannedChange::new(format!("gitea runner {name}"), "register").with_detail(
                format!(
                    "fetch the {} registration token, register against {instance_url} with labels [{}]; \
                     the token is passed via GITEA_RUNNER_REGISTRATION_TOKEN, never argv",
                    scope.label(),
                    labels.join(", ")
                ),
            ),
            Step::Run {
                argv,
                tolerate_failure,
            } => {
                let change = PlannedChange::new(argv.join(" "), "run");
                if *tolerate_failure {
                    change.with_detail("failure tolerated")
                } else {
                    change
                }
            }
            Step::Deregister {
                runner_id,
                scope,
                scope_known,
            } => PlannedChange::new(format!("gitea runner id {runner_id}"), "deregister")
                .with_detail(format!(
                    "DELETE {}/{runner_id} ({} scope)",
                    scope.runners_path(),
                    if *scope_known { "recorded" } else { "caller-supplied" }
                )),
            Step::Remove { path, recursive } => PlannedChange::new(
                path.display().to_string(),
                if *recursive { "remove-dir" } else { "remove-file" },
            ),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceOp {
    /// Install the definition into the manager and start it at boot and now.
    Load,
    Unload,
    Restart,
    /// Bring a down service up, clearing whatever state keeps it down.
    Start,
}

/// The manager commands for `op`, given the service's current `state`.
pub fn service_steps(layout: &Layout, op: ServiceOp, uid: u32, state: ServiceState) -> Vec<Step> {
    let svc = layout.service.as_str();
    let unit = layout.unit_path.to_string_lossy().to_string();
    match layout.init {
        Init::Launchd => {
            let domain = format!("gui/{uid}");
            let target = layout.launchd_target(uid);
            match op {
                ServiceOp::Load => vec![run(&["launchctl", "bootstrap", &domain, &unit], false)],
                ServiceOp::Unload => vec![run(&["launchctl", "bootout", &target], true)],
                ServiceOp::Restart => vec![run(&["launchctl", "kickstart", "-k", &target], false)],
                ServiceOp::Start if state == ServiceState::NotLoaded => {
                    vec![run(&["launchctl", "bootstrap", &domain, &unit], false)]
                }
                ServiceOp::Start => vec![run(&["launchctl", "kickstart", &target], false)],
            }
        }
        Init::Systemd => match op {
            ServiceOp::Load => vec![
                run(&["systemctl", "daemon-reload"], false),
                run(&["systemctl", "enable", "--now", svc], false),
            ],
            ServiceOp::Unload => vec![run(&["systemctl", "disable", "--now", svc], true)],
            ServiceOp::Restart => vec![run(&["systemctl", "restart", svc], false)],
            ServiceOp::Start => vec![
                run(&["systemctl", "reset-failed", svc], true),
                run(&["systemctl", "start", svc], false),
            ],
        },
        // `zap` only when crashed: a crashed service refuses `start`, but
        // zapping a RUNNING one marks it stopped while the process lives on,
        // and the next start launches a second runner beside it.
        Init::Openrc => match (op, state) {
            (ServiceOp::Load, _) => vec![
                run(&["rc-update", "add", svc, "default"], false),
                run(&["rc-service", svc, "start"], false),
            ],
            (ServiceOp::Unload, _) => vec![
                run(&["rc-service", svc, "stop"], true),
                run(&["rc-update", "del", svc, "default"], true),
            ],
            (ServiceOp::Restart | ServiceOp::Start, ServiceState::Crashed) => vec![
                run(&["rc-service", svc, "zap"], false),
                run(&["rc-service", svc, "start"], false),
            ],
            (ServiceOp::Restart, _) => vec![run(&["rc-service", svc, "restart"], false)],
            (ServiceOp::Start, _) => vec![run(&["rc-service", svc, "start"], false)],
        },
    }
}

/// Create the runner's service account. `group_exists` covers a group left
/// behind by an earlier, partly removed install. In docker mode the account
/// joins the `docker` group: the runner process needs the socket to start
/// job containers (jobs themselves never get it; see `docker_host: "-"`),
/// and socket access is root-equivalent on that host.
pub fn user_steps(
    init: Init,
    user: &str,
    home: &Path,
    docker: bool,
    group_exists: bool,
) -> Vec<Step> {
    let home = home.to_string_lossy();
    let mut steps = match init {
        Init::Launchd => return Vec::new(),
        Init::Systemd => {
            let group_flag = if group_exists {
                "--gid"
            } else {
                "--user-group"
            };
            let mut argv = vec!["useradd", "--system", group_flag];
            if group_exists {
                argv.push(user);
            }
            argv.extend([
                "--home-dir",
                &home,
                "--no-create-home",
                "--shell",
                "/usr/sbin/nologin",
                user,
            ]);
            vec![run(&argv, false)]
        }
        Init::Openrc => {
            let mut steps = Vec::new();
            if !group_exists {
                steps.push(run(&["addgroup", "-S", user], false));
            }
            steps.push(run(
                &[
                    "adduser",
                    "-S",
                    "-D",
                    "-H",
                    "-h",
                    &home,
                    "-s",
                    "/sbin/nologin",
                    "-G",
                    user,
                    user,
                ],
                false,
            ));
            steps
        }
    };
    if docker {
        steps.extend(docker_group_steps(init, user));
    }
    steps
}

/// Add an existing account to the `docker` group.
pub fn docker_group_steps(init: Init, user: &str) -> Vec<Step> {
    match init {
        Init::Launchd => Vec::new(),
        Init::Openrc => vec![run(&["addgroup", user, "docker"], false)],
        Init::Systemd => vec![run(&["usermod", "-aG", "docker", user], false)],
    }
}

/// What the plugin did to the service account, as recorded for uninstall.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AccountRecord {
    pub created: bool,
    pub added_docker_group: bool,
}

impl AccountRecord {
    pub fn from_state(state: Option<&RunnerState>) -> AccountRecord {
        state
            .map(|s| AccountRecord {
                created: s.created_account,
                added_docker_group: s.added_docker_group,
            })
            .unwrap_or_default()
    }

    /// `still_applied` judged by the local account databases, which are what
    /// userdel/deluser and gpasswd -d/delgroup can change: a membership that
    /// only a directory grants is not ours to revoke.
    pub fn observed_locally(self, user: &str, passwd: &str, groups: &str) -> AccountRecord {
        self.still_applied(
            local_user_exists(passwd, user),
            local_group_lists(groups, "docker", user),
        )
    }

    /// The part of this record still in effect, so the undo steps can fail
    /// hard (and be retried) without tripping over an already-undone change.
    pub fn still_applied(self, user_exists: bool, in_docker_group: bool) -> AccountRecord {
        AccountRecord {
            created: self.created && user_exists,
            added_docker_group: self.added_docker_group && in_docker_group,
        }
    }
}

/// Account steps for an install, and what they will have done.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AccountPlan {
    pub steps: Vec<Step>,
    pub record: AccountRecord,
}

/// What NSS says about the runner's account before install.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AccountFacts {
    pub user_exists: bool,
    pub group_exists: bool,
    pub in_docker_group: bool,
}

/// Decide whether to create the account, grant an existing one the `docker`
/// group, or reuse it as is.
pub fn account_plan(
    init: Init,
    user: Option<&str>,
    home: &Path,
    docker: bool,
    facts: AccountFacts,
) -> AccountPlan {
    let Some(user) = user else {
        return AccountPlan::default();
    };
    if !facts.user_exists {
        return AccountPlan {
            steps: user_steps(init, user, home, docker, facts.group_exists),
            record: AccountRecord {
                created: true,
                added_docker_group: false,
            },
        };
    }
    if docker && !facts.in_docker_group {
        return AccountPlan {
            steps: docker_group_steps(init, user),
            record: AccountRecord {
                created: false,
                added_docker_group: true,
            },
        };
    }
    AccountPlan::default()
}

/// One-line description of `plan` for the install summary.
pub fn account_summary(plan: &AccountPlan, user: &str) -> Option<String> {
    match plan.record {
        AccountRecord { created: true, .. } => Some(format!("creates account {user}")),
        AccountRecord {
            added_docker_group: true,
            ..
        } => Some(format!(
            "grants existing account {user} the docker group (root-equivalent on this host)"
        )),
        _ => None,
    }
}

/// Take back a `docker` grant made to a reused account.
pub fn docker_group_revoke_steps(init: Init, user: &str) -> Vec<Step> {
    match init {
        Init::Launchd => Vec::new(),
        Init::Systemd => vec![run(&["gpasswd", "-d", user, "docker"], false)],
        Init::Openrc => vec![run(&["delgroup", user, "docker"], false)],
    }
}

/// Remove the runner's account (and, on Alpine, its group).
pub fn user_removal_steps(init: Init, user: &str) -> Vec<Step> {
    match init {
        Init::Launchd => Vec::new(),
        Init::Systemd => vec![run(&["userdel", user], false)],
        Init::Openrc => vec![
            run(&["deluser", user], false),
            run(&["delgroup", user], true),
        ],
    }
}

fn unit_mode(init: Init) -> u32 {
    match init {
        Init::Openrc => 0o755,
        Init::Launchd | Init::Systemd => 0o644,
    }
}

/// Everything an install needs that is not in the layout.
#[derive(Debug, Clone)]
pub struct InstallSpec<'a> {
    pub layout: &'a Layout,
    pub uid: u32,
    pub artifact: Artifact,
    pub config_yaml: String,
    pub unit: String,
    pub labels: Vec<String>,
    pub instance_url: String,
    pub scope: Scope,
    pub account: AccountPlan,
}

pub fn install_steps(spec: &InstallSpec<'_>) -> Vec<Step> {
    let l = spec.layout;
    let state = RunnerState {
        scope: spec.scope.label(),
        version: spec.artifact.version.clone(),
        runner_id: None,
        created_account: spec.account.record.created,
        added_docker_group: spec.account.record.added_docker_group,
    };
    // Recorded before the account is touched (the state file lives outside
    // the install dir), so an install that fails later still leaves uninstall
    // what it needs to undo the account and docker grant.
    let mut steps = vec![Step::RecordState {
        path: l.state_file(),
        state: state.clone(),
        runner_file: None,
    }];
    steps.extend(spec.account.steps.iter().cloned());
    if let (Some(user), false) = (&l.user, spec.account.steps.is_empty()) {
        steps.push(Step::ReconcileAccount {
            path: l.state_file(),
            user: user.clone(),
        });
    }
    // A managed Linux install dir is root:<account> 0750: the runner can read
    // its binary and config but write only `data/`.
    let dir_mode = if l.user.is_some() { 0o750 } else { 0o700 };
    steps.extend([
        Step::CreateDir {
            path: l.dir.clone(),
            mode: dir_mode,
        },
        Step::CreateDir {
            path: l.data.clone(),
            mode: 0o700,
        },
        Step::InstallBinary {
            artifact: spec.artifact.clone(),
            dest: l.binary.clone(),
        },
        Step::WriteFile {
            path: l.config.clone(),
            contents: spec.config_yaml.clone(),
            mode: 0o644,
            what: "act_runner config.yaml".to_string(),
        },
        Step::Register {
            binary: l.binary.clone(),
            config: l.config.clone(),
            dir: l.data.clone(),
            name: l.name.clone(),
            labels: spec.labels.clone(),
            instance_url: spec.instance_url.clone(),
            scope: spec.scope.clone(),
        },
        Step::Chmod {
            path: l.runner_file.clone(),
            mode: 0o600,
        },
        Step::RecordState {
            path: l.state_file(),
            state,
            runner_file: Some(l.runner_file.clone()),
        },
    ]);
    if let Some(user) = &l.user {
        steps.push(Step::Chown {
            path: l.data.clone(),
            user: Some(user.clone()),
            group: user.clone(),
            recursive: true,
        });
        steps.push(Step::Chown {
            path: l.dir.clone(),
            user: None,
            group: user.clone(),
            recursive: false,
        });
    }
    steps.push(Step::WriteFile {
        path: l.unit_path.clone(),
        contents: spec.unit.clone(),
        mode: unit_mode(l.init),
        what: format!("{:?} service definition", l.init).to_lowercase(),
    });
    steps.extend(service_steps(
        l,
        ServiceOp::Load,
        spec.uid,
        ServiceState::NotLoaded,
    ));
    steps
}

/// The scope to deregister under: the recorded one, checked against what the
/// caller passed. Disagreement is an error, not a guess.
pub fn deregister_scope(recorded: Option<&str>, given: Option<&str>) -> Result<(Scope, bool)> {
    match (recorded, given) {
        (Some(r), Some(g)) => {
            let (r, g): (Scope, Scope) = (r.parse()?, g.parse()?);
            if r != g {
                bail!(
                    "runner was registered under scope '{}', not '{}'",
                    r.label(),
                    g.label()
                );
            }
            Ok((r, true))
        }
        (Some(r), None) => Ok((r.parse()?, true)),
        (None, Some(g)) => Ok((g.parse()?, false)),
        (None, None) => Ok((Scope::Instance, false)),
    }
}

#[allow(clippy::too_many_arguments)]
pub fn uninstall_steps(
    layout: &Layout,
    uid: u32,
    state: ServiceState,
    runner_id: Option<i64>,
    scope: &Scope,
    scope_known: bool,
    keep_files: bool,
    account: AccountRecord,
) -> Vec<Step> {
    let mut steps = service_steps(layout, ServiceOp::Unload, uid, state);
    steps.push(Step::Remove {
        path: layout.unit_path.clone(),
        recursive: false,
    });
    if layout.init == Init::Systemd {
        steps.push(run(&["systemctl", "daemon-reload"], true));
    }
    if let Some(id) = runner_id {
        steps.push(Step::Deregister {
            runner_id: id,
            scope: scope.clone(),
            scope_known,
        });
    }
    // Account changes precede the removals, and the state file goes last: a
    // failed revoke or userdel stops here with the record intact to retry.
    if let Some(user) = &layout.user {
        if !keep_files && account.created {
            steps.extend(user_removal_steps(layout.init, user));
        }
        if account.added_docker_group && !account.created {
            steps.extend(docker_group_revoke_steps(layout.init, user));
        }
    }
    if !keep_files {
        steps.push(Step::Remove {
            path: layout.dir.clone(),
            recursive: true,
        });
        steps.push(Step::Remove {
            path: layout.state_file(),
            recursive: false,
        });
    }
    steps
}

/// `recorded` is the managed install's state, rewritten with the new version.
/// `check_major` guards a hand-placed install against a silent major jump.
pub fn upgrade_steps(
    layout: &Layout,
    uid: u32,
    state: ServiceState,
    artifact: &Artifact,
    recorded: Option<&RunnerState>,
    check_major: Option<u64>,
) -> Vec<Step> {
    let mut steps = Vec::new();
    if let Some(major) = check_major {
        steps.push(Step::CheckMajor {
            binary: layout.binary.clone(),
            major,
        });
    }
    steps.push(Step::InstallBinary {
        artifact: artifact.clone(),
        dest: layout.binary.clone(),
    });
    if let Some(st) = recorded {
        steps.push(Step::RecordState {
            path: layout.state_file(),
            state: RunnerState {
                version: artifact.version.clone(),
                ..st.clone()
            },
            runner_file: None,
        });
    }
    let op = if state == ServiceState::Running {
        ServiceOp::Restart
    } else {
        ServiceOp::Start
    };
    steps.extend(service_steps(layout, op, uid, state));
    steps
}

/// Fresh renders a heal may write. `None` for an install this plugin did not
/// create: rewriting a hand-placed file from our template would move its paths.
#[derive(Debug, Clone, Default)]
pub struct Rerender {
    pub unit: Option<String>,
    pub config: Option<String>,
}

/// Steps that address `findings`. Reload subsumes restart and start (it
/// re-reads the definition and starts the job), restart subsumes start.
pub fn heal_steps(
    layout: &Layout,
    uid: u32,
    state: ServiceState,
    findings: &[Finding],
    rerender: &Rerender,
) -> Vec<Step> {
    let wants = |r: Remedy| findings.iter().any(|f| f.remedy == r);
    let mut steps = Vec::new();
    let mut reload = wants(Remedy::Reload);

    if wants(Remedy::RewriteUnit) {
        match (&rerender.unit, layout.init) {
            (Some(unit), init) => steps.push(Step::WriteFile {
                path: layout.unit_path.clone(),
                contents: unit.clone(),
                mode: unit_mode(init),
                what: "service definition (re-rendered)".to_string(),
            }),
            (None, Init::Launchd) => steps.push(run(
                &[
                    "plutil",
                    "-replace",
                    "ProcessType",
                    "-string",
                    "Interactive",
                    &layout.unit_path.to_string_lossy(),
                ],
                false,
            )),
            (None, _) => {}
        }
        reload = true;
    }

    let mut restart = wants(Remedy::Restart);
    if wants(Remedy::RewriteConfig)
        && let Some(cfg) = &rerender.config
    {
        steps.push(Step::WriteFile {
            path: layout.config.clone(),
            contents: cfg.clone(),
            mode: 0o644,
            what: "act_runner config.yaml (re-rendered)".to_string(),
        });
        restart = true;
    }

    // Only launchd needs an unload/load to re-read its definition; systemd and
    // OpenRC re-read on restart (after a daemon-reload), and unloading them
    // would drop the boot-time enablement.
    let restart_op = if state == ServiceState::Running {
        ServiceOp::Restart
    } else {
        ServiceOp::Start
    };
    if reload {
        match layout.init {
            Init::Launchd => {
                steps.extend(service_steps(layout, ServiceOp::Unload, uid, state));
                steps.extend(service_steps(
                    layout,
                    ServiceOp::Load,
                    uid,
                    ServiceState::NotLoaded,
                ));
            }
            Init::Systemd => {
                steps.push(run(&["systemctl", "daemon-reload"], false));
                steps.extend(service_steps(layout, restart_op, uid, state));
            }
            Init::Openrc => steps.extend(service_steps(layout, restart_op, uid, state)),
        }
    } else if restart {
        steps.extend(service_steps(layout, restart_op, uid, state));
    } else if wants(Remedy::Start) {
        steps.extend(service_steps(layout, ServiceOp::Start, uid, state));
    }
    steps
}

/// Paths a step list writes under, so execution can refuse up front when the
/// plugin lacks permission instead of failing halfway.
pub fn touched_paths(steps: &[Step]) -> Vec<&Path> {
    steps
        .iter()
        .filter_map(|s| match s {
            Step::CreateDir { path, .. }
            | Step::WriteFile { path, .. }
            | Step::Remove { path, .. }
            | Step::Chmod { path, .. }
            | Step::Chown { path, .. }
            | Step::RecordState { path, .. }
            | Step::ReconcileAccount { path, .. } => Some(path.as_path()),
            Step::InstallBinary { dest, .. } => Some(dest.as_path()),
            _ => None,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runner::health::FindingKind;

    fn layout(init: Init) -> Layout {
        Layout::managed(init, "r1", Path::new("/Users/op"))
    }

    fn actions(steps: &[Step]) -> Vec<String> {
        steps
            .iter()
            .map(|s| {
                let c = s.to_change();
                format!("{} {}", c.action, c.target)
            })
            .collect()
    }

    fn finding(kind: FindingKind, remedy: Remedy) -> Finding {
        Finding {
            kind,
            detail: String::new(),
            remedy,
        }
    }

    fn artifact() -> Artifact {
        let src =
            crate::runner::release::Source::parse(crate::runner::release::DEFAULT_SOURCE, &[])
                .unwrap();
        crate::runner::release::artifact(&src, "4.1.0", "linux-amd64").unwrap()
    }

    fn spec(l: &Layout, account_steps: Vec<Step>) -> InstallSpec<'_> {
        InstallSpec {
            layout: l,
            uid: 501,
            artifact: artifact(),
            config_yaml: "cfg".into(),
            unit: "unit".into(),
            labels: vec!["macos:host".into()],
            instance_url: "https://gitea.test".into(),
            scope: Scope::Instance,
            account: AccountPlan {
                record: AccountRecord {
                    created: !account_steps.is_empty(),
                    added_docker_group: false,
                },
                steps: account_steps,
            },
        }
    }

    #[test]
    fn scope_parses_and_maps_to_api_paths() {
        assert_eq!("".parse::<Scope>().unwrap(), Scope::Instance);
        assert_eq!(
            "org:argyle-labs".parse::<Scope>().unwrap().runners_path(),
            "/orgs/argyle-labs/actions/runners"
        );
        assert_eq!(
            "repo:skey/homepage"
                .parse::<Scope>()
                .unwrap()
                .runners_path(),
            "/repos/skey/homepage/actions/runners"
        );
        assert!("org:".parse::<Scope>().is_err());
        assert!("repo:nope".parse::<Scope>().is_err());
    }

    #[test]
    fn scope_refuses_traversal_and_url_metacharacters() {
        for bad in [
            "org:..",
            "org:.",
            "org:a/b",
            "org:a?x",
            "org:a#x",
            "org:a%2F",
            "org:a b",
            "repo:../x",
            "repo:a/..",
            "repo:a/b/c",
            "repo:a/b?x",
            "repo:a/b#x",
        ] {
            assert!(bad.parse::<Scope>().is_err(), "accepted {bad:?}");
        }
        assert_eq!(encode_segment("a b/?#"), "a%20b%2F%3F%23");
        assert_eq!(
            Scope::Org("we/ird".into()).runners_path(),
            "/orgs/we%2Fird/actions/runners"
        );
    }

    #[test]
    fn install_plan_orders_binary_config_register_secure_unit_load() {
        let l = layout(Init::Launchd);
        let steps = install_steps(&spec(&l, vec![]));
        let a = actions(&steps);
        assert_eq!(a.len(), 10, "{a:?}");
        assert!(matches!(
            &steps[0],
            Step::RecordState { runner_file: None, state, .. } if state.runner_id.is_none()
        ));
        assert!(matches!(steps[1], Step::CreateDir { mode: 0o700, .. }));
        assert!(a[2].starts_with("create-dir ") && a[2].ends_with("/r1/data"));
        assert!(a[3].starts_with("install-binary ") && a[3].ends_with("/r1/act_runner"));
        assert!(a[4].starts_with("write ") && a[4].ends_with("config.yaml"));
        assert_eq!(a[5], "register gitea runner r1");
        assert!(a[6].starts_with("chmod ") && a[6].ends_with("/r1/data/.runner"));
        assert!(matches!(steps[6], Step::Chmod { mode: 0o600, .. }));
        assert!(a[7].starts_with("record "));
        assert!(a[8].ends_with("com.argyle.gitea-runner.r1.plist"));
        assert_eq!(
            a[9],
            "run launchctl bootstrap gui/501 /Users/op/Library/LaunchAgents/com.argyle.gitea-runner.r1.plist"
        );
        let register = steps[5].to_change().detail.unwrap();
        assert!(
            register.contains("GITEA_RUNNER_REGISTRATION_TOKEN"),
            "{register}"
        );
        match &steps[7] {
            Step::RecordState {
                path,
                state,
                runner_file,
            } => {
                assert!(
                    !path.starts_with(&l.dir),
                    "state must live outside the runner dir"
                );
                assert_eq!(state.scope, "instance");
                assert_eq!(runner_file.as_deref(), Some(l.runner_file.as_path()));
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn install_plan_shows_source_url_and_host() {
        let l = layout(Init::Launchd);
        let detail = install_steps(&spec(&l, vec![]))[3]
            .to_change()
            .detail
            .unwrap();
        assert!(detail.contains(
            "https://gitea.com/gitea/runner/releases/download/v4.1.0/gitea-runner-4.1.0-linux-amd64"
        ));
        assert!(detail.contains("host gitea.com"));
        assert!(
            detail.contains("b781d26b0f82269e73f6fae813a84c8ba5a215ea65cd7949c2fb3db5e0ccc8cf")
        );
    }

    /// The runner account may own only `data/`; everything that steers an
    /// admin action or gets executed stays root-owned.
    #[test]
    fn linux_install_ownership_per_path() {
        let l = layout(Init::Systemd);
        let acct = l.user.clone().unwrap();
        assert_eq!(acct, "gitea-runner-r1");
        let steps = install_steps(&spec(&l, vec![]));
        let chowns: Vec<(&Path, Option<&str>, &str, bool)> = steps
            .iter()
            .filter_map(|s| match s {
                Step::Chown {
                    path,
                    user,
                    group,
                    recursive,
                } => Some((path.as_path(), user.as_deref(), group.as_str(), *recursive)),
                _ => None,
            })
            .collect();
        assert_eq!(
            chowns,
            vec![
                (l.data.as_path(), Some(acct.as_str()), acct.as_str(), true),
                (l.dir.as_path(), None, acct.as_str(), false),
            ]
        );
        for root_owned in [&l.binary, &l.config, &l.unit_path, &l.state_file()] {
            assert!(
                !chowns.iter().any(|(p, u, _, rec)| u.is_some()
                    && (*p == root_owned.as_path() || (*rec && root_owned.starts_with(p)))),
                "{} would be owned by the runner",
                root_owned.display()
            );
        }
        for runner_owned in [
            &l.runner_file,
            &l.log,
            &l.data.join("work"),
            &l.data.join("cache"),
        ] {
            assert!(
                runner_owned.starts_with(&l.data),
                "{}",
                runner_owned.display()
            );
        }
        assert!(matches!(steps[1], Step::CreateDir { mode: 0o750, .. }));
    }

    #[test]
    fn linux_account_creation_steps() {
        let l = layout(Init::Systemd);
        let fresh = actions(&user_steps(
            Init::Systemd,
            "gitea-runner-r1",
            &l.data,
            true,
            false,
        ));
        assert!(
            fresh[0].starts_with("run useradd --system --user-group "),
            "{fresh:?}"
        );
        assert_eq!(fresh[1], "run usermod -aG docker gitea-runner-r1");
        let regroup = actions(&user_steps(
            Init::Systemd,
            "gitea-runner-r1",
            &l.data,
            false,
            true,
        ));
        assert!(
            regroup[0].starts_with("run useradd --system --gid gitea-runner-r1 "),
            "{regroup:?}"
        );

        let alpine = actions(&user_steps(
            Init::Openrc,
            "gitea-runner-r1",
            &l.data,
            false,
            false,
        ));
        assert_eq!(alpine[0], "run addgroup -S gitea-runner-r1");
        assert!(alpine[1].starts_with("run adduser -S -D -H"));
        let alpine_group_left = actions(&user_steps(
            Init::Openrc,
            "gitea-runner-r1",
            &l.data,
            false,
            true,
        ));
        assert_eq!(alpine_group_left.len(), 1, "{alpine_group_left:?}");
        assert!(alpine_group_left[0].starts_with("run adduser "));
        assert!(user_steps(Init::Launchd, "x", &l.data, true, false).is_empty());
    }

    #[test]
    fn openrc_unit_is_executable() {
        let l = layout(Init::Openrc);
        let steps = install_steps(&spec(&l, vec![]));
        let unit = steps
            .iter()
            .find_map(|s| match s {
                Step::WriteFile { mode, path, .. } if path.starts_with("/etc/init.d") => {
                    Some(*mode)
                }
                _ => None,
            })
            .unwrap();
        assert_eq!(unit, 0o755);
    }

    #[test]
    fn deregister_scope_prefers_the_record_and_rejects_disagreement() {
        assert_eq!(
            deregister_scope(Some("org:a"), None).unwrap(),
            (Scope::Org("a".into()), true)
        );
        assert_eq!(
            deregister_scope(Some("org:a"), Some("org:a")).unwrap(),
            (Scope::Org("a".into()), true)
        );
        assert!(deregister_scope(Some("org:a"), Some("instance")).is_err());
        assert_eq!(
            deregister_scope(None, Some("org:b")).unwrap(),
            (Scope::Org("b".into()), false)
        );
        assert_eq!(
            deregister_scope(None, None).unwrap(),
            (Scope::Instance, false)
        );
    }

    #[test]
    fn uninstall_plan_stops_removes_deregisters() {
        let l = layout(Init::Openrc);
        let steps = uninstall_steps(
            &l,
            0,
            ServiceState::Running,
            Some(7),
            &Scope::Instance,
            true,
            false,
            AccountRecord {
                created: true,
                added_docker_group: false,
            },
        );
        let a = actions(&steps);
        assert_eq!(
            a,
            vec![
                "run rc-service gitea-runner-r1 stop",
                "run rc-update del gitea-runner-r1 default",
                "remove-file /etc/init.d/gitea-runner-r1",
                "deregister gitea runner id 7",
                "run deluser gitea-runner-r1",
                "run delgroup gitea-runner-r1",
                "remove-dir /var/lib/gitea-runner/r1",
                "remove-file /var/lib/gitea-runner/.orca/r1.json",
            ]
        );
        assert!(matches!(
            steps[0],
            Step::Run {
                tolerate_failure: true,
                ..
            }
        ));
        let kept = uninstall_steps(
            &l,
            0,
            ServiceState::Stopped,
            None,
            &Scope::Instance,
            false,
            true,
            AccountRecord {
                created: true,
                added_docker_group: false,
            },
        );
        assert!(
            !actions(&kept)
                .iter()
                .any(|a| a.starts_with("remove-dir") || a.starts_with("deregister"))
        );
    }

    #[test]
    fn keep_files_keeps_the_account_that_owns_data() {
        let l = layout(Init::Systemd);
        let kept = actions(&uninstall_steps(
            &l,
            0,
            ServiceState::Running,
            Some(7),
            &Scope::Instance,
            true,
            true,
            AccountRecord {
                created: true,
                added_docker_group: false,
            },
        ));
        assert!(!kept.iter().any(|a| a.contains("userdel")), "{kept:?}");
        let removed = actions(&uninstall_steps(
            &l,
            0,
            ServiceState::Running,
            Some(7),
            &Scope::Instance,
            true,
            false,
            AccountRecord {
                created: true,
                added_docker_group: false,
            },
        ));
        assert_eq!(
            removed.last().unwrap(),
            "remove-file /var/lib/gitea-runner/.orca/r1.json"
        );
        let userdel = removed
            .iter()
            .position(|a| a == "run userdel gitea-runner-r1")
            .expect("userdel step");
        assert!(
            userdel
                < removed
                    .iter()
                    .position(|a| a.starts_with("remove-dir "))
                    .expect("remove-dir step"),
            "{removed:?}"
        );
    }

    #[test]
    fn only_an_account_the_plugin_created_is_removed() {
        let l = layout(Init::Openrc);
        let reused = actions(&uninstall_steps(
            &l,
            0,
            ServiceState::Running,
            Some(7),
            &Scope::Instance,
            true,
            false,
            AccountRecord {
                created: false,
                added_docker_group: false,
            },
        ));
        assert!(
            !reused
                .iter()
                .any(|a| a.contains("deluser") || a.contains("delgroup")),
            "{reused:?}"
        );
    }

    #[test]
    fn account_plan_table() {
        let home = Path::new("/var/lib/gitea-runner/r1/data");
        let u = Some("gitea-runner-r1");
        let facts = |user_exists, group_exists, in_docker_group| AccountFacts {
            user_exists,
            group_exists,
            in_docker_group,
        };
        // (init, docker, facts, expected actions, created, added_docker_group)
        type Case<'a> = (Init, bool, AccountFacts, Vec<&'a str>, bool, bool);
        let cases: Vec<Case> = vec![
            (
                Init::Systemd,
                true,
                facts(false, false, false),
                vec![
                    "run useradd --system --user-group",
                    "run usermod -aG docker gitea-runner-r1",
                ],
                true,
                false,
            ),
            (
                Init::Openrc,
                false,
                facts(false, true, false),
                vec!["run adduser -S -D -H"],
                true,
                false,
            ),
            (
                Init::Systemd,
                true,
                facts(true, true, false),
                vec!["run usermod -aG docker gitea-runner-r1"],
                false,
                true,
            ),
            (
                Init::Openrc,
                true,
                facts(true, true, false),
                vec!["run addgroup gitea-runner-r1 docker"],
                false,
                true,
            ),
            (
                Init::Systemd,
                true,
                facts(true, true, true),
                vec![],
                false,
                false,
            ),
            (
                Init::Systemd,
                false,
                facts(true, true, false),
                vec![],
                false,
                false,
            ),
        ];
        for (init, docker, f, want, created, added) in cases {
            let plan = account_plan(init, u, home, docker, f);
            let got = actions(&plan.steps);
            assert_eq!(got.len(), want.len(), "{init:?} {docker} {f:?}: {got:?}");
            for (g, w) in got.iter().zip(&want) {
                assert!(g.starts_with(w), "{init:?} {docker} {f:?}: {g} !~ {w}");
            }
            assert_eq!(plan.record.created, created, "{init:?} {docker} {f:?}");
            assert_eq!(
                plan.record.added_docker_group, added,
                "{init:?} {docker} {f:?}"
            );
        }
        assert_eq!(
            account_plan(Init::Launchd, None, home, false, facts(false, false, false)),
            AccountPlan::default()
        );
    }

    #[test]
    fn install_summary_names_the_docker_grant() {
        let grant = account_plan(
            Init::Systemd,
            Some("gitea-runner-r1"),
            Path::new("/x"),
            true,
            AccountFacts {
                user_exists: true,
                group_exists: true,
                in_docker_group: false,
            },
        );
        let line = account_summary(&grant, "gitea-runner-r1").unwrap();
        assert!(line.contains("docker group"), "{line}");
        assert_eq!(account_summary(&AccountPlan::default(), "u"), None);
    }

    #[test]
    fn install_records_what_it_did_to_the_account() {
        let l = layout(Init::Systemd);
        let reused = install_steps(&InstallSpec {
            account: account_plan(
                Init::Systemd,
                l.user.as_deref(),
                &l.data,
                true,
                AccountFacts {
                    user_exists: true,
                    group_exists: true,
                    in_docker_group: false,
                },
            ),
            ..spec(&l, vec![])
        });
        let state = reused
            .iter()
            .find_map(|s| match s {
                Step::RecordState { state, .. } => Some(state.clone()),
                _ => None,
            })
            .unwrap();
        assert!(!state.created_account);
        assert!(state.added_docker_group);
    }

    #[test]
    fn uninstall_revokes_a_docker_grant_only_on_a_reused_account() {
        let uninstall = |init, keep_files, created, added| {
            actions(&uninstall_steps(
                &layout(init),
                0,
                ServiceState::Running,
                Some(7),
                &Scope::Instance,
                true,
                keep_files,
                AccountRecord {
                    created,
                    added_docker_group: added,
                },
            ))
        };
        let sysd = uninstall(Init::Systemd, false, false, true);
        let revoke = sysd
            .iter()
            .position(|a| a == "run gpasswd -d gitea-runner-r1 docker")
            .expect("revoke step");
        assert_eq!(
            sysd.len() - 3,
            revoke,
            "revoke precedes both removals: {sysd:?}"
        );
        assert_eq!(
            sysd.last().unwrap(),
            "remove-file /var/lib/gitea-runner/.orca/r1.json"
        );
        assert!(!sysd.iter().any(|a| a.contains("userdel")));
        let kept = uninstall(Init::Openrc, true, false, true);
        assert_eq!(kept.last().unwrap(), "run delgroup gitea-runner-r1 docker");
        let created = uninstall(Init::Systemd, false, true, true);
        assert!(
            !created.iter().any(|a| a.contains("gpasswd")),
            "{created:?}"
        );
        let untouched = uninstall(Init::Systemd, false, false, false);
        assert!(
            !untouched
                .iter()
                .any(|a| a.contains("gpasswd") || a.contains("userdel"))
        );
    }

    #[test]
    fn account_state_is_recorded_before_the_account_is_touched() {
        let l = layout(Init::Systemd);
        let steps = install_steps(&InstallSpec {
            account: account_plan(
                Init::Systemd,
                l.user.as_deref(),
                &l.data,
                true,
                AccountFacts {
                    user_exists: true,
                    group_exists: true,
                    in_docker_group: false,
                },
            ),
            ..spec(&l, vec![])
        });
        let first_account = steps
            .iter()
            .position(|s| matches!(s, Step::Run { argv, .. } if argv[0] == "usermod"))
            .unwrap();
        let register = steps
            .iter()
            .position(|s| matches!(s, Step::Register { .. }))
            .unwrap();
        let records: Vec<(usize, &RunnerState, bool)> = steps
            .iter()
            .enumerate()
            .filter_map(|(i, s)| match s {
                Step::RecordState {
                    state, runner_file, ..
                } => Some((i, state, runner_file.is_some())),
                _ => None,
            })
            .collect();
        let (first, early, reads_runner) = records[0];
        assert!(first < first_account && first < register);
        assert!(!reads_runner && early.runner_id.is_none());
        assert!(early.added_docker_group && !early.created_account);
        let (last, late, reads_runner) = records[records.len() - 1];
        assert!(last > register && reads_runner && late.added_docker_group);
    }

    #[test]
    fn account_record_is_reconciled_right_after_the_account_steps() {
        let l = layout(Init::Systemd);
        let steps = install_steps(&spec(
            &l,
            user_steps(Init::Systemd, "gitea-runner-r1", &l.data, true, false),
        ));
        let a = actions(&steps);
        assert!(a[1].starts_with("run useradd "), "{a:?}");
        assert_eq!(a[2], "run usermod -aG docker gitea-runner-r1");
        assert!(
            matches!(&steps[3], Step::ReconcileAccount { user, .. } if user == "gitea-runner-r1")
        );
        assert!(a[4].starts_with("create-dir "), "{a:?}");
        assert!(
            matches!(&steps[0], Step::RecordState { state, runner_file: None, .. } if state.runner_id.is_none())
        );
        let none = install_steps(&spec(&l, vec![]));
        assert!(
            !none
                .iter()
                .any(|s| matches!(s, Step::ReconcileAccount { .. }))
        );
    }

    #[test]
    fn state_only_install_still_uninstalls_its_account_changes() {
        let l = layout(Init::Systemd);
        assert!(!l.dir.exists() && !l.config.exists());
        let a = actions(&uninstall_steps(
            &l,
            0,
            ServiceState::NotLoaded,
            None,
            &Scope::Instance,
            true,
            false,
            AccountRecord {
                created: false,
                added_docker_group: true,
            },
        ));
        let revoke = a
            .iter()
            .position(|x| x == "run gpasswd -d gitea-runner-r1 docker")
            .expect("revoke step");
        assert_eq!(
            a.last().unwrap(),
            "remove-file /var/lib/gitea-runner/.orca/r1.json"
        );
        assert!(revoke < a.len() - 1);
    }

    #[test]
    fn account_undo_steps_fail_hard_for_retry() {
        for s in docker_group_revoke_steps(Init::Systemd, "u")
            .iter()
            .chain(&docker_group_revoke_steps(Init::Openrc, "u"))
            .chain(&user_removal_steps(Init::Systemd, "u"))
            .chain(&user_removal_steps(Init::Openrc, "u")[..1])
        {
            assert!(
                matches!(
                    s,
                    Step::Run {
                        tolerate_failure: false,
                        ..
                    }
                ),
                "{s:?}"
            );
        }
    }

    #[test]
    fn account_record_still_applied() {
        let created = AccountRecord {
            created: true,
            added_docker_group: false,
        };
        let granted = AccountRecord {
            created: false,
            added_docker_group: true,
        };
        assert_eq!(granted.still_applied(true, false), AccountRecord::default());
        assert_eq!(
            created.still_applied(false, false),
            AccountRecord::default()
        );
        assert_eq!(granted.still_applied(true, true), granted);
    }

    #[test]
    fn old_state_without_account_fields_fails_safe() {
        let st: RunnerState = plugin_toolkit::serde_json::from_str(
            r#"{"scope":"instance","version":"4.1.0","runner_id":3}"#,
        )
        .unwrap();
        assert_eq!(
            AccountRecord::from_state(Some(&st)),
            AccountRecord::default()
        );
    }

    #[test]
    fn upgrade_plan_swaps_binary_records_version_then_restarts() {
        let l = layout(Init::Systemd);
        let st = RunnerState {
            scope: "instance".into(),
            version: "3.1.0".into(),
            runner_id: Some(7),
            created_account: true,
            added_docker_group: false,
        };
        let a = actions(&upgrade_steps(
            &l,
            0,
            ServiceState::Running,
            &artifact(),
            Some(&st),
            None,
        ));
        assert_eq!(a.len(), 3, "{a:?}");
        assert!(a[0].starts_with("install-binary"));
        assert_eq!(a[1], "record orca runner state");
        assert_eq!(a[2], "run systemctl restart gitea-runner-r1.service");
    }

    #[test]
    fn unmanaged_upgrade_checks_the_major_first() {
        let l = Layout::legacy_candidates(Init::Openrc, Path::new("/root"))[0].clone();
        let steps = upgrade_steps(&l, 0, ServiceState::Running, &artifact(), None, Some(4));
        assert!(matches!(steps[0], Step::CheckMajor { major: 4, .. }));
        assert!(actions(&steps)[1].starts_with("install-binary"));
    }

    #[test]
    fn openrc_restart_zaps_only_when_crashed() {
        let l = layout(Init::Openrc);
        let crashed = actions(&service_steps(
            &l,
            ServiceOp::Restart,
            0,
            ServiceState::Crashed,
        ));
        assert_eq!(
            crashed,
            vec![
                "run rc-service gitea-runner-r1 zap",
                "run rc-service gitea-runner-r1 start"
            ]
        );
        let running = actions(&service_steps(
            &l,
            ServiceOp::Restart,
            0,
            ServiceState::Running,
        ));
        assert_eq!(running, vec!["run rc-service gitea-runner-r1 restart"]);
    }

    #[test]
    fn heal_restarts_an_offline_runner() {
        let l = layout(Init::Launchd);
        let steps = heal_steps(
            &l,
            501,
            ServiceState::Running,
            &[finding(FindingKind::GiteaOffline, Remedy::Restart)],
            &Rerender::default(),
        );
        assert_eq!(
            actions(&steps),
            vec!["run launchctl kickstart -k gui/501/com.argyle.gitea-runner.r1"]
        );
    }

    #[test]
    fn heal_rewrites_a_throttled_plist_and_rebootstraps() {
        let l = layout(Init::Launchd);
        let steps = heal_steps(
            &l,
            501,
            ServiceState::Running,
            &[
                finding(FindingKind::ThrottledPriority, Remedy::RewriteUnit),
                finding(FindingKind::GiteaOffline, Remedy::Restart),
            ],
            &Rerender {
                unit: Some("<plist/>".into()),
                config: None,
            },
        );
        let a = actions(&steps);
        assert_eq!(a.len(), 3, "{a:?}");
        assert!(a[0].starts_with("write ") && a[0].ends_with(".plist"));
        assert_eq!(
            a[1],
            "run launchctl bootout gui/501/com.argyle.gitea-runner.r1"
        );
        assert!(a[2].starts_with("run launchctl bootstrap gui/501 "));
    }

    #[test]
    fn heal_patches_a_hand_placed_plist_in_place() {
        let l = Layout::legacy_candidates(Init::Launchd, Path::new("/Users/op"))[0].clone();
        let steps = heal_steps(
            &l,
            501,
            ServiceState::Running,
            &[finding(FindingKind::ThrottledPriority, Remedy::RewriteUnit)],
            &Rerender::default(),
        );
        let a = actions(&steps);
        assert!(a[0].starts_with("run plutil -replace ProcessType -string Interactive "));
        assert_eq!(
            a[1],
            "run launchctl bootout gui/501/com.argyle.gitea-act-runner"
        );
    }

    #[test]
    fn heal_reload_on_systemd_keeps_the_unit_enabled() {
        let l = layout(Init::Systemd);
        let steps = heal_steps(
            &l,
            0,
            ServiceState::Running,
            &[finding(FindingKind::ThrottledPriority, Remedy::RewriteUnit)],
            &Rerender {
                unit: Some("[Unit]".into()),
                config: None,
            },
        );
        let a = actions(&steps);
        assert!(a[0].ends_with("gitea-runner-r1.service"));
        assert_eq!(
            &a[1..],
            &[
                "run systemctl daemon-reload",
                "run systemctl restart gitea-runner-r1.service"
            ]
        );
        assert!(!a.iter().any(|x| x.contains("disable")));
    }

    #[test]
    fn heal_fixes_capacity_by_rewriting_config_and_restarting() {
        let l = layout(Init::Systemd);
        let steps = heal_steps(
            &l,
            0,
            ServiceState::Running,
            &[finding(
                FindingKind::HostCapacityUnsafe,
                Remedy::RewriteConfig,
            )],
            &Rerender {
                unit: None,
                config: Some("capacity: 1".into()),
            },
        );
        let a = actions(&steps);
        assert!(a[0].ends_with("config.yaml"));
        assert_eq!(a[1], "run systemctl restart gitea-runner-r1.service");
    }

    #[test]
    fn heal_starts_a_crashed_service_and_ignores_manual_findings() {
        let l = layout(Init::Openrc);
        let steps = heal_steps(
            &l,
            0,
            ServiceState::Crashed,
            &[
                finding(FindingKind::ServiceDown, Remedy::Start),
                finding(FindingKind::Disabled, Remedy::Manual),
            ],
            &Rerender::default(),
        );
        assert_eq!(
            actions(&steps),
            vec![
                "run rc-service gitea-runner-r1 zap",
                "run rc-service gitea-runner-r1 start"
            ]
        );
        assert!(heal_steps(&l, 0, ServiceState::Running, &[], &Rerender::default()).is_empty());
    }
}
