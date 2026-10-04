//! Ordered steps for every mutating runner verb.
//!
//! A verb builds its step list once; a dry run renders it as the plan and an
//! execute runs exactly that list. The plan an operator approves is therefore
//! the work that happens, not a separate description of it.

use std::path::{Path, PathBuf};

use plugin_toolkit::contract::plan::PlannedChange;
use plugin_toolkit::prelude::*;

use super::health::{Finding, Remedy, ServiceState};
use super::layout::{Init, Layout};

/// Who a runner serves, which picks the Gitea endpoints that mint its
/// registration token and delete it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Scope {
    Instance,
    Org(String),
    Repo(String, String),
}

impl std::str::FromStr for Scope {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self> {
        let s = s.trim();
        if s.is_empty() || s == "instance" {
            return Ok(Scope::Instance);
        }
        if let Some(org) = s.strip_prefix("org:").filter(|o| !o.is_empty()) {
            return Ok(Scope::Org(org.to_string()));
        }
        if let Some((owner, repo)) = s.strip_prefix("repo:").and_then(|r| r.split_once('/'))
            && !owner.is_empty()
            && !repo.is_empty()
        {
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
            Scope::Org(o) => format!("/orgs/{o}/actions/runners"),
            Scope::Repo(o, r) => format!("/repos/{o}/{r}/actions/runners"),
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    CreateDir(PathBuf),
    /// Resolve, download and checksum-verify the release, then atomically
    /// replace `dest`.
    InstallBinary {
        version: String,
        dest: PathBuf,
    },
    WriteFile {
        path: PathBuf,
        contents: String,
        mode: u32,
        what: String,
    },
    /// `act_runner register` with a registration token minted at run time, so
    /// the token never appears in a plan.
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
            Step::CreateDir(p) => PlannedChange::new(p.display().to_string(), "create-dir"),
            Step::InstallBinary { version, dest } => {
                PlannedChange::new(dest.display().to_string(), "install-binary").with_detail(
                    format!("download runner {version}, verify sha256 against the release checksum, replace atomically"),
                )
            }
            Step::WriteFile { path, mode, what, .. } => {
                PlannedChange::new(path.display().to_string(), "write")
                    .with_detail(format!("{what} (mode {mode:o})"))
            }
            Step::Register {
                name,
                labels,
                instance_url,
                scope,
                ..
            } => PlannedChange::new(format!("gitea runner {name}"), "register").with_detail(format!(
                "mint a {} registration token, register against {instance_url} with labels [{}]",
                scope.label(),
                labels.join(", ")
            )),
            Step::Run { argv, tolerate_failure } => {
                let change = PlannedChange::new(argv.join(" "), "run");
                if *tolerate_failure {
                    change.with_detail("failure tolerated")
                } else {
                    change
                }
            }
            Step::Deregister { runner_id, scope } => {
                PlannedChange::new(format!("gitea runner id {runner_id}"), "deregister")
                    .with_detail(format!("DELETE {}/{runner_id}", scope.runners_path()))
            }
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
    pub version: &'a str,
    pub config_yaml: String,
    pub unit: String,
    pub labels: Vec<String>,
    pub instance_url: String,
    pub scope: Scope,
}

pub fn install_steps(spec: &InstallSpec<'_>) -> Vec<Step> {
    let l = spec.layout;
    let mut steps = vec![
        Step::CreateDir(l.dir.clone()),
        Step::InstallBinary {
            version: spec.version.to_string(),
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
            dir: l.dir.clone(),
            name: l.name.clone(),
            labels: spec.labels.clone(),
            instance_url: spec.instance_url.clone(),
            scope: spec.scope.clone(),
        },
        Step::WriteFile {
            path: l.unit_path.clone(),
            contents: spec.unit.clone(),
            mode: unit_mode(l.init),
            what: format!("{:?} service definition", l.init).to_lowercase(),
        },
    ];
    steps.extend(service_steps(
        l,
        ServiceOp::Load,
        spec.uid,
        ServiceState::NotLoaded,
    ));
    steps
}

pub fn uninstall_steps(
    layout: &Layout,
    uid: u32,
    state: ServiceState,
    runner_id: Option<i64>,
    scope: &Scope,
    keep_files: bool,
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
        });
    }
    if !keep_files {
        steps.push(Step::Remove {
            path: layout.dir.clone(),
            recursive: true,
        });
    }
    steps
}

pub fn upgrade_steps(layout: &Layout, uid: u32, state: ServiceState, version: &str) -> Vec<Step> {
    let mut steps = vec![Step::InstallBinary {
        version: version.to_string(),
        dest: layout.binary.clone(),
    }];
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
            Step::CreateDir(p) => Some(p.as_path()),
            Step::InstallBinary { dest, .. } => Some(dest.as_path()),
            Step::WriteFile { path, .. } | Step::Remove { path, .. } => Some(path.as_path()),
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
    fn install_plan_orders_binary_config_register_unit_load() {
        let l = layout(Init::Launchd);
        let steps = install_steps(&InstallSpec {
            layout: &l,
            uid: 501,
            version: "4.1.0",
            config_yaml: "cfg".into(),
            unit: "plist".into(),
            labels: vec!["macos:host".into()],
            instance_url: "http://gitea.test:3000".into(),
            scope: Scope::Instance,
        });
        let a = actions(&steps);
        assert_eq!(a.len(), 6, "{a:?}");
        assert!(a[0].starts_with("create-dir "));
        assert!(a[1].starts_with("install-binary ") && a[1].ends_with("/r1/act_runner"));
        assert!(a[2].starts_with("write ") && a[2].ends_with("config.yaml"));
        assert_eq!(a[3], "register gitea runner r1");
        assert!(a[4].ends_with("com.argyle.gitea-runner.r1.plist"));
        assert_eq!(
            a[5],
            "run launchctl bootstrap gui/501 /Users/op/Library/LaunchAgents/com.argyle.gitea-runner.r1.plist"
        );
        let register = steps[3].to_change().detail.unwrap();
        assert!(register.contains("instance registration token"));
        assert!(!register.to_lowercase().contains("token="), "{register}");
    }

    #[test]
    fn install_plan_on_systemd_reloads_and_enables() {
        let l = layout(Init::Systemd);
        let steps = install_steps(&InstallSpec {
            layout: &l,
            uid: 0,
            version: "latest",
            config_yaml: String::new(),
            unit: String::new(),
            labels: vec![],
            instance_url: "http://g".into(),
            scope: Scope::Org("argyle-labs".into()),
        });
        let a = actions(&steps);
        assert_eq!(a[a.len() - 2], "run systemctl daemon-reload");
        assert_eq!(
            a[a.len() - 1],
            "run systemctl enable --now gitea-runner-r1.service"
        );
        match &steps[4] {
            Step::WriteFile { mode, .. } => assert_eq!(*mode, 0o644),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn openrc_unit_is_executable() {
        let l = layout(Init::Openrc);
        let steps = install_steps(&InstallSpec {
            layout: &l,
            uid: 0,
            version: "latest",
            config_yaml: String::new(),
            unit: String::new(),
            labels: vec![],
            instance_url: "http://g".into(),
            scope: Scope::Instance,
        });
        match &steps[4] {
            Step::WriteFile { mode, path, .. } => {
                assert_eq!(*mode, 0o755);
                assert_eq!(path, &PathBuf::from("/etc/init.d/gitea-runner-r1"));
            }
            other => panic!("unexpected {other:?}"),
        }
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
            false,
        );
        let a = actions(&steps);
        assert_eq!(
            a,
            vec![
                "run rc-service gitea-runner-r1 stop",
                "run rc-update del gitea-runner-r1 default",
                "remove-file /etc/init.d/gitea-runner-r1",
                "deregister gitea runner id 7",
                "remove-dir /var/lib/gitea-runner/r1",
            ]
        );
        assert!(matches!(
            steps[0],
            Step::Run {
                tolerate_failure: true,
                ..
            }
        ));
        let kept = uninstall_steps(&l, 0, ServiceState::Stopped, None, &Scope::Instance, true);
        assert!(
            !actions(&kept)
                .iter()
                .any(|a| a.starts_with("remove-dir") || a.starts_with("deregister"))
        );
    }

    #[test]
    fn upgrade_plan_swaps_binary_then_restarts() {
        let l = layout(Init::Systemd);
        let a = actions(&upgrade_steps(&l, 0, ServiceState::Running, "4.1.0"));
        assert_eq!(a.len(), 2);
        assert!(a[0].starts_with("install-binary"));
        assert_eq!(a[1], "run systemctl restart gitea-runner-r1.service");
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
