//! Runner health classification — pure, so every rule is unit-tested.
//!
//! Inputs come from two places that can disagree: the host (is the service
//! running? how is it configured?) and Gitea (does it see the runner polling?).
//! The disagreements are the interesting failures: a process that is up but
//! has stopped fetching tasks looks healthy to the service manager and dead to
//! Gitea.

use plugin_toolkit::prelude::*;

use super::layout::Mode;

/// What the service manager reports for the runner.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum ServiceState {
    Running,
    Stopped,
    /// OpenRC `crashed` / systemd `failed`: it died and was not restarted.
    Crashed,
    /// launchd has no job by this label loaded.
    NotLoaded,
    Unknown,
}

/// Gitea's view of one runner.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct GiteaRunnerView {
    pub id: i64,
    pub name: String,
    /// Gitea's status string (`offline`, `idle`, `active`, ...).
    pub status: String,
    pub online: bool,
    pub busy: bool,
    pub disabled: bool,
    /// Label names (the `runs-on` keys).
    pub labels: Vec<String>,
}

impl GiteaRunnerView {
    /// Gitea reports `offline` once a runner has not polled for about a minute;
    /// every other status means it is polling.
    pub fn is_online_status(status: &str) -> bool {
        !status.is_empty() && !status.eq_ignore_ascii_case("offline")
    }
}

/// A job Gitea is holding for a runner.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct WaitingJob {
    pub id: i64,
    pub labels: Vec<String>,
    pub waited_secs: i64,
}

/// What Gitea said about this runner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GiteaSide {
    Found(GiteaRunnerView),
    /// Gitea answered and has no runner with this id/name.
    Missing,
    /// Gitea could not be asked (unreachable, or the token lacks admin scope).
    Unavailable(String),
}

/// launchd scheduling class: what the plist asks for, and what the loaded job
/// actually runs with. They differ until the job is booted out and back in.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LaunchdPriority {
    pub plist_process_type: Option<String>,
    pub loaded_spawn_type: Option<String>,
}

/// Everything health classification looks at.
#[derive(Debug, Clone)]
pub struct Observation {
    pub service: ServiceState,
    pub mode: Option<Mode>,
    pub capacity: Option<u32>,
    pub launchd: Option<LaunchdPriority>,
    pub gitea: GiteaSide,
    pub waiting_jobs: Vec<WaitingJob>,
    /// Newest "failed to fetch task" log line, as evidence.
    pub last_fetch_error: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum FindingKind {
    ServiceDown,
    /// Process running, Gitea says offline: the fetch loop is dead.
    GiteaOffline,
    /// Gitea says online and idle while a job it can run sits waiting.
    Starved,
    /// launchd plist has no `ProcessType=Interactive`.
    ThrottledPriority,
    /// Plist is right but the loaded job still runs at the old class.
    PriorityNotApplied,
    /// Host executor configured with capacity > 1.
    HostCapacityUnsafe,
    /// Local registration exists but Gitea no longer knows the runner.
    NotRegistered,
    Disabled,
    GiteaUnavailable,
}

/// What fixes a finding.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "camelCase")]
pub enum Remedy {
    /// Bring a stopped/crashed service back up.
    Start,
    Restart,
    /// Unload and reload the service definition (launchd re-reads the plist).
    Reload,
    /// Re-render the service unit, then reload.
    RewriteUnit,
    /// Re-render config.yaml, then restart.
    RewriteConfig,
    /// Needs an operator: re-register, re-enable, or fix credentials.
    Manual,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct Finding {
    pub kind: FindingKind,
    pub detail: String,
    pub remedy: Remedy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum HealthStatus {
    Healthy,
    /// Working, but misconfigured in a way that costs throughput or safety.
    Degraded,
    /// Not taking work.
    Down,
    /// Could not be judged.
    Unknown,
}

/// Default for how long a matching job may wait on an idle online runner
/// before the runner counts as starved.
pub const DEFAULT_STALL_AFTER_SECS: i64 = 600;

fn finding(kind: FindingKind, remedy: Remedy, detail: impl Into<String>) -> Finding {
    Finding {
        kind,
        detail: detail.into(),
        remedy,
    }
}

fn job_fits(job: &WaitingJob, runner_labels: &[String]) -> bool {
    !job.labels.is_empty() && job.labels.iter().all(|l| runner_labels.contains(l))
}

/// Classify one runner.
pub fn classify(obs: &Observation, stall_after_secs: i64) -> (HealthStatus, Vec<Finding>) {
    let mut findings = Vec::new();
    let running = obs.service == ServiceState::Running;

    match obs.service {
        ServiceState::Running | ServiceState::Unknown => {}
        state => findings.push(finding(
            FindingKind::ServiceDown,
            Remedy::Start,
            format!("service is {state:?}"),
        )),
    }

    let evidence = obs
        .last_fetch_error
        .as_deref()
        .map(|l| format!("; last fetch error: {l}"))
        .unwrap_or_default();

    match &obs.gitea {
        GiteaSide::Found(g) => {
            if g.disabled {
                findings.push(finding(
                    FindingKind::Disabled,
                    Remedy::Manual,
                    "runner is disabled in Gitea",
                ));
            }
            if running && !g.online {
                findings.push(finding(
                    FindingKind::GiteaOffline,
                    Remedy::Restart,
                    format!(
                        "process is running but Gitea reports '{}' — it has stopped polling for tasks{evidence}",
                        g.status
                    ),
                ));
            }
            if running && g.online && !g.busy && !g.disabled {
                let starved: Vec<&WaitingJob> = obs
                    .waiting_jobs
                    .iter()
                    .filter(|j| j.waited_secs >= stall_after_secs && job_fits(j, &g.labels))
                    .collect();
                if let Some(oldest) = starved.iter().max_by_key(|j| j.waited_secs) {
                    findings.push(finding(
                        FindingKind::Starved,
                        Remedy::Restart,
                        format!(
                            "online and idle while {} matching job(s) wait; oldest #{} waiting {}s{evidence}",
                            starved.len(),
                            oldest.id,
                            oldest.waited_secs
                        ),
                    ));
                }
            }
        }
        GiteaSide::Missing => findings.push(finding(
            FindingKind::NotRegistered,
            Remedy::Manual,
            "Gitea has no runner matching the local registration; reinstall to re-register",
        )),
        GiteaSide::Unavailable(why) => findings.push(finding(
            FindingKind::GiteaUnavailable,
            Remedy::Manual,
            format!("could not read Gitea's runner list: {why}"),
        )),
    }

    if let Some(ld) = &obs.launchd {
        let interactive = |s: &str| s.to_ascii_lowercase().contains("interactive");
        match ld.plist_process_type.as_deref() {
            Some(pt) if interactive(pt) => {
                if let Some(spawn) = ld.loaded_spawn_type.as_deref()
                    && !interactive(spawn)
                {
                    findings.push(finding(
                        FindingKind::PriorityNotApplied,
                        Remedy::Reload,
                        format!(
                            "plist sets ProcessType=Interactive but the loaded job runs as '{spawn}'; launchd only re-reads it on bootout + bootstrap"
                        ),
                    ));
                }
            }
            other => findings.push(finding(
                FindingKind::ThrottledPriority,
                Remedy::RewriteUnit,
                format!(
                    "plist ProcessType is {}; launchd throttles it to background priority (30-minute builds measured on mint)",
                    other.unwrap_or("unset")
                ),
            )),
        }
    }

    if obs.mode == Some(Mode::Host)
        && let Some(cap) = obs.capacity
        && cap > 1
    {
        findings.push(finding(
            FindingKind::HostCapacityUnsafe,
            Remedy::RewriteConfig,
            format!(
                "host executor with capacity {cap}: concurrent jobs share one work tree and corrupt each other's builds"
            ),
        ));
    }

    let has = |k: FindingKind| findings.iter().any(|f| f.kind == k);
    let status = if has(FindingKind::ServiceDown)
        || has(FindingKind::GiteaOffline)
        || has(FindingKind::Starved)
        || has(FindingKind::NotRegistered)
        || has(FindingKind::Disabled)
    {
        HealthStatus::Down
    } else if has(FindingKind::GiteaUnavailable) {
        HealthStatus::Unknown
    } else if findings.is_empty() {
        HealthStatus::Healthy
    } else {
        HealthStatus::Degraded
    };
    (status, findings)
}

/// Infer the executor mode from act_runner label specs (`name:host` vs
/// `name:docker://image`), for installs this plugin did not create.
pub fn mode_from_labels(labels: &[String]) -> Option<Mode> {
    let schemes: Vec<&str> = labels.iter().filter_map(|l| l.split(':').nth(1)).collect();
    if schemes.is_empty() {
        None
    } else if schemes.iter().all(|s| *s == "host") {
        Some(Mode::Host)
    } else {
        Some(Mode::Docker)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gitea(status: &str, busy: bool) -> GiteaSide {
        GiteaSide::Found(GiteaRunnerView {
            id: 3,
            name: "mint".into(),
            status: status.into(),
            online: GiteaRunnerView::is_online_status(status),
            busy,
            disabled: false,
            labels: vec!["macos".into(), "arm64".into(), "self-hosted".into()],
        })
    }

    fn obs(service: ServiceState, g: GiteaSide) -> Observation {
        Observation {
            service,
            mode: Some(Mode::Host),
            capacity: Some(1),
            launchd: Some(LaunchdPriority {
                plist_process_type: Some("Interactive".into()),
                loaded_spawn_type: Some("interactive (4)".into()),
            }),
            gitea: g,
            waiting_jobs: vec![],
            last_fetch_error: None,
        }
    }

    fn kinds(f: &[Finding]) -> Vec<FindingKind> {
        f.iter().map(|f| f.kind).collect()
    }

    #[test]
    fn healthy_runner_has_no_findings() {
        let (s, f) = classify(&obs(ServiceState::Running, gitea("idle", false)), 600);
        assert_eq!(s, HealthStatus::Healthy);
        assert!(f.is_empty(), "{f:?}");
    }

    #[test]
    fn running_process_that_gitea_sees_offline_is_down_and_restarted() {
        let mut o = obs(ServiceState::Running, gitea("offline", false));
        o.last_fetch_error = Some("connection reset by peer".into());
        let (s, f) = classify(&o, 600);
        assert_eq!(s, HealthStatus::Down);
        assert_eq!(kinds(&f), vec![FindingKind::GiteaOffline]);
        assert_eq!(f[0].remedy, Remedy::Restart);
        assert!(f[0].detail.contains("connection reset by peer"));
    }

    #[test]
    fn stopped_service_reports_down_once_not_also_offline() {
        let (s, f) = classify(&obs(ServiceState::Crashed, gitea("offline", false)), 600);
        assert_eq!(s, HealthStatus::Down);
        assert_eq!(kinds(&f), vec![FindingKind::ServiceDown]);
        assert_eq!(f[0].remedy, Remedy::Start);
    }

    #[test]
    fn idle_online_runner_with_an_old_matching_job_is_starved() {
        let mut o = obs(ServiceState::Running, gitea("idle", false));
        o.waiting_jobs = vec![
            WaitingJob {
                id: 1,
                labels: vec!["ubuntu-latest".into()],
                waited_secs: 9_000,
            },
            WaitingJob {
                id: 2,
                labels: vec!["macos".into()],
                waited_secs: 30,
            },
            WaitingJob {
                id: 3,
                labels: vec!["macos".into(), "arm64".into()],
                waited_secs: 21_600,
            },
        ];
        let (s, f) = classify(&o, 600);
        assert_eq!(s, HealthStatus::Down);
        assert_eq!(kinds(&f), vec![FindingKind::Starved]);
        assert!(f[0].detail.contains("#3"), "{}", f[0].detail);
    }

    #[test]
    fn busy_runner_is_not_starved_by_a_queue() {
        let mut o = obs(ServiceState::Running, gitea("active", true));
        o.waiting_jobs = vec![WaitingJob {
            id: 1,
            labels: vec!["macos".into()],
            waited_secs: 9_000,
        }];
        assert_eq!(classify(&o, 600).0, HealthStatus::Healthy);
    }

    #[test]
    fn missing_process_type_is_throttled() {
        let mut o = obs(ServiceState::Running, gitea("idle", false));
        o.launchd = Some(LaunchdPriority {
            plist_process_type: None,
            loaded_spawn_type: Some("daemon (3)".into()),
        });
        let (s, f) = classify(&o, 600);
        assert_eq!(s, HealthStatus::Degraded);
        assert_eq!(kinds(&f), vec![FindingKind::ThrottledPriority]);
        assert_eq!(f[0].remedy, Remedy::RewriteUnit);
    }

    #[test]
    fn interactive_plist_not_yet_reloaded_is_flagged() {
        // mint, 2026-10-03: plist fixed with plutil, job never rebootstrapped.
        let mut o = obs(ServiceState::Running, gitea("idle", false));
        o.launchd = Some(LaunchdPriority {
            plist_process_type: Some("Interactive".into()),
            loaded_spawn_type: Some("daemon (3)".into()),
        });
        let (s, f) = classify(&o, 600);
        assert_eq!(s, HealthStatus::Degraded);
        assert_eq!(kinds(&f), vec![FindingKind::PriorityNotApplied]);
        assert_eq!(f[0].remedy, Remedy::Reload);
    }

    #[test]
    fn host_capacity_above_one_is_flagged() {
        let mut o = obs(ServiceState::Running, gitea("idle", false));
        o.capacity = Some(3);
        let (s, f) = classify(&o, 600);
        assert_eq!(s, HealthStatus::Degraded);
        assert_eq!(kinds(&f), vec![FindingKind::HostCapacityUnsafe]);
        o.mode = Some(Mode::Docker);
        assert_eq!(classify(&o, 600).0, HealthStatus::Healthy);
    }

    #[test]
    fn gitea_unreachable_is_unknown_not_healthy() {
        let (s, f) = classify(
            &obs(ServiceState::Running, GiteaSide::Unavailable("403".into())),
            600,
        );
        assert_eq!(s, HealthStatus::Unknown);
        assert_eq!(kinds(&f), vec![FindingKind::GiteaUnavailable]);
    }

    #[test]
    fn deleted_registration_is_down_and_manual() {
        let (s, f) = classify(&obs(ServiceState::Running, GiteaSide::Missing), 600);
        assert_eq!(s, HealthStatus::Down);
        assert_eq!(f[0].remedy, Remedy::Manual);
    }

    #[test]
    fn mode_is_inferred_from_label_schemes() {
        assert_eq!(
            mode_from_labels(&["macos:host".into(), "arm64:host".into()]),
            Some(Mode::Host)
        );
        assert_eq!(
            mode_from_labels(&["ubuntu-latest:docker://node:20".into()]),
            Some(Mode::Docker)
        );
        assert_eq!(mode_from_labels(&["bare".into()]), None);
    }
}
