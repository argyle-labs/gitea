//! The host this plugin process runs on: who it runs as, which runners are
//! installed here, and what state each one is in.
//!
//! Everything here is LOCAL. Acting on a runner on another host means orca
//! routing the `gitea.runner.*` call to the gitea plugin on that host; the
//! plugin has no capability to reach across hosts itself.

use std::path::{Path, PathBuf};
use std::time::Duration;

use plugin_toolkit::prelude::*;
use plugin_toolkit::process::Command;

use super::health::{ServiceState, mode_from_labels};
use super::layout::{Init, Layout, Mode, managed_root};
use super::render::{config_capacity, plist_process_type};

const CMD_TIMEOUT: Duration = Duration::from_secs(120);
const LOG_TAIL_BYTES: u64 = 64 * 1024;

#[derive(Debug, Clone)]
pub struct LocalHost {
    pub init: Init,
    pub home: PathBuf,
    pub uid: u32,
}

#[derive(Debug, Clone)]
pub struct CmdOut {
    pub ok: bool,
    pub code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
}

impl LocalHost {
    pub fn current() -> Result<Self> {
        let init = Init::detect().ok_or_else(|| {
            anyhow!("no supported service manager on this host (need launchd, systemd or OpenRC)")
        })?;
        let home = std::env::var_os("HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/root"));
        let uid = effective_uid(&home)?;
        Ok(Self { init, home, uid })
    }

    pub fn is_root(&self) -> bool {
        self.uid == 0
    }

    /// Why this process cannot write `paths`, if it cannot. Linux runner
    /// layouts live under `/etc` and `/var/lib`; a non-root orca daemon has no
    /// way to write them, and orca offers plugins no privileged seam for it.
    pub fn write_blocker(&self, paths: &[&Path]) -> Option<String> {
        if self.is_root() {
            return None;
        }
        let outside: Vec<String> = paths
            .iter()
            .filter(|p| !p.starts_with(&self.home))
            .map(|p| p.display().to_string())
            .collect();
        (!outside.is_empty()).then(|| {
            format!(
                "this plugin runs as uid {} and would need root to write {}; orca has no privileged \
                 service-install seam for plugins yet (see the PR's orca-gap list)",
                self.uid,
                outside.join(", ")
            )
        })
    }

    pub async fn run(&self, argv: &[String], cwd: Option<&Path>) -> Result<CmdOut> {
        let (prog, args) = argv.split_first().ok_or_else(|| anyhow!("empty command"))?;
        let mut cmd = Command::new(prog).args(args);
        if let Some(dir) = cwd {
            cmd = cmd.current_dir(dir);
        }
        let out = plugin_toolkit::time::timeout(CMD_TIMEOUT, cmd.output())
            .await
            .ok_or_else(|| anyhow!("`{prog}` timed out after {}s", CMD_TIMEOUT.as_secs()))?
            .with_context(|| format!("spawn `{prog}`"))?;
        Ok(CmdOut {
            ok: out.status.success,
            code: out.status.code,
            stdout: String::from_utf8_lossy(&out.stdout).trim().to_string(),
            stderr: String::from_utf8_lossy(&out.stderr).trim().to_string(),
        })
    }

    /// Runner installs on this host: managed ones under the managed root, plus
    /// hand-placed installs at the fleet's historical paths.
    pub fn discover(&self) -> Vec<Layout> {
        let mut found = Vec::new();
        if let Ok(entries) = std::fs::read_dir(managed_root(self.init, &self.home)) {
            let mut names: Vec<String> = entries
                .flatten()
                .filter(|e| e.path().is_dir())
                .filter_map(|e| e.file_name().to_str().map(str::to_string))
                .collect();
            names.sort();
            found.extend(
                names
                    .iter()
                    .map(|n| Layout::managed(self.init, n, &self.home))
                    .filter(|l| l.config.exists() || l.runner_file.exists()),
            );
        }
        for mut legacy in Layout::legacy_candidates(self.init, &self.home) {
            if legacy.runner_file.exists() || legacy.unit_path.exists() {
                legacy.name = read_registration(&legacy.runner_file)
                    .map(|r| r.name)
                    .unwrap_or_else(|| legacy.service.clone());
                found.push(legacy);
            }
        }
        found
    }

    /// Find the install for runner `name`.
    pub fn find(&self, name: &str) -> Option<Layout> {
        self.discover().into_iter().find(|l| l.name == name)
    }

    /// The service manager's view: state, plus launchd's loaded spawn type.
    pub async fn service_state(&self, layout: &Layout) -> (ServiceState, Option<String>) {
        let argv: Vec<String> = match layout.init {
            Init::Launchd => vec![
                "launchctl".into(),
                "print".into(),
                layout.launchd_target(self.uid),
            ],
            Init::Systemd => vec![
                "systemctl".into(),
                "is-active".into(),
                layout.service.clone(),
            ],
            Init::Openrc => {
                if !layout.unit_path.exists() {
                    return (ServiceState::NotLoaded, None);
                }
                vec!["rc-service".into(), layout.service.clone(), "status".into()]
            }
        };
        let Ok(out) = self.run(&argv, None).await else {
            return (ServiceState::Unknown, None);
        };
        match layout.init {
            Init::Launchd if !out.ok => (ServiceState::NotLoaded, None),
            Init::Launchd => parse_launchctl_print(&out.stdout),
            Init::Systemd => (parse_systemctl_active(&out.stdout), None),
            Init::Openrc => (
                parse_openrc_status(&format!("{}\n{}", out.stdout, out.stderr)),
                None,
            ),
        }
    }

    pub async fn binary_version(&self, binary: &Path) -> Option<String> {
        if !binary.exists() {
            return None;
        }
        let out = self
            .run(&[binary.display().to_string(), "--version".into()], None)
            .await
            .ok()?;
        out.ok.then(|| parse_version(&out.stdout)).flatten()
    }

    pub async fn inspect(&self, layout: &Layout) -> LocalInstall {
        let reg = read_registration(&layout.runner_file);
        let config = std::fs::read_to_string(&layout.config).ok();
        let (service_state, loaded_spawn_type) = self.service_state(layout).await;
        let process_type = (layout.init == Init::Launchd)
            .then(|| std::fs::read_to_string(&layout.unit_path).ok())
            .flatten()
            .and_then(|p| plist_process_type(&p));
        let labels = reg.as_ref().map(|r| r.labels.clone()).unwrap_or_default();
        LocalInstall {
            name: layout.name.clone(),
            managed: layout.managed,
            init: layout.init,
            dir: layout.dir.display().to_string(),
            binary: layout.binary.display().to_string(),
            service: layout.service.clone(),
            unit_path: layout.unit_path.display().to_string(),
            version: self.binary_version(&layout.binary).await,
            mode: mode_from_labels(&labels),
            capacity: config.as_deref().and_then(config_capacity),
            registered_id: reg.as_ref().map(|r| r.id),
            address: reg.as_ref().map(|r| r.address.clone()),
            labels,
            service_state,
            process_type,
            loaded_spawn_type,
            last_fetch_error: read_tail(&layout.log).as_deref().and_then(last_fetch_error),
        }
    }
}

/// One install on this host as the host sees it.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct LocalInstall {
    pub name: String,
    /// False for a hand-placed install found at a historical path.
    pub managed: bool,
    pub init: Init,
    pub dir: String,
    pub binary: String,
    pub service: String,
    pub unit_path: String,
    pub version: Option<String>,
    pub mode: Option<Mode>,
    pub capacity: Option<u32>,
    /// Gitea runner id from the local registration file.
    pub registered_id: Option<i64>,
    /// Gitea address the runner registered against.
    pub address: Option<String>,
    pub labels: Vec<String>,
    pub service_state: ServiceState,
    /// launchd only: `ProcessType` in the plist.
    pub process_type: Option<String>,
    /// launchd only: the scheduling class the loaded job actually has.
    pub loaded_spawn_type: Option<String>,
    pub last_fetch_error: Option<String>,
}

/// The parts of act_runner's `.runner` file this plugin reads. The file also
/// holds the runner's secret token, which is deliberately not deserialized.
#[derive(Debug, Clone, Deserialize)]
pub struct Registration {
    pub id: i64,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub address: String,
    #[serde(default)]
    pub labels: Vec<String>,
}

pub fn read_registration(path: &Path) -> Option<Registration> {
    let text = std::fs::read_to_string(path).ok()?;
    plugin_toolkit::serde_json::from_str(&text).ok()
}

#[cfg(target_os = "linux")]
fn effective_uid(_home: &Path) -> Result<u32> {
    let status = std::fs::read_to_string("/proc/self/status").context("read /proc/self/status")?;
    parse_proc_euid(&status).ok_or_else(|| anyhow!("no Uid line in /proc/self/status"))
}

/// macOS has no procfs. launchd's per-user domain is keyed by the uid owning
/// `$HOME`, which is the uid this LaunchAgent-scoped plugin acts as.
#[cfg(not(target_os = "linux"))]
fn effective_uid(home: &Path) -> Result<u32> {
    use std::os::unix::fs::MetadataExt;
    Ok(std::fs::metadata(home)
        .with_context(|| format!("stat {}", home.display()))?
        .uid())
}

/// Effective uid (second field) of `/proc/self/status`'s `Uid:` line.
pub fn parse_proc_euid(status: &str) -> Option<u32> {
    status
        .lines()
        .find_map(|l| l.strip_prefix("Uid:"))
        .and_then(|rest| rest.split_whitespace().nth(1))
        .and_then(|v| v.parse().ok())
}

/// `launchctl print` → (state, spawn type). Only the job's own top-level
/// `state =` line counts; nested endpoint blocks carry their own `state`.
pub fn parse_launchctl_print(out: &str) -> (ServiceState, Option<String>) {
    let mut state = ServiceState::Unknown;
    let mut spawn = None;
    for line in out.lines() {
        let indent = line.len() - line.trim_start().len();
        let line = line.trim();
        if indent <= 1
            && state == ServiceState::Unknown
            && let Some(v) = line.strip_prefix("state = ")
        {
            state = if v.trim() == "running" {
                ServiceState::Running
            } else {
                ServiceState::Stopped
            };
        }
        if spawn.is_none()
            && let Some(v) = line.strip_prefix("spawn type = ")
        {
            spawn = Some(v.trim().to_string());
        }
    }
    (state, spawn)
}

pub fn parse_systemctl_active(out: &str) -> ServiceState {
    match out.lines().next().unwrap_or("").trim() {
        "active" | "reloading" | "activating" => ServiceState::Running,
        "inactive" | "deactivating" => ServiceState::Stopped,
        "failed" => ServiceState::Crashed,
        _ => ServiceState::Unknown,
    }
}

pub fn parse_openrc_status(out: &str) -> ServiceState {
    let out = out.to_ascii_lowercase();
    if out.contains("status: crashed") {
        ServiceState::Crashed
    } else if out.contains("status: started") {
        ServiceState::Running
    } else if out.contains("status: stopped") {
        ServiceState::Stopped
    } else {
        ServiceState::Unknown
    }
}

/// `gitea-runner version v4.1.0` / `act_runner version v0.2.11` → the version.
pub fn parse_version(out: &str) -> Option<String> {
    out.split_whitespace()
        .last()
        .filter(|v| v.chars().any(|c| c.is_ascii_digit()))
        .map(str::to_string)
}

/// The newest "failed to fetch task" line, if it is newer than the newest
/// sign of work. A fetch error the runner has since recovered from is noise.
pub fn last_fetch_error(log: &str) -> Option<String> {
    let mut last_err = None;
    for line in log.lines() {
        if line.contains("failed to fetch task") {
            last_err = Some(line.trim().to_string());
        } else if line.contains("msg=\"task ") || line.contains("declare successfully") {
            last_err = None;
        }
    }
    last_err
}

fn read_tail(path: &Path) -> Option<String> {
    use std::io::{Read, Seek, SeekFrom};
    let mut f = std::fs::File::open(path).ok()?;
    let len = f.metadata().ok()?.len();
    f.seek(SeekFrom::Start(len.saturating_sub(LOG_TAIL_BYTES)))
        .ok()?;
    let mut buf = Vec::new();
    f.read_to_end(&mut buf).ok()?;
    Some(String::from_utf8_lossy(&buf).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proc_status_euid() {
        let s = "Name:\torca\nUid:\t1000\t0\t0\t0\nGid:\t1000\t1000\t1000\t1000\n";
        assert_eq!(parse_proc_euid(s), Some(0));
        assert_eq!(parse_proc_euid("Name:\tx\n"), None);
    }

    #[test]
    fn launchctl_print_reads_job_state_and_spawn_type() {
        // Shape captured from mint, 2026-10-03.
        let out = "gui/501/com.argyle.gitea-act-runner = {\n\tactive count = 1\n\tstate = running\n\tprogram = /Users/op/.local/bin/act_runner\n\tendpoints = {\n\t\t\"x\" = {\n\t\t\tstate = active\n\t\t}\n\t}\n\tpid = 57010\n\tspawn type = daemon (3)\n}\n";
        let (state, spawn) = parse_launchctl_print(out);
        assert_eq!(state, ServiceState::Running);
        assert_eq!(spawn.as_deref(), Some("daemon (3)"));
        let (stopped, _) = parse_launchctl_print("x = {\n\tstate = not running\n}\n");
        assert_eq!(stopped, ServiceState::Stopped);
    }

    #[test]
    fn systemctl_and_openrc_states() {
        assert_eq!(parse_systemctl_active("active\n"), ServiceState::Running);
        assert_eq!(parse_systemctl_active("failed"), ServiceState::Crashed);
        assert_eq!(parse_systemctl_active("inactive"), ServiceState::Stopped);
        assert_eq!(
            parse_openrc_status(" * status: crashed"),
            ServiceState::Crashed
        );
        assert_eq!(
            parse_openrc_status(" * status: started"),
            ServiceState::Running
        );
        assert_eq!(
            parse_openrc_status(" * status: stopped"),
            ServiceState::Stopped
        );
    }

    #[test]
    fn version_from_either_binary_name() {
        assert_eq!(
            parse_version("gitea-runner version v3.1.0").as_deref(),
            Some("v3.1.0")
        );
        assert_eq!(
            parse_version("act_runner version v0.2.11\n").as_deref(),
            Some("v0.2.11")
        );
        assert_eq!(parse_version("usage"), None);
    }

    #[test]
    fn fetch_error_counts_only_when_not_followed_by_work() {
        let stuck = "time=\"t1\" level=info msg=\"task 7 repo is x\"\ntime=\"t2\" level=error msg=\"failed to fetch task\" error=\"connection reset by peer\"\n";
        assert!(
            last_fetch_error(stuck)
                .unwrap()
                .contains("connection reset")
        );
        let recovered = format!("{stuck}time=\"t3\" level=info msg=\"task 8 repo is x\"\n");
        assert_eq!(last_fetch_error(&recovered), None);
    }

    #[test]
    fn registration_file_never_carries_the_token_forward() {
        let dir = std::env::temp_dir().join(format!("gitea-reg-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join(".runner");
        std::fs::write(
            &p,
            r#"{"WARNING":"x","id":3,"uuid":"u","name":"mint","token":"SECRET","address":"http://g:3000","labels":["macos:host"]}"#,
        )
        .unwrap();
        let reg = read_registration(&p).unwrap();
        assert_eq!(reg.id, 3);
        assert_eq!(reg.name, "mint");
        assert!(!format!("{reg:?}").contains("SECRET"));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn write_blocker_only_for_non_root_outside_home() {
        let host = LocalHost {
            init: Init::Systemd,
            home: PathBuf::from("/home/orca"),
            uid: 1000,
        };
        assert!(host.write_blocker(&[Path::new("/home/orca/x")]).is_none());
        let why = host
            .write_blocker(&[Path::new("/etc/systemd/system/a.service")])
            .unwrap();
        assert!(why.contains("need root"), "{why}");
        let root = LocalHost { uid: 0, ..host };
        assert!(root.write_blocker(&[Path::new("/etc/x")]).is_none());
    }
}
