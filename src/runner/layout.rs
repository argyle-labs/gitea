//! Where a runner lives on its host: service manager, executor mode, and the
//! on-disk layout of one install (binary, config, registration, unit file).

use std::path::{Path, PathBuf};

use plugin_toolkit::prelude::*;

/// The service manager that supervises the runner on this host.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum Init {
    Launchd,
    Systemd,
    Openrc,
}

impl Init {
    /// Detect this host's service manager. A systemd host can carry a stray
    /// `/sbin/openrc-run`, so systemd's runtime dir is checked first.
    pub fn detect() -> Option<Init> {
        if cfg!(target_os = "macos") {
            return Some(Init::Launchd);
        }
        if !cfg!(target_os = "linux") {
            return None;
        }
        if Path::new("/run/systemd/system").exists() {
            return Some(Init::Systemd);
        }
        if Path::new("/run/openrc").exists() || Path::new("/sbin/openrc-run").exists() {
            return Some(Init::Openrc);
        }
        None
    }
}

/// How the runner executes jobs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    /// Jobs run directly on the host (act's host executor). All jobs share one
    /// work tree, which is why capacity is pinned to 1.
    Host,
    /// Each job runs in its own container; needs a reachable Docker daemon.
    Docker,
}

impl std::str::FromStr for Mode {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self> {
        match s.to_ascii_lowercase().as_str() {
            "host" | "self-hosted" => Ok(Mode::Host),
            "docker" | "container" => Ok(Mode::Docker),
            other => bail!("unknown runner mode '{other}' (expected host | docker)"),
        }
    }
}

/// Every path and name one runner install uses.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Layout {
    pub name: String,
    pub init: Init,
    /// Working directory: config, registration file, logs, cache, job work.
    pub dir: PathBuf,
    pub binary: PathBuf,
    pub config: PathBuf,
    /// act_runner's registration file. Holds the runner's secret token.
    pub runner_file: PathBuf,
    pub log: PathBuf,
    /// launchd label, systemd unit name, or OpenRC service name.
    pub service: String,
    /// The plist / unit / init script on disk.
    pub unit_path: PathBuf,
    /// False for a hand-placed install this plugin found but did not create.
    pub managed: bool,
    /// Unprivileged account the service runs as. `None` runs it as whoever
    /// the service manager uses: the daemon user for a launchd agent, root
    /// for a hand-placed Linux install.
    pub user: Option<String>,
}

const LAUNCHD_LABEL_PREFIX: &str = "com.argyle.gitea-runner.";
/// Account managed Linux runners run as, so a job never runs as root.
pub const RUNNER_USER: &str = "gitea-runner";
const LINUX_ROOT: &str = "/var/lib/gitea-runner";

/// Root under which managed installs live. The launchd root avoids
/// `Application Support`: host-executor jobs build inside it, and a space in
/// the path breaks a surprising number of build scripts.
pub fn managed_root(init: Init, home: &Path) -> PathBuf {
    match init {
        Init::Launchd => home.join(".local/share/orca/gitea-runner"),
        Init::Systemd | Init::Openrc => PathBuf::from(LINUX_ROOT),
    }
}

/// Runner names become path segments and service names.
pub fn validate_name(name: &str) -> Result<()> {
    let ok = !name.is_empty()
        && name.len() <= 64
        && !name.starts_with('.')
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'));
    if !ok {
        bail!("invalid runner name '{name}': use 1-64 of [A-Za-z0-9._-], not starting with '.'");
    }
    Ok(())
}

impl Layout {
    /// The layout this plugin creates for runner `name`.
    pub fn managed(init: Init, name: &str, home: &Path) -> Layout {
        let dir = managed_root(init, home).join(name);
        let (service, unit_path) = match init {
            Init::Launchd => {
                let label = format!("{LAUNCHD_LABEL_PREFIX}{name}");
                let plist = home.join(format!("Library/LaunchAgents/{label}.plist"));
                (label, plist)
            }
            Init::Systemd => {
                let unit = format!("gitea-runner-{name}.service");
                let path = PathBuf::from(format!("/etc/systemd/system/{unit}"));
                (unit, path)
            }
            Init::Openrc => {
                let svc = format!("gitea-runner-{name}");
                let path = PathBuf::from(format!("/etc/init.d/{svc}"));
                (svc, path)
            }
        };
        Layout {
            name: name.to_string(),
            init,
            binary: dir.join("act_runner"),
            config: dir.join("config.yaml"),
            runner_file: dir.join(".runner"),
            log: dir.join("runner.log"),
            dir,
            service,
            unit_path,
            managed: true,
            user: (init != Init::Launchd).then(|| RUNNER_USER.to_string()),
        }
    }

    /// Plugin-owned record of how the runner was installed (scope, version).
    pub fn state_file(&self) -> PathBuf {
        self.dir.join("orca-runner.json")
    }

    /// Hand-placed installs that predate this plugin, at the paths the fleet
    /// actually used (mint's LaunchAgent; baldur/freyr's OpenRC script). Their
    /// `name` is a placeholder until the registration file is read.
    pub fn legacy_candidates(init: Init, home: &Path) -> Vec<Layout> {
        match init {
            Init::Launchd => {
                let dir = home.join(".gitea-runner");
                vec![Layout {
                    name: String::new(),
                    init,
                    binary: home.join(".local/bin/act_runner"),
                    config: dir.join("config.yaml"),
                    runner_file: dir.join(".runner"),
                    log: dir.join("runner.err.log"),
                    dir,
                    service: "com.argyle.gitea-act-runner".to_string(),
                    unit_path: home.join("Library/LaunchAgents/com.argyle.gitea-act-runner.plist"),
                    managed: false,
                    user: None,
                }]
            }
            Init::Openrc => {
                let dir = PathBuf::from("/etc/act_runner");
                vec![Layout {
                    name: String::new(),
                    init,
                    binary: PathBuf::from("/usr/local/bin/act_runner"),
                    config: dir.join("config.yaml"),
                    runner_file: dir.join(".runner"),
                    log: PathBuf::from("/var/log/act_runner.log"),
                    dir,
                    service: "act_runner".to_string(),
                    unit_path: PathBuf::from("/etc/init.d/act_runner"),
                    managed: false,
                    user: None,
                }]
            }
            Init::Systemd => Vec::new(),
        }
    }

    /// The launchd service target (`gui/<uid>/<label>`) `launchctl` addresses.
    pub fn launchd_target(&self, uid: u32) -> String {
        format!("gui/{uid}/{}", self.service)
    }
}

/// `<os>-<arch>` as the runner release names its binaries, for the platform
/// this plugin was compiled for.
pub fn release_target() -> Option<&'static str> {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("macos", "aarch64") => Some("darwin-arm64"),
        ("macos", "x86_64") => Some("darwin-amd64"),
        ("linux", "x86_64") => Some("linux-amd64"),
        ("linux", "aarch64") => Some("linux-arm64"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn managed_layout_per_init() {
        let home = Path::new("/Users/op");
        let l = Layout::managed(Init::Launchd, "mint", home);
        assert_eq!(
            l.dir,
            PathBuf::from("/Users/op/.local/share/orca/gitea-runner/mint")
        );
        assert_eq!(l.service, "com.argyle.gitea-runner.mint");
        assert_eq!(
            l.unit_path,
            PathBuf::from("/Users/op/Library/LaunchAgents/com.argyle.gitea-runner.mint.plist")
        );
        assert_eq!(
            l.launchd_target(501),
            "gui/501/com.argyle.gitea-runner.mint"
        );

        let s = Layout::managed(Init::Systemd, "baldur", home);
        assert_eq!(s.dir, PathBuf::from("/var/lib/gitea-runner/baldur"));
        assert_eq!(s.service, "gitea-runner-baldur.service");
        assert_eq!(
            s.unit_path,
            PathBuf::from("/etc/systemd/system/gitea-runner-baldur.service")
        );

        assert_eq!(l.user, None);
        assert_eq!(s.user.as_deref(), Some(RUNNER_USER));
        assert_eq!(
            s.state_file(),
            PathBuf::from("/var/lib/gitea-runner/baldur/orca-runner.json")
        );

        let o = Layout::managed(Init::Openrc, "freyr", home);
        assert_eq!(o.service, "gitea-runner-freyr");
        assert_eq!(o.unit_path, PathBuf::from("/etc/init.d/gitea-runner-freyr"));
        assert!(o.managed);
    }

    #[test]
    fn names_that_escape_a_path_are_refused() {
        assert!(validate_name("mint-macos-arm64").is_ok());
        assert!(validate_name("baldur_1.x").is_ok());
        for bad in ["", "../etc", "a/b", ".hidden", "has space", "semi;colon"] {
            assert!(validate_name(bad).is_err(), "accepted {bad:?}");
        }
    }

    #[test]
    fn mode_parses_aliases() {
        assert_eq!("host".parse::<Mode>().unwrap(), Mode::Host);
        assert_eq!("Docker".parse::<Mode>().unwrap(), Mode::Docker);
        assert!("k8s".parse::<Mode>().is_err());
    }

    #[test]
    fn legacy_layouts_match_the_fleet_paths() {
        let home = Path::new("/Users/op");
        let mac = &Layout::legacy_candidates(Init::Launchd, home)[0];
        assert_eq!(mac.service, "com.argyle.gitea-act-runner");
        assert!(!mac.managed);
        let rc = &Layout::legacy_candidates(Init::Openrc, home)[0];
        assert_eq!(rc.unit_path, PathBuf::from("/etc/init.d/act_runner"));
        assert!(Layout::legacy_candidates(Init::Systemd, home).is_empty());
    }
}
