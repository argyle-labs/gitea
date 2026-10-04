//! Pure renderers for everything a runner install writes to disk: act_runner's
//! `config.yaml` and the supervising service unit for each service manager.

use std::path::Path;

use super::layout::{Init, Layout, Mode};

/// How long a docker-mode runner waits for the Docker socket to ANSWER before
/// giving up. Waiting on the docker *service* is not enough: dockerd reports
/// started seconds before `/var/run/docker.sock` accepts connections, and a
/// runner that starts into that gap exits with "socket not found".
pub const DOCKER_WAIT_SECS: u32 = 120;

/// Highest capacity the default picks for a containerized runner.
const MAX_DEFAULT_DOCKER_CAPACITY: u32 = 4;

/// The settled capacity plus, when the request was overridden, why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Capacity {
    pub value: u32,
    pub note: Option<String>,
}

/// Decide the runner's job capacity.
///
/// Host mode is pinned to 1: the host executor runs every job in one shared
/// work tree, so two concurrent Rust builds delete each other's `target/*.d`
/// files mid-compile. Containerized jobs are isolated, so they default to a
/// quarter of the host's cores, bounded to `1..=4`.
pub fn effective_capacity(mode: Mode, requested: Option<u32>, cores: u32) -> Capacity {
    match mode {
        Mode::Host => Capacity {
            value: 1,
            note: requested.filter(|r| *r != 1).map(|r| {
                format!(
                    "capacity {r} forced to 1: the host executor shares one work tree between jobs"
                )
            }),
        },
        Mode::Docker => match requested {
            Some(0) | None => Capacity {
                value: (cores / 4).clamp(1, MAX_DEFAULT_DOCKER_CAPACITY),
                note: None,
            },
            Some(r) => Capacity {
                value: r,
                note: None,
            },
        },
    }
}

/// Labels a runner advertises when the caller names none. act_runner's label
/// syntax is `<name>:<scheme>[:<image>]`; the name is what `runs-on` matches.
pub fn default_labels(mode: Mode, release_target: &str) -> Vec<String> {
    match mode {
        Mode::Docker => [
            ("ubuntu-latest", "gitea/runner-images:ubuntu-latest"),
            ("ubuntu-24.04", "gitea/runner-images:ubuntu-24.04"),
            ("ubuntu-22.04", "gitea/runner-images:ubuntu-22.04"),
        ]
        .iter()
        .map(|(name, image)| format!("{name}:docker://{image}"))
        .collect(),
        Mode::Host => {
            let (os, arch) = release_target
                .split_once('-')
                .unwrap_or((release_target, ""));
            let os = if os == "darwin" { "macos" } else { os };
            let mut names = vec![os.to_string(), "self-hosted".to_string()];
            if !arch.is_empty() {
                names.push(arch.to_string());
            }
            names.into_iter().map(|n| format!("{n}:host")).collect()
        }
    }
}

/// Refuse label specs that could break out of the comma-joined `--labels`
/// list or the quoted YAML they are written into.
pub fn validate_labels(labels: &[String]) -> anyhow::Result<()> {
    for l in labels {
        let ok = !l.is_empty()
            && l.len() <= 255
            && l.chars()
                .all(|c| c.is_ascii_alphanumeric() || "._-:/@+".contains(c));
        if !ok {
            anyhow::bail!("invalid runner label '{l}': use [A-Za-z0-9._-:/@+]");
        }
    }
    Ok(())
}

/// The label names (`runs-on` keys) from act_runner label specs.
pub fn label_names(labels: &[String]) -> Vec<String> {
    labels
        .iter()
        .map(|l| l.split(':').next().unwrap_or(l).to_string())
        .collect()
}

/// Inputs for `config.yaml`.
#[derive(Debug, Clone)]
pub struct RunnerConfig<'a> {
    pub layout: &'a Layout,
    pub mode: Mode,
    pub capacity: u32,
    pub labels: &'a [String],
}

fn yaml_str(s: &str) -> String {
    format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
}

fn yaml_path(p: &Path) -> String {
    yaml_str(&p.to_string_lossy())
}

/// Render act_runner's `config.yaml`. Labels are written here (not only at
/// registration) so a label change takes effect on the next restart.
pub fn render_config(cfg: &RunnerConfig<'_>) -> String {
    let l = cfg.layout;
    let mut out = String::new();
    out.push_str("# Managed by orca (gitea plugin). Rewritten on install, upgrade and heal.\n");
    out.push_str("log:\n  level: info\n");
    out.push_str("runner:\n");
    out.push_str(&format!("  file: {}\n", yaml_path(&l.runner_file)));
    out.push_str(&format!("  capacity: {}\n", cfg.capacity));
    out.push_str("  timeout: 3h\n");
    // The service manager stops the runner on restart/upgrade; a long drain
    // would just be SIGKILLed by systemd/launchd anyway.
    out.push_str("  shutdown_timeout: 30s\n");
    out.push_str("  fetch_timeout: 5s\n");
    out.push_str("  fetch_interval: 2s\n");
    out.push_str("  labels:\n");
    for label in cfg.labels {
        out.push_str(&format!("    - {}\n", yaml_str(label)));
    }
    out.push_str("cache:\n  enabled: true\n");
    out.push_str(&format!("  dir: {}\n", yaml_path(&l.data.join("cache"))));
    out.push_str("container:\n");
    out.push_str("  network: \"\"\n");
    out.push_str("  privileged: false\n");
    // "-": the runner finds the Docker host for itself but does NOT mount its
    // socket into job containers. Empty would mount it, handing every job
    // root on the host.
    out.push_str("  docker_host: \"-\"\n");
    out.push_str("host:\n");
    out.push_str(&format!(
        "  workdir_parent: {}\n",
        yaml_path(&l.data.join("work"))
    ));
    if cfg.mode == Mode::Host {
        out.push_str("# host executor: jobs share the work tree above, so capacity stays 1.\n");
    }
    out
}

fn xml(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

/// Default `PATH` for a launchd runner. launchd starts agents with a bare
/// `/usr/bin:/bin:/usr/sbin:/sbin`, which hides rustup and Homebrew from
/// host-executor jobs.
pub fn default_launchd_path(home: &Path) -> String {
    format!(
        "{}/.cargo/bin:/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin",
        home.display()
    )
}

/// Render the LaunchAgent plist.
///
/// `ProcessType=Interactive` is load-bearing: without it launchd applies
/// "light resource limits" and schedules the runner at background priority
/// (measured 2026-10-03: rustc at pri 20 vs 31, darwin builds 30+ min).
pub fn render_launchd_plist(layout: &Layout, home: &Path, path_env: &str) -> String {
    let s = |v: &str| format!("<string>{}</string>", xml(v));
    let p = |v: &Path| s(&v.to_string_lossy());
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	{label}
	<key>ProgramArguments</key>
	<array>
		{bin}
		<string>daemon</string>
		<string>--config</string>
		{cfg}
	</array>
	<key>WorkingDirectory</key>
	{dir}
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<true/>
	<key>ProcessType</key>
	<string>Interactive</string>
	<key>EnvironmentVariables</key>
	<dict>
		<key>HOME</key>
		{home}
		<key>PATH</key>
		{path}
	</dict>
	<key>StandardOutPath</key>
	{log}
	<key>StandardErrorPath</key>
	{log}
</dict>
</plist>
"#,
        label = s(&layout.service),
        bin = p(&layout.binary),
        cfg = p(&layout.config),
        dir = p(&layout.dir),
        home = p(home),
        path = s(path_env),
        log = p(&layout.log),
    )
}

/// Render the systemd unit. `StartLimitIntervalSec=0` keeps `Restart=always`
/// from giving up after systemd's default five fast failures — a runner that
/// stops retrying is exactly the silent outage this exists to prevent.
pub fn render_systemd_unit(layout: &Layout, mode: Mode) -> String {
    let mut unit = String::new();
    unit.push_str("# Managed by orca (gitea plugin).\n[Unit]\n");
    unit.push_str(&format!(
        "Description=Gitea Actions runner ({})\n",
        layout.name
    ));
    unit.push_str("Wants=network-online.target\n");
    if mode == Mode::Docker {
        unit.push_str("After=network-online.target docker.service\n");
        unit.push_str("Requires=docker.service\n");
    } else {
        unit.push_str("After=network-online.target\n");
    }
    unit.push_str("StartLimitIntervalSec=0\n\n[Service]\nType=simple\n");
    if let Some(user) = &layout.user {
        unit.push_str(&format!("User={user}\nGroup={user}\n"));
    }
    unit.push_str(&format!("WorkingDirectory={}\n", layout.dir.display()));
    if mode == Mode::Docker {
        // `$$` is systemd's escape for a literal `$`.
        unit.push_str(&format!(
            "ExecStartPre=/bin/sh -c 'i=0; while [ $$i -lt {DOCKER_WAIT_SECS} ]; do docker info >/dev/null 2>&1 && exit 0; i=$$((i+1)); sleep 1; done; echo \"docker did not answer within {DOCKER_WAIT_SECS}s\" >&2; exit 1'\n"
        ));
    }
    unit.push_str(&format!(
        "ExecStart={} daemon --config {}\n",
        layout.binary.display(),
        layout.config.display()
    ));
    unit.push_str("Restart=always\nRestartSec=5\n\n[Install]\nWantedBy=multi-user.target\n");
    unit
}

/// Render the OpenRC init script. `supervise-daemon` respawns a crashed
/// runner; a plain `command_background` daemon stays `[ crashed ]` until
/// someone notices.
pub fn render_openrc_script(layout: &Layout, mode: Mode) -> String {
    let mut s = String::new();
    s.push_str("#!/sbin/openrc-run\n# Managed by orca (gitea plugin).\n\n");
    s.push_str(&format!("name=\"{}\"\n", layout.service));
    s.push_str(&format!(
        "description=\"Gitea Actions runner ({})\"\n",
        layout.name
    ));
    s.push_str("supervisor=\"supervise-daemon\"\n");
    s.push_str(&format!("command=\"{}\"\n", layout.binary.display()));
    if let Some(user) = &layout.user {
        s.push_str(&format!("command_user=\"{user}:{user}\"\n"));
    }
    s.push_str(&format!(
        "command_args=\"daemon --config {}\"\n",
        layout.config.display()
    ));
    s.push_str(&format!("directory=\"{}\"\n", layout.dir.display()));
    s.push_str(&format!("output_log=\"{}\"\n", layout.log.display()));
    s.push_str(&format!("error_log=\"{}\"\n", layout.log.display()));
    s.push_str("respawn_delay=5\n");
    // 0 = respawn forever.
    s.push_str("respawn_max=0\n\n");
    s.push_str("depend() {\n\tneed net\n");
    if mode == Mode::Docker {
        s.push_str("\tneed docker\n\tafter docker\n");
    }
    s.push_str("}\n");
    if mode == Mode::Docker {
        s.push_str(&format!(
            "\nstart_pre() {{\n\ti=0\n\twhile [ \"$i\" -lt {DOCKER_WAIT_SECS} ]; do\n\t\tdocker info >/dev/null 2>&1 && return 0\n\t\ti=$((i + 1))\n\t\tsleep 1\n\tdone\n\teerror \"docker did not answer within {DOCKER_WAIT_SECS}s\"\n\treturn 1\n}}\n"
        ));
    }
    s
}

/// Render the service unit for `layout.init`.
pub fn render_service(layout: &Layout, mode: Mode, home: &Path, path_env: &str) -> String {
    match layout.init {
        Init::Launchd => render_launchd_plist(layout, home, path_env),
        Init::Systemd => render_systemd_unit(layout, mode),
        Init::Openrc => render_openrc_script(layout, mode),
    }
}

/// `ProcessType` from a launchd plist, if set.
pub fn plist_process_type(plist: &str) -> Option<String> {
    let after = plist.split("<key>ProcessType</key>").nth(1)?;
    let start = after.find("<string>")? + "<string>".len();
    let end = after[start..].find("</string>")?;
    Some(after[start..start + end].trim().to_string())
}

/// `runner.capacity` from an act_runner `config.yaml`. A line scan, not a YAML
/// parser: act_runner's config is flat two-level YAML and this reads one key.
pub fn config_capacity(yaml: &str) -> Option<u32> {
    let mut in_runner = false;
    for line in yaml.lines() {
        if line.trim_start().starts_with('#') || line.trim().is_empty() {
            continue;
        }
        if !line.starts_with(' ') && !line.starts_with('\t') {
            in_runner = line.trim_end() == "runner:";
            continue;
        }
        if in_runner && let Some(v) = line.trim().strip_prefix("capacity:") {
            return v.trim().parse().ok();
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn layout(init: Init) -> Layout {
        Layout::managed(init, "r1", Path::new("/Users/op"))
    }

    #[test]
    fn host_capacity_is_forced_to_one_with_a_reason() {
        let c = effective_capacity(Mode::Host, Some(3), 16);
        assert_eq!(c.value, 1);
        assert!(c.note.unwrap().contains("forced to 1"));
        assert_eq!(effective_capacity(Mode::Host, None, 16).note, None);
        assert_eq!(effective_capacity(Mode::Host, Some(1), 16).note, None);
    }

    #[test]
    fn docker_capacity_defaults_from_cores_and_honors_requests() {
        assert_eq!(effective_capacity(Mode::Docker, None, 2).value, 1);
        assert_eq!(effective_capacity(Mode::Docker, None, 8).value, 2);
        assert_eq!(effective_capacity(Mode::Docker, None, 64).value, 4);
        assert_eq!(effective_capacity(Mode::Docker, Some(6), 8).value, 6);
    }

    #[test]
    fn default_labels_per_mode() {
        let mac = default_labels(Mode::Host, "darwin-arm64");
        assert_eq!(mac, vec!["macos:host", "self-hosted:host", "arm64:host"]);
        let docker = default_labels(Mode::Docker, "linux-amd64");
        assert!(
            docker
                .contains(&"ubuntu-latest:docker://gitea/runner-images:ubuntu-latest".to_string())
        );
        assert_eq!(label_names(&docker)[0], "ubuntu-latest");
    }

    #[test]
    fn config_carries_capacity_labels_and_absolute_paths() {
        let l = layout(Init::Launchd);
        let labels = vec!["macos:host".to_string(), "arm64:host".to_string()];
        let yaml = render_config(&RunnerConfig {
            layout: &l,
            mode: Mode::Host,
            capacity: 1,
            labels: &labels,
        });
        assert!(yaml.contains("  capacity: 1\n"));
        assert!(yaml.contains("    - \"macos:host\"\n"));
        assert!(
            yaml.contains("  file: \"/Users/op/.local/share/orca/gitea-runner/r1/data/.runner\"\n")
        );
        assert!(
            yaml.contains(
                "workdir_parent: \"/Users/op/.local/share/orca/gitea-runner/r1/data/work\""
            )
        );
        assert_eq!(config_capacity(&yaml), Some(1));
    }

    #[test]
    fn config_never_mounts_the_docker_socket_into_jobs() {
        let l = layout(Init::Systemd);
        let yaml = render_config(&RunnerConfig {
            layout: &l,
            mode: Mode::Docker,
            capacity: 2,
            labels: &["ubuntu-latest:docker://node:20".to_string()],
        });
        assert!(yaml.contains("  docker_host: \"-\"\n"), "{yaml}");
        assert!(!yaml.contains("docker_host: \"\""));
        assert!(!yaml.contains("privileged: true"));
    }

    #[test]
    fn config_capacity_reads_only_the_runner_section() {
        let yaml =
            "log:\n  level: info\nrunner:\n  file: .runner\n  capacity: 3\ncache:\n  capacity: 9\n";
        assert_eq!(config_capacity(yaml), Some(3));
        assert_eq!(config_capacity("cache:\n  capacity: 9\n"), None);
    }

    #[test]
    fn labels_that_could_inject_are_refused() {
        assert!(
            validate_labels(&["ubuntu-latest:docker://gitea/runner-images:ubuntu-latest".into()])
                .is_ok()
        );
        for bad in ["a,b", "a\nb", "a\"b", "a b", ""] {
            assert!(
                validate_labels(&[bad.to_string()]).is_err(),
                "accepted {bad:?}"
            );
        }
    }

    #[test]
    fn yaml_strings_are_escaped() {
        assert_eq!(yaml_str(r#"a"b\c"#), r#""a\"b\\c""#);
    }

    #[test]
    fn launchd_plist_is_interactive_keepalive_runatload() {
        let l = layout(Init::Launchd);
        let plist = render_launchd_plist(&l, Path::new("/Users/op"), "/usr/bin:/bin");
        assert_eq!(plist_process_type(&plist).as_deref(), Some("Interactive"));
        assert!(plist.contains("<key>KeepAlive</key>\n\t<true/>"));
        assert!(plist.contains("<key>RunAtLoad</key>\n\t<true/>"));
        assert!(plist.contains("<string>com.argyle.gitea-runner.r1</string>"));
        assert!(
            plist.contains(
                "<string>/Users/op/.local/share/orca/gitea-runner/r1/act_runner</string>"
            )
        );
        assert!(plist.contains("<string>daemon</string>"));
    }

    #[test]
    fn launchd_plist_escapes_xml() {
        let mut l = layout(Init::Launchd);
        l.dir = PathBuf::from("/tmp/a&b");
        let plist = render_launchd_plist(&l, Path::new("/Users/op"), "/bin");
        assert!(plist.contains("<string>/tmp/a&amp;b</string>"));
    }

    #[test]
    fn plist_without_process_type_reads_none() {
        assert_eq!(
            plist_process_type("<dict><key>Label</key><string>x</string></dict>"),
            None
        );
    }

    #[test]
    fn systemd_docker_unit_waits_for_the_socket_and_always_restarts() {
        let l = layout(Init::Systemd);
        let unit = render_systemd_unit(&l, Mode::Docker);
        assert!(unit.contains("After=network-online.target docker.service\n"));
        assert!(unit.contains("Requires=docker.service\n"));
        assert!(unit.contains("ExecStartPre=/bin/sh -c 'i=0; while [ $$i -lt 120 ]"));
        assert!(unit.contains("docker info"));
        assert!(unit.contains("Restart=always\n"));
        assert!(unit.contains("StartLimitIntervalSec=0\n"));
        assert!(unit.contains("User=gitea-runner-r1\nGroup=gitea-runner-r1\n"));
        assert!(unit.contains(
            "ExecStart=/var/lib/gitea-runner/r1/act_runner daemon --config /var/lib/gitea-runner/r1/config.yaml\n"
        ));
    }

    #[test]
    fn systemd_host_unit_has_no_docker_dependency() {
        let unit = render_systemd_unit(&layout(Init::Systemd), Mode::Host);
        assert!(!unit.contains("docker"));
        assert!(unit.contains("Restart=always\n"));
    }

    #[test]
    fn openrc_script_supervises_and_gates_on_docker() {
        let l = layout(Init::Openrc);
        let script = render_openrc_script(&l, Mode::Docker);
        assert!(script.starts_with("#!/sbin/openrc-run\n"));
        assert!(script.contains("supervisor=\"supervise-daemon\"\n"));
        assert!(script.contains("respawn_max=0\n"));
        assert!(script.contains("command_user=\"gitea-runner-r1:gitea-runner-r1\"\n"));
        assert!(script.contains("\tneed docker\n"));
        assert!(script.contains("start_pre() {"));
        assert!(script.contains("docker info >/dev/null 2>&1 && return 0"));
        let host = render_openrc_script(&l, Mode::Host);
        assert!(!host.contains("docker"));
    }
}
