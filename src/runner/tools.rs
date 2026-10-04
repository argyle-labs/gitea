//! `gitea.runner.*` verbs.
//!
//! Every verb acts on the orca system it runs on; a runner on another system
//! is managed by the gitea plugin on that system.
//!
//! Mutating verbs set `execute_gated = false` and own their `execute` opt-in,
//! because the central gate can only return a generic plan while these verbs
//! can say exactly which files, commands and API calls they would run.
//! Opting out of the central gate also opts out of the role check orca runs
//! inside it, so [`authorize_execute`] replaces it: execute is refused unless
//! the call carries an admin caller identity. Without `execute: true` a verb
//! returns its `ExecutionPlan` and touches nothing.

use plugin_toolkit::contract::CallerIdentity;
use plugin_toolkit::contract::plan::ExecutionPlan;
use plugin_toolkit::prelude::*;

use super::api;
use super::exec::{Executor, StepOutcome};
use super::health::{
    self, DEFAULT_STALL_AFTER_SECS, Finding, GiteaRunnerView, GiteaSide, HealthStatus,
    LaunchdPriority, Observation, WaitingJob, mode_from_labels,
};
use super::host::{LocalHost, LocalInstall, lookup_group, lookup_user};
use super::layout::{self, Init, Layout, Mode};
use super::plan::{self, Rerender, RunnerState, Scope, Step};
use super::release::{self, DEFAULT_VERSION, Source};
use super::render;
use crate::Config;

/// Operator allowlist of `scheme://host[:port]` origins a runner may register
/// against over plain http (comma-separated, set on the orca daemon).
pub const PLAINTEXT_ORIGINS_ENV: &str = "ORCA_GITEA_RUNNER_PLAINTEXT_ORIGINS";

/// A dry-run plan, or the record of what was applied.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(untagged)]
pub enum RunnerChange {
    Plan(ExecutionPlan),
    Applied(AppliedChange),
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct AppliedChange {
    /// Always `false`: changes were applied.
    pub dry_run: bool,
    pub tool: String,
    pub runner: String,
    pub summary: String,
    pub steps: Vec<StepOutcome>,
    /// For `heal`: the findings that drove the steps.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub findings: Vec<Finding>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
}

fn default_install_version() -> String {
    DEFAULT_VERSION.to_string()
}
fn default_scope() -> String {
    "instance".to_string()
}

/// Fail closed: applying changes needs an identified admin caller. A call
/// with no caller identity is refused, never assumed trusted.
pub fn authorize_execute(tool: &str, caller: Option<&CallerIdentity>) -> Result<()> {
    match caller {
        Some(c) if c.role == "admin" => Ok(()),
        Some(c) => bail!(
            "{tool}: execute requires role 'admin'; caller '{}' has '{}'",
            c.username,
            c.role
        ),
        None => bail!(
            "{tool}: execute refused: the call carries no caller identity, so admin cannot be verified"
        ),
    }
}

fn guard(tool: &str, execute: bool, ctx: &ToolCtx) -> Result<()> {
    if execute {
        authorize_execute(tool, ctx.caller().as_ref())?;
    }
    Ok(())
}

async fn gitea_config(endpoint: &str) -> Result<Config> {
    crate::tools::resolve_config(endpoint).await
}

fn release_target() -> Result<&'static str> {
    layout::release_target().ok_or_else(|| {
        anyhow!(
            "no runner release for {}-{}",
            std::env::consts::OS,
            std::env::consts::ARCH
        )
    })
}

fn default_mode(init: Init) -> Mode {
    match init {
        Init::Launchd => Mode::Host,
        Init::Systemd | Init::Openrc => Mode::Docker,
    }
}

fn cores() -> u32 {
    std::thread::available_parallelism()
        .map(|n| n.get() as u32)
        .unwrap_or(1)
}

/// `scheme://host[:port]`, lowercased, of an http(s) URL without userinfo.
pub fn origin(url: &str) -> Option<String> {
    let (scheme, rest) = url.trim().split_once("://")?;
    let scheme = scheme.to_ascii_lowercase();
    if scheme != "http" && scheme != "https" {
        return None;
    }
    let authority = rest.split(['/', '?', '#']).next()?;
    if authority.is_empty() || authority.contains('@') {
        return None;
    }
    Some(format!("{scheme}://{}", authority.to_ascii_lowercase()))
}

/// Check the URL a runner will dial. It must be one of the endpoint's own
/// origins (so a caller cannot point the runner, and the registration token,
/// at an arbitrary server), and https unless the operator allowlisted that
/// plain-http origin.
pub fn check_instance_url(
    url: &str,
    endpoint_origins: &[String],
    plaintext_ok: &[String],
) -> Result<String> {
    let o = origin(url).ok_or_else(|| anyhow!("instance_url '{url}' is not an http(s) URL"))?;
    if !endpoint_origins.contains(&o) {
        bail!(
            "instance_url origin {o} is not one of the endpoint's routes [{}]",
            endpoint_origins.join(", ")
        );
    }
    if o.starts_with("http://") && !plaintext_ok.contains(&o) {
        bail!(
            "instance_url {o} is plain http; allow it explicitly in {PLAINTEXT_ORIGINS_ENV} on the orca daemon"
        );
    }
    Ok(url.trim().trim_end_matches('/').to_string())
}

fn plaintext_allowlist() -> Vec<String> {
    std::env::var(PLAINTEXT_ORIGINS_ENV)
        .unwrap_or_default()
        .split(',')
        .filter_map(origin)
        .collect()
}

/// Return the plan, or run it and report. A failed step is an error that
/// names the step and what already ran: a partial apply must never read as
/// success.
#[allow(clippy::too_many_arguments)]
async fn plan_or_apply<A: Serialize>(
    tool: &str,
    args: &A,
    execute: bool,
    caller: Option<&CallerIdentity>,
    runner: &str,
    summary: String,
    steps: Vec<Step>,
    exec: Executor<'_>,
    findings: Vec<Finding>,
    mut notes: Vec<String>,
) -> Result<RunnerChange> {
    let blocker = exec.host.write_blocker(&plan::touched_paths(&steps));
    if !execute {
        let inputs = plugin_toolkit::serde_json::to_value(args)?;
        let mut summary = summary;
        for n in notes.iter().chain(blocker.iter()) {
            summary.push_str("; ");
            summary.push_str(n);
        }
        if steps.is_empty() {
            summary.push_str("; nothing to change");
        }
        let changes = steps.iter().map(Step::to_change).collect();
        return Ok(RunnerChange::Plan(
            ExecutionPlan::generic(tool, inputs.into()).detailed(summary, changes),
        ));
    }
    authorize_execute(tool, caller)?;
    if let Some(why) = blocker {
        bail!("{tool}: refusing to execute: {why}");
    }
    let (outcomes, err) = exec.run(&steps).await;
    if let Some(e) = err {
        let done: Vec<String> = outcomes
            .iter()
            .filter(|o| o.ok)
            .map(|o| format!("{} {}", o.action, o.target))
            .collect();
        let failed = outcomes
            .last()
            .map(|o| format!("{} {}", o.action, o.target));
        bail!(
            "{tool} failed at `{}`: {e:#}. Already applied: [{}]",
            failed.unwrap_or_default(),
            done.join("; ")
        );
    }
    if steps.is_empty() {
        notes.push("nothing to change".to_string());
    }
    Ok(RunnerChange::Applied(AppliedChange {
        dry_run: false,
        tool: tool.to_string(),
        runner: runner.to_string(),
        summary,
        steps: outcomes,
        findings,
        notes,
    }))
}

// ═══════════════════════════════════════════════════════════════════════════
// gitea.runner.list
// ═══════════════════════════════════════════════════════════════════════════

#[derive(clap::Args, Serialize, Deserialize, JsonSchema)]
pub struct RunnerListArgs {
    /// Registered Gitea endpoint. Omit to list only this host's installs.
    #[arg(long)]
    #[serde(default)]
    pub endpoint: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct RunnerView {
    pub name: String,
    /// Gitea's view (online, busy, labels). `None` when Gitea does not know it
    /// or was not asked.
    pub gitea: Option<GiteaRunnerView>,
    /// The install on THIS host. `None` for a runner that lives elsewhere.
    pub local: Option<LocalInstall>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct RunnerListOutput {
    pub runners: Vec<RunnerView>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gitea_error: Option<String>,
    pub note: String,
}

fn join(locals: Vec<LocalInstall>, gitea: &[GiteaRunnerView]) -> Vec<RunnerView> {
    let mut claimed = vec![false; gitea.len()];
    let mut out: Vec<RunnerView> = locals
        .into_iter()
        .map(|l| {
            let idx = gitea
                .iter()
                .position(|g| Some(g.id) == l.registered_id)
                .or_else(|| gitea.iter().position(|g| g.name == l.name));
            if let Some(i) = idx {
                claimed[i] = true;
            }
            RunnerView {
                name: l.name.clone(),
                gitea: idx.map(|i| gitea[i].clone()),
                local: Some(l),
            }
        })
        .collect();
    out.extend(
        gitea
            .iter()
            .zip(claimed)
            .filter(|(_, c)| !c)
            .map(|(g, _)| RunnerView {
                name: g.name.clone(),
                gitea: Some(g.clone()),
                local: None,
            }),
    );
    out
}

/// Runners Gitea knows, joined with the installs on this host.
#[orca_tool(domain = "gitea", verb = "runner.list")]
pub async fn gitea_runner_list(args: RunnerListArgs, _ctx: &ToolCtx) -> Result<RunnerListOutput> {
    let host = LocalHost::current()?;
    let mut locals = Vec::new();
    for l in host.discover() {
        locals.push(host.inspect(&l).await);
    }
    let (gitea, gitea_error) = match &args.endpoint {
        Some(ep) => match async { api::list_runners(&gitea_config(ep).await?).await }.await {
            Ok(g) => (g, None),
            Err(e) => (Vec::new(), Some(format!("{e:#}"))),
        },
        None => (
            Vec::new(),
            Some("no endpoint given; Gitea was not asked".to_string()),
        ),
    };
    Ok(RunnerListOutput {
        runners: join(locals, &gitea),
        gitea_error,
        note: "`local` describes the system this call ran on; installs on other systems are \
               reported by the gitea plugin there"
            .to_string(),
    })
}

// ═══════════════════════════════════════════════════════════════════════════
// gitea.runner.health
// ═══════════════════════════════════════════════════════════════════════════

#[derive(clap::Args, Serialize, Deserialize, JsonSchema)]
pub struct RunnerHealthArgs {
    /// Registered Gitea endpoint.
    #[arg(long)]
    pub endpoint: String,
    /// Only this runner. Omit for every runner on this host.
    #[arg(long)]
    #[serde(default)]
    pub name: Option<String>,
    /// How long a matching job may wait on an idle runner before the runner
    /// counts as starved.
    #[arg(long)]
    #[serde(default)]
    pub stall_after_secs: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct RunnerHealth {
    pub name: String,
    pub status: HealthStatus,
    pub findings: Vec<Finding>,
    pub local: LocalInstall,
    pub gitea: Option<GiteaRunnerView>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct RunnerHealthOutput {
    pub runners: Vec<RunnerHealth>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
}

/// Gitea's runner list and job queue, gathered once per call.
struct GiteaSnapshot {
    runners: std::result::Result<Vec<GiteaRunnerView>, String>,
    waiting: Vec<WaitingJob>,
    notes: Vec<String>,
}

async fn gitea_snapshot(cfg: &Config) -> GiteaSnapshot {
    let runners = api::list_runners(cfg).await.map_err(|e| format!("{e:#}"));
    let mut notes = Vec::new();
    let waiting = match api::waiting_jobs(cfg).await {
        Ok(w) => w,
        Err(e) => {
            notes.push(format!("starvation check skipped: {e:#}"));
            Vec::new()
        }
    };
    GiteaSnapshot {
        runners,
        waiting,
        notes,
    }
}

fn observe(local: &LocalInstall, snap: &GiteaSnapshot) -> (Observation, Option<GiteaRunnerView>) {
    let gitea = match &snap.runners {
        Err(e) => GiteaSide::Unavailable(e.clone()),
        Ok(list) => match local
            .registered_id
            .and_then(|id| list.iter().find(|g| g.id == id))
        {
            Some(g) => GiteaSide::Found(g.clone()),
            None => GiteaSide::Missing,
        },
    };
    let found = match &gitea {
        GiteaSide::Found(g) => Some(g.clone()),
        _ => None,
    };
    let obs = Observation {
        service: local.service_state,
        mode: local.mode,
        capacity: local.capacity,
        launchd: (local.init == Init::Launchd).then(|| LaunchdPriority {
            plist_process_type: local.process_type.clone(),
            loaded_spawn_type: local.loaded_spawn_type.clone(),
        }),
        gitea,
        waiting_jobs: snap.waiting.clone(),
        last_fetch_error: local.last_fetch_error.clone(),
    };
    (obs, found)
}

/// Classify each runner on this host: service state, Gitea liveness, task
/// starvation, launchd priority, and host-executor capacity.
#[orca_tool(domain = "gitea", verb = "runner.health")]
pub async fn gitea_runner_health(
    args: RunnerHealthArgs,
    _ctx: &ToolCtx,
) -> Result<RunnerHealthOutput> {
    let host = LocalHost::current()?;
    let cfg = gitea_config(&args.endpoint).await?;
    let snap = gitea_snapshot(&cfg).await;
    let stall = args.stall_after_secs.unwrap_or(DEFAULT_STALL_AFTER_SECS);
    let mut runners = Vec::new();
    for l in host.discover() {
        if args.name.as_deref().is_some_and(|n| n != l.name) {
            continue;
        }
        let local = host.inspect(&l).await;
        let (obs, gitea) = observe(&local, &snap);
        let (status, findings) = health::classify(&obs, stall);
        runners.push(RunnerHealth {
            name: l.name,
            status,
            findings,
            local,
            gitea,
        });
    }
    let mut notes = snap.notes;
    if runners.is_empty() {
        notes.push(match &args.name {
            Some(n) => format!("no runner named '{n}' is installed on this host"),
            None => "no runners are installed on this host".to_string(),
        });
    }
    Ok(RunnerHealthOutput { runners, notes })
}

// ═══════════════════════════════════════════════════════════════════════════
// gitea.runner.install
// ═══════════════════════════════════════════════════════════════════════════

#[derive(clap::Args, Serialize, Deserialize, JsonSchema)]
pub struct RunnerInstallArgs {
    /// Registered Gitea endpoint the runner registers with.
    #[arg(long)]
    pub endpoint: String,
    /// Runner name in Gitea; also names its directory and service.
    #[arg(long)]
    pub name: String,
    /// Picks the default labels when none are given: `host` or `docker`.
    /// The executor mode itself follows the labels. Default: host on macOS,
    /// docker on Linux.
    #[arg(long)]
    #[serde(default)]
    pub mode: Option<String>,
    /// act_runner label spec (`name:host`, `name:docker://image`). Repeatable.
    #[arg(long = "label")]
    #[serde(default)]
    pub labels: Vec<String>,
    /// Concurrent jobs. Forced to 1 whenever any label runs on the host;
    /// docker-only runners default from the core count.
    #[arg(long)]
    #[serde(default)]
    pub capacity: Option<u32>,
    /// Runner release version; must be one this plugin pins a checksum for.
    #[arg(long, default_value = DEFAULT_VERSION)]
    #[serde(default = "default_install_version")]
    pub version: String,
    /// `instance`, `org:<org>` or `repo:<owner>/<repo>`.
    #[arg(long, default_value = "instance")]
    #[serde(default = "default_scope")]
    pub scope: String,
    /// Gitea URL the runner dials. Must be one of the endpoint's routes.
    /// Default: the endpoint's resolved address, as seen from this system.
    #[arg(long)]
    #[serde(default)]
    pub instance_url: Option<String>,
    /// launchd only: PATH for host-executor jobs.
    #[arg(long)]
    #[serde(default)]
    pub path_env: Option<String>,
    /// Allow host-executor labels on a runner that would run as root. Host
    /// jobs then run as root on this system.
    #[arg(long)]
    #[serde(default)]
    pub force_host_as_root: bool,
    /// Apply. Omitted, returns the plan and changes nothing.
    #[arg(long)]
    #[serde(default)]
    pub execute: bool,
}

/// Host-executor jobs run as the service's account. Refuse that being root
/// unless explicitly forced.
pub fn check_host_as_root(mode: Mode, runs_as_root: bool, force: bool) -> Result<()> {
    if mode == Mode::Host && runs_as_root && !force {
        bail!(
            "host-executor labels would run CI jobs as root on this system; use docker labels, \
             run the orca daemon unprivileged, or pass force_host_as_root"
        );
    }
    Ok(())
}

/// Install, register and supervise a Gitea Actions runner on this system.
#[orca_tool(
    domain = "gitea",
    verb = "runner.install",
    role = "admin",
    execute_gated = false
)]
pub async fn gitea_runner_install(args: RunnerInstallArgs, ctx: &ToolCtx) -> Result<RunnerChange> {
    const TOOL: &str = "gitea.runner.install";
    guard(TOOL, args.execute, ctx)?;
    layout::validate_name(&args.name)?;
    let host = LocalHost::current()?;
    if let Some(existing) = host.find(&args.name) {
        bail!(
            "runner '{}' is already installed at {} — use gitea.runner.upgrade, or uninstall first",
            args.name,
            existing.dir.display()
        );
    }
    let target = release_target()?;
    let artifact = release::artifact(&Source::configured()?, &args.version, target)?;
    let label_mode = match &args.mode {
        Some(m) => m.parse()?,
        None => default_mode(host.init),
    };
    let labels = if args.labels.is_empty() {
        render::default_labels(label_mode, target)
    } else {
        args.labels.clone()
    };
    render::validate_labels(&labels)?;
    let mode = mode_from_labels(&labels).unwrap_or(label_mode);
    if mode == Mode::Docker && host.init == Init::Launchd {
        bail!("docker labels are not supported for launchd (macOS) runners; use host labels");
    }
    if host.init != Init::Launchd {
        layout::account_for(&args.name)?;
    }
    let l = Layout::managed(host.init, &args.name, &host.home);
    let runs_as_root = l.user.is_none() && host.is_root();
    check_host_as_root(mode, runs_as_root, args.force_host_as_root)?;

    let scope: Scope = args.scope.parse()?;
    let cfg = gitea_config(&args.endpoint).await?;
    let mut endpoint_origins: Vec<String> = crate::tools::endpoint_route_urls(&args.endpoint)?
        .iter()
        .filter_map(|u| origin(u))
        .collect();
    endpoint_origins.extend(origin(&cfg.base_url));
    let instance_url = check_instance_url(
        &args
            .instance_url
            .clone()
            .unwrap_or_else(|| api::instance_url(&cfg)),
        &endpoint_origins,
        &plaintext_allowlist(),
    )?;

    let capacity = render::effective_capacity(mode, args.capacity, cores());
    let path_env = args
        .path_env
        .clone()
        .unwrap_or_else(|| render::default_launchd_path(&host.home));
    let config_yaml = render::render_config(&render::RunnerConfig {
        layout: &l,
        mode,
        capacity: capacity.value,
        labels: &labels,
    });
    let unit = render::render_service(&l, mode, &host.home, &path_env);
    let create_user = match &l.user {
        Some(u) if lookup_user(u).await.is_none() => plan::user_steps(
            host.init,
            u,
            &l.data,
            mode == Mode::Docker,
            lookup_group(u).await.is_some(),
        ),
        _ => Vec::new(),
    };
    let summary = format!(
        "install runner '{}' {} ({} executor, capacity {}, {}) from {} registering with {instance_url} as {}",
        args.name,
        artifact.version,
        format!("{mode:?}").to_lowercase(),
        capacity.value,
        format!("{:?}", host.init).to_lowercase(),
        artifact.host,
        scope.label()
    );
    let steps = plan::install_steps(&plan::InstallSpec {
        layout: &l,
        uid: host.uid,
        artifact,
        config_yaml,
        unit,
        labels: labels.clone(),
        instance_url,
        scope,
        create_user,
    });
    let exec = Executor {
        host: &host,
        gitea: Some(&cfg),
    };
    let mut notes: Vec<String> = capacity.note.into_iter().collect();
    notes.push(
        "Gitea reuses one registration token per scope and offers no API to rotate it; \
         reset it in Gitea after installs if it may have been exposed"
            .to_string(),
    );
    plan_or_apply(
        TOOL,
        &args,
        args.execute,
        ctx.caller().as_ref(),
        &args.name,
        summary,
        steps,
        exec,
        Vec::new(),
        notes,
    )
    .await
}

// ═══════════════════════════════════════════════════════════════════════════
// gitea.runner.uninstall
// ═══════════════════════════════════════════════════════════════════════════

#[derive(clap::Args, Serialize, Deserialize, JsonSchema)]
pub struct RunnerUninstallArgs {
    /// Registered Gitea endpoint to deregister from.
    #[arg(long)]
    pub endpoint: String,
    #[arg(long)]
    pub name: String,
    /// Scope the runner was registered in. Normally read from the install's
    /// own record; if given, it must agree with that record.
    #[arg(long)]
    #[serde(default)]
    pub scope: Option<String>,
    /// Keep the runner's directory (cache, logs, registration).
    #[arg(long)]
    #[serde(default)]
    pub keep_files: bool,
    /// Apply. Omitted, returns the plan and changes nothing.
    #[arg(long)]
    #[serde(default)]
    pub execute: bool,
}

/// Stop and remove a runner's service, deregister it from Gitea, and delete
/// its files.
#[orca_tool(
    domain = "gitea",
    verb = "runner.uninstall",
    role = "admin",
    execute_gated = false
)]
pub async fn gitea_runner_uninstall(
    args: RunnerUninstallArgs,
    ctx: &ToolCtx,
) -> Result<RunnerChange> {
    const TOOL: &str = "gitea.runner.uninstall";
    guard(TOOL, args.execute, ctx)?;
    let host = LocalHost::current()?;
    let l = host.find(&args.name).ok_or_else(|| {
        anyhow!(
            "no runner named '{}' is installed on this system",
            args.name
        )
    })?;
    if !l.managed {
        bail!(
            "runner '{}' is a hand-placed install at {}; this plugin only removes installs it created",
            args.name,
            l.dir.display()
        );
    }
    let recorded = RunnerState::read(&l.state_file());
    let (scope, scope_known) = plan::deregister_scope(
        recorded.as_ref().map(|r| r.scope.as_str()),
        args.scope.as_deref(),
    )?;
    let (state, _) = host.service_state(&l).await;
    // Only the root-owned record is trusted: `.runner` is writable by the
    // runner account, so a job could aim deregistration at another runner.
    let runner_id = recorded.as_ref().and_then(|r| r.runner_id);
    let cfg = gitea_config(&args.endpoint).await?;
    let steps = plan::uninstall_steps(
        &l,
        host.uid,
        state,
        runner_id,
        &scope,
        scope_known,
        args.keep_files,
    );
    let mut notes = Vec::new();
    if runner_id.is_none() {
        notes.push(
            "no recorded Gitea runner id; nothing is deregistered — delete it in Gitea if it exists"
                .to_string(),
        );
    }
    let exec = Executor {
        host: &host,
        gitea: Some(&cfg),
    };
    plan_or_apply(
        TOOL,
        &args,
        args.execute,
        ctx.caller().as_ref(),
        &args.name,
        format!("uninstall runner '{}'", args.name),
        steps,
        exec,
        Vec::new(),
        notes,
    )
    .await
}

// ═══════════════════════════════════════════════════════════════════════════
// gitea.runner.upgrade
// ═══════════════════════════════════════════════════════════════════════════

#[derive(clap::Args, Serialize, Deserialize, JsonSchema)]
pub struct RunnerUpgradeArgs {
    #[arg(long)]
    pub name: String,
    /// Target runner version; must be pinned in this plugin. Defaults to the
    /// newest pinned version for installs this plugin created; required for
    /// hand-placed ones.
    #[arg(long)]
    #[serde(default)]
    pub version: Option<String>,
    /// Permit upgrading a hand-placed install this plugin did not create.
    #[arg(long)]
    #[serde(default)]
    pub allow_unmanaged: bool,
    /// Permit a hand-placed install to cross a major version.
    #[arg(long)]
    #[serde(default)]
    pub allow_major_upgrade: bool,
    /// Apply. Omitted, returns the plan and changes nothing.
    #[arg(long)]
    #[serde(default)]
    pub execute: bool,
}

/// Version and major-version guard for an upgrade.
pub fn upgrade_target(
    managed: bool,
    requested: Option<&str>,
    allow_unmanaged: bool,
    allow_major_upgrade: bool,
) -> Result<(String, Option<u64>)> {
    if managed {
        return Ok((requested.unwrap_or(DEFAULT_VERSION).to_string(), None));
    }
    if !allow_unmanaged {
        bail!("this runner is a hand-placed install; pass allow_unmanaged to upgrade it");
    }
    let version = requested
        .ok_or_else(|| anyhow!("upgrading a hand-placed install needs an explicit version"))?;
    let check = if allow_major_upgrade {
        None
    } else {
        release::major(&release::validate_version(version)?)
    };
    Ok((version.to_string(), check))
}

/// Replace a runner's binary with a pinned, checksum-verified release and
/// restart it.
#[orca_tool(
    domain = "gitea",
    verb = "runner.upgrade",
    role = "admin",
    execute_gated = false
)]
pub async fn gitea_runner_upgrade(args: RunnerUpgradeArgs, ctx: &ToolCtx) -> Result<RunnerChange> {
    const TOOL: &str = "gitea.runner.upgrade";
    guard(TOOL, args.execute, ctx)?;
    let host = LocalHost::current()?;
    let l = host.find(&args.name).ok_or_else(|| {
        anyhow!(
            "no runner named '{}' is installed on this system",
            args.name
        )
    })?;
    let (version, check_major) = upgrade_target(
        l.managed,
        args.version.as_deref(),
        args.allow_unmanaged,
        args.allow_major_upgrade,
    )?;
    let artifact = release::artifact(&Source::configured()?, &version, release_target()?)?;
    let (state, _) = host.service_state(&l).await;
    let recorded = RunnerState::read(&l.state_file());
    let steps = plan::upgrade_steps(
        &l,
        host.uid,
        state,
        &artifact,
        recorded.as_ref(),
        check_major,
    );
    let summary = format!(
        "upgrade runner '{}' from {} to {} ({})",
        args.name,
        recorded
            .as_ref()
            .map(|r| r.version.as_str())
            .unwrap_or("an unrecorded version"),
        artifact.version,
        artifact.url
    );
    let exec = Executor {
        host: &host,
        gitea: None,
    };
    plan_or_apply(
        TOOL,
        &args,
        args.execute,
        ctx.caller().as_ref(),
        &args.name,
        summary,
        steps,
        exec,
        Vec::new(),
        Vec::new(),
    )
    .await
}

// ═══════════════════════════════════════════════════════════════════════════
// gitea.runner.heal
// ═══════════════════════════════════════════════════════════════════════════

#[derive(clap::Args, Serialize, Deserialize, JsonSchema)]
pub struct RunnerHealArgs {
    /// Registered Gitea endpoint (to see what Gitea sees).
    #[arg(long)]
    pub endpoint: String,
    #[arg(long)]
    pub name: String,
    /// See `gitea.runner.health`.
    #[arg(long)]
    #[serde(default)]
    pub stall_after_secs: Option<i64>,
    /// launchd only: PATH used when re-rendering a managed plist.
    #[arg(long)]
    #[serde(default)]
    pub path_env: Option<String>,
    /// Apply. Omitted, returns the plan and changes nothing.
    #[arg(long)]
    #[serde(default)]
    pub execute: bool,
}

/// Diagnose a runner and fix what can be fixed: restart a crashed or
/// non-polling runner, re-apply launchd's interactive priority, pin a host
/// executor to capacity 1. Every step names the finding that caused it.
#[orca_tool(
    domain = "gitea",
    verb = "runner.heal",
    role = "admin",
    execute_gated = false
)]
pub async fn gitea_runner_heal(args: RunnerHealArgs, ctx: &ToolCtx) -> Result<RunnerChange> {
    const TOOL: &str = "gitea.runner.heal";
    guard(TOOL, args.execute, ctx)?;
    let host = LocalHost::current()?;
    let l = host.find(&args.name).ok_or_else(|| {
        anyhow!(
            "no runner named '{}' is installed on this system",
            args.name
        )
    })?;
    let cfg = gitea_config(&args.endpoint).await?;
    let snap = gitea_snapshot(&cfg).await;
    let local = host.inspect(&l).await;
    let (obs, _) = observe(&local, &snap);
    let (status, findings) = health::classify(
        &obs,
        args.stall_after_secs.unwrap_or(DEFAULT_STALL_AFTER_SECS),
    );

    let rerender = if l.managed {
        let mode = local.mode.unwrap_or_else(|| default_mode(l.init));
        let path_env = args
            .path_env
            .clone()
            .unwrap_or_else(|| render::default_launchd_path(&host.home));
        let labels = local.labels.clone();
        Rerender {
            unit: Some(render::render_service(&l, mode, &host.home, &path_env)),
            config: Some(render::render_config(&render::RunnerConfig {
                layout: &l,
                mode,
                capacity: render::effective_capacity(mode, local.capacity, cores()).value,
                labels: &labels,
            })),
        }
    } else {
        Rerender::default()
    };
    let steps = plan::heal_steps(&l, host.uid, local.service_state, &findings, &rerender);

    let reasons: Vec<String> = findings
        .iter()
        .map(|f| format!("{:?}: {}", f.kind, f.detail))
        .collect();
    let status = format!("{status:?}").to_lowercase();
    let summary = if reasons.is_empty() {
        format!("runner '{}' is {status}", args.name)
    } else {
        format!(
            "runner '{}' is {status}: {}",
            args.name,
            reasons.join(" | ")
        )
    };
    let mut notes = snap.notes;
    if !l.managed
        && findings
            .iter()
            .any(|f| f.remedy == health::Remedy::RewriteConfig)
    {
        notes.push(
            "hand-placed install: config.yaml is not rewritten; reinstall via gitea.runner.install to manage it"
                .to_string(),
        );
    }
    let exec = Executor {
        host: &host,
        gitea: Some(&cfg),
    };
    plan_or_apply(
        TOOL,
        &args,
        args.execute,
        ctx.caller().as_ref(),
        &args.name,
        summary,
        steps,
        exec,
        findings,
        notes,
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runner::health::ServiceState;

    fn local(name: &str, id: Option<i64>) -> LocalInstall {
        LocalInstall {
            name: name.into(),
            managed: true,
            init: Init::Launchd,
            dir: String::new(),
            binary: String::new(),
            service: String::new(),
            unit_path: String::new(),
            version: None,
            mode: Some(Mode::Host),
            capacity: Some(1),
            registered_id: id,
            address: None,
            labels: vec![],
            service_state: ServiceState::Running,
            process_type: None,
            loaded_spawn_type: None,
            last_fetch_error: None,
        }
    }

    fn remote(id: i64, name: &str) -> GiteaRunnerView {
        GiteaRunnerView {
            id,
            name: name.into(),
            status: "idle".into(),
            online: true,
            busy: false,
            disabled: false,
            labels: vec![],
        }
    }

    #[test]
    fn join_matches_by_id_then_name_and_keeps_remote_runners() {
        let views = join(
            vec![
                local("mint", Some(3)),
                local("renamed-locally", Some(9)),
                local("fresh", None),
            ],
            &[
                remote(3, "mint-macos-arm64"),
                remote(9, "x"),
                remote(5, "baldur-runner"),
                remote(6, "fresh"),
            ],
        );
        let names: Vec<(&str, Option<i64>, bool)> = views
            .iter()
            .map(|v| {
                (
                    v.name.as_str(),
                    v.gitea.as_ref().map(|g| g.id),
                    v.local.is_some(),
                )
            })
            .collect();
        assert_eq!(
            names,
            vec![
                ("mint", Some(3), true),
                ("renamed-locally", Some(9), true),
                ("fresh", Some(6), true),
                ("baldur-runner", Some(5), false),
            ]
        );
    }

    #[test]
    fn observe_marks_a_missing_registration() {
        let snap = GiteaSnapshot {
            runners: Ok(vec![remote(1, "other")]),
            waiting: vec![],
            notes: vec![],
        };
        let (obs, found) = observe(&local("mint", Some(3)), &snap);
        assert_eq!(obs.gitea, GiteaSide::Missing);
        assert!(found.is_none());
        let snap = GiteaSnapshot {
            runners: Err("403".into()),
            waiting: vec![],
            notes: vec![],
        };
        assert!(matches!(
            observe(&local("mint", Some(3)), &snap).0.gitea,
            GiteaSide::Unavailable(_)
        ));
    }

    fn admin() -> CallerIdentity {
        CallerIdentity {
            user_id: "u1".into(),
            username: "scott".into(),
            role: "admin".into(),
            can_mutate: true,
        }
    }

    fn upgrade_args(execute: bool) -> RunnerUpgradeArgs {
        RunnerUpgradeArgs {
            name: "r1".into(),
            version: Some("4.1.0".into()),
            allow_unmanaged: false,
            allow_major_upgrade: false,
            execute,
        }
    }

    fn artifact() -> release::Artifact {
        release::artifact(
            &Source::parse(release::DEFAULT_SOURCE, &[]).unwrap(),
            "4.1.0",
            "darwin-arm64",
        )
        .unwrap()
    }

    #[test]
    fn execute_needs_an_admin_caller() {
        assert!(authorize_execute("t", Some(&admin())).is_ok());
        let none = authorize_execute("t", None).unwrap_err().to_string();
        assert!(none.contains("no caller identity"), "{none}");
        let mut reader = admin();
        reader.role = "read".into();
        reader.can_mutate = true;
        let err = authorize_execute("t", Some(&reader))
            .unwrap_err()
            .to_string();
        assert!(err.contains("requires role 'admin'"), "{err}");
    }

    #[tokio::test]
    async fn dispatched_execute_without_a_caller_is_refused_before_anything_runs() {
        let ctx = plugin_toolkit::tool_manifest::minimal_ctx();
        for (tool, args) in [
            (
                "gitea.runner.upgrade",
                json!({"name": "r1", "execute": true}),
            ),
            (
                "gitea.runner.heal",
                json!({"endpoint": "e", "name": "r1", "execute": true}),
            ),
            (
                "gitea.runner.uninstall",
                json!({"endpoint": "e", "name": "r1", "execute": true}),
            ),
            (
                "gitea.runner.install",
                json!({"endpoint": "e", "name": "r1", "execute": true}),
            ),
        ] {
            let err = plugin_toolkit::dispatch::dispatch(tool, args, &ctx)
                .await
                .unwrap_err()
                .to_string();
            assert!(err.contains("no caller identity"), "{tool}: {err}");
        }
    }

    // orca's derive marks every write-shaped verb a data mutation, so a
    // `can_mutate` non-admin could pass orca's surface check; the plugin's own
    // check is what refuses them (`execute_needs_an_admin_caller`).
    #[test]
    fn mutating_verbs_require_admin() {
        for verb in ["install", "uninstall", "upgrade", "heal"] {
            let name = format!("gitea.runner.{verb}");
            assert_eq!(
                plugin_toolkit::dispatch::required_role(&name),
                Some("admin"),
                "{name}"
            );
        }
    }

    #[test]
    fn instance_url_must_be_an_endpoint_origin_and_https_unless_allowed() {
        let origins = vec![
            "https://gitea.test".to_string(),
            "http://10.0.0.20:3000".to_string(),
        ];
        assert_eq!(
            check_instance_url("https://gitea.test/", &origins, &[]).unwrap(),
            "https://gitea.test"
        );
        assert!(check_instance_url("https://evil.test", &origins, &[]).is_err());
        assert!(check_instance_url("https://gitea.test@evil.test", &origins, &[]).is_err());
        let plain = check_instance_url("http://10.0.0.20:3000", &origins, &[]).unwrap_err();
        assert!(plain.to_string().contains(PLAINTEXT_ORIGINS_ENV), "{plain}");
        assert!(
            check_instance_url(
                "http://10.0.0.20:3000",
                &origins,
                &["http://10.0.0.20:3000".into()]
            )
            .is_ok()
        );
        assert!(check_instance_url("ftp://gitea.test", &origins, &[]).is_err());
        assert_eq!(
            origin("HTTPS://Gitea.Test:443/x?y").as_deref(),
            Some("https://gitea.test:443")
        );
    }

    #[test]
    fn host_labels_as_root_are_refused_unless_forced() {
        assert!(check_host_as_root(Mode::Host, true, false).is_err());
        assert!(check_host_as_root(Mode::Host, true, true).is_ok());
        assert!(check_host_as_root(Mode::Host, false, false).is_ok());
        assert!(check_host_as_root(Mode::Docker, true, false).is_ok());
    }

    #[test]
    fn unmanaged_upgrades_need_opt_in_explicit_version_and_same_major() {
        assert_eq!(
            upgrade_target(true, None, false, false).unwrap(),
            (DEFAULT_VERSION.to_string(), None)
        );
        assert!(upgrade_target(false, Some("4.1.0"), false, false).is_err());
        assert!(upgrade_target(false, None, true, false).is_err());
        assert_eq!(
            upgrade_target(false, Some("4.1.0"), true, false).unwrap().1,
            Some(4)
        );
        assert_eq!(
            upgrade_target(false, Some("4.1.0"), true, true).unwrap().1,
            None
        );
    }

    #[tokio::test]
    async fn dry_run_returns_a_detailed_plan_and_touches_nothing() {
        let home = std::env::temp_dir().join(format!("gitea-plan-{}", std::process::id()));
        let host = LocalHost {
            init: Init::Launchd,
            home: home.clone(),
            uid: 501,
        };
        let l = Layout::managed(Init::Launchd, "r1", &home);
        let steps = plan::upgrade_steps(&l, 501, ServiceState::Running, &artifact(), None, None);
        let exec = Executor {
            host: &host,
            gitea: None,
        };
        let out = plan_or_apply(
            "gitea.runner.upgrade",
            &upgrade_args(false),
            false,
            None,
            "r1",
            "upgrade".into(),
            steps,
            exec,
            vec![],
            vec![],
        )
        .await
        .unwrap();
        let RunnerChange::Plan(plan) = out else {
            panic!("expected a plan");
        };
        assert!(plan.dry_run && plan.detailed);
        assert_eq!(plan.tool, "gitea.runner.upgrade");
        assert_eq!(plan.changes.len(), 2);
        assert_eq!(plan.changes[0].action, "install-binary");
        assert!(
            plan.changes[0]
                .detail
                .as_deref()
                .unwrap()
                .contains("host gitea.com")
        );
        assert_eq!(
            plan.changes[1].target,
            "launchctl kickstart -k gui/501/com.argyle.gitea-runner.r1"
        );
        assert!(!home.exists(), "dry run must not create anything");
        let json = plugin_toolkit::serde_json::to_string(&RunnerChange::Plan(plan)).unwrap();
        assert!(json.contains("\"dryRun\":true"), "{json}");
    }

    #[tokio::test]
    async fn execute_is_refused_without_admin_even_past_the_verb_guard() {
        let host = LocalHost {
            init: Init::Launchd,
            home: std::env::temp_dir().join("gitea-noexec"),
            uid: 501,
        };
        let exec = Executor {
            host: &host,
            gitea: None,
        };
        let err = plan_or_apply(
            "t",
            &upgrade_args(true),
            true,
            None,
            "r1",
            "s".into(),
            vec![Step::Run {
                argv: vec!["false".into()],
                tolerate_failure: false,
            }],
            exec,
            vec![],
            vec![],
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(err.contains("no caller identity"), "{err}");
    }

    #[tokio::test]
    async fn dry_run_names_a_privilege_blocker_and_execute_refuses() {
        let host = LocalHost {
            init: Init::Systemd,
            home: "/home/orca".into(),
            uid: 1000,
        };
        let l = Layout::managed(Init::Systemd, "r1", &host.home);
        let steps = plan::upgrade_steps(&l, 1000, ServiceState::Running, &artifact(), None, None);
        let mk = || Executor {
            host: &host,
            gitea: None,
        };
        let RunnerChange::Plan(plan) = plan_or_apply(
            "t",
            &upgrade_args(false),
            false,
            None,
            "r1",
            "s".into(),
            steps.clone(),
            mk(),
            vec![],
            vec![],
        )
        .await
        .unwrap() else {
            panic!("expected plan");
        };
        assert!(plan.summary.contains("need root"), "{}", plan.summary);
        let err = plan_or_apply(
            "t",
            &upgrade_args(true),
            true,
            Some(&admin()),
            "r1",
            "s".into(),
            steps,
            mk(),
            vec![],
            vec![],
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(err.contains("refusing to execute"), "{err}");
    }
}
