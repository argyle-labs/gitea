//! `gitea.runner.*` verbs.
//!
//! Every verb acts on the host the call runs on. To manage a runner on another
//! orca host, route the call there (`--peer <host>` on the CLI, `X-Orca-Peer`
//! on REST, `peer` on MCP) so the gitea plugin on THAT host executes it.
//!
//! Mutating verbs own their `execute` opt-in instead of using the toolkit's
//! central gate: the central gate can only return a generic plan, and these
//! verbs can say exactly which files, commands and API calls they would run.
//! Without `execute: true` they return that `ExecutionPlan` and touch nothing.

use plugin_toolkit::contract::plan::ExecutionPlan;
use plugin_toolkit::prelude::*;

use super::api;
use super::exec::{Executor, StepOutcome};
use super::health::{
    self, DEFAULT_STALL_AFTER_SECS, Finding, GiteaRunnerView, GiteaSide, HealthStatus,
    LaunchdPriority, Observation, WaitingJob,
};
use super::host::{LocalHost, LocalInstall, read_registration};
use super::layout::{self, Init, Layout, Mode};
use super::plan::{self, Rerender, Scope, Step};
use super::release::DEFAULT_RELEASE_API;
use super::render;
use crate::Config;

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

fn default_version() -> String {
    "latest".to_string()
}
fn default_scope() -> String {
    "instance".to_string()
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

/// Return the plan, or run it and report. A failed step is an error that
/// names the step and what already ran: a partial apply must never read as
/// success.
#[allow(clippy::too_many_arguments)]
async fn plan_or_apply<A: Serialize>(
    tool: &str,
    args: &A,
    execute: bool,
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
        note: "`local` describes the host this call ran on; route the call to another orca host \
               (peer) to see its installs"
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
    /// `host` or `docker`. Default: host on macOS, docker on Linux.
    #[arg(long)]
    #[serde(default)]
    pub mode: Option<String>,
    /// act_runner label spec (`name:host`, `name:docker://image`). Repeatable.
    /// Default depends on mode and platform.
    #[arg(long = "label")]
    #[serde(default)]
    pub labels: Vec<String>,
    /// Concurrent jobs. Forced to 1 in host mode; docker mode defaults from
    /// the core count.
    #[arg(long)]
    #[serde(default)]
    pub capacity: Option<u32>,
    /// Runner release version, or `latest`.
    #[arg(long, default_value = "latest")]
    #[serde(default = "default_version")]
    pub version: String,
    /// `instance`, `org:<org>` or `repo:<owner>/<repo>`.
    #[arg(long, default_value = "instance")]
    #[serde(default = "default_scope")]
    pub scope: String,
    /// Gitea URL the runner dials. Default: the endpoint's resolved address,
    /// as seen from this host.
    #[arg(long)]
    #[serde(default)]
    pub instance_url: Option<String>,
    /// Release API to fetch the runner from (for an internal mirror).
    #[arg(long)]
    #[serde(default)]
    pub release_api: Option<String>,
    /// launchd only: PATH for host-executor jobs.
    #[arg(long)]
    #[serde(default)]
    pub path_env: Option<String>,
    /// Apply. Omitted, returns the plan and changes nothing.
    #[arg(long)]
    #[serde(default)]
    pub execute: bool,
}

/// Install, register and supervise a Gitea Actions runner on this host.
#[orca_tool(
    domain = "gitea",
    verb = "runner.install",
    data_mutation = true,
    role = "admin",
    execute_gated = false
)]
pub async fn gitea_runner_install(args: RunnerInstallArgs, _ctx: &ToolCtx) -> Result<RunnerChange> {
    const TOOL: &str = "gitea.runner.install";
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
    let mode = match &args.mode {
        Some(m) => m.parse()?,
        None => default_mode(host.init),
    };
    if mode == Mode::Docker && host.init == Init::Launchd {
        bail!("docker mode is not supported for launchd (macOS) runners; use mode=host");
    }
    let scope: Scope = args.scope.parse()?;
    let cfg = gitea_config(&args.endpoint).await?;
    let instance_url = args
        .instance_url
        .clone()
        .unwrap_or_else(|| api::instance_url(&cfg));
    let labels = if args.labels.is_empty() {
        render::default_labels(mode, target)
    } else {
        args.labels.clone()
    };
    let capacity = render::effective_capacity(mode, args.capacity, cores());
    let l = Layout::managed(host.init, &args.name, &host.home);
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
    let steps = plan::install_steps(&plan::InstallSpec {
        layout: &l,
        uid: host.uid,
        version: &args.version,
        config_yaml,
        unit,
        labels: labels.clone(),
        instance_url: instance_url.clone(),
        scope: scope.clone(),
    });
    let summary = format!(
        "install runner '{}' ({} mode, capacity {}, {}) registering with {instance_url} as {}",
        args.name,
        format!("{mode:?}").to_lowercase(),
        capacity.value,
        format!("{:?}", host.init).to_lowercase(),
        scope.label()
    );
    let release_api = args.release_api.as_deref().unwrap_or(DEFAULT_RELEASE_API);
    let exec = Executor {
        host: &host,
        gitea: Some(&cfg),
        release_api,
        release_target: target,
    };
    plan_or_apply(
        TOOL,
        &args,
        args.execute,
        &args.name,
        summary,
        steps,
        exec,
        Vec::new(),
        capacity.note.into_iter().collect(),
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
    /// Scope the runner was registered in.
    #[arg(long, default_value = "instance")]
    #[serde(default = "default_scope")]
    pub scope: String,
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
    data_mutation = true,
    role = "admin",
    execute_gated = false
)]
pub async fn gitea_runner_uninstall(
    args: RunnerUninstallArgs,
    _ctx: &ToolCtx,
) -> Result<RunnerChange> {
    const TOOL: &str = "gitea.runner.uninstall";
    let host = LocalHost::current()?;
    let l = host
        .find(&args.name)
        .ok_or_else(|| anyhow!("no runner named '{}' is installed on this host", args.name))?;
    if !l.managed {
        bail!(
            "runner '{}' is a hand-placed install at {}; this plugin only removes installs it created",
            args.name,
            l.dir.display()
        );
    }
    let scope: Scope = args.scope.parse()?;
    let (state, _) = host.service_state(&l).await;
    let runner_id = read_registration(&l.runner_file).map(|r| r.id);
    let cfg = gitea_config(&args.endpoint).await?;
    let steps = plan::uninstall_steps(&l, host.uid, state, runner_id, &scope, args.keep_files);
    let mut notes = Vec::new();
    if runner_id.is_none() {
        notes.push("no local registration file; nothing to deregister in Gitea".to_string());
    }
    let exec = Executor {
        host: &host,
        gitea: Some(&cfg),
        release_api: DEFAULT_RELEASE_API,
        release_target: "",
    };
    plan_or_apply(
        TOOL,
        &args,
        args.execute,
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
    /// Target runner release version, or `latest`.
    #[arg(long, default_value = "latest")]
    #[serde(default = "default_version")]
    pub version: String,
    /// Release API to fetch the runner from (for an internal mirror).
    #[arg(long)]
    #[serde(default)]
    pub release_api: Option<String>,
    /// Apply. Omitted, returns the plan and changes nothing.
    #[arg(long)]
    #[serde(default)]
    pub execute: bool,
}

/// Replace a runner's binary with a checksum-verified release and restart it.
#[orca_tool(
    domain = "gitea",
    verb = "runner.upgrade",
    data_mutation = true,
    role = "admin",
    execute_gated = false
)]
pub async fn gitea_runner_upgrade(args: RunnerUpgradeArgs, _ctx: &ToolCtx) -> Result<RunnerChange> {
    const TOOL: &str = "gitea.runner.upgrade";
    let host = LocalHost::current()?;
    let l = host
        .find(&args.name)
        .ok_or_else(|| anyhow!("no runner named '{}' is installed on this host", args.name))?;
    let target = release_target()?;
    let (state, _) = host.service_state(&l).await;
    let current = host.binary_version(&l.binary).await;
    let steps = plan::upgrade_steps(&l, host.uid, state, &args.version);
    let summary = format!(
        "upgrade runner '{}' from {} to {}",
        args.name,
        current.as_deref().unwrap_or("unknown"),
        args.version
    );
    let release_api = args.release_api.as_deref().unwrap_or(DEFAULT_RELEASE_API);
    let exec = Executor {
        host: &host,
        gitea: None,
        release_api,
        release_target: target,
    };
    plan_or_apply(
        TOOL,
        &args,
        args.execute,
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
    data_mutation = true,
    role = "admin",
    execute_gated = false
)]
pub async fn gitea_runner_heal(args: RunnerHealArgs, _ctx: &ToolCtx) -> Result<RunnerChange> {
    const TOOL: &str = "gitea.runner.heal";
    let host = LocalHost::current()?;
    let l = host
        .find(&args.name)
        .ok_or_else(|| anyhow!("no runner named '{}' is installed on this host", args.name))?;
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
        release_api: DEFAULT_RELEASE_API,
        release_target: "",
    };
    plan_or_apply(
        TOOL,
        &args,
        args.execute,
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

    #[tokio::test]
    async fn dry_run_returns_a_detailed_plan_and_touches_nothing() {
        let home = std::env::temp_dir().join(format!("gitea-plan-{}", std::process::id()));
        let host = LocalHost {
            init: Init::Launchd,
            home: home.clone(),
            uid: 501,
        };
        let l = Layout::managed(Init::Launchd, "r1", &home);
        let steps = plan::upgrade_steps(&l, 501, ServiceState::Running, "4.1.0");
        let exec = Executor {
            host: &host,
            gitea: None,
            release_api: "http://unreachable.invalid",
            release_target: "darwin-arm64",
        };
        let args = RunnerUpgradeArgs {
            name: "r1".into(),
            version: "4.1.0".into(),
            release_api: None,
            execute: false,
        };
        let out = plan_or_apply(
            "gitea.runner.upgrade",
            &args,
            false,
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
        assert_eq!(
            plan.changes[1].target,
            "launchctl kickstart -k gui/501/com.argyle.gitea-runner.r1"
        );
        assert!(!home.exists(), "dry run must not create anything");
        let json = plugin_toolkit::serde_json::to_string(&RunnerChange::Plan(plan)).unwrap();
        assert!(json.contains("\"dryRun\":true"), "{json}");
    }

    #[tokio::test]
    async fn dry_run_names_a_privilege_blocker_and_execute_refuses() {
        let host = LocalHost {
            init: Init::Systemd,
            home: "/home/orca".into(),
            uid: 1000,
        };
        let l = Layout::managed(Init::Systemd, "r1", &host.home);
        let steps = plan::upgrade_steps(&l, 1000, ServiceState::Running, "latest");
        let mk = || Executor {
            host: &host,
            gitea: None,
            release_api: "",
            release_target: "linux-amd64",
        };
        let args = RunnerUpgradeArgs {
            name: "r1".into(),
            version: "latest".into(),
            release_api: None,
            execute: false,
        };
        let RunnerChange::Plan(plan) = plan_or_apply(
            "t",
            &args,
            false,
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
            &args,
            true,
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
