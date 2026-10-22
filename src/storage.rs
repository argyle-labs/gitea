//! Gitea storage pressure: Actions artifact usage per repo, the disk of the
//! host running Gitea (orca's `system.health` probe of the endpoint's
//! `host_system`), watermark-driven artifact cleanup, admin cron tasks, and a
//! `diagnostics` provider that surfaces pressure before the disk fills.

use plugin_toolkit::contract::BoxFuture;
use plugin_toolkit::contract::diagnostics::{
    DiagnoseArgs, DiagnosticsProvider, Finding, RepairArgs, RepairOutcome, RepairSpec, Severity,
};
use plugin_toolkit::contract::plan::{ExecutionPlan, PlannedChange};
use plugin_toolkit::prelude::*;
use plugin_toolkit::serde_json::{Value, json};
use plugin_toolkit::time::Timestamp;
use std::time::{Duration, Instant};

use crate::Config;
use crate::artifacts::{
    ArtifactPruneOutput, CLEANUP_TASK, HOUR_SECS, Listing, StaleArtifact, all_repos,
    delete_artifacts, delete_changes, list_stale, repo_page, run_cron,
};
use crate::runner::api::verified_client;
use crate::runner::tools::authorize_execute;
use crate::tools::GiteaEndpoint;

const BUDGET_SECS: u64 = 25;
const GIB: i64 = 1 << 30;
pub const ARTIFACT_WARN_BYTES: i64 = 50 * GIB;
pub const ARTIFACT_CRIT_BYTES: i64 = 100 * GIB;
pub const MIN_REMEDIATE_AGE_HOURS: i64 = 1;
const PROVIDER: &str = "gitea";
const REMEDIATE_REPAIR: &str = "storage-remediate";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct Watermarks {
    pub high: u32,
    pub low: u32,
    pub crit: u32,
}

impl Default for Watermarks {
    fn default() -> Self {
        Self {
            high: 80,
            low: 70,
            crit: 95,
        }
    }
}

impl Watermarks {
    pub fn from_endpoint(row: &GiteaEndpoint) -> Result<Self> {
        Self::resolve(
            &row.name,
            row.disk_high_pct,
            row.disk_low_pct,
            row.disk_crit_pct,
        )
    }

    pub fn resolve(
        endpoint: &str,
        high: Option<u32>,
        low: Option<u32>,
        crit: Option<u32>,
    ) -> Result<Self> {
        let d = Self::default();
        let w = Self {
            high: high.unwrap_or(d.high),
            low: low.unwrap_or(d.low),
            crit: crit.unwrap_or(d.crit),
        };
        plugin_toolkit::anyhow::ensure!(
            w.low < w.high && w.high <= w.crit && w.crit <= 100,
            "endpoint {}: watermarks must satisfy low < high <= crit <= 100 (low={}, high={}, crit={})",
            endpoint,
            w.low,
            w.high,
            w.crit
        );
        Ok(w)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct DiskUsage {
    pub path: String,
    pub total_gb: u64,
    pub avail_gb: u64,
    pub used_pct: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum Pressure {
    Ok,
    Warn,
    Crit,
}

pub fn pressure(disk: Option<&DiskUsage>, artifact_bytes: i64, w: Watermarks) -> Pressure {
    match disk {
        Some(d) if u32::from(d.used_pct) >= w.crit => Pressure::Crit,
        Some(d) if u32::from(d.used_pct) >= w.high => Pressure::Warn,
        Some(_) => Pressure::Ok,
        None if artifact_bytes >= ARTIFACT_CRIT_BYTES => Pressure::Crit,
        None if artifact_bytes >= ARTIFACT_WARN_BYTES => Pressure::Warn,
        None => Pressure::Ok,
    }
}

/// Bytes to free so usage drops under the low watermark; 0 below the high one.
/// Without a disk reading, artifact bytes stand in against the artifact
/// thresholds scaled by the same low/high ratio.
pub fn bytes_to_free(disk: Option<&DiskUsage>, artifact_bytes: i64, w: Watermarks) -> i64 {
    if pressure(disk, artifact_bytes, w) == Pressure::Ok {
        return 0;
    }
    match disk {
        Some(d) => {
            let total = d.total_gb as i64 * GIB;
            let used = total - d.avail_gb as i64 * GIB;
            (used - total * i64::from(w.low) / 100).max(0)
        }
        None => {
            (artifact_bytes - ARTIFACT_WARN_BYTES * i64::from(w.low) / i64::from(w.high)).max(0)
        }
    }
}

/// Oldest artifacts first, skipping any younger than `min_age_hours`, until
/// their bytes reach `need`.
pub fn oldest_until(
    mut all: Vec<StaleArtifact>,
    need: i64,
    min_age_hours: i64,
) -> Vec<StaleArtifact> {
    all.retain(|a| a.age_hours >= min_age_hours);
    all.sort_by(|a, b| b.age_hours.cmp(&a.age_hours).then(a.id.cmp(&b.id)));
    let mut sum = 0;
    let mut out = Vec::new();
    for a in all {
        if sum >= need {
            break;
        }
        sum += a.bytes;
        out.push(a);
    }
    out
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct RetentionCheck {
    /// `ARTIFACT_RETENTION_DAYS` as declared on the endpoint; Gitea exposes no
    /// API for it.
    pub configured_days: Option<u32>,
    /// Age in days of the oldest unexpired artifact.
    pub observed_days: i64,
    pub uploaded_24h_bytes: i64,
    /// Days of uploads at the observed rate that fit the artifact budget.
    pub recommended_days: Option<i64>,
    pub flagged: bool,
}

/// `budget_bytes` is what artifacts may occupy: up to the low watermark on a
/// known disk, the warn threshold otherwise.
pub fn retention_check(
    configured_days: Option<u32>,
    oldest_age_hours: i64,
    uploaded_24h_bytes: i64,
    budget_bytes: i64,
) -> RetentionCheck {
    let observed_days = (oldest_age_hours + 23) / 24;
    let recommended_days =
        (uploaded_24h_bytes > 0).then(|| (budget_bytes / uploaded_24h_bytes).max(1));
    let effective = configured_days.map_or(observed_days, i64::from);
    RetentionCheck {
        configured_days,
        observed_days,
        uploaded_24h_bytes,
        recommended_days,
        flagged: recommended_days.is_some_and(|r| effective > r),
    }
}

pub fn artifact_budget(disk: Option<&DiskUsage>, artifact_bytes: i64, w: Watermarks) -> i64 {
    match disk {
        Some(d) => {
            let total = d.total_gb as i64 * GIB;
            let other = total - d.avail_gb as i64 * GIB - artifact_bytes;
            (total * i64::from(w.low) / 100 - other).max(0)
        }
        None => ARTIFACT_WARN_BYTES,
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct RepoArtifacts {
    pub repo: String,
    pub count: usize,
    pub bytes: i64,
}

/// Per-repo totals, largest first.
pub fn per_repo(artifacts: &[StaleArtifact]) -> Vec<RepoArtifacts> {
    let mut out: Vec<RepoArtifacts> = Vec::new();
    for a in artifacts {
        match out.iter_mut().find(|r| r.repo == a.repo) {
            Some(r) => {
                r.count += 1;
                r.bytes += a.bytes;
            }
            None => out.push(RepoArtifacts {
                repo: a.repo.clone(),
                count: 1,
                bytes: a.bytes,
            }),
        }
    }
    out.sort_by(|a, b| b.bytes.cmp(&a.bytes).then(a.repo.cmp(&b.repo)));
    out
}

pub fn parse_disk(health: &Value) -> std::result::Result<DiskUsage, String> {
    match health.get("disk") {
        None | Some(Value::Null) => Err("system.health reported no disk".to_string()),
        Some(d) => plugin_toolkit::serde_json::from_value(d.clone())
            .map_err(|e| format!("system.health disk: {e}")),
    }
}

async fn host_disk(system: Option<&str>) -> (Option<DiskUsage>, Option<String>) {
    let Some(id) = system.map(str::to_string) else {
        return (
            None,
            Some("endpoint has no host_system; disk usage unknown".to_string()),
        );
    };
    let called = tokio::task::spawn_blocking(move || {
        plugin_toolkit::tool_call::call_json("system.health", json!({ "id": id }))
    })
    .await;
    match called {
        Ok(Ok(v)) => match parse_disk(&v) {
            Ok(d) => (Some(d), None),
            Err(e) => (None, Some(e)),
        },
        Ok(Err(e)) => (None, Some(format!("system.health: {e:#}"))),
        Err(e) => (None, Some(format!("system.health: {e}"))),
    }
}

async fn org_repos(
    cfg: &Config,
    org: Option<&str>,
    deadline: Instant,
) -> Result<(Vec<String>, Vec<String>)> {
    let http = verified_client(cfg)?;
    let (mut repos, complete) = all_repos(|page| repo_page(&http, cfg, page), deadline).await?;
    let mut unreached = Vec::new();
    if !complete {
        unreached.push(format!(
            "repos after the first {} (listing ran out of time)",
            repos.len()
        ));
    }
    if let Some(org) = org {
        repos.retain(|r| r.split_once('/').is_some_and(|(o, _)| o == org));
    }
    Ok((repos, unreached))
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct StorageReport {
    pub endpoint: String,
    pub repos: Vec<RepoArtifacts>,
    pub artifact_count: usize,
    pub artifact_bytes: i64,
    pub disk: Option<DiskUsage>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disk_error: Option<String>,
    pub watermarks: Watermarks,
    pub pressure: Pressure,
    pub retention: RetentionCheck,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unlisted: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unreached: Vec<String>,
}

struct Scan {
    cfg: Config,
    report: StorageReport,
    artifacts: Vec<StaleArtifact>,
}

async fn scan(endpoint: &str, org: Option<&str>, deadline: Instant) -> Result<Scan> {
    let row = crate::tools::endpoint_db::require(endpoint)?;
    let watermarks = Watermarks::from_endpoint(&row)?;
    let cfg = crate::tools::resolve_config(endpoint).await?;
    let (repos, mut unreached) = org_repos(&cfg, org, deadline).await?;
    let Listing {
        stale: artifacts,
        unlisted,
        unreached: rest,
    } = list_stale(&cfg, &repos, i64::MAX, None, deadline).await?;
    unreached.splice(0..0, rest);
    let (disk, disk_error) = host_disk(row.host_system.as_deref()).await;
    let artifact_bytes: i64 = artifacts.iter().map(|a| a.bytes).sum();
    let uploaded_24h = artifacts
        .iter()
        .filter(|a| a.age_hours < 24)
        .map(|a| a.bytes)
        .sum();
    let oldest = artifacts.iter().map(|a| a.age_hours).max().unwrap_or(0);
    let report = StorageReport {
        endpoint: endpoint.to_string(),
        repos: per_repo(&artifacts),
        artifact_count: artifacts.len(),
        artifact_bytes,
        pressure: pressure(disk.as_ref(), artifact_bytes, watermarks),
        retention: retention_check(
            row.artifact_retention_days,
            oldest,
            uploaded_24h,
            artifact_budget(disk.as_ref(), artifact_bytes, watermarks),
        ),
        disk,
        disk_error,
        watermarks,
        unlisted,
        unreached,
    };
    Ok(Scan {
        cfg,
        report,
        artifacts,
    })
}

fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(BUDGET_SECS)
}

#[derive(clap::Args, Serialize, Deserialize, JsonSchema)]
pub struct StorageDetailArgs {
    /// Registered Gitea endpoint.
    #[arg(long)]
    pub endpoint: String,
    /// Only repos owned by this org or user.
    #[arg(long)]
    #[serde(default)]
    pub org: Option<String>,
}

/// Actions artifact count and bytes per repo, disk usage of the host running
/// Gitea, watermark pressure and the artifact retention check.
#[orca_tool(domain = "gitea", verb = "storage.detail", role = "admin")]
pub async fn gitea_storage_detail(args: StorageDetailArgs, ctx: &ToolCtx) -> Result<StorageReport> {
    authorize_execute("gitea.storage.detail", ctx.caller().as_ref())?;
    Ok(scan(&args.endpoint, args.org.as_deref(), deadline())
        .await?
        .report)
}

#[derive(clap::Args, Serialize, Deserialize, JsonSchema)]
pub struct ArtifactDeleteArgs {
    /// Registered Gitea endpoint.
    #[arg(long)]
    pub endpoint: String,
    /// Only repos owned by this org or user; omitted, every repo.
    #[arg(long)]
    #[serde(default)]
    pub org: Option<String>,
    /// Delete artifacts older than this many hours.
    #[arg(long, default_value_t = 24)]
    #[serde(default = "default_older_than_hours")]
    pub older_than_hours: u32,
    /// Artifact name pattern; `*` matches any run of characters.
    #[arg(long)]
    #[serde(default)]
    pub name: Option<String>,
    /// Return the plan and change nothing. Omitted, applies.
    #[arg(long)]
    #[serde(default)]
    pub dry_run: bool,
}

fn default_older_than_hours() -> u32 {
    24
}

/// Delete Actions artifacts older than N hours, optionally by name pattern and
/// org, then start `cleanup_actions` to free their storage.
#[orca_tool(
    domain = "gitea",
    verb = "actions.artifacts.delete",
    data_mutation = true,
    role = "admin",
    execute_gated = false
)]
pub async fn gitea_actions_artifacts_delete(
    args: ArtifactDeleteArgs,
    ctx: &ToolCtx,
) -> Result<ArtifactPruneOutput> {
    const TOOL: &str = "gitea.actions.artifacts.delete";
    authorize_execute(TOOL, ctx.caller().as_ref())?;
    let deadline = deadline();
    let cfg = crate::tools::resolve_config(&args.endpoint).await?;
    let (repos, mut unreached) = org_repos(&cfg, args.org.as_deref(), deadline).await?;
    let cutoff = Timestamp::now().unix_seconds() - i64::from(args.older_than_hours) * HOUR_SECS;
    let Listing {
        stale,
        unlisted,
        unreached: rest,
    } = list_stale(&cfg, &repos, cutoff, args.name.as_deref(), deadline).await?;
    unreached.splice(0..0, rest);
    let bytes = stale.iter().map(|a| a.bytes).sum();
    let plan = ExecutionPlan::generic(TOOL, plugin_toolkit::serde_json::to_value(&args)?.into())
        .detailed(
            format!(
                "delete {} artifact(s) ({bytes} bytes) older than {} hour(s), then run {CLEANUP_TASK}",
                stale.len(),
                args.older_than_hours
            ),
            delete_changes(&stale),
        );
    apply(
        cfg,
        plan,
        stale,
        bytes,
        unlisted,
        unreached,
        args.dry_run,
        deadline,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn apply(
    cfg: Config,
    plan: ExecutionPlan,
    stale: Vec<StaleArtifact>,
    bytes: i64,
    unlisted: Vec<String>,
    mut unreached: Vec<String>,
    dry_run: bool,
    deadline: Instant,
) -> Result<ArtifactPruneOutput> {
    let mut out = ArtifactPruneOutput {
        dry_run,
        plan,
        bytes,
        deleted: vec![],
        failed: vec![],
        unlisted,
        unreached: vec![],
        cleanup_started: None,
        cleanup_error: None,
    };
    if dry_run {
        out.unreached = unreached;
        return Ok(out);
    }
    let done = delete_artifacts(&cfg, &stale, deadline).await?;
    out.deleted = done.deleted;
    out.failed = done.failed;
    unreached.splice(0..0, done.unreached);
    out.unreached = unreached;
    let (started, error) = run_cron(&cfg, CLEANUP_TASK, deadline).await?;
    out.cleanup_started = Some(started);
    out.cleanup_error = error;
    Ok(out)
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, clap::ValueEnum,
)]
#[serde(rename_all = "snake_case")]
#[value(rename_all = "snake_case")]
pub enum CronTask {
    CleanupActions,
    DeleteOldActions,
    ArchiveCleanup,
    CleanupPackages,
}

impl CronTask {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CleanupActions => "cleanup_actions",
            Self::DeleteOldActions => "delete_old_actions",
            Self::ArchiveCleanup => "archive_cleanup",
            Self::CleanupPackages => "cleanup_packages",
        }
    }
}

#[derive(clap::Args, Serialize, Deserialize, JsonSchema)]
pub struct CronExecArgs {
    /// Registered Gitea endpoint.
    #[arg(long)]
    pub endpoint: String,
    /// Gitea admin cron task to start.
    #[arg(long, value_enum)]
    pub task: CronTask,
    /// Return the plan and change nothing. Omitted, applies.
    #[arg(long)]
    #[serde(default)]
    pub dry_run: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct CronExecOutput {
    pub dry_run: bool,
    pub plan: ExecutionPlan,
    pub started: bool,
}

/// Start a Gitea admin cron task now (`POST /admin/cron/{task}`). Needs a token
/// with the write:admin scope.
#[orca_tool(
    domain = "gitea",
    verb = "admin.cron.exec",
    data_mutation = true,
    role = "admin",
    execute_gated = false
)]
pub async fn gitea_admin_cron_exec(args: CronExecArgs, ctx: &ToolCtx) -> Result<CronExecOutput> {
    const TOOL: &str = "gitea.admin.cron.exec";
    authorize_execute(TOOL, ctx.caller().as_ref())?;
    let task = args.task.as_str();
    let plan = ExecutionPlan::generic(TOOL, plugin_toolkit::serde_json::to_value(&args)?.into())
        .detailed(
            format!("start Gitea cron task {task}"),
            vec![PlannedChange::new(task, "start-cron-task")],
        );
    if args.dry_run {
        return Ok(CronExecOutput {
            dry_run: true,
            plan,
            started: false,
        });
    }
    let cfg = crate::tools::resolve_config(&args.endpoint).await?;
    match run_cron(&cfg, task, deadline()).await? {
        (true, _) => Ok(CronExecOutput {
            dry_run: false,
            plan,
            started: true,
        }),
        (false, error) => bail!(error.unwrap_or_else(|| format!("{task}: not started"))),
    }
}

#[derive(clap::Args, Serialize, Deserialize, JsonSchema)]
pub struct StorageRemediateArgs {
    /// Registered Gitea endpoint.
    #[arg(long)]
    pub endpoint: String,
    /// Return the plan and change nothing. Omitted, applies.
    #[arg(long)]
    #[serde(default)]
    pub dry_run: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct StorageRemediateOutput {
    pub pressure: Pressure,
    pub disk: Option<DiskUsage>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disk_error: Option<String>,
    pub watermarks: Watermarks,
    /// Bytes to free to reach the low watermark.
    pub need_bytes: i64,
    #[serde(flatten)]
    pub cleanup: ArtifactPruneOutput,
}

async fn remediate(endpoint: &str, dry_run: bool) -> Result<StorageRemediateOutput> {
    const TOOL: &str = "gitea.storage.remediate";
    let deadline = deadline();
    let Scan {
        cfg,
        report,
        artifacts,
    } = scan(endpoint, None, deadline).await?;
    let need = bytes_to_free(
        report.disk.as_ref(),
        report.artifact_bytes,
        report.watermarks,
    );
    let stale = oldest_until(artifacts, need, MIN_REMEDIATE_AGE_HOURS);
    let bytes = stale.iter().map(|a| a.bytes).sum();
    let summary = if need == 0 {
        format!(
            "below the {}% high watermark; nothing to delete",
            report.watermarks.high
        )
    } else {
        format!(
            "{:?} pressure: delete the {} oldest artifact(s) ({bytes} of {need} bytes needed to reach the {}% low watermark), then run {CLEANUP_TASK}",
            report.pressure,
            stale.len(),
            report.watermarks.low
        )
    };
    let plan = ExecutionPlan::generic(
        TOOL,
        json!({ "endpoint": endpoint, "dry_run": dry_run }).into(),
    )
    .detailed(summary, delete_changes(&stale));
    let cleanup = if need == 0 {
        ArtifactPruneOutput {
            dry_run,
            plan,
            bytes: 0,
            deleted: vec![],
            failed: vec![],
            unlisted: report.unlisted,
            unreached: report.unreached,
            cleanup_started: None,
            cleanup_error: None,
        }
    } else {
        apply(
            cfg,
            plan,
            stale,
            bytes,
            report.unlisted,
            report.unreached,
            dry_run,
            deadline,
        )
        .await?
    };
    Ok(StorageRemediateOutput {
        pressure: report.pressure,
        disk: report.disk,
        disk_error: report.disk_error,
        watermarks: report.watermarks,
        need_bytes: need,
        cleanup,
    })
}

/// Watermark cleanup: at or above the endpoint's high watermark (default 80%),
/// delete the oldest Actions artifacts until usage would fall under the low
/// watermark (default 70%), then start `cleanup_actions`. Below the high
/// watermark it does nothing, so it is safe to run from an orca schedule.
#[orca_tool(
    domain = "gitea",
    verb = "storage.remediate",
    data_mutation = true,
    role = "admin",
    execute_gated = false
)]
pub async fn gitea_storage_remediate(
    args: StorageRemediateArgs,
    ctx: &ToolCtx,
) -> Result<StorageRemediateOutput> {
    authorize_execute("gitea.storage.remediate", ctx.caller().as_ref())?;
    remediate(&args.endpoint, args.dry_run).await
}

fn gb(bytes: i64) -> String {
    format!("{:.1} GiB", bytes as f64 / GIB as f64)
}

pub fn pressure_finding(r: &StorageReport) -> Finding {
    let severity = match r.pressure {
        Pressure::Ok => Severity::Ok,
        Pressure::Warn => Severity::Warn,
        Pressure::Crit => Severity::Crit,
    };
    let disk = match (&r.disk, &r.disk_error) {
        (Some(d), _) => format!(
            "disk {}% used ({} GiB free of {} GiB at {})",
            d.used_pct, d.avail_gb, d.total_gb, d.path
        ),
        (None, Some(e)) => format!("disk unknown: {e}"),
        (None, None) => "disk unknown".to_string(),
    };
    Finding {
        id: format!("storage-pressure:{}", r.endpoint),
        provider: PROVIDER.to_string(),
        severity,
        title: format!("Gitea {} storage pressure: {:?}", r.endpoint, r.pressure),
        detail: format!(
            "{disk}; {} Actions artifact(s) use {}; watermarks high {}% low {}% critical {}%",
            r.artifact_count,
            gb(r.artifact_bytes),
            r.watermarks.high,
            r.watermarks.low,
            r.watermarks.crit
        ),
        repair: (r.pressure != Pressure::Ok).then(|| RepairSpec {
            id: format!("{REMEDIATE_REPAIR}::{}", r.endpoint),
            description: format!(
                "delete the oldest Actions artifacts on {} until usage is under {}%, then run {CLEANUP_TASK}",
                r.endpoint, r.watermarks.low
            ),
            automatic: false,
            privileged: true,
            delegate: None,
        }),
    }
}

pub fn retention_finding(r: &StorageReport) -> Finding {
    let c = &r.retention;
    let effective = c
        .configured_days
        .map_or(format!("~{} day(s) observed", c.observed_days), |d| {
            format!("{d} day(s) configured")
        });
    Finding {
        id: format!("artifact-retention:{}", r.endpoint),
        provider: PROVIDER.to_string(),
        severity: if c.flagged {
            Severity::Warn
        } else {
            Severity::Ok
        },
        title: format!("Gitea {} ARTIFACT_RETENTION_DAYS", r.endpoint),
        detail: match c.recommended_days {
            Some(rec) => format!(
                "retention {effective}; {} uploaded in the last 24h; at that rate {rec} day(s) fit the artifact budget — set [actions] ARTIFACT_RETENTION_DAYS <= {rec} in app.ini",
                gb(c.uploaded_24h_bytes)
            ),
            None => format!("retention {effective}; no uploads in the last 24h"),
        },
        repair: None,
    }
}

async fn diagnose() -> Vec<Finding> {
    let endpoints = match crate::tools::endpoint_db::list() {
        Ok(e) => e,
        Err(e) => {
            return vec![Finding {
                id: "storage-scan".to_string(),
                provider: PROVIDER.to_string(),
                severity: Severity::Crit,
                title: "Gitea endpoints could not be listed".to_string(),
                detail: format!("{e:#}"),
                repair: None,
            }];
        }
    };
    let mut out = Vec::new();
    for ep in endpoints.into_iter().filter(|e| e.enabled) {
        match scan(&ep.name, None, deadline()).await {
            Ok(s) => {
                out.push(pressure_finding(&s.report));
                out.push(retention_finding(&s.report));
            }
            Err(e) => out.push(Finding {
                id: format!("storage-scan:{}", ep.name),
                provider: PROVIDER.to_string(),
                severity: Severity::Warn,
                title: format!("Gitea {} storage could not be scanned", ep.name),
                detail: format!("{e:#}"),
                repair: None,
            }),
        }
    }
    out
}

async fn repair(args: RepairArgs) -> RepairOutcome {
    let fail = |message: String| RepairOutcome {
        id: args.repair_id.clone(),
        provider: PROVIDER.to_string(),
        ok: false,
        message,
    };
    let Some(endpoint) = args
        .repair_id
        .strip_prefix(REMEDIATE_REPAIR)
        .and_then(|r| r.strip_prefix("::"))
    else {
        return fail(format!("unknown gitea repair '{}'", args.repair_id));
    };
    match remediate(endpoint, false).await {
        Ok(o) => RepairOutcome {
            id: args.repair_id.clone(),
            provider: PROVIDER.to_string(),
            ok: o.cleanup.failed.is_empty() && o.cleanup.cleanup_error.is_none(),
            message: format!(
                "deleted {} artifact(s) ({}){}",
                o.cleanup.deleted.len(),
                gb(o.cleanup.deleted.iter().map(|a| a.bytes).sum()),
                o.cleanup
                    .cleanup_error
                    .map(|e| format!("; {e}"))
                    .unwrap_or_default()
            ),
        },
        Err(e) => fail(format!("{e:#}")),
    }
}

pub struct GiteaDiagnostics;

impl DiagnosticsProvider for GiteaDiagnostics {
    fn name(&self) -> &str {
        PROVIDER
    }

    fn diagnose(&self, _args: DiagnoseArgs) -> BoxFuture<'_, anyhow::Result<Vec<Finding>>> {
        Box::pin(async move { Ok(diagnose().await) })
    }

    fn repair(&self, args: RepairArgs) -> BoxFuture<'_, anyhow::Result<RepairOutcome>> {
        Box::pin(async move { Ok(repair(args).await) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn disk(used_pct: u8, total_gb: u64, avail_gb: u64) -> DiskUsage {
        DiskUsage {
            path: "/".into(),
            total_gb,
            avail_gb,
            used_pct,
        }
    }

    fn art(repo: &str, id: i64, bytes: i64, age_hours: i64) -> StaleArtifact {
        StaleArtifact {
            repo: repo.into(),
            id,
            name: Some(format!("a{id}")),
            bytes,
            age_days: age_hours / 24,
            age_hours,
        }
    }

    fn row(high: Option<u32>, low: Option<u32>, crit: Option<u32>) -> Result<Watermarks> {
        Watermarks::resolve("home", high, low, crit)
    }

    #[test]
    fn watermarks_default_and_validate() {
        assert_eq!(row(None, None, None).unwrap(), Watermarks::default());
        assert_eq!(
            row(Some(85), Some(60), None).unwrap(),
            Watermarks {
                high: 85,
                low: 60,
                crit: 95
            }
        );
        assert!(row(Some(70), Some(80), None).is_err());
        assert!(row(Some(96), None, None).is_err());
    }

    #[test]
    fn pressure_uses_disk_then_artifact_bytes() {
        let w = Watermarks::default();
        assert_eq!(pressure(Some(&disk(79, 100, 21)), 0, w), Pressure::Ok);
        assert_eq!(pressure(Some(&disk(80, 100, 20)), 0, w), Pressure::Warn);
        assert_eq!(pressure(Some(&disk(95, 100, 5)), 0, w), Pressure::Crit);
        assert_eq!(pressure(None, ARTIFACT_WARN_BYTES - 1, w), Pressure::Ok);
        assert_eq!(pressure(None, ARTIFACT_WARN_BYTES, w), Pressure::Warn);
        assert_eq!(pressure(None, ARTIFACT_CRIT_BYTES, w), Pressure::Crit);
    }

    #[test]
    fn bytes_to_free_reaches_the_low_watermark() {
        let w = Watermarks::default();
        assert_eq!(bytes_to_free(Some(&disk(79, 100, 21)), 0, w), 0);
        assert_eq!(
            bytes_to_free(Some(&disk(100, 211, 0)), 0, w),
            211 * GIB - 211 * GIB * 70 / 100
        );
        assert_eq!(bytes_to_free(None, 10 * GIB, w), 0);
        assert_eq!(
            bytes_to_free(None, 100 * GIB, w),
            100 * GIB - ARTIFACT_WARN_BYTES * 70 / 80
        );
    }

    #[test]
    fn oldest_first_until_enough_and_never_fresh_ones() {
        let all = vec![
            art("o/a", 1, 10, 5),
            art("o/a", 2, 10, 100),
            art("o/b", 3, 10, 50),
            art("o/b", 4, 1000, 0),
        ];
        let ids: Vec<i64> = oldest_until(all.clone(), 15, 1)
            .iter()
            .map(|a| a.id)
            .collect();
        assert_eq!(ids, vec![2, 3]);
        let ids: Vec<i64> = oldest_until(all.clone(), 0, 1)
            .iter()
            .map(|a| a.id)
            .collect();
        assert!(ids.is_empty());
        let ids: Vec<i64> = oldest_until(all, i64::MAX, 1)
            .iter()
            .map(|a| a.id)
            .collect();
        assert_eq!(ids, vec![2, 3, 1]);
    }

    #[test]
    fn retention_flags_a_window_longer_than_the_budget_holds() {
        let c = retention_check(Some(7), 160, 20 * GIB, 60 * GIB);
        assert_eq!(c.recommended_days, Some(3));
        assert!(c.flagged);
        let c = retention_check(None, 40, 20 * GIB, 60 * GIB);
        assert_eq!(c.observed_days, 2);
        assert!(!c.flagged);
        let c = retention_check(Some(90), 2000, 0, 60 * GIB);
        assert_eq!(c.recommended_days, None);
        assert!(!c.flagged);
        assert_eq!(
            retention_check(Some(7), 0, 100 * GIB, GIB).recommended_days,
            Some(1)
        );
    }

    #[test]
    fn artifact_budget_excludes_non_artifact_usage() {
        let w = Watermarks::default();
        assert_eq!(
            artifact_budget(Some(&disk(100, 200, 0)), 150 * GIB, w),
            140 * GIB - 50 * GIB
        );
        assert_eq!(artifact_budget(Some(&disk(100, 200, 0)), 0, w), 0);
        assert_eq!(artifact_budget(None, 0, w), ARTIFACT_WARN_BYTES);
    }

    #[test]
    fn per_repo_totals_largest_first() {
        let got = per_repo(&[
            art("o/a", 1, 5, 1),
            art("o/b", 2, 7, 1),
            art("o/a", 3, 5, 1),
        ]);
        assert_eq!(
            got,
            vec![
                RepoArtifacts {
                    repo: "o/a".into(),
                    count: 2,
                    bytes: 10
                },
                RepoArtifacts {
                    repo: "o/b".into(),
                    count: 1,
                    bytes: 7
                },
            ]
        );
    }

    #[test]
    fn parses_disk_from_system_health() {
        let v = json!({"healthy": true, "disk": {"path": "/", "totalGb": 211, "availGb": 0, "usedPct": 100}});
        assert_eq!(parse_disk(&v).unwrap(), disk(100, 211, 0));
        assert!(parse_disk(&json!({"disk": null})).is_err());
        assert!(parse_disk(&json!({})).is_err());
    }

    #[tokio::test]
    async fn disk_is_unknown_without_a_host_system() {
        let (d, e) = host_disk(None).await;
        assert!(d.is_none());
        assert!(e.unwrap().contains("host_system"));
    }

    #[tokio::test]
    async fn disk_probe_outside_orca_reports_why() {
        let (d, e) = host_disk(Some("sys")).await;
        assert!(d.is_none());
        assert!(e.unwrap().contains("system.health"));
    }

    fn report(pressure: Pressure, flagged: bool) -> StorageReport {
        StorageReport {
            endpoint: "home".into(),
            repos: vec![],
            artifact_count: 3,
            artifact_bytes: 151 * GIB,
            disk: Some(disk(100, 211, 0)),
            disk_error: None,
            watermarks: Watermarks::default(),
            pressure,
            retention: RetentionCheck {
                configured_days: Some(7),
                observed_days: 7,
                uploaded_24h_bytes: 20 * GIB,
                recommended_days: Some(3),
                flagged,
            },
            unlisted: vec![],
            unreached: vec![],
        }
    }

    #[test]
    fn pressure_finding_maps_severity_and_offers_remediation() {
        let f = pressure_finding(&report(Pressure::Crit, false));
        assert_eq!(f.severity, Severity::Crit);
        assert_eq!(f.id, "storage-pressure:home");
        let r = f.repair.unwrap();
        assert_eq!(r.id, "storage-remediate::home");
        assert!(!r.automatic && r.privileged);
        let f = pressure_finding(&report(Pressure::Ok, false));
        assert_eq!(f.severity, Severity::Ok);
        assert!(f.repair.is_none());
    }

    #[test]
    fn retention_finding_warns_when_flagged() {
        let f = retention_finding(&report(Pressure::Ok, true));
        assert_eq!(f.severity, Severity::Warn);
        assert!(
            f.detail.contains("ARTIFACT_RETENTION_DAYS <= 3"),
            "{}",
            f.detail
        );
        assert_eq!(
            retention_finding(&report(Pressure::Ok, false)).severity,
            Severity::Ok
        );
    }

    #[tokio::test]
    async fn unknown_repair_id_is_refused() {
        let o = repair(RepairArgs {
            provider: PROVIDER.into(),
            repair_id: "nope".into(),
            confirm: true,
        })
        .await;
        assert!(!o.ok);
        assert!(o.message.contains("unknown gitea repair"));
    }

    #[test]
    fn cron_tasks_map_to_gitea_names_and_need_admin() {
        assert_eq!(CronTask::CleanupActions.as_str(), "cleanup_actions");
        assert_eq!(CronTask::DeleteOldActions.as_str(), "delete_old_actions");
        assert_eq!(CronTask::ArchiveCleanup.as_str(), "archive_cleanup");
        assert_eq!(CronTask::CleanupPackages.as_str(), "cleanup_packages");
        let a: CronExecArgs = plugin_toolkit::serde_json::from_value(
            json!({"endpoint": "e", "task": "cleanup_packages"}),
        )
        .unwrap();
        assert_eq!(a.task, CronTask::CleanupPackages);
        for tool in [
            "gitea.admin.cron.exec",
            "gitea.storage.detail",
            "gitea.storage.remediate",
            "gitea.actions.artifacts.delete",
        ] {
            assert_eq!(
                plugin_toolkit::dispatch::required_role(tool),
                Some("admin"),
                "{tool}"
            );
        }
    }

    #[test]
    fn delete_defaults_to_a_day_and_execute() {
        let a: ArtifactDeleteArgs =
            plugin_toolkit::serde_json::from_value(json!({"endpoint": "e"})).unwrap();
        assert_eq!(a.older_than_hours, 24);
        assert!(a.name.is_none() && a.org.is_none() && !a.dry_run);
    }

    #[tokio::test]
    async fn dry_runs_without_admin_caller_are_refused() {
        let ctx = plugin_toolkit::tool_manifest::minimal_ctx();
        for (tool, args) in [
            (
                "gitea.actions.artifacts.delete",
                json!({"endpoint": "e", "dry_run": true}),
            ),
            (
                "gitea.storage.remediate",
                json!({"endpoint": "e", "dry_run": true}),
            ),
            (
                "gitea.admin.cron.exec",
                json!({"endpoint": "e", "task": "cleanup_actions", "dry_run": true}),
            ),
            ("gitea.storage.detail", json!({"endpoint": "e"})),
        ] {
            let err = plugin_toolkit::dispatch::dispatch(tool, args, &ctx)
                .await
                .unwrap_err()
                .to_string();
            assert!(err.contains("caller identity"), "{tool}: {err}");
        }
    }
}
