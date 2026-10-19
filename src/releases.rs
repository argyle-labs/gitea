use std::collections::HashMap;
use std::future::Future;
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};

use plugin_toolkit::prelude::*;
use plugin_toolkit::time::Timestamp;
use serde::de::DeserializeOwned;

use crate::Config;
use crate::ci::{CiJob, StuckKind, classify_queued, job_view, split_repo};
use crate::generated::types;
use crate::runner::api::{self as runner_api, runner_view};
use crate::runner::health::GiteaRunnerView;

pub const DEFAULT_ORG: &str = "argyle-labs";
pub const RELEASE_WORKFLOWS: [&str; 2] = ["release.yml", "release-draft.yml"];
const PAGE: usize = 50;
const MAX_PAGES: u32 = 40;
const PARALLEL: usize = 4;
const REPO_CACHE_TTL: Duration = Duration::from_secs(120);
const LOG_TAIL_LINES: usize = 20;
const LOG_LINE_CHARS: usize = 400;
const DEFAULT_SINCE_SECS: i64 = 24 * 3600;
const SETUP_FAILURE_WINDOW_SECS: i64 = 24 * 3600;

fn encode(s: &str) -> String {
    plugin_toolkit::url::encode(s)
}

fn repo_path(full: &str) -> Result<String> {
    let (o, r) = split_repo(full)?;
    Ok(format!("/repos/{}/{}", encode(o), encode(r)))
}

fn real_time(t: Option<&Timestamp>) -> Option<Timestamp> {
    t.filter(|t| t.unix_seconds() > 0).cloned()
}

async fn get_text(cfg: &Config, path: &str) -> Result<(String, Option<i64>)> {
    let url = format!("{}{path}", cfg.base_url.trim_end_matches('/'));
    let resp = runner_api::verified_client(cfg)?
        .get(url)
        .send()
        .await
        .map_err(|e| anyhow!("GET {path}: {e}"))?;
    let status = resp.status().as_u16();
    let total = resp
        .headers()
        .get("x-total-count")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.trim().parse::<i64>().ok());
    let body = resp.text().await.map_err(|e| anyhow!("GET {path}: {e}"))?;
    if !(200..300).contains(&status) {
        let excerpt: String = body.trim().chars().take(300).collect();
        bail!("GET {path}: HTTP {status}: {excerpt}");
    }
    Ok((body, total))
}

async fn get_json<T: DeserializeOwned>(cfg: &Config, path: &str) -> Result<T> {
    let (body, _) = get_text(cfg, path).await?;
    plugin_toolkit::serde_json::from_str(&body).map_err(|e| anyhow!("GET {path}: {e}"))
}

fn with_page(path: &str, page: u32) -> String {
    let sep = if path.contains('?') { '&' } else { '?' };
    format!("{path}{sep}limit={PAGE}&page={page}")
}

async fn get_pages<T: DeserializeOwned>(
    cfg: &Config,
    path: &str,
    items: impl Fn(&str) -> Result<Vec<T>>,
    more: impl Fn(&[T]) -> bool,
) -> Result<Vec<T>> {
    let mut out = Vec::new();
    for page in 1..=MAX_PAGES {
        let paged = with_page(path, page);
        let (body, total) = get_text(cfg, &paged).await?;
        let batch = items(&body).map_err(|e| anyhow!("GET {paged}: {e}"))?;
        let full = batch.len() >= PAGE;
        let keep_going = more(&batch);
        out.extend(batch);
        if !full || !keep_going || total.is_some_and(|t| out.len() as i64 >= t) {
            break;
        }
    }
    Ok(out)
}

fn json_array<T: DeserializeOwned>(body: &str) -> Result<Vec<T>> {
    Ok(plugin_toolkit::serde_json::from_str(body)?)
}

async fn bounded<T, F, Fut>(items: Vec<T>, f: F) -> Vec<Fut::Output>
where
    F: Fn(T) -> Fut,
    Fut: Future,
{
    let mut out = Vec::with_capacity(items.len());
    let mut rest = items.into_iter().peekable();
    while rest.peek().is_some() {
        let chunk: Vec<Fut> = rest.by_ref().take(PARALLEL).map(&f).collect();
        out.extend(plugin_toolkit::reactor::join_all(chunk).await);
    }
    out
}

#[derive(Deserialize)]
struct RawRepo {
    full_name: String,
    #[serde(default)]
    archived: bool,
}

type RepoCache = HashMap<String, (Instant, Vec<String>)>;

static REPO_CACHE: LazyLock<Mutex<RepoCache>> = LazyLock::new(|| Mutex::new(HashMap::new()));

pub async fn org_repos(cfg: &Config, org: &str) -> Result<Vec<String>> {
    let key = format!("{}|{org}", cfg.base_url);
    if let Some((at, repos)) = REPO_CACHE.lock().unwrap().get(&key)
        && at.elapsed() < REPO_CACHE_TTL
    {
        return Ok(repos.clone());
    }
    let raw: Vec<RawRepo> = get_pages(
        cfg,
        &format!("/orgs/{}/repos", encode(org)),
        json_array,
        |_| true,
    )
    .await?;
    let repos: Vec<String> = raw
        .into_iter()
        .filter(|r| !r.archived)
        .map(|r| r.full_name)
        .collect();
    REPO_CACHE
        .lock()
        .unwrap()
        .insert(key, (Instant::now(), repos.clone()));
    Ok(repos)
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, clap::ValueEnum,
)]
#[serde(rename_all = "lowercase")]
pub enum ReleaseKind {
    Rc,
    Stable,
}

pub fn release_kind(tag: &str, prerelease: bool) -> ReleaseKind {
    if prerelease || tag.contains("-rc") {
        ReleaseKind::Rc
    } else {
        ReleaseKind::Stable
    }
}

pub fn publish_url(html_url: &str) -> String {
    html_url.replacen("/releases/tag/", "/releases/edit/", 1)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ReleaseView {
    pub repo: String,
    pub tag: String,
    pub name: Option<String>,
    pub kind: ReleaseKind,
    pub draft: bool,
    pub prerelease: bool,
    pub created_at: Option<Timestamp>,
    pub age_secs: Option<i64>,
    pub url: Option<String>,
    pub publish_url: Option<String>,
}

pub fn release_view(repo: &str, r: &types::Release, now: i64) -> ReleaseView {
    let tag = r.tag_name.clone().unwrap_or_default();
    let prerelease = r.prerelease.unwrap_or(false);
    let created_at = real_time(r.created_at.as_ref());
    ReleaseView {
        repo: repo.to_string(),
        kind: release_kind(&tag, prerelease),
        tag,
        name: r.name.clone().filter(|n| !n.is_empty()),
        draft: r.draft.unwrap_or(false),
        prerelease,
        age_secs: created_at.as_ref().map(|t| (now - t.unix_seconds()).max(0)),
        created_at,
        url: r.html_url.clone(),
        publish_url: r.html_url.as_deref().map(publish_url),
    }
}

pub fn select_releases(
    mut views: Vec<ReleaseView>,
    draft_only: bool,
    kind: Option<ReleaseKind>,
) -> Vec<ReleaseView> {
    views.retain(|v| (!draft_only || v.draft) && kind.is_none_or(|k| v.kind == k));
    views.sort_by_key(|v| std::cmp::Reverse(v.created_at.as_ref().map(|t| t.unix_seconds())));
    views
}

async fn repo_releases(cfg: &Config, repo: &str, draft_only: bool) -> Result<Vec<types::Release>> {
    let filter = if draft_only { "?draft=true" } else { "" };
    get_pages(
        cfg,
        &format!("{}/releases{filter}", repo_path(repo)?),
        json_array,
        |_| true,
    )
    .await
}

pub async fn list_releases(
    cfg: &Config,
    org: &str,
    draft_only: bool,
    kind: Option<ReleaseKind>,
    now: i64,
) -> Result<ReleaseListOutput> {
    let repos = org_repos(cfg, org).await?;
    let fetched = bounded(repos, |repo| async move {
        let got = repo_releases(cfg, &repo, draft_only).await;
        (repo, got)
    })
    .await;
    let mut views = Vec::new();
    let mut notes = Vec::new();
    for (repo, got) in fetched {
        match got {
            Ok(list) => views.extend(list.iter().map(|r| release_view(&repo, r, now))),
            Err(e) => notes.push(format!("{repo}: {e:#}")),
        }
    }
    Ok(ReleaseListOutput {
        org: org.to_string(),
        releases: select_releases(views, draft_only, kind),
        notes,
    })
}

#[derive(clap::Args, Serialize, Deserialize, JsonSchema)]
pub struct ReleaseListArgs {
    /// Registered Gitea endpoint.
    #[arg(long)]
    pub endpoint: String,
    /// Organization to scan (default argyle-labs).
    #[arg(long)]
    #[serde(default)]
    pub org: Option<String>,
    /// Only unpublished drafts (default true).
    #[arg(long)]
    #[serde(default)]
    pub draft_only: Option<bool>,
    /// Only rc or stable releases.
    #[arg(long, value_enum)]
    #[serde(default)]
    pub kind: Option<ReleaseKind>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ReleaseListOutput {
    pub org: String,
    pub releases: Vec<ReleaseView>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
}

/// Draft and unpublished releases across an organization.
#[orca_tool(domain = "gitea", verb = "release.list", role = "read")]
pub async fn gitea_release_list(
    args: ReleaseListArgs,
    _ctx: &ToolCtx,
) -> Result<ReleaseListOutput> {
    let cfg = crate::tools::resolve_config(&args.endpoint).await?;
    list_releases(
        &cfg,
        args.org.as_deref().unwrap_or(DEFAULT_ORG),
        args.draft_only.unwrap_or(true),
        args.kind,
        Timestamp::now().unix_seconds(),
    )
    .await
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct RawRun {
    #[serde(default)]
    pub id: i64,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub display_title: Option<String>,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub conclusion: Option<String>,
    #[serde(default)]
    pub html_url: Option<String>,
    #[serde(default)]
    pub created_at: Option<Timestamp>,
    #[serde(default)]
    pub started_at: Option<Timestamp>,
    #[serde(default)]
    pub completed_at: Option<Timestamp>,
    #[serde(default)]
    pub repository: Option<RawRunRepo>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct RawRunRepo {
    #[serde(default)]
    pub full_name: Option<String>,
}

#[derive(Deserialize)]
struct RawRuns {
    #[serde(default)]
    workflow_runs: Vec<RawRun>,
}

pub fn release_workflow(path: &str) -> Option<&'static str> {
    let file = path.split('@').next()?;
    RELEASE_WORKFLOWS.into_iter().find(|w| *w == file)
}

pub fn tag_of(path: &str) -> Option<String> {
    path.split_once("@refs/tags/").map(|(_, t)| t.to_string())
}

pub fn parse_since(since: Option<&str>, now: i64) -> Result<i64> {
    let Some(s) = since.map(str::trim).filter(|s| !s.is_empty()) else {
        return Ok(now - DEFAULT_SINCE_SECS);
    };
    if let Ok(t) = Timestamp::parse_rfc3339(s) {
        return Ok(t.unix_seconds());
    }
    let (n, unit) = s.split_at(s.len() - 1);
    let scale = match unit {
        "m" => 60,
        "h" => 3600,
        "d" => 86_400,
        _ => bail!("since must be RFC3339 or a span like 90m, 24h, 7d; got {s:?}"),
    };
    let n: i64 = n
        .parse()
        .map_err(|_| anyhow!("since must be RFC3339 or a span like 90m, 24h, 7d; got {s:?}"))?;
    Ok(now - n * scale)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum FailureStage {
    Setup,
    Step,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct RunFailure {
    pub job: Option<String>,
    pub job_id: Option<i64>,
    pub stage: FailureStage,
    pub step: Option<String>,
    pub runner_name: Option<String>,
    pub log_tail: Vec<String>,
    pub url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ReleaseRun {
    pub repo: String,
    pub run_id: i64,
    pub workflow: String,
    pub tag: Option<String>,
    pub title: Option<String>,
    pub status: String,
    pub conclusion: Option<String>,
    pub created_at: Option<Timestamp>,
    pub duration_secs: Option<i64>,
    pub url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure: Option<RunFailure>,
}

impl ReleaseRun {
    pub fn failed(&self) -> bool {
        self.conclusion.as_deref() == Some("failure")
    }
}

pub fn release_run_view(r: &RawRun, now: i64) -> Option<ReleaseRun> {
    let path = r.path.as_deref()?;
    let workflow = release_workflow(path)?;
    let repo = r
        .repository
        .as_ref()
        .and_then(|repo| repo.full_name.clone())
        .or_else(|| {
            r.html_url
                .as_deref()
                .and_then(crate::ci::repo_from_actions_url)
        })?;
    let started = real_time(r.started_at.as_ref());
    let completed = real_time(r.completed_at.as_ref());
    let duration_secs = match (started, completed) {
        (Some(s), Some(c)) => Some((c.unix_seconds() - s.unix_seconds()).max(0)),
        (Some(s), None) => Some((now - s.unix_seconds()).max(0)),
        _ => None,
    };
    Some(ReleaseRun {
        repo,
        run_id: r.id,
        workflow: workflow.to_string(),
        tag: tag_of(path),
        title: r.display_title.clone(),
        status: r.status.clone().unwrap_or_default(),
        conclusion: r.conclusion.clone().filter(|c| !c.is_empty()),
        created_at: real_time(r.created_at.as_ref()),
        duration_secs,
        url: r.html_url.clone(),
        failure: None,
    })
}

pub fn status_matches(run: &ReleaseRun, status: Option<&str>) -> bool {
    status.is_none_or(|s| run.status == s || run.conclusion.as_deref() == Some(s))
}

fn concluded(step: &types::ActionWorkflowStep, c: &str) -> bool {
    step.conclusion.as_deref() == Some(c)
}

pub fn is_setup_failure(job: &types::ActionWorkflowJob) -> bool {
    job.conclusion.as_deref() == Some("failure")
        && !job
            .steps
            .iter()
            .any(|s| concluded(s, "success") || concluded(s, "failure"))
}

pub fn failing_stage(job: &types::ActionWorkflowJob) -> (FailureStage, Option<String>) {
    if is_setup_failure(job) {
        return (FailureStage::Setup, None);
    }
    let step = job
        .steps
        .iter()
        .find(|s| concluded(s, "failure"))
        .and_then(|s| s.name.clone());
    (FailureStage::Step, step)
}

fn strip_timestamp(line: &str) -> &str {
    match line.split_once(' ') {
        Some((ts, rest)) if Timestamp::parse_rfc3339(ts).is_ok() => rest,
        _ => line,
    }
}

pub fn log_tail(log: &str, n: usize) -> Vec<String> {
    let lines: Vec<String> = log
        .lines()
        .map(|l| strip_timestamp(l).trim_end())
        .filter(|l| {
            !l.trim().is_empty()
                && !l.starts_with("::group::")
                && !l.starts_with("::endgroup::")
                && !l.starts_with("Cleaning up container")
        })
        .map(|l| l.chars().take(LOG_LINE_CHARS).collect())
        .collect();
    lines[lines.len().saturating_sub(n)..].to_vec()
}

pub fn first_failed_job(jobs: &[types::ActionWorkflowJob]) -> Option<&types::ActionWorkflowJob> {
    jobs.iter()
        .find(|j| j.conclusion.as_deref() == Some("failure"))
}

pub async fn run_failure(cfg: &Config, run: &ReleaseRun) -> RunFailure {
    let blank = |error: String| RunFailure {
        job: None,
        job_id: None,
        stage: FailureStage::Step,
        step: None,
        runner_name: None,
        log_tail: Vec::new(),
        url: run.url.clone(),
        error: Some(error),
    };
    let base = match repo_path(&run.repo) {
        Ok(b) => b,
        Err(e) => return blank(format!("{e:#}")),
    };
    let jobs: types::ActionWorkflowJobsResponse =
        match get_json(cfg, &format!("{base}/actions/runs/{}/jobs", run.run_id)).await {
            Ok(j) => j,
            Err(e) => return blank(format!("{e:#}")),
        };
    let Some(job) = first_failed_job(&jobs.jobs) else {
        return blank("no job concluded failure".to_string());
    };
    let (stage, step) = failing_stage(job);
    let (log_tail, error) = match job.id {
        Some(id) => match get_text(cfg, &format!("{base}/actions/jobs/{id}/logs")).await {
            Ok((log, _)) => (log_tail(&log, LOG_TAIL_LINES), None),
            Err(e) => (Vec::new(), Some(format!("{e:#}"))),
        },
        None => (Vec::new(), Some("failed job has no id".to_string())),
    };
    RunFailure {
        job: job.name.clone(),
        job_id: job.id,
        stage,
        step,
        runner_name: job.runner_name.clone().filter(|n| !n.is_empty()),
        log_tail,
        url: job.html_url.clone().or_else(|| run.url.clone()),
        error,
    }
}

pub async fn list_release_runs(
    cfg: &Config,
    org: &str,
    since: i64,
    status: Option<&str>,
    now: i64,
) -> Result<Vec<ReleaseRun>> {
    let runs = release_runs(cfg, org, since, status, now).await?;
    Ok(with_failures(cfg, runs).await)
}

pub async fn release_runs(
    cfg: &Config,
    org: &str,
    since: i64,
    status: Option<&str>,
    now: i64,
) -> Result<Vec<ReleaseRun>> {
    let raw: Vec<RawRun> = get_pages(
        cfg,
        &format!("/orgs/{}/actions/runs", encode(org)),
        |body| Ok(plugin_toolkit::serde_json::from_str::<RawRuns>(body)?.workflow_runs),
        |page| {
            page.iter()
                .filter_map(|r| real_time(r.created_at.as_ref()))
                .all(|t| t.unix_seconds() >= since)
        },
    )
    .await?;
    let runs: Vec<ReleaseRun> = raw
        .iter()
        .filter(|r| real_time(r.created_at.as_ref()).is_none_or(|t| t.unix_seconds() >= since))
        .filter_map(|r| release_run_view(r, now))
        .filter(|r| status_matches(r, status))
        .collect();
    Ok(runs)
}

pub async fn with_failures(cfg: &Config, runs: Vec<ReleaseRun>) -> Vec<ReleaseRun> {
    bounded(runs, |mut run| async move {
        if run.failed() {
            run.failure = Some(run_failure(cfg, &run).await);
        }
        run
    })
    .await
}

#[derive(clap::Args, Serialize, Deserialize, JsonSchema)]
pub struct ReleaseRunsArgs {
    /// Registered Gitea endpoint.
    #[arg(long)]
    pub endpoint: String,
    /// Organization to scan (default argyle-labs).
    #[arg(long)]
    #[serde(default)]
    pub org: Option<String>,
    /// RFC3339 time or span such as 90m, 24h, 7d (default 24h).
    #[arg(long)]
    #[serde(default)]
    pub since: Option<String>,
    /// Status or conclusion, e.g. in_progress, queued, failure, success.
    #[arg(long)]
    #[serde(default)]
    pub status: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ReleaseRunsOutput {
    pub org: String,
    pub since: Option<Timestamp>,
    pub runs: Vec<ReleaseRun>,
}

/// Recent release.yml and release-draft.yml runs across an organization.
#[orca_tool(domain = "gitea", verb = "release.runs", role = "read")]
pub async fn gitea_release_runs(
    args: ReleaseRunsArgs,
    _ctx: &ToolCtx,
) -> Result<ReleaseRunsOutput> {
    let now = Timestamp::now().unix_seconds();
    let since = parse_since(args.since.as_deref(), now)?;
    let org = args.org.as_deref().unwrap_or(DEFAULT_ORG);
    let cfg = crate::tools::resolve_config(&args.endpoint).await?;
    Ok(ReleaseRunsOutput {
        org: org.to_string(),
        since: Timestamp::from_unix_seconds(since),
        runs: list_release_runs(&cfg, org, since, args.status.as_deref(), now).await?,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum RunnerScope {
    Instance,
    Org,
    Repo,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct FleetRunner {
    pub scope: RunnerScope,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repo: Option<String>,
    #[serde(flatten)]
    pub runner: GiteaRunnerView,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum FleetFlagKind {
    SetupFailures,
    NoOnlineRunner,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct FleetFlag {
    pub kind: FleetFlagKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runner: Option<String>,
    pub labels: Vec<String>,
    pub count: usize,
    pub detail: String,
    pub job_urls: Vec<String>,
}

#[derive(Deserialize)]
struct RawJobs {
    #[serde(default)]
    jobs: Vec<types::ActionWorkflowJob>,
}

pub fn setup_failure_flags(
    runners: &[FleetRunner],
    failed: &[types::ActionWorkflowJob],
    since: i64,
) -> Vec<FleetFlag> {
    let mut by_runner: Vec<(&str, Vec<&types::ActionWorkflowJob>)> = Vec::new();
    for job in failed.iter().filter(|j| {
        is_setup_failure(j)
            && real_time(j.created_at.as_ref()).is_some_and(|t| t.unix_seconds() >= since)
    }) {
        let Some(name) = job.runner_name.as_deref().filter(|n| !n.is_empty()) else {
            continue;
        };
        match by_runner.iter_mut().find(|(n, _)| *n == name) {
            Some((_, jobs)) => jobs.push(job),
            None => by_runner.push((name, vec![job])),
        }
    }
    by_runner
        .into_iter()
        .filter_map(|(name, jobs)| {
            let r = runners.iter().find(|r| r.runner.name == name && r.runner.online)?;
            Some(FleetFlag {
                kind: FleetFlagKind::SetupFailures,
                runner: Some(name.to_string()),
                labels: r.runner.labels.clone(),
                count: jobs.len(),
                detail: format!(
                    "online but {} recent job(s) failed before any step ran (task fetch or action setup)",
                    jobs.len()
                ),
                job_urls: jobs.iter().filter_map(|j| j.html_url.clone()).collect(),
            })
        })
        .collect()
}

pub fn queued_label_flags(
    runners: &[FleetRunner],
    queued: &[types::ActionWorkflowJob],
    every_runner_visible: bool,
    now: i64,
) -> Vec<FleetFlag> {
    let pool: Vec<GiteaRunnerView> = runners.iter().map(|r| r.runner.clone()).collect();
    let mut flags: Vec<FleetFlag> = Vec::new();
    for job in queued {
        let view: CiJob = job_view(job, now);
        let Some(stuck) = classify_queued(&view, Some(&pool), 0) else {
            continue;
        };
        let unserved = match stuck.kind {
            StuckKind::MatchingRunnersOffline => true,
            StuckKind::NoMatchingRunner => every_runner_visible,
            _ => false,
        };
        if !unserved {
            continue;
        }
        let mut labels = view.labels.clone();
        labels.sort();
        match flags.iter_mut().find(|f| f.labels == labels) {
            Some(f) => {
                f.count += 1;
                f.job_urls.extend(view.url.clone());
            }
            None => flags.push(FleetFlag {
                kind: FleetFlagKind::NoOnlineRunner,
                runner: None,
                detail: String::new(),
                labels,
                count: 1,
                job_urls: view.url.into_iter().collect(),
            }),
        }
    }
    for f in &mut flags {
        f.detail = format!(
            "{} queued job(s) need [{}] and no online runner carries it",
            f.count,
            f.labels.join(", ")
        );
    }
    flags
}

async fn runners_at(cfg: &Config, path: &str) -> Result<Vec<GiteaRunnerView>> {
    let resp: types::ActionRunnersResponse = get_json(cfg, path).await?;
    Ok(resp.runners.into_iter().map(runner_view).collect())
}

fn scoped(scope: RunnerScope, repo: Option<&str>, list: Vec<GiteaRunnerView>) -> Vec<FleetRunner> {
    list.into_iter()
        .map(|runner| FleetRunner {
            scope,
            repo: repo.map(str::to_string),
            runner,
        })
        .collect()
}

async fn newest_jobs(
    cfg: &Config,
    org: &str,
    status: &str,
) -> Result<Vec<types::ActionWorkflowJob>> {
    let path = format!(
        "/orgs/{}/actions/jobs?status={status}&sort=id&order=desc&limit={PAGE}&page=1",
        encode(org)
    );
    Ok(get_json::<RawJobs>(cfg, &path).await?.jobs)
}

pub fn admin_unavailable(e: &anyhow::Error) -> String {
    let msg = format!("{e:#}");
    if msg.contains("HTTP 401") || msg.contains("HTTP 403") {
        "unavailable: token lacks read:admin".to_string()
    } else {
        format!("unavailable: {msg}")
    }
}

pub async fn runner_fleet(cfg: &Config, org: &str, now: i64) -> Result<RunnerFleetOutput> {
    let mut notes = Vec::new();
    let mut runners = scoped(
        RunnerScope::Org,
        None,
        runners_at(cfg, &format!("/orgs/{}/actions/runners", encode(org))).await?,
    );
    let instance_runners = match runners_at(cfg, "/admin/actions/runners").await {
        Ok(list) => {
            runners.extend(scoped(RunnerScope::Instance, None, list));
            None
        }
        Err(e) => Some(admin_unavailable(&e)),
    };
    let repos = org_repos(cfg, org).await?;
    let per_repo = bounded(repos, |repo| async move {
        let got = match repo_path(&repo) {
            Ok(base) => runners_at(cfg, &format!("{base}/actions/runners")).await,
            Err(e) => Err(e),
        };
        (repo, got)
    })
    .await;
    for (repo, got) in per_repo {
        match got {
            Ok(list) => runners.extend(scoped(RunnerScope::Repo, Some(&repo), list)),
            Err(e) => notes.push(format!("{repo} runners: {e:#}")),
        }
    }
    let mut flags = Vec::new();
    match newest_jobs(cfg, org, "failure").await {
        Ok(failed) => flags.extend(setup_failure_flags(
            &runners,
            &failed,
            now - SETUP_FAILURE_WINDOW_SECS,
        )),
        Err(e) => notes.push(format!("failed jobs unavailable: {e:#}")),
    }
    match newest_jobs(cfg, org, "queued").await {
        Ok(queued) => flags.extend(queued_label_flags(
            &runners,
            &queued,
            instance_runners.is_none(),
            now,
        )),
        Err(e) => notes.push(format!("queued jobs unavailable: {e:#}")),
    }
    Ok(RunnerFleetOutput {
        org: org.to_string(),
        runners,
        instance_runners,
        flags,
        notes,
    })
}

#[derive(clap::Args, Serialize, Deserialize, JsonSchema)]
pub struct RunnerFleetArgs {
    /// Registered Gitea endpoint.
    #[arg(long)]
    pub endpoint: String,
    /// Organization to scan (default argyle-labs).
    #[arg(long)]
    #[serde(default)]
    pub org: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct RunnerFleetOutput {
    pub org: String,
    pub runners: Vec<FleetRunner>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub instance_runners: Option<String>,
    pub flags: Vec<FleetFlag>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
}

/// Instance, org and repo runners as Gitea sees them, with unhealthy ones flagged.
#[orca_tool(domain = "gitea", verb = "runner.fleet", role = "read")]
pub async fn gitea_runner_fleet(
    args: RunnerFleetArgs,
    _ctx: &ToolCtx,
) -> Result<RunnerFleetOutput> {
    let cfg = crate::tools::resolve_config(&args.endpoint).await?;
    runner_fleet(
        &cfg,
        args.org.as_deref().unwrap_or(DEFAULT_ORG),
        Timestamp::now().unix_seconds(),
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ts(s: &str) -> Timestamp {
        Timestamp::parse_rfc3339(s).unwrap()
    }

    fn job(json: &str) -> types::ActionWorkflowJob {
        plugin_toolkit::serde_json::from_str(json).unwrap()
    }

    fn fleet(name: &str, labels: &[&str], online: bool) -> FleetRunner {
        FleetRunner {
            scope: RunnerScope::Org,
            repo: None,
            runner: GiteaRunnerView {
                id: 1,
                name: name.into(),
                status: if online { "online" } else { "offline" }.into(),
                online,
                busy: false,
                disabled: false,
                labels: labels.iter().map(|l| l.to_string()).collect(),
            },
        }
    }

    #[test]
    fn release_fixture_parses_into_a_view() {
        let r: types::Release = plugin_toolkit::serde_json::from_str(
            r#"{"id":2930,"tag_name":"v0.1.2-rc.5","name":"smb v0.1.2-rc.5","draft":true,"prerelease":true,
                "created_at":"2026-10-19T10:04:16-06:00","published_at":null,
                "html_url":"https://git.test/argyle-labs/smb/releases/tag/v0.1.2-rc.5","assets":[]}"#,
        )
        .unwrap();
        let now = ts("2026-10-19T17:04:16Z").unix_seconds();
        let v = release_view("argyle-labs/smb", &r, now);
        assert_eq!(v.kind, ReleaseKind::Rc);
        assert!(v.draft);
        assert_eq!(v.age_secs, Some(3600));
        assert_eq!(
            v.publish_url.as_deref(),
            Some("https://git.test/argyle-labs/smb/releases/edit/v0.1.2-rc.5")
        );
    }

    #[test]
    fn kind_comes_from_prerelease_or_rc_tag() {
        assert_eq!(release_kind("v1.0.0", false), ReleaseKind::Stable);
        assert_eq!(release_kind("v1.0.0-rc.2", false), ReleaseKind::Rc);
        assert_eq!(release_kind("v1.0.0", true), ReleaseKind::Rc);
    }

    #[test]
    fn selection_filters_and_sorts_newest_first() {
        let v = |tag: &str, draft: bool, at: &str| ReleaseView {
            repo: "o/r".into(),
            tag: tag.into(),
            name: None,
            kind: release_kind(tag, false),
            draft,
            prerelease: false,
            created_at: Some(ts(at)),
            age_secs: None,
            url: None,
            publish_url: None,
        };
        let all = vec![
            v("v1.0.0", true, "2026-10-01T00:00:00Z"),
            v("v1.1.0-rc.1", true, "2026-10-02T00:00:00Z"),
            v("v0.9.0", false, "2026-10-03T00:00:00Z"),
        ];
        let drafts = select_releases(all.clone(), true, None);
        assert_eq!(
            drafts.iter().map(|r| r.tag.as_str()).collect::<Vec<_>>(),
            vec!["v1.1.0-rc.1", "v1.0.0"]
        );
        let stable = select_releases(all, false, Some(ReleaseKind::Stable));
        assert_eq!(
            stable.iter().map(|r| r.tag.as_str()).collect::<Vec<_>>(),
            vec!["v0.9.0", "v1.0.0"]
        );
    }

    #[test]
    fn run_fixture_keeps_only_release_workflows() {
        let runs: RawRuns = plugin_toolkit::serde_json::from_str(
            r#"{"workflow_runs":[
              {"id":7228,"path":"release.yml@refs/tags/v0.0.1-rc.4","display_title":"Release v0.0.1-rc.4","status":"queued","conclusion":null,
               "html_url":"https://git.test/argyle-labs/komga/actions/runs/7228","created_at":"2026-10-19T09:52:22-06:00",
               "started_at":"1969-12-31T17:00:00-07:00","completed_at":"1969-12-31T17:00:00-07:00","repository":{"full_name":"argyle-labs/komga"}},
              {"id":7236,"path":"release-draft.yml@refs/heads/main","display_title":"Release draft RC","status":"completed","conclusion":"success",
               "html_url":"https://git.test/argyle-labs/smb/actions/runs/7236","created_at":"2026-10-19T10:04:15-06:00",
               "started_at":"2026-10-19T10:04:15-06:00","completed_at":"2026-10-19T10:04:17-06:00"},
              {"id":7238,"path":"ci.yml@refs/pull/17/head","status":"in_progress","repository":{"full_name":"argyle-labs/mqtt"}}
            ]}"#,
        )
        .unwrap();
        let now = ts("2026-10-19T17:00:00Z").unix_seconds();
        let views: Vec<ReleaseRun> = runs
            .workflow_runs
            .iter()
            .filter_map(|r| release_run_view(r, now))
            .collect();
        assert_eq!(views.len(), 2);
        assert_eq!(views[0].tag.as_deref(), Some("v0.0.1-rc.4"));
        assert_eq!(views[0].workflow, "release.yml");
        assert_eq!(views[0].duration_secs, None);
        assert_eq!(views[1].repo, "argyle-labs/smb");
        assert_eq!(views[1].workflow, "release-draft.yml");
        assert_eq!(views[1].tag, None);
        assert_eq!(views[1].duration_secs, Some(2));
        assert!(status_matches(&views[1], Some("success")));
        assert!(status_matches(&views[1], Some("completed")));
        assert!(!status_matches(&views[0], Some("failure")));
    }

    #[test]
    fn since_accepts_rfc3339_and_spans() {
        let now = 100_000;
        assert_eq!(parse_since(None, now).unwrap(), now - 86_400);
        assert_eq!(parse_since(Some("90m"), now).unwrap(), now - 5_400);
        assert_eq!(parse_since(Some("2d"), now).unwrap(), now - 172_800);
        assert_eq!(parse_since(Some("1970-01-01T00:01:00Z"), now).unwrap(), 60);
        assert!(parse_since(Some("soon"), now).is_err());
        assert!(parse_since(Some("xh"), now).is_err());
    }

    #[test]
    fn failing_step_is_the_first_failed_step() {
        let j = job(r#"{"id":1,"name":"build","conclusion":"failure","steps":[
                {"number":0,"name":"checkout","conclusion":"success"},
                {"number":1,"name":"cargo build","conclusion":"failure"},
                {"number":2,"name":"upload","conclusion":"skipped"}]}"#);
        assert_eq!(
            failing_stage(&j),
            (FailureStage::Step, Some("cargo build".into()))
        );
        assert!(!is_setup_failure(&j));
    }

    #[test]
    fn a_job_that_fails_before_any_step_ran_is_a_setup_failure() {
        let cancelled = job(
            r#"{"id":14427,"name":"build-aarch64-darwin","conclusion":"failure","runner_name":"mint","steps":[
                {"number":0,"name":"Run job-plugin-release-build","status":"completed","conclusion":"cancelled"}]}"#,
        );
        assert_eq!(failing_stage(&cancelled), (FailureStage::Setup, None));
        let empty = job(r#"{"id":2,"conclusion":"failure","steps":[]}"#);
        assert!(is_setup_failure(&empty));
        let skipped = job(r#"{"id":3,"conclusion":"skipped","steps":[]}"#);
        assert!(!is_setup_failure(&skipped));
    }

    #[test]
    fn log_tail_drops_timestamps_and_group_noise() {
        let log = "2026-10-19T15:04:42.0456430Z ::group::Runner Information\n\
                   2026-10-19T15:04:42.0456450Z Runner labels: macos\n\
                   2026-10-19T15:04:42.0456470Z ::endgroup::\n\
                   2026-10-19T15:04:42.0484390Z Prepare all required actions\n\
                   \n\
                   2026-10-19T15:04:42.3795240Z ##[error]git fetch: exit status 1\n\
                   2026-10-19T15:04:42.3797150Z Cleaning up container for job build\n\
                   2026-10-19T15:04:42.3820560Z Job failed\n";
        assert_eq!(
            log_tail(log, 3),
            vec![
                "Prepare all required actions",
                "##[error]git fetch: exit status 1",
                "Job failed"
            ]
        );
        assert_eq!(log_tail(log, 20).len(), 4);
        assert_eq!(log_tail("", 20), Vec::<String>::new());
    }

    #[test]
    fn online_runner_with_setup_failures_is_flagged() {
        let runners = vec![
            fleet("mint", &["macos"], true),
            fleet("freyr", &["ubuntu-latest"], false),
        ];
        let failed = vec![
            job(
                r#"{"id":1,"conclusion":"failure","runner_name":"mint","created_at":"2026-10-19T15:00:00Z","html_url":"https://git.test/o/r/actions/runs/1/jobs/1","steps":[]}"#,
            ),
            job(
                r#"{"id":2,"conclusion":"failure","runner_name":"mint","created_at":"2026-10-19T15:00:00Z","steps":[{"name":"build","conclusion":"failure"}]}"#,
            ),
            job(
                r#"{"id":3,"conclusion":"failure","runner_name":"mint","created_at":"2026-10-01T15:00:00Z","steps":[]}"#,
            ),
            job(
                r#"{"id":4,"conclusion":"failure","runner_name":"freyr","created_at":"2026-10-19T15:00:00Z","steps":[]}"#,
            ),
        ];
        let since = ts("2026-10-19T00:00:00Z").unix_seconds();
        let flags = setup_failure_flags(&runners, &failed, since);
        assert_eq!(flags.len(), 1, "{flags:?}");
        assert_eq!(flags[0].kind, FleetFlagKind::SetupFailures);
        assert_eq!(flags[0].runner.as_deref(), Some("mint"));
        assert_eq!(flags[0].count, 1);
        assert_eq!(flags[0].job_urls.len(), 1);
    }

    #[test]
    fn queued_labels_without_an_online_runner_are_flagged_once() {
        let runners = vec![
            fleet("mint-arm64", &["linux-arm64"], false),
            fleet("baldur", &["ubuntu-latest"], true),
        ];
        let queued = vec![
            job(
                r#"{"id":1,"status":"queued","labels":["linux-arm64"],"created_at":"2026-10-19T15:00:00Z","html_url":"https://git.test/o/a/actions/runs/1/jobs/1"}"#,
            ),
            job(
                r#"{"id":2,"status":"queued","labels":["linux-arm64"],"created_at":"2026-10-19T15:00:00Z","html_url":"https://git.test/o/b/actions/runs/2/jobs/2"}"#,
            ),
            job(
                r#"{"id":3,"status":"queued","labels":["ubuntu-latest"],"created_at":"2026-10-19T15:00:00Z"}"#,
            ),
            job(
                r#"{"id":4,"status":"queued","labels":["windows"],"created_at":"2026-10-19T15:00:00Z"}"#,
            ),
        ];
        let flags = queued_label_flags(
            &runners,
            &queued,
            true,
            ts("2026-10-19T16:00:00Z").unix_seconds(),
        );
        assert_eq!(flags.len(), 2, "{flags:?}");
        assert_eq!(flags[0].labels, vec!["linux-arm64"]);
        assert_eq!(flags[0].count, 2);
        assert_eq!(flags[0].job_urls.len(), 2);
        assert!(
            flags[0].detail.starts_with("2 queued job(s)"),
            "{}",
            flags[0].detail
        );
        assert_eq!(flags[1].labels, vec!["windows"]);
        let partial = queued_label_flags(
            &runners,
            &queued,
            false,
            ts("2026-10-19T16:00:00Z").unix_seconds(),
        );
        assert_eq!(partial.len(), 1, "{partial:?}");
        assert_eq!(partial[0].labels, vec!["linux-arm64"]);
    }

    #[test]
    fn admin_403_reads_as_missing_scope() {
        assert_eq!(
            admin_unavailable(&anyhow!("GET /admin/actions/runners: HTTP 403: forbidden")),
            "unavailable: token lacks read:admin"
        );
        assert!(admin_unavailable(&anyhow!("timeout")).starts_with("unavailable: timeout"));
    }

    fn with_http(
        route: impl Fn(&str) -> (u16, Vec<(&'static str, String)>, String) + Send + 'static,
        f: impl std::future::Future<Output = ()>,
    ) -> Vec<String> {
        let urls = std::sync::Arc::new(Mutex::new(Vec::<String>::new()));
        let seen = urls.clone();
        plugin_toolkit::capsink::with_cap_sink(
            Box::new(move |_c: &str, json: &str| {
                let req: plugin_toolkit::serde_json::Value =
                    plugin_toolkit::serde_json::from_str(json).unwrap();
                let url = req["url"].as_str().unwrap_or_default().to_string();
                let (status, headers, body) = route(&url);
                seen.lock().unwrap().push(url);
                Ok(plugin_toolkit::serde_json::json!({
                    "status": status,
                    "headers": headers,
                    "body": body.into_bytes(),
                })
                .to_string())
            }),
            || {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap()
                    .block_on(f)
            },
        );
        urls.lock().unwrap().clone()
    }

    #[test]
    fn org_repos_paginate_skip_archived_and_cache() {
        let urls = with_http(
            |url| {
                let body = if url.contains("page=1") {
                    let repos: Vec<String> = (0..PAGE)
                        .map(|i| format!(r#"{{"full_name":"o/r{i}","archived":{}}}"#, i == 0))
                        .collect();
                    format!("[{}]", repos.join(","))
                } else {
                    r#"[{"full_name":"o/last"}]"#.to_string()
                };
                (200, vec![("X-Total-Count", "51".to_string())], body)
            },
            async {
                let cfg = Config::new("https://cache.test/api/v1", "k");
                let repos = org_repos(&cfg, "o").await.unwrap();
                assert_eq!(repos.len(), PAGE);
                assert_eq!(repos.last().map(String::as_str), Some("o/last"));
                assert_eq!(org_repos(&cfg, "o").await.unwrap(), repos);
            },
        );
        assert_eq!(urls.len(), 2, "{urls:?}");
        assert!(
            urls[1].ends_with("/orgs/o/repos?limit=50&page=2"),
            "{}",
            urls[1]
        );
    }

    #[test]
    fn failed_run_reads_jobs_then_the_failed_jobs_log() {
        let urls = with_http(
            |url| {
                if url.ends_with("/actions/runs/9/jobs") {
                    (
                        200,
                        vec![],
                        r#"{"jobs":[{"id":20,"name":"build","conclusion":"success","steps":[]},
                                    {"id":21,"name":"publish","conclusion":"failure","runner_name":"baldur",
                                     "html_url":"https://git.test/o/r/actions/runs/9/jobs/21",
                                     "steps":[{"name":"upload","conclusion":"failure"}]}]}"#
                            .into(),
                    )
                } else if url.ends_with("/actions/jobs/21/logs") {
                    (200, vec![], "2026-10-19T15:04:42Z ##[error]boom\n".into())
                } else {
                    panic!("unexpected {url}")
                }
            },
            async {
                let cfg = Config::new("https://run.test/api/v1", "k");
                let run = ReleaseRun {
                    repo: "o/r".into(),
                    run_id: 9,
                    workflow: "release.yml".into(),
                    tag: Some("v1.0.0".into()),
                    title: None,
                    status: "completed".into(),
                    conclusion: Some("failure".into()),
                    created_at: None,
                    duration_secs: None,
                    url: None,
                    failure: None,
                };
                let runs = with_failures(&cfg, vec![run]).await;
                let f = runs[0].failure.as_ref().unwrap();
                assert_eq!(f.job.as_deref(), Some("publish"));
                assert_eq!(f.step.as_deref(), Some("upload"));
                assert_eq!(f.runner_name.as_deref(), Some("baldur"));
                assert_eq!(f.log_tail, vec!["##[error]boom"]);
                assert_eq!(f.error, None);
            },
        );
        assert_eq!(urls.len(), 2, "{urls:?}");
    }
}
