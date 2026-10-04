//! `gitea.ci.status` and `gitea.pr.list`: read-only answers to "what is CI
//! doing" and "which PRs are open, and is their CI green", each in one call.
//!
//! Fetching lives in the `fetch_*` functions; everything that shapes or judges
//! the data is pure so it is unit-tested without a Gitea.

use plugin_toolkit::prelude::*;
use plugin_toolkit::time::Timestamp;

use crate::Config;
use crate::generated::types;
use crate::runner::api::{self as runner_api, status_error};
use crate::runner::health::{DEFAULT_STALL_AFTER_SECS, GiteaRunnerView};

/// Default for how long a job may run before it is reported as stuck.
pub const DEFAULT_LONG_RUNNING_SECS: i64 = 3600;
const JOB_PAGE: i64 = 50;
const CHECKS_PAGE: i64 = 50;
const MAX_LIMIT: u32 = 100;

fn clamp_limit(limit: Option<u32>, default: u32) -> u32 {
    limit.unwrap_or(default).clamp(1, MAX_LIMIT)
}

fn age(now: i64, t: Option<&Timestamp>) -> Option<i64> {
    t.map(|t| (now - t.unix_seconds()).max(0))
}

/// `owner/repo` from a Gitea Actions URL (`.../owner/repo/actions/runs/N...`).
/// Jobs carry no repository field, only URLs.
pub fn repo_from_actions_url(url: &str) -> Option<String> {
    let (before, _) = url.split_once("/actions/runs/")?;
    let mut parts = before.rsplit('/');
    let repo = parts.next().filter(|s| !s.is_empty())?;
    let owner = parts.next().filter(|s| !s.is_empty() && !s.contains(':'))?;
    Some(format!("{owner}/{repo}"))
}

// ═══════════════════════════════════════════════════════════════════════════
// Runs and jobs
// ═══════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct CiRun {
    pub id: i64,
    pub repo: Option<String>,
    pub title: Option<String>,
    /// Workflow file path.
    pub workflow: Option<String>,
    pub branch: Option<String>,
    pub event: Option<String>,
    /// `queued`, `waiting` (blocked on `needs`), `in_progress` or `completed`.
    pub status: String,
    /// Set once completed: `success`, `failure`, `cancelled` or `skipped`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conclusion: Option<String>,
    pub run_number: Option<i64>,
    pub actor: Option<String>,
    /// Seconds since the run started.
    pub age_secs: Option<i64>,
    /// Wall time of a completed run.
    pub duration_secs: Option<i64>,
    pub url: Option<String>,
}

pub fn run_view(r: &types::ActionWorkflowRun, now: i64) -> CiRun {
    let repo = r
        .repository
        .as_ref()
        .and_then(|repo| repo.full_name.clone())
        .or_else(|| r.html_url.as_deref().and_then(repo_from_actions_url));
    let duration_secs = match (&r.started_at, &r.completed_at) {
        (Some(s), Some(c)) => Some((c.unix_seconds() - s.unix_seconds()).max(0)),
        _ => None,
    };
    CiRun {
        id: r.id.unwrap_or_default(),
        repo,
        title: r.display_title.clone(),
        workflow: r.path.clone(),
        branch: r.head_branch.clone(),
        event: r.event.clone(),
        status: r.status.clone().unwrap_or_default(),
        conclusion: r.conclusion.clone().filter(|c| !c.is_empty()),
        run_number: r.run_number,
        actor: r.actor.as_ref().and_then(|u| u.login.clone()),
        age_secs: age(now, r.started_at.as_ref()),
        duration_secs,
        url: r.html_url.clone(),
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct CiJob {
    pub id: i64,
    pub run_id: Option<i64>,
    pub name: Option<String>,
    pub repo: Option<String>,
    pub branch: Option<String>,
    pub status: String,
    /// The `runs-on` labels a runner must carry.
    pub labels: Vec<String>,
    pub runner_name: Option<String>,
    /// Seconds in the current state: since creation while queued or blocked,
    /// since start while running.
    pub age_secs: i64,
    pub url: Option<String>,
}

pub fn job_view(j: &types::ActionWorkflowJob, now: i64) -> CiJob {
    let status = j.status.clone().unwrap_or_default();
    let since = if status == "in_progress" {
        j.started_at.as_ref().or(j.created_at.as_ref())
    } else {
        j.created_at.as_ref()
    };
    CiJob {
        id: j.id.unwrap_or_default(),
        run_id: j.run_id,
        name: j.name.clone(),
        repo: j
            .html_url
            .as_deref()
            .or(j.run_url.as_deref())
            .and_then(repo_from_actions_url),
        branch: j.head_branch.clone(),
        status,
        labels: j.labels.clone(),
        runner_name: j.runner_name.clone().filter(|n| !n.is_empty()),
        age_secs: age(now, since).unwrap_or_default(),
        url: j.html_url.clone(),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum StuckKind {
    /// No enabled runner carries every label the job asks for.
    NoMatchingRunner,
    /// Runners with the labels exist, but none is polling.
    MatchingRunnersOffline,
    /// Every online matching runner is busy: a capacity shortfall.
    MatchingRunnersBusy,
    /// An online, idle matching runner is not taking the job: the runner is
    /// wedged (see `gitea.runner.health` on its system).
    NotPickedUp,
    /// The runner list could not be read, so the cause is unknown.
    RunnersUnknown,
    /// Running longer than the long-running threshold.
    LongRunning,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct StuckJob {
    pub kind: StuckKind,
    pub detail: String,
    pub job: CiJob,
}

fn runner_fits(job: &CiJob, r: &GiteaRunnerView) -> bool {
    !r.disabled && job.labels.iter().all(|l| r.labels.contains(l))
}

fn names(rs: &[&GiteaRunnerView]) -> String {
    rs.iter()
        .map(|r| r.name.as_str())
        .collect::<Vec<_>>()
        .join(", ")
}

/// Why a queued job that has waited past `stall_after_secs` is not running.
pub fn classify_queued(
    job: &CiJob,
    runners: Option<&[GiteaRunnerView]>,
    stall_after_secs: i64,
) -> Option<StuckJob> {
    if job.age_secs < stall_after_secs {
        return None;
    }
    let waited = format!("queued {}s", job.age_secs);
    let labels = job.labels.join(", ");
    let (kind, detail) = match runners {
        None => (
            StuckKind::RunnersUnknown,
            format!("{waited}; the runner list could not be read"),
        ),
        Some(runners) => {
            let fit: Vec<&GiteaRunnerView> =
                runners.iter().filter(|r| runner_fits(job, r)).collect();
            let online: Vec<&GiteaRunnerView> = fit.iter().copied().filter(|r| r.online).collect();
            let idle: Vec<&GiteaRunnerView> = online.iter().copied().filter(|r| !r.busy).collect();
            if fit.is_empty() {
                (
                    StuckKind::NoMatchingRunner,
                    format!("{waited}; no enabled runner carries [{labels}]"),
                )
            } else if online.is_empty() {
                (
                    StuckKind::MatchingRunnersOffline,
                    format!("{waited}; matching runners are offline: {}", names(&fit)),
                )
            } else if idle.is_empty() {
                (
                    StuckKind::MatchingRunnersBusy,
                    format!(
                        "{waited}; every matching runner is busy: {}",
                        names(&online)
                    ),
                )
            } else {
                (
                    StuckKind::NotPickedUp,
                    format!(
                        "{waited} while idle matching runners poll: {}; check gitea.runner.health on their systems",
                        names(&idle)
                    ),
                )
            }
        }
    };
    Some(StuckJob {
        kind,
        detail,
        job: job.clone(),
    })
}

pub fn classify_running(job: &CiJob, long_running_secs: i64) -> Option<StuckJob> {
    (job.age_secs >= long_running_secs).then(|| StuckJob {
        kind: StuckKind::LongRunning,
        detail: format!(
            "running {}s on {}",
            job.age_secs,
            job.runner_name.as_deref().unwrap_or("an unknown runner")
        ),
        job: job.clone(),
    })
}

/// The newest runs across the instance.
pub async fn fetch_runs(cfg: &Config, limit: u32) -> Result<Vec<types::ActionWorkflowRun>> {
    let client = runner_api::verified_generated_client(cfg)?;
    let resp = client
        .list_admin_workflow_runs(None, None, None, None, Some(limit.into()), None, None)
        .await
        .map_err(|e| match e.status() {
            Some(s) => status_error("list workflow runs", s.as_u16(), ""),
            None => anyhow!("list workflow runs: {e}"),
        })?;
    Ok(resp.into_inner().workflow_runs)
}

/// One page of jobs in `status` (a Gitea Actions API filter), and the total
/// Gitea reports so a truncated page can be flagged.
pub async fn fetch_jobs(
    cfg: &Config,
    status: &str,
) -> Result<(Vec<types::ActionWorkflowJob>, Option<i64>)> {
    let client = runner_api::verified_generated_client(cfg)?;
    let resp = client
        .list_admin_workflow_jobs(Some(JOB_PAGE), None, None, None, Some(status))
        .await
        .map_err(|e| match e.status() {
            Some(s) => status_error(&format!("list {status} jobs"), s.as_u16(), ""),
            None => anyhow!("list {status} jobs: {e}"),
        })?
        .into_inner();
    Ok((resp.jobs, resp.total_count))
}

// ═══════════════════════════════════════════════════════════════════════════
// gitea.ci.status
// ═══════════════════════════════════════════════════════════════════════════

#[derive(clap::Args, Serialize, Deserialize, JsonSchema)]
pub struct CiStatusArgs {
    /// Registered Gitea endpoint.
    #[arg(long)]
    pub endpoint: String,
    /// How many recent runs to show (1-100, default 20).
    #[arg(long)]
    #[serde(default)]
    pub limit: Option<u32>,
    /// How long a job may stay queued before it is reported as stuck.
    #[arg(long)]
    #[serde(default)]
    pub stall_after_secs: Option<i64>,
    /// How long a job may run before it is reported as stuck.
    #[arg(long)]
    #[serde(default)]
    pub long_running_secs: Option<i64>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct RunnerCounts {
    pub total: usize,
    pub online: usize,
    pub busy: usize,
    pub disabled: usize,
}

pub fn runner_counts(runners: &[GiteaRunnerView]) -> RunnerCounts {
    RunnerCounts {
        total: runners.len(),
        online: runners.iter().filter(|r| r.online).count(),
        busy: runners.iter().filter(|r| r.busy).count(),
        disabled: runners.iter().filter(|r| r.disabled).count(),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct CiStatusOutput {
    pub runner_counts: RunnerCounts,
    pub runners: Vec<GiteaRunnerView>,
    /// Waiting for a runner.
    pub queued: Vec<CiJob>,
    /// Waiting on other jobs (`needs`) or approval; no runner can take these yet.
    pub blocked: Vec<CiJob>,
    pub running: Vec<CiJob>,
    /// Queued past the stall threshold or running past the long-running one,
    /// each with the likely cause.
    pub stuck: Vec<StuckJob>,
    pub recent_runs: Vec<CiRun>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
}

/// Jobs fetched per status, or the error that status's fetch hit.
pub struct JobPages {
    pub queued: Result<(Vec<types::ActionWorkflowJob>, Option<i64>)>,
    pub blocked: Result<(Vec<types::ActionWorkflowJob>, Option<i64>)>,
    pub running: Result<(Vec<types::ActionWorkflowJob>, Option<i64>)>,
}

/// The Actions API filters behind each list. `waiting` selects jobs blocked
/// on `needs` and `in_progress` only running ones: Gitea offers no filter for
/// jobs being cancelled, so those are not listed.
pub async fn fetch_job_pages(cfg: &Config) -> JobPages {
    JobPages {
        queued: fetch_jobs(cfg, "queued").await,
        blocked: fetch_jobs(cfg, "waiting").await,
        running: fetch_jobs(cfg, "in_progress").await,
    }
}

/// Assemble the CI picture from what was fetched. A failed fetch becomes a
/// note, never a silently empty list.
pub fn ci_status(
    runners: Result<Vec<GiteaRunnerView>>,
    pages: JobPages,
    runs: Result<Vec<types::ActionWorkflowRun>>,
    now: i64,
    stall_after_secs: i64,
    long_running_secs: i64,
) -> CiStatusOutput {
    let mut notes = Vec::new();
    let mut jobs =
        |what: &str, page: Result<(Vec<types::ActionWorkflowJob>, Option<i64>)>| match page {
            Ok((list, total)) => {
                if let Some(total) = total.filter(|t| *t > list.len() as i64) {
                    notes.push(format!("{what}: showing {} of {total} jobs", list.len()));
                }
                list.iter().map(|j| job_view(j, now)).collect()
            }
            Err(e) => {
                notes.push(format!("{what} jobs unavailable: {e:#}"));
                Vec::new()
            }
        };
    let queued: Vec<CiJob> = jobs("queued", pages.queued);
    let blocked: Vec<CiJob> = jobs("blocked", pages.blocked);
    let running: Vec<CiJob> = jobs("running", pages.running);
    let runners = match runners {
        Ok(r) => Some(r),
        Err(e) => {
            notes.push(format!("runner list unavailable: {e:#}"));
            None
        }
    };
    let mut stuck: Vec<StuckJob> = queued
        .iter()
        .filter_map(|j| classify_queued(j, runners.as_deref(), stall_after_secs))
        .chain(
            running
                .iter()
                .filter_map(|j| classify_running(j, long_running_secs)),
        )
        .collect();
    stuck.sort_by_key(|s| std::cmp::Reverse(s.job.age_secs));
    let recent_runs = match runs {
        Ok(r) => r.iter().map(|r| run_view(r, now)).collect(),
        Err(e) => {
            notes.push(format!("recent runs unavailable: {e:#}"));
            Vec::new()
        }
    };
    let runners = runners.unwrap_or_default();
    CiStatusOutput {
        runner_counts: runner_counts(&runners),
        runners,
        queued,
        blocked,
        running,
        stuck,
        recent_runs,
        notes,
    }
}

/// Instance-wide CI state: runners, queued/blocked/running jobs, jobs that
/// look stuck and why, and the most recent workflow runs.
#[orca_tool(domain = "gitea", verb = "ci.status", role = "admin")]
pub async fn gitea_ci_status(args: CiStatusArgs, _ctx: &ToolCtx) -> Result<CiStatusOutput> {
    let cfg = crate::tools::resolve_config(&args.endpoint).await?;
    let runners = runner_api::list_runners(&cfg).await;
    let pages = fetch_job_pages(&cfg).await;
    let runs = fetch_runs(&cfg, clamp_limit(args.limit, 20)).await;
    Ok(ci_status(
        runners,
        pages,
        runs,
        Timestamp::now().unix_seconds(),
        args.stall_after_secs.unwrap_or(DEFAULT_STALL_AFTER_SECS),
        args.long_running_secs.unwrap_or(DEFAULT_LONG_RUNNING_SECS),
    ))
}

// ═══════════════════════════════════════════════════════════════════════════
// gitea.pr.list
// ═══════════════════════════════════════════════════════════════════════════

/// Commit-status rollup for a PR head, as Gitea Actions reports it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct PrCi {
    /// `success`, `pending`, `failure`, `error`, `warning`, `skipped`, or
    /// `none` when nothing has reported on the head commit.
    pub state: String,
    pub checks: Vec<PrCheck>,
    /// Set when Gitea has more checks than one page holds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct PrCheck {
    pub context: String,
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
}

/// The combined-status body. For a commit nothing has reported on, Gitea
/// answers `pending` with a null list, which reads as `none` here.
#[derive(Debug, Default, Deserialize)]
pub struct RawCombinedStatus {
    #[serde(default)]
    pub state: Option<String>,
    #[serde(default)]
    pub statuses: Option<Vec<RawCommitStatus>>,
}

#[derive(Debug, Deserialize)]
pub struct RawCommitStatus {
    #[serde(default)]
    pub context: Option<String>,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub target_url: Option<String>,
}

/// `total` is Gitea's `X-Total-Count`: the body's own count is only the page
/// length, and its `state` is rolled up from that page alone.
pub fn pr_ci(raw: RawCombinedStatus, total: Option<i64>) -> PrCi {
    let checks: Vec<PrCheck> = raw
        .statuses
        .unwrap_or_default()
        .into_iter()
        .map(|s| PrCheck {
            context: s.context.unwrap_or_default(),
            status: s.status.unwrap_or_default(),
            description: s.description.filter(|d| !d.is_empty()),
            url: s.target_url.filter(|u| !u.is_empty()),
        })
        .collect();
    let state = match raw.state.filter(|s| !s.is_empty()) {
        Some(s) if !checks.is_empty() => s,
        _ => "none".to_string(),
    };
    let note = total.filter(|t| *t > checks.len() as i64).map(|t| {
        format!(
            "showing {} of {t} checks; the state covers only these",
            checks.len()
        )
    });
    PrCi {
        state,
        checks,
        note,
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct PrView {
    pub repo: String,
    pub number: i64,
    pub title: Option<String>,
    pub author: Option<String>,
    pub head_branch: Option<String>,
    pub head_sha: Option<String>,
    pub base_branch: Option<String>,
    pub draft: bool,
    pub mergeable: Option<bool>,
    /// Seconds since the PR last changed.
    pub updated_secs_ago: Option<i64>,
    pub url: Option<String>,
    /// Absent when the status could not be read; see `ci_error`.
    pub ci: Option<PrCi>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ci_error: Option<String>,
    /// Set when the PR itself could not be read; only the search fields are
    /// filled in.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

pub fn pr_view(repo: &str, pr: &types::PullRequest, now: i64) -> PrView {
    PrView {
        repo: repo.to_string(),
        number: pr.number.unwrap_or_default(),
        title: pr.title.clone(),
        author: pr.user.as_ref().and_then(|u| u.login.clone()),
        head_branch: pr.head.as_ref().and_then(|h| h.ref_.clone()),
        head_sha: pr.head.as_ref().and_then(|h| h.sha.clone()),
        base_branch: pr.base.as_ref().and_then(|b| b.ref_.clone()),
        draft: pr.draft.unwrap_or(false),
        mergeable: pr.mergeable,
        updated_secs_ago: age(now, pr.updated_at.as_ref()),
        url: pr.html_url.clone(),
        ci: None,
        ci_error: None,
        error: None,
    }
}

/// A PR found by listing or search, and its full record or why that could
/// not be read.
pub struct FetchedPr {
    pub repo: String,
    pub number: i64,
    pub title: Option<String>,
    pub url: Option<String>,
    pub pr: std::result::Result<types::PullRequest, String>,
}

pub fn fetched_view(f: &FetchedPr, now: i64) -> PrView {
    match &f.pr {
        Ok(pr) => pr_view(&f.repo, pr, now),
        Err(e) => PrView {
            repo: f.repo.clone(),
            number: f.number,
            title: f.title.clone(),
            author: None,
            head_branch: None,
            head_sha: None,
            base_branch: None,
            draft: false,
            mergeable: None,
            updated_secs_ago: None,
            url: f.url.clone(),
            ci: None,
            ci_error: None,
            error: Some(e.clone()),
        },
    }
}

/// `(owner, repo)` of an `owner/repo` string.
pub fn split_repo(full: &str) -> Result<(&str, &str)> {
    let segment = |s: &str| !s.is_empty() && s != "." && s != ".." && !s.contains('/');
    match full.split_once('/') {
        Some((o, r)) if segment(o) && segment(r) => Ok((o, r)),
        _ => bail!("repo must be 'owner/name', got {full:?}"),
    }
}

/// `owner/repo` and number of each open PR, newest first. With `repo`, that
/// repository's PRs; otherwise a search across every repository the token
/// can see, optionally limited to one owner.
async fn fetch_open_prs(
    cfg: &Config,
    repo: Option<&str>,
    owner: Option<&str>,
    limit: u32,
) -> Result<Vec<FetchedPr>> {
    let client = runner_api::verified_generated_client(cfg)?;
    if let Some(full) = repo {
        let (o, r) = split_repo(full)?;
        let prs = client
            .repo_list_pull_requests(
                o,
                r,
                None,
                None,
                Some(limit.into()),
                None,
                None,
                None,
                None,
                Some(types::RepoListPullRequestsState::Open),
            )
            .await
            .map_err(|e| match e.status() {
                Some(s) => status_error(&format!("list PRs in {full}"), s.as_u16(), ""),
                None => anyhow!("list PRs in {full}: {e}"),
            })?
            .into_inner();
        return Ok(prs
            .into_iter()
            .map(|p| FetchedPr {
                repo: full.to_string(),
                number: p.number.unwrap_or_default(),
                title: p.title.clone(),
                url: p.html_url.clone(),
                pr: Ok(p),
            })
            .collect());
    }
    let issues = client
        .issue_search_issues(
            None,
            None,
            None,
            None,
            None,
            Some(limit.into()),
            None,
            None,
            owner,
            None,
            None,
            None,
            None,
            None,
            Some(types::IssueSearchIssuesState::Open),
            None,
            Some(types::IssueSearchIssuesType::Pulls),
        )
        .await
        .map_err(|e| match e.status() {
            Some(s) => status_error("search open PRs", s.as_u16(), ""),
            None => anyhow!("search open PRs: {e}"),
        })?
        .into_inner();
    let mut out = Vec::new();
    for issue in issues {
        let (Some(full), Some(number)) = (
            issue.repository.as_ref().and_then(|r| r.full_name.clone()),
            issue.number,
        ) else {
            continue;
        };
        let pr = match split_repo(&full) {
            Ok((o, r)) => client
                .repo_get_pull_request(o, r, number)
                .await
                .map(|p| p.into_inner())
                .map_err(|e| format!("read PR {full}#{number}: {e}")),
            Err(e) => Err(format!("{e:#}")),
        };
        out.push(FetchedPr {
            repo: full,
            number,
            title: issue.title.clone(),
            url: issue.html_url.clone(),
            pr,
        });
    }
    Ok(out)
}

/// The head commit's statuses (one page) and Gitea's total count.
async fn fetch_combined_status(
    cfg: &Config,
    repo: &str,
    sha: &str,
) -> Result<(RawCombinedStatus, Option<i64>)> {
    let (o, r) = split_repo(repo)?;
    let url = format!(
        "{}/repos/{}/{}/commits/{}/status?limit={CHECKS_PAGE}&page=1",
        cfg.base_url.trim_end_matches('/'),
        crate::runner::plan::encode_segment(o),
        crate::runner::plan::encode_segment(r),
        crate::runner::plan::encode_segment(sha),
    );
    let resp = runner_api::verified_client(cfg)?
        .get(url)
        .send()
        .await
        .map_err(|e| anyhow!("read CI status of {repo}@{sha}: {e}"))?;
    let status = resp.status().as_u16();
    let total = resp
        .headers()
        .get("x-total-count")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.trim().parse::<i64>().ok());
    let body = resp
        .text()
        .await
        .map_err(|e| anyhow!("read CI status of {repo}@{sha}: {e}"))?;
    if !(200..300).contains(&status) {
        return Err(status_error(
            &format!("CI status of {repo}@{sha}"),
            status,
            &body,
        ));
    }
    Ok((plugin_toolkit::serde_json::from_str(&body)?, total))
}

/// Open PRs as views, each with its head commit's CI state. A PR or status
/// that cannot be read is reported on its own entry.
pub async fn list_open_prs(
    cfg: &Config,
    repo: Option<&str>,
    owner: Option<&str>,
    limit: u32,
    now: i64,
) -> Result<Vec<PrView>> {
    let mut prs = Vec::new();
    for f in fetch_open_prs(cfg, repo, owner, limit).await? {
        let mut view = fetched_view(&f, now);
        if view.error.is_none() {
            match view.head_sha.as_deref() {
                Some(sha) => match fetch_combined_status(cfg, &f.repo, sha).await {
                    Ok((raw, total)) => view.ci = Some(pr_ci(raw, total)),
                    Err(e) => view.ci_error = Some(format!("{e:#}")),
                },
                None => view.ci_error = Some("PR has no head commit".to_string()),
            }
        }
        prs.push(view);
    }
    Ok(prs)
}

#[derive(clap::Args, Serialize, Deserialize, JsonSchema)]
pub struct PrListArgs {
    /// Registered Gitea endpoint.
    #[arg(long)]
    pub endpoint: String,
    /// Only this repository (`owner/name`).
    #[arg(long)]
    #[serde(default)]
    pub repo: Option<String>,
    /// Only repositories of this user or organization.
    #[arg(long)]
    #[serde(default)]
    pub owner: Option<String>,
    /// Maximum PRs to return (1-100, default 30).
    #[arg(long)]
    #[serde(default)]
    pub limit: Option<u32>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct PrCiCounts {
    pub success: usize,
    pub pending: usize,
    pub failing: usize,
    pub none: usize,
    pub unknown: usize,
}

pub fn pr_ci_counts(prs: &[PrView]) -> PrCiCounts {
    let mut c = PrCiCounts::default();
    for pr in prs {
        match pr.ci.as_ref().map(|ci| ci.state.as_str()) {
            Some("success") => c.success += 1,
            Some("pending") => c.pending += 1,
            Some("failure" | "error") => c.failing += 1,
            Some("none") => c.none += 1,
            _ => c.unknown += 1,
        }
    }
    c
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct PrListOutput {
    pub counts: PrCiCounts,
    pub prs: Vec<PrView>,
}

/// Open pull requests with the CI state of each head commit.
#[orca_tool(domain = "gitea", verb = "pr.list", role = "admin")]
pub async fn gitea_pr_list(args: PrListArgs, _ctx: &ToolCtx) -> Result<PrListOutput> {
    if args.repo.is_some() && args.owner.is_some() {
        bail!("give --repo or --owner, not both");
    }
    let cfg = crate::tools::resolve_config(&args.endpoint).await?;
    let prs = list_open_prs(
        &cfg,
        args.repo.as_deref(),
        args.owner.as_deref(),
        clamp_limit(args.limit, 30),
        Timestamp::now().unix_seconds(),
    )
    .await?;
    Ok(PrListOutput {
        counts: pr_ci_counts(&prs),
        prs,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ts(secs: i64) -> Timestamp {
        Timestamp::from_unix_seconds(secs).unwrap()
    }

    fn runner(name: &str, labels: &[&str], online: bool, busy: bool) -> GiteaRunnerView {
        GiteaRunnerView {
            id: 1,
            name: name.into(),
            status: if online { "idle" } else { "offline" }.into(),
            online,
            busy,
            disabled: false,
            labels: labels.iter().map(|l| l.to_string()).collect(),
        }
    }

    fn job(status: &str, labels: &[&str], age_secs: i64) -> CiJob {
        CiJob {
            id: 7,
            run_id: Some(3),
            name: Some("build".into()),
            repo: Some("o/r".into()),
            branch: Some("main".into()),
            status: status.into(),
            labels: labels.iter().map(|l| l.to_string()).collect(),
            runner_name: None,
            age_secs,
            url: None,
        }
    }

    #[test]
    fn repo_is_read_from_actions_urls() {
        assert_eq!(
            repo_from_actions_url("https://git.test/argyle/orca/actions/runs/12/jobs/0"),
            Some("argyle/orca".into())
        );
        assert_eq!(
            repo_from_actions_url("https://git.test/sub/path/o/r/actions/runs/1"),
            Some("o/r".into())
        );
        assert_eq!(
            repo_from_actions_url("https://git.test/actions/runs/1"),
            None
        );
        assert_eq!(repo_from_actions_url("https://git.test/o/r/pulls/1"), None);
    }

    #[test]
    fn queued_jobs_are_judged_against_the_runner_pool() {
        let linux = ["ubuntu-latest"];
        let stall = 600;
        let cases: Vec<(Vec<GiteaRunnerView>, StuckKind)> = vec![
            (
                vec![runner("mac", &["macos"], true, false)],
                StuckKind::NoMatchingRunner,
            ),
            (
                vec![runner("a", &["ubuntu-latest"], false, false)],
                StuckKind::MatchingRunnersOffline,
            ),
            (
                vec![runner("a", &["ubuntu-latest"], true, true)],
                StuckKind::MatchingRunnersBusy,
            ),
            (
                vec![
                    runner("a", &["ubuntu-latest"], true, true),
                    runner("b", &["ubuntu-latest", "x"], true, false),
                ],
                StuckKind::NotPickedUp,
            ),
        ];
        for (pool, want) in cases {
            let got = classify_queued(&job("queued", &linux, 900), Some(&pool), stall).unwrap();
            assert_eq!(got.kind, want, "{pool:?}: {}", got.detail);
        }
        let mut disabled = runner("a", &["ubuntu-latest"], true, false);
        disabled.disabled = true;
        assert_eq!(
            classify_queued(&job("queued", &linux, 900), Some(&[disabled]), stall)
                .unwrap()
                .kind,
            StuckKind::NoMatchingRunner
        );
        assert_eq!(
            classify_queued(&job("queued", &linux, 900), None, stall)
                .unwrap()
                .kind,
            StuckKind::RunnersUnknown
        );
        assert!(classify_queued(&job("queued", &linux, 30), Some(&[]), stall).is_none());
    }

    #[test]
    fn long_runs_are_flagged_with_their_runner() {
        let mut j = job("in_progress", &[], 7200);
        j.runner_name = Some("baldur".into());
        let s = classify_running(&j, 3600).unwrap();
        assert_eq!(s.kind, StuckKind::LongRunning);
        assert!(s.detail.contains("baldur"), "{}", s.detail);
        assert!(classify_running(&job("in_progress", &[], 60), 3600).is_none());
    }

    #[test]
    fn job_age_counts_from_start_once_running() {
        let j = types::ActionWorkflowJob {
            created_at: Some(ts(1_000)),
            started_at: Some(ts(1_500)),
            status: Some("in_progress".into()),
            html_url: Some("https://git.test/o/r/actions/runs/4/jobs/1".into()),
            runner_name: Some(String::new()),
            ..Default::default()
        };
        let v = job_view(&j, 2_000);
        assert_eq!(v.age_secs, 500);
        assert_eq!(v.repo.as_deref(), Some("o/r"));
        assert_eq!(v.runner_name, None);
        let queued = types::ActionWorkflowJob {
            status: Some("queued".into()),
            ..j
        };
        assert_eq!(job_view(&queued, 2_000).age_secs, 1_000);
    }

    #[test]
    fn run_view_reports_duration_and_repo() {
        let r = types::ActionWorkflowRun {
            id: Some(9),
            started_at: Some(ts(100)),
            completed_at: Some(ts(160)),
            status: Some("completed".into()),
            conclusion: Some("failure".into()),
            html_url: Some("https://git.test/o/r/actions/runs/9".into()),
            ..Default::default()
        };
        let v = run_view(&r, 200);
        assert_eq!(v.duration_secs, Some(60));
        assert_eq!(v.age_secs, Some(100));
        assert_eq!(v.repo.as_deref(), Some("o/r"));
        assert_eq!(v.conclusion.as_deref(), Some("failure"));
    }

    #[test]
    fn ci_status_turns_failed_fetches_into_notes() {
        let queued = types::ActionWorkflowJob {
            id: Some(1),
            status: Some("queued".into()),
            created_at: Some(ts(0)),
            labels: vec!["ubuntu-latest".into()],
            ..Default::default()
        };
        let out = ci_status(
            Ok(vec![runner("a", &["ubuntu-latest"], false, false)]),
            JobPages {
                queued: Ok((vec![queued], Some(80))),
                blocked: Err(anyhow!("HTTP 500")),
                running: Ok((vec![], Some(0))),
            },
            Err(anyhow!("HTTP 403")),
            10_000,
            600,
            3600,
        );
        assert_eq!(out.queued.len(), 1);
        assert_eq!(out.stuck[0].kind, StuckKind::MatchingRunnersOffline);
        assert_eq!(out.runner_counts.total, 1);
        assert_eq!(out.runner_counts.online, 0);
        let notes = out.notes.join("\n");
        assert!(notes.contains("showing 1 of 80"), "{notes}");
        assert!(notes.contains("blocked jobs unavailable"), "{notes}");
        assert!(notes.contains("recent runs unavailable"), "{notes}");
    }

    #[test]
    fn pr_ci_reads_an_empty_state_as_none() {
        let empty: RawCombinedStatus =
            plugin_toolkit::serde_json::from_str(r#"{"state":"","statuses":null}"#).unwrap();
        assert_eq!(pr_ci(empty, Some(0)).state, "none");
        let raw: RawCombinedStatus = plugin_toolkit::serde_json::from_str(
            r#"{"state":"failure","statuses":[{"context":"CI / test (pull_request)","status":"failure","description":"","target_url":"https://git.test/o/r/actions/runs/2"}]}"#,
        )
        .unwrap();
        let ci = pr_ci(raw, Some(1));
        assert_eq!(ci.note, None);
        assert_eq!(ci.state, "failure");
        assert_eq!(ci.checks[0].context, "CI / test (pull_request)");
        assert_eq!(ci.checks[0].description, None);
    }

    #[test]
    fn pr_counts_bucket_by_ci_state() {
        let pr = |state: Option<&str>| PrView {
            repo: "o/r".into(),
            number: 1,
            title: None,
            author: None,
            head_branch: None,
            head_sha: None,
            base_branch: None,
            draft: false,
            mergeable: None,
            updated_secs_ago: None,
            url: None,
            ci: state.map(|s| PrCi {
                state: s.into(),
                checks: vec![],
                note: None,
            }),
            ci_error: None,
            error: None,
        };
        let c = pr_ci_counts(&[
            pr(Some("success")),
            pr(Some("error")),
            pr(Some("failure")),
            pr(Some("pending")),
            pr(Some("none")),
            pr(None),
        ]);
        assert_eq!(
            c,
            PrCiCounts {
                success: 1,
                pending: 1,
                failing: 2,
                none: 1,
                unknown: 1
            }
        );
    }

    #[test]
    fn repo_argument_must_be_owner_slash_name() {
        assert_eq!(split_repo("o/r").unwrap(), ("o", "r"));
        for bad in [
            "o", "o/", "/r", "o/r/x", "./r", "../r", "o/.", "o/..", "../..",
        ] {
            assert!(split_repo(bad).is_err(), "{bad}");
        }
    }

    /// Run `f` with HTTP answered by `route(url) -> (status, headers, body)`,
    /// returning the request URLs in order.
    fn with_http(
        route: impl Fn(&str) -> (u16, Vec<(&'static str, &'static str)>, String) + Send + 'static,
        f: impl std::future::Future<Output = ()>,
    ) -> Vec<String> {
        let urls = std::sync::Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let seen = urls.clone();
        plugin_toolkit::capsink::with_cap_sink(
            Box::new(move |_c: &str, json: &str| {
                let req: plugin_toolkit::serde_json::Value =
                    plugin_toolkit::serde_json::from_str(json).unwrap();
                let url = req["url"].as_str().unwrap_or_default().to_string();
                assert!(req["insecure"] == false, "{json}");
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

    fn cfg() -> Config {
        Config::new("https://git.test/api/v1", "k").insecure(true)
    }

    #[test]
    fn combined_status_is_paged_and_flags_truncation() {
        let urls = with_http(
            |_| {
                (
                    200,
                    vec![("X-Total-Count", "60")],
                    r#"{"state":"success","statuses":[{"context":"ci","status":"success"}]}"#
                        .into(),
                )
            },
            async {
                let (raw, total) = fetch_combined_status(&cfg(), "o/r x", "abc").await.unwrap();
                assert_eq!(total, Some(60));
                let ci = pr_ci(raw, total);
                assert_eq!(ci.state, "success");
                assert!(ci.note.unwrap().contains("1 of 60"));
            },
        );
        assert!(
            urls[0].ends_with("/repos/o/r%20x/commits/abc/status?limit=50&page=1"),
            "{}",
            urls[0]
        );
    }

    #[test]
    fn job_lists_use_the_matching_gitea_filters() {
        let urls = with_http(
            |_| (200, vec![], r#"{"jobs":[],"total_count":0}"#.into()),
            async {
                let pages = fetch_job_pages(&cfg()).await;
                assert!(pages.queued.is_ok() && pages.blocked.is_ok() && pages.running.is_ok());
            },
        );
        let status = |u: &str| {
            u.split(['?', '&'])
                .find_map(|kv| kv.strip_prefix("status="))
                .unwrap_or_default()
                .to_string()
        };
        assert_eq!(
            urls.iter().map(|u| status(u)).collect::<Vec<_>>(),
            vec!["queued", "waiting", "in_progress"],
            "{urls:?}"
        );
    }

    #[test]
    fn pr_list_searches_then_reads_each_pr_and_keeps_going_past_a_bad_one() {
        let urls = with_http(
            |url| {
                if url.contains("/repos/issues/search") {
                    (
                        200,
                        vec![],
                        r#"[{"number":5,"title":"good","html_url":"https://git.test/o/r/pulls/5","repository":{"full_name":"o/r"}},
                            {"number":6,"title":"gone","html_url":"https://git.test/o/r/pulls/6","repository":{"full_name":"o/r"}}]"#
                            .into(),
                    )
                } else if url.ends_with("/repos/o/r/pulls/5") {
                    (
                        200,
                        vec![],
                        r#"{"number":5,"title":"good","head":{"ref":"feat","sha":"aaa"},"base":{"ref":"main"}}"#.into(),
                    )
                } else if url.ends_with("/repos/o/r/pulls/6") {
                    (404, vec![], r#"{"message":"not found"}"#.into())
                } else if url.contains("/commits/aaa/status") {
                    (
                        200,
                        vec![("X-Total-Count", "1")],
                        r#"{"state":"failure","statuses":[{"context":"ci","status":"failure"}]}"#
                            .into(),
                    )
                } else {
                    panic!("unexpected request {url}")
                }
            },
            async {
                let prs = list_open_prs(&cfg(), None, Some("o"), 30, 0).await.unwrap();
                assert_eq!(prs.len(), 2);
                assert_eq!(prs[0].head_branch.as_deref(), Some("feat"));
                assert_eq!(prs[0].ci.as_ref().unwrap().state, "failure");
                assert_eq!(prs[0].error, None);
                assert_eq!(prs[1].number, 6);
                assert_eq!(prs[1].title.as_deref(), Some("gone"));
                assert!(prs[1].error.as_deref().unwrap().contains("o/r#6"));
                assert!(prs[1].ci.is_none() && prs[1].ci_error.is_none());
                assert_eq!(pr_ci_counts(&prs).failing, 1);
                assert_eq!(pr_ci_counts(&prs).unknown, 1);
            },
        );
        assert!(urls[0].contains("/repos/issues/search"), "{}", urls[0]);
        assert!(
            urls[0].contains("type=pulls") && urls[0].contains("state=open"),
            "{}",
            urls[0]
        );
        assert!(urls[0].contains("owner=o"), "{}", urls[0]);
        assert_eq!(urls.len(), 4, "{urls:?}");
    }
}
