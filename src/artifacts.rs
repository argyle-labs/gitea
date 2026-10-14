//! `gitea.actions.artifacts.prune`: delete Actions artifacts older than a
//! retention window on every repo, then run Gitea's `cleanup_actions` cron
//! task so the storage is freed now rather than at the next scheduled run.
//!
//! Gitea's own `[actions] ARTIFACT_RETENTION_DAYS` lives in app.ini and has no
//! API; this verb enforces a retention window through the API instead.

use plugin_toolkit::contract::plan::{ExecutionPlan, PlannedChange};
use plugin_toolkit::prelude::*;
use plugin_toolkit::time::{Timestamp, timeout};
use std::time::{Duration, Instant};

use crate::Config;
use crate::generated::types::ActionArtifact;
use crate::runner::api::{status_error, verified_client, verified_generated_client};
use crate::runner::tools::authorize_execute;
use crate::signing::left;

/// Total budget of one call, under orca's 35s plugin-call timeout.
const PRUNE_SECS: u64 = 25;
const CLEANUP_TASK: &str = "cleanup_actions";
const DAY_SECS: i64 = 86_400;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct StaleArtifact {
    pub repo: String,
    pub id: i64,
    pub name: Option<String>,
    pub bytes: i64,
    pub age_days: i64,
}

/// Artifacts created before `cutoff` (unix seconds) that Gitea has not already
/// expired. Artifacts with no creation time are kept: their age is unknown.
pub fn stale_artifacts(
    repo: &str,
    artifacts: &[ActionArtifact],
    now: i64,
    cutoff: i64,
) -> Vec<StaleArtifact> {
    artifacts
        .iter()
        .filter(|a| a.expired != Some(true))
        .filter_map(|a| {
            let created = a.created_at.as_ref()?.unix_seconds();
            let id = a.id?;
            (created < cutoff).then(|| StaleArtifact {
                repo: repo.to_string(),
                id,
                name: a.name.clone(),
                bytes: a.size_in_bytes.unwrap_or_default(),
                age_days: (now - created) / DAY_SECS,
            })
        })
        .collect()
}

#[derive(clap::Args, Serialize, Deserialize, JsonSchema)]
pub struct ArtifactPruneArgs {
    /// Registered Gitea endpoint.
    #[arg(long)]
    pub endpoint: String,
    /// Keep artifacts younger than this many days.
    #[arg(long, default_value_t = 1)]
    #[serde(default = "default_keep_days")]
    pub keep_days: u32,
    /// Return the plan and change nothing. Omitted, applies.
    #[arg(long)]
    #[serde(default)]
    pub dry_run: bool,
}

fn default_keep_days() -> u32 {
    1
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ArtifactPruneOutput {
    pub dry_run: bool,
    pub plan: ExecutionPlan,
    /// Total size of the artifacts selected for deletion.
    pub bytes: i64,
    /// Artifacts deleted; empty on a dry run.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub deleted: Vec<StaleArtifact>,
    /// `owner/name#id (HTTP status or error)` of each delete that failed.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub failed: Vec<String>,
    /// Repos whose artifacts could not be listed, with the reason.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unlisted: Vec<String>,
    /// Repos not reached before the time budget ran out; re-run to finish.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unreached: Vec<String>,
    /// Whether the `cleanup_actions` cron task was started; `None` on a dry run.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cleanup_started: Option<bool>,
    /// Why the `cleanup_actions` cron task could not be started.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cleanup_error: Option<String>,
}

/// `owner/name` of every repo, paging via `fetch`. The flag is false when the
/// deadline cut paging off and the list is partial.
async fn all_repos<F, Fut>(fetch: F, deadline: Instant) -> Result<(Vec<String>, bool)>
where
    F: Fn(usize) -> Fut,
    Fut: std::future::Future<Output = Result<Vec<String>>>,
{
    let mut out = Vec::new();
    for page in 1.. {
        if left(deadline).is_zero() {
            return Ok((out, false));
        }
        let Some(batch) = timeout(left(deadline), fetch(page)).await else {
            return Ok((out, false));
        };
        let batch = batch?;
        if batch.is_empty() {
            break;
        }
        out.extend(batch);
    }
    Ok((out, true))
}

/// One page of repo names. An admin token's search sees every repo.
async fn repo_page(
    client: &plugin_toolkit::reqwest::Client,
    cfg: &Config,
    page: usize,
) -> Result<Vec<String>> {
    #[derive(Deserialize)]
    struct Page {
        data: Vec<Repo>,
    }
    #[derive(Deserialize)]
    struct Repo {
        full_name: String,
    }
    let url = format!(
        "{}/repos/search?limit=50&page={page}",
        cfg.base_url.trim_end_matches('/')
    );
    let resp = client
        .get(url)
        .send()
        .await
        .map_err(|e| anyhow!("search repos: {e}"))?;
    let status = resp.status().as_u16();
    let body = resp.text().await.unwrap_or_default();
    if !(200..300).contains(&status) {
        return Err(status_error("search repos", status, &body));
    }
    let page: Page =
        plugin_toolkit::serde_json::from_str(&body).map_err(|e| anyhow!("search repos: {e}"))?;
    Ok(page.data.into_iter().map(|r| r.full_name).collect())
}

struct Listing {
    stale: Vec<StaleArtifact>,
    unlisted: Vec<String>,
    unreached: Vec<String>,
}

const ARTIFACT_PAGE: usize = 50;

/// Every artifact of a repo, paging until `total_count` is reached. `fetch`
/// returns one page and the total. `Ok(None)` when the deadline cut paging off.
async fn all_artifacts<F, Fut>(fetch: F, deadline: Instant) -> Result<Option<Vec<ActionArtifact>>>
where
    F: Fn(usize) -> Fut,
    Fut: std::future::Future<Output = Result<(i64, Vec<ActionArtifact>)>>,
{
    let mut out = Vec::new();
    for page in 1.. {
        if left(deadline).is_zero() {
            return Ok(None);
        }
        let Some(res) = timeout(left(deadline), fetch(page)).await else {
            return Ok(None);
        };
        let (total, batch) = res?;
        let empty = batch.is_empty();
        out.extend(batch);
        if empty || out.len() as i64 >= total {
            break;
        }
    }
    Ok(Some(out))
}

/// One page of a repo's artifacts, read raw: the generated client exposes no
/// paging parameters.
async fn artifact_page(
    client: &plugin_toolkit::reqwest::Client,
    cfg: &Config,
    full: &str,
    page: usize,
) -> Result<(i64, Vec<ActionArtifact>)> {
    #[derive(Deserialize)]
    struct Page {
        total_count: i64,
        artifacts: Vec<ActionArtifact>,
    }
    let url = format!(
        "{}/repos/{full}/actions/artifacts?limit={ARTIFACT_PAGE}&page={page}",
        cfg.base_url.trim_end_matches('/')
    );
    let resp = client
        .get(url)
        .send()
        .await
        .map_err(|e| anyhow!("list artifacts: {e}"))?;
    let status = resp.status().as_u16();
    let body = resp.text().await.unwrap_or_default();
    if !(200..300).contains(&status) {
        return Err(status_error("list artifacts", status, &body));
    }
    let page: Page =
        plugin_toolkit::serde_json::from_str(&body).map_err(|e| anyhow!("list artifacts: {e}"))?;
    Ok((page.total_count, page.artifacts))
}

async fn list_stale(
    cfg: &Config,
    repos: &[String],
    keep_days: u32,
    deadline: Instant,
) -> Result<Listing> {
    let client = verified_client(cfg)?;
    let now = Timestamp::now().unix_seconds();
    let cutoff = now - i64::from(keep_days) * DAY_SECS;
    let mut listing = Listing {
        stale: Vec::new(),
        unlisted: Vec::new(),
        unreached: Vec::new(),
    };
    for (i, full) in repos.iter().enumerate() {
        if left(deadline).is_zero() {
            listing.unreached.extend_from_slice(&repos[i..]);
            break;
        }
        if full.split_once('/').is_none() {
            listing.unlisted.push(format!("{full} (not owner/name)"));
            continue;
        }
        match all_artifacts(|page| artifact_page(&client, cfg, full, page), deadline).await {
            Ok(Some(all)) => listing
                .stale
                .extend(stale_artifacts(full, &all, now, cutoff)),
            Ok(None) => {
                listing.unreached.extend_from_slice(&repos[i..]);
                break;
            }
            Err(e) => listing.unlisted.push(format!("{full} ({e})")),
        }
    }
    Ok(listing)
}

/// Delete Actions artifacts older than `keep_days` on every repo, then start
/// Gitea's `cleanup_actions` task to free their storage.
#[orca_tool(
    domain = "gitea",
    verb = "actions.artifacts.prune",
    data_mutation = true,
    role = "admin",
    execute_gated = false
)]
pub async fn gitea_actions_artifacts_prune(
    args: ArtifactPruneArgs,
    ctx: &ToolCtx,
) -> Result<ArtifactPruneOutput> {
    const TOOL: &str = "gitea.actions.artifacts.prune";
    // The plan lists every repo and artifact, so a dry run needs admin too.
    authorize_execute(TOOL, ctx.caller().as_ref())?;
    let deadline = Instant::now() + Duration::from_secs(PRUNE_SECS);
    let cfg = crate::tools::resolve_config(&args.endpoint).await?;
    let http = verified_client(&cfg)?;
    let (repos, complete) = all_repos(|page| repo_page(&http, &cfg, page), deadline).await?;
    let Listing {
        stale,
        unlisted,
        mut unreached,
    } = list_stale(&cfg, &repos, args.keep_days, deadline).await?;
    if !complete {
        unreached.push(format!(
            "repos after the first {} (listing ran out of time)",
            repos.len()
        ));
    }
    let bytes = stale.iter().map(|a| a.bytes).sum();
    let changes = stale
        .iter()
        .map(|a| {
            PlannedChange::new(format!("{}#{}", a.repo, a.id), "delete-artifact").with_detail(
                format!(
                    "{} ({} bytes, {} days old)",
                    a.name.as_deref().unwrap_or("?"),
                    a.bytes,
                    a.age_days
                ),
            )
        })
        .collect();
    let plan = ExecutionPlan::generic(TOOL, plugin_toolkit::serde_json::to_value(&args)?.into())
        .detailed(
            format!(
                "delete {} artifact(s) ({bytes} bytes) older than {} day(s), then run {CLEANUP_TASK}",
                stale.len(),
                args.keep_days
            ),
            changes,
        );
    let mut out = ArtifactPruneOutput {
        dry_run: args.dry_run,
        plan,
        bytes,
        deleted: vec![],
        failed: vec![],
        unlisted,
        unreached: vec![],
        cleanup_started: None,
        cleanup_error: None,
    };
    if args.dry_run {
        out.unreached = unreached;
        return Ok(out);
    }
    let client = verified_generated_client(&cfg)?;
    for (i, a) in stale.iter().enumerate() {
        if left(deadline).is_zero() {
            let mut rest: Vec<String> = stale[i..].iter().map(|a| a.repo.clone()).collect();
            rest.dedup();
            unreached.splice(0..0, rest);
            break;
        }
        let (owner, repo) = a.repo.split_once('/').unwrap_or((&a.repo, ""));
        match timeout(
            left(deadline),
            client.delete_artifact(owner, repo, &a.id.to_string()),
        )
        .await
        {
            None => out.failed.push(format!(
                "{}#{} (no answer within the time budget)",
                a.repo, a.id
            )),
            Some(Ok(_)) => out.deleted.push(a.clone()),
            Some(Err(e)) => out.failed.push(match e.status() {
                Some(s) => format!("{}#{} (HTTP {})", a.repo, a.id, s.as_u16()),
                None => format!("{}#{} ({e})", a.repo, a.id),
            }),
        }
    }
    out.unreached = unreached;
    let cleanup = timeout(left(deadline), client.admin_cron_run(CLEANUP_TASK)).await;
    out.cleanup_started = Some(matches!(cleanup, Some(Ok(_))));
    out.cleanup_error = match cleanup {
        None => Some(format!("{CLEANUP_TASK}: no answer within the time budget")),
        Some(Ok(_)) => None,
        Some(Err(e)) => Some(match e.status() {
            Some(s) => format!("{CLEANUP_TASK}: HTTP {}", s.as_u16()),
            None => format!("{CLEANUP_TASK}: {e}"),
        }),
    };
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use plugin_toolkit::serde_json::json;

    fn artifact(id: i64, created: Option<&str>, expired: Option<bool>) -> ActionArtifact {
        plugin_toolkit::serde_json::from_value(json!({
            "id": id,
            "name": format!("a{id}"),
            "size_in_bytes": 100,
            "created_at": created,
            "expired": expired,
        }))
        .unwrap()
    }

    #[test]
    fn selects_only_unexpired_artifacts_older_than_cutoff() {
        let now = Timestamp::parse_rfc3339("2026-10-13T00:00:00Z")
            .unwrap()
            .unix_seconds();
        let cutoff = now - DAY_SECS;
        let all = [
            artifact(1, Some("2026-10-10T00:00:00Z"), None),
            artifact(2, Some("2026-10-12T12:00:00Z"), None),
            artifact(3, Some("2026-10-01T00:00:00Z"), Some(true)),
            artifact(4, None, None),
        ];
        let got = stale_artifacts("o/r", &all, now, cutoff);
        assert_eq!(
            got,
            vec![StaleArtifact {
                repo: "o/r".into(),
                id: 1,
                name: Some("a1".into()),
                bytes: 100,
                age_days: 3,
            }]
        );
    }

    #[test]
    fn prune_requires_admin_and_defaults_to_one_day_and_execute() {
        assert_eq!(
            plugin_toolkit::dispatch::required_role("gitea.actions.artifacts.prune"),
            Some("admin")
        );
        let args: ArtifactPruneArgs =
            plugin_toolkit::serde_json::from_value(json!({"endpoint": "e"})).unwrap();
        assert_eq!(args.keep_days, 1);
        assert!(!args.dry_run);
    }

    #[tokio::test]
    async fn pages_until_total_count() {
        let deadline = Instant::now() + Duration::from_secs(5);
        let calls = std::sync::atomic::AtomicUsize::new(0);
        let got = all_artifacts(
            |page| {
                calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                async move {
                    let batch = match page {
                        1 => (1..=50).map(|i| artifact(i, None, None)).collect(),
                        2 => vec![artifact(51, None, None)],
                        _ => panic!("read past total_count"),
                    };
                    Ok((51, batch))
                }
            },
            deadline,
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(got.len(), 51);
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn paging_stops_at_the_deadline() {
        let deadline = Instant::now();
        let got = all_artifacts(|_| async { Ok((1, vec![])) }, deadline)
            .await
            .unwrap();
        assert!(got.is_none());
    }

    #[tokio::test]
    async fn a_hung_artifact_page_is_cut_off_at_the_deadline() {
        let deadline = Instant::now() + Duration::from_millis(50);
        let got = all_artifacts(
            |_| async {
                plugin_toolkit::time::sleep(Duration::from_secs(60)).await;
                Ok((1, vec![]))
            },
            deadline,
        )
        .await
        .unwrap();
        assert!(got.is_none());
    }

    #[tokio::test]
    async fn repo_listing_out_of_time_returns_what_it_found() {
        let deadline = Instant::now() + Duration::from_millis(200);
        let (repos, complete) = all_repos(
            |page| async move {
                if page == 1 {
                    Ok(vec!["o/a".to_string(), "o/b".to_string()])
                } else {
                    plugin_toolkit::time::sleep(Duration::from_secs(60)).await;
                    Ok(vec![])
                }
            },
            deadline,
        )
        .await
        .unwrap();
        assert_eq!(repos, ["o/a", "o/b"]);
        assert!(!complete);
    }

    #[tokio::test]
    async fn repo_listing_stops_at_an_empty_page() {
        let deadline = Instant::now() + Duration::from_secs(5);
        let (repos, complete) = all_repos(
            |page| async move {
                Ok(if page == 1 {
                    vec!["o/a".to_string()]
                } else {
                    vec![]
                })
            },
            deadline,
        )
        .await
        .unwrap();
        assert_eq!(repos, ["o/a"]);
        assert!(complete);
    }

    #[tokio::test]
    async fn dry_run_without_admin_caller_is_refused() {
        let ctx = plugin_toolkit::tool_manifest::minimal_ctx();
        let err = plugin_toolkit::dispatch::dispatch(
            "gitea.actions.artifacts.prune",
            json!({"endpoint": "e", "dry_run": true}),
            &ctx,
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(err.contains("caller identity"), "{err}");
    }
}
