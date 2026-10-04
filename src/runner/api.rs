//! Gitea's side of runner management: the runner list, the waiting-job queue,
//! registration tokens, and deregistration.

use plugin_toolkit::prelude::*;
use plugin_toolkit::time::Timestamp;

use super::health::{GiteaRunnerView, WaitingJob};
use super::plan::Scope;
use crate::Config;

/// Turn a Gitea HTTP status into an actionable message. 401/403 are the common
/// case: runner administration needs an admin-scoped token, and the fleet's
/// default token has historically lacked it.
fn status_error(what: &str, status: u16, body: &str) -> anyhow::Error {
    let hint = match status {
        401 | 403 => " — the endpoint token needs admin scope (write:admin) to manage runners",
        404 => " — not found",
        _ => "",
    };
    let body = body.trim();
    let body = if body.len() > 300 { &body[..300] } else { body };
    anyhow!("{what}: HTTP {status}{hint}: {body}")
}

/// Every instance-level runner.
pub async fn list_runners(cfg: &Config) -> Result<Vec<GiteaRunnerView>> {
    let client = cfg.build_generated_client()?;
    let resp = client
        .get_admin_runners(None)
        .await
        .map_err(|e| match e.status() {
            Some(s) => status_error("list runners", s.as_u16(), ""),
            None => anyhow!("list runners: {e}"),
        })?;
    Ok(resp
        .into_inner()
        .runners
        .into_iter()
        .map(|r| {
            let status = r.status.unwrap_or_default();
            GiteaRunnerView {
                id: r.id.unwrap_or_default(),
                name: r.name.unwrap_or_default(),
                online: GiteaRunnerView::is_online_status(&status),
                status,
                busy: r.busy.unwrap_or(false),
                disabled: r.disabled.unwrap_or(false),
                labels: r.labels.into_iter().filter_map(|l| l.name).collect(),
            }
        })
        .collect())
}

/// Jobs Gitea is holding for a runner, newest first, with how long each has
/// waited.
pub async fn waiting_jobs(cfg: &Config) -> Result<Vec<WaitingJob>> {
    let client = cfg.build_generated_client()?;
    let resp = client
        .list_admin_workflow_jobs(Some(50), None, None, None, Some("waiting"))
        .await
        .map_err(|e| match e.status() {
            Some(s) => status_error("list waiting jobs", s.as_u16(), ""),
            None => anyhow!("list waiting jobs: {e}"),
        })?;
    let now = Timestamp::now().unix_seconds();
    Ok(resp
        .into_inner()
        .jobs
        .into_iter()
        .map(|j| WaitingJob {
            id: j.id.unwrap_or_default(),
            labels: j.labels,
            waited_secs: j
                .created_at
                .map(|t| now - t.unix_seconds())
                .unwrap_or_default(),
        })
        .collect())
}

fn api_url(cfg: &Config, path: &str) -> String {
    format!("{}{path}", cfg.base_url.trim_end_matches('/'))
}

#[derive(Deserialize)]
struct TokenBody {
    token: String,
}

/// Mint a runner registration token. The generated client discards this
/// endpoint's body (the spec declares no schema for it), so it is read raw.
pub async fn registration_token(cfg: &Config, scope: &Scope) -> Result<String> {
    let url = api_url(cfg, &format!("{}/registration-token", scope.runners_path()));
    let resp = cfg
        .build_reqwest_client()?
        .post(url)
        .send()
        .await
        .map_err(|e| anyhow!("mint registration token: {e}"))?;
    let status = resp.status().as_u16();
    let body = resp
        .text()
        .await
        .map_err(|e| anyhow!("read token response: {e}"))?;
    if !(200..300).contains(&status) {
        return Err(status_error("mint registration token", status, &body));
    }
    let parsed: TokenBody = plugin_toolkit::serde_json::from_str(&body)
        .map_err(|_| anyhow!("registration-token response had no `token` field"))?;
    Ok(parsed.token)
}

/// Delete a runner in Gitea. Already-gone is success: the goal state holds.
pub async fn deregister(cfg: &Config, scope: &Scope, runner_id: i64) -> Result<bool> {
    let url = api_url(cfg, &format!("{}/{runner_id}", scope.runners_path()));
    let resp = cfg
        .build_reqwest_client()?
        .delete(url)
        .send()
        .await
        .map_err(|e| anyhow!("deregister runner {runner_id}: {e}"))?;
    let status = resp.status().as_u16();
    match status {
        200..=299 => Ok(true),
        404 => Ok(false),
        _ => {
            let body = resp.text().await.unwrap_or_default();
            Err(status_error(
                &format!("deregister runner {runner_id}"),
                status,
                &body,
            ))
        }
    }
}

/// The Gitea root URL a runner registers against (the API root minus
/// `/api/v1`).
pub fn instance_url(cfg: &Config) -> String {
    cfg.base_url
        .trim_end_matches('/')
        .trim_end_matches("/api/v1")
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn instance_url_strips_the_api_root() {
        let cfg = Config::new("http://gitea.test:3000/api/v1", "t");
        assert_eq!(instance_url(&cfg), "http://gitea.test:3000");
    }

    #[test]
    fn forbidden_names_the_missing_scope() {
        let e = status_error(
            "list runners",
            403,
            "{\"message\":\"token does not have at least one of required scope(s): [read:admin]\"}",
        );
        assert!(e.to_string().contains("admin scope"), "{e}");
    }
}
