//! Gitea's side of runner management: the runner list, the waiting-job queue,
//! registration tokens, and deregistration.

use plugin_toolkit::prelude::*;
use plugin_toolkit::time::Timestamp;

use super::health::{GiteaRunnerView, WaitingJob};
use super::plan::Scope;
use crate::Config;

/// Turn a Gitea HTTP status into an actionable message. 401/403 almost always
/// mean the endpoint token lacks the admin scope runner administration needs.
pub(crate) fn status_error(what: &str, status: u16, body: &str) -> anyhow::Error {
    let hint = match status {
        401 | 403 => " — the endpoint token needs admin scope (write:admin) to manage runners",
        404 => " — not found",
        _ => "",
    };
    let body: String = body.trim().chars().take(300).collect();
    anyhow!("{what}: HTTP {status}{hint}: {body}")
}

/// Marks an API failure worth retrying: no response, 429, or 5xx.
#[derive(Debug)]
pub(crate) struct Transient(pub String);

impl std::fmt::Display for Transient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Transient {}

pub(crate) fn is_transient(e: &anyhow::Error) -> bool {
    e.downcast_ref::<Transient>().is_some()
}

fn classify(what: &str, status: Option<u16>, detail: &str) -> anyhow::Error {
    match status {
        Some(s @ (429 | 500..=599)) => {
            anyhow::Error::new(Transient(status_error(what, s, detail).to_string()))
        }
        Some(s) => status_error(what, s, detail),
        None => anyhow::Error::new(Transient(format!("{what}: {detail}"))),
    }
}

/// Every instance-level runner.
pub async fn list_runners(cfg: &Config) -> Result<Vec<GiteaRunnerView>> {
    let client = verified_generated_client(cfg)?;
    let resp = client
        .get_admin_runners(None)
        .await
        .map_err(|e| match e.status() {
            Some(s) => classify("list runners", Some(s.as_u16()), ""),
            None => classify("list runners", None, &e.to_string()),
        })?;
    Ok(resp
        .into_inner()
        .runners
        .into_iter()
        .map(runner_view)
        .collect())
}

pub(crate) fn runner_view(r: crate::generated::types::ActionRunner) -> GiteaRunnerView {
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
}

/// One runner by id, `None` when Gitea has no such runner.
pub async fn runner_by_id(cfg: &Config, id: i64) -> Result<Option<GiteaRunnerView>> {
    Ok(list_runners(cfg).await?.into_iter().find(|r| r.id == id))
}

/// Jobs Gitea is holding for a runner, newest first, with how long each has
/// waited. The API's `queued` filter is the runner queue; its `waiting` filter
/// is jobs blocked on `needs`, which no runner can take yet.
pub async fn waiting_jobs(cfg: &Config) -> Result<Vec<WaitingJob>> {
    let client = verified_generated_client(cfg)?;
    let resp = client
        .list_admin_workflow_jobs(Some(50), None, None, None, Some("queued"))
        .await
        .map_err(|e| match e.status() {
            Some(s) => status_error("list queued jobs", s.as_u16(), ""),
            None => anyhow!("list queued jobs: {e}"),
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

/// Every runner-administration call carries an admin token, so it always
/// verifies TLS, whatever the endpoint's `insecure` flag says for ordinary
/// API use.
pub(crate) fn verified_client(cfg: &Config) -> Result<plugin_toolkit::reqwest::Client> {
    Ok(cfg.clone().insecure(false).build_reqwest_client()?)
}

pub(crate) fn verified_generated_client(cfg: &Config) -> Result<crate::generated::Client> {
    Ok(cfg.clone().insecure(false).build_generated_client()?)
}

#[derive(Deserialize)]
struct TokenBody {
    token: String,
}

/// Fetch the scope's runner registration token. The generated client discards
/// this endpoint's body (the spec declares no schema for it), so it is read raw.
/// Gitea returns the scope's current reusable token here and has no API to
/// rotate it.
pub async fn registration_token(cfg: &Config, scope: &Scope) -> Result<String> {
    let url = api_url(cfg, &format!("{}/registration-token", scope.runners_path()));
    let resp = verified_client(cfg)?
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

fn generated_error(what: &str, e: crate::generated::Error<()>) -> anyhow::Error {
    match e.status() {
        Some(s) => classify(what, Some(s.as_u16()), ""),
        None => classify(what, None, &e.to_string()),
    }
}

/// Whether `runner_id` exists in `scope`'s runner collection.
pub async fn runner_in_scope(cfg: &Config, scope: &Scope, runner_id: i64) -> Result<bool> {
    let what = format!("look up runner {runner_id} under {}", scope.label());
    let client = verified_generated_client(cfg)?;
    let id = runner_id.to_string();
    let result = match scope {
        Scope::Instance => client.get_admin_runner(&id).await.map(|_| ()),
        Scope::Org(o) => client.get_org_runner(o, &id).await.map(|_| ()),
        Scope::Repo(o, r) => client.get_repo_runner(o, r, &id).await.map(|_| ()),
    };
    match result {
        Ok(()) => Ok(true),
        Err(e) if e.status().map(|s| s.as_u16()) == Some(404) => Ok(false),
        Err(e) => Err(generated_error(&what, e)),
    }
}

/// Set a runner's `disabled` flag. Gitea assigns no new job to a disabled
/// runner; one already running finishes. Called only after
/// [`runner_in_scope`] found the runner, so a 404/405 here means the server
/// predates the edit-runner endpoint.
pub async fn set_disabled(
    cfg: &Config,
    scope: &Scope,
    runner_id: i64,
    disabled: bool,
) -> Result<()> {
    let what = format!("set runner {runner_id} disabled={disabled}");
    let client = verified_generated_client(cfg)?;
    let id = runner_id.to_string();
    let body = crate::generated::types::EditActionRunnerOption { disabled };
    let result = match scope {
        Scope::Instance => client.update_admin_runner(&id, &body).await.map(|_| ()),
        Scope::Org(o) => client.update_org_runner(o, &id, &body).await.map(|_| ()),
        Scope::Repo(o, r) => client
            .update_repo_runner(o, r, &id, &body)
            .await
            .map(|_| ()),
    };
    match result {
        Ok(()) => Ok(()),
        Err(e) if matches!(e.status().map(|s| s.as_u16()), Some(404 | 405)) => Err(anyhow!(
            "{what}: Gitea too old for runner drain (needs >=1.26)"
        )),
        Err(e) => Err(generated_error(&what, e)),
    }
}

/// Delete a runner in Gitea. Already-gone is success: the goal state holds.
pub async fn deregister(cfg: &Config, scope: &Scope, runner_id: i64) -> Result<bool> {
    let url = api_url(cfg, &format!("{}/{runner_id}", scope.runners_path()));
    let resp = verified_client(cfg)?
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
    fn credential_calls_ignore_the_insecure_flag() {
        let captured = std::sync::Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let cap = captured.clone();
        let reply = plugin_toolkit::serde_json::json!({"status": 200, "headers": [], "body": b"{\"token\":\"t\"}".to_vec()}).to_string();
        plugin_toolkit::capsink::with_cap_sink(
            Box::new(move |_c: &str, json: &str| {
                cap.lock().unwrap().push(json.to_string());
                Ok(reply.clone())
            }),
            || {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap();
                rt.block_on(async {
                    let cfg = Config::new("https://gitea.test/api/v1", "k").insecure(true);
                    let t = registration_token(&cfg, &Scope::Org("a b".into()))
                        .await
                        .unwrap();
                    assert_eq!(t, "t");
                });
            },
        );
        let reqs = captured.lock().unwrap();
        assert!(reqs[0].contains("\"insecure\":false"), "{}", reqs[0]);
        assert!(
            reqs[0].contains("/orgs/a%20b/actions/runners/registration-token"),
            "{}",
            reqs[0]
        );
    }

    #[test]
    fn starvation_reads_the_runner_queue_not_blocked_jobs() {
        let captured = std::sync::Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let cap = captured.clone();
        let reply = plugin_toolkit::serde_json::json!({"status": 200, "headers": [], "body": b"{\"jobs\":[],\"total_count\":0}".to_vec()}).to_string();
        plugin_toolkit::capsink::with_cap_sink(
            Box::new(move |_c: &str, json: &str| {
                cap.lock().unwrap().push(json.to_string());
                Ok(reply.clone())
            }),
            || {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap();
                rt.block_on(async {
                    let cfg = Config::new("https://gitea.test/api/v1", "k");
                    assert!(waiting_jobs(&cfg).await.unwrap().is_empty());
                });
            },
        );
        let reqs = captured.lock().unwrap();
        assert!(reqs[0].contains("status=queued"), "{}", reqs[0]);
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
