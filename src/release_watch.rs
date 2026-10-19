use plugin_toolkit::abi::BackendDef;
use plugin_toolkit::contract::notification_source::{
    DISMISS_OP, FixLink, Ingested, POLL_OP, Severity,
};
use plugin_toolkit::prelude::*;
use plugin_toolkit::serde_json::Value;
use plugin_toolkit::time::Timestamp;

use crate::releases::{
    DEFAULT_ORG, FailureStage, ReleaseRun, ReleaseView, list_releases, release_runs, with_failures,
};

pub const SOURCE: &str = "gitea-releases";
const PREFIX: &str = "gitea.__notification_source";
const RUN_WINDOW_SECS: i64 = 48 * 3600;
pub const STALE_DRAFT_SECS: i64 = 24 * 3600;

pub fn backend_def() -> BackendDef {
    BackendDef {
        domain: "notification_source".to_string(),
        name: SOURCE.to_string(),
        kind: SOURCE.to_string(),
        capabilities: vec![POLL_OP.to_string()],
        invoke_prefix: PREFIX.to_string(),
        ..Default::default()
    }
}

pub fn dispatcher(tool: &str, _args: Value) -> Option<std::result::Result<Value, Value>> {
    let op = tool.strip_prefix(PREFIX)?.strip_prefix('.')?;
    Some(match op {
        POLL_OP => plugin_toolkit::reactor::block_on(poll())
            .and_then(|found| Ok(plugin_toolkit::serde_json::to_value(found)?))
            .map_err(|e| Value::String(format!("{e:#}"))),
        DISMISS_OP => Ok(Value::Null),
        other => Err(Value::String(format!("unknown {SOURCE} op {other:?}"))),
    })
}

pub fn latest_failures(runs: &[ReleaseRun]) -> Vec<ReleaseRun> {
    let mut seen: Vec<(&str, &str)> = Vec::new();
    let mut out = Vec::new();
    for run in runs.iter().filter(|r| r.status == "completed") {
        let key = (run.repo.as_str(), run.workflow.as_str());
        if seen.contains(&key) {
            continue;
        }
        seen.push(key);
        if run.failed() {
            out.push(run.clone());
        }
    }
    out
}

fn run_body(run: &ReleaseRun) -> String {
    let mut lines = vec![format!("workflow: {}", run.workflow)];
    if let Some(f) = &run.failure {
        let job = f.job.as_deref().unwrap_or("unknown job");
        let step = match (f.stage, f.step.as_deref()) {
            (FailureStage::Setup, _) => "setup (before any step ran)".to_string(),
            (FailureStage::Step, Some(s)) => s.to_string(),
            (FailureStage::Step, None) => "unknown step".to_string(),
        };
        lines.push(format!("job: {job}"));
        lines.push(format!("step: {step}"));
        if let Some(r) = &f.runner_name {
            lines.push(format!("runner: {r}"));
        }
        if let Some(e) = &f.error {
            lines.push(format!("detail unavailable: {e}"));
        }
        lines.extend(f.log_tail.iter().cloned());
    }
    lines.join("\n")
}

pub fn run_alert(endpoint: &str, run: &ReleaseRun) -> Ingested {
    let what = run
        .tag
        .clone()
        .or_else(|| run.title.clone())
        .unwrap_or_else(|| format!("run {}", run.run_id));
    let url = run
        .failure
        .as_ref()
        .and_then(|f| f.url.clone())
        .or_else(|| run.url.clone());
    Ingested {
        source_ref: format!("{endpoint}:run:{}", run.run_id),
        severity: Severity::Error,
        actionable: true,
        title: format!("Release failed: {} {what}", run.repo),
        body: Some(run_body(run)),
        fix: url.map(|url| FixLink {
            url: Some(url),
            ..Default::default()
        }),
    }
}

pub fn draft_alert(endpoint: &str, draft: &ReleaseView) -> Ingested {
    let created = draft
        .created_at
        .as_ref()
        .map(Timestamp::to_rfc3339)
        .unwrap_or_else(|| "unknown".to_string());
    Ingested {
        source_ref: format!("{endpoint}:draft:{}:{}", draft.repo, draft.tag),
        severity: Severity::Warn,
        actionable: true,
        title: format!(
            "Release draft awaiting approval: {} {}",
            draft.repo, draft.tag
        ),
        body: Some(format!("drafted {created}")),
        fix: draft
            .publish_url
            .clone()
            .or_else(|| draft.url.clone())
            .map(|url| FixLink {
                url: Some(url),
                ..Default::default()
            }),
    }
}

pub fn stale_drafts(drafts: &[ReleaseView], stale_after_secs: i64) -> Vec<&ReleaseView> {
    drafts
        .iter()
        .filter(|d| d.draft && d.age_secs.is_some_and(|a| a >= stale_after_secs))
        .collect()
}

async fn endpoint_alerts(endpoint: &str, now: i64) -> Result<Vec<Ingested>> {
    let cfg = crate::tools::resolve_config(endpoint).await?;
    let runs = release_runs(&cfg, DEFAULT_ORG, now - RUN_WINDOW_SECS, None, now).await?;
    let failed = with_failures(&cfg, latest_failures(&runs)).await;
    let drafts = list_releases(&cfg, DEFAULT_ORG, true, None, now).await?;
    if !drafts.notes.is_empty() {
        bail!("draft scan incomplete: {}", drafts.notes.join("; "));
    }
    let mut out: Vec<Ingested> = failed.iter().map(|r| run_alert(endpoint, r)).collect();
    out.extend(
        stale_drafts(&drafts.releases, STALE_DRAFT_SECS)
            .into_iter()
            .map(|d| draft_alert(endpoint, d)),
    );
    Ok(out)
}

pub async fn poll() -> Result<Vec<Ingested>> {
    let now = Timestamp::now().unix_seconds();
    let mut out = Vec::new();
    for ep in crate::tools::endpoint_db::list()?
        .into_iter()
        .filter(|e| e.enabled)
    {
        out.extend(
            endpoint_alerts(&ep.name, now)
                .await
                .with_context(|| format!("endpoint {}", ep.name))?,
        );
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::releases::{ReleaseKind, RunFailure};

    fn run(id: i64, repo: &str, workflow: &str, status: &str, conclusion: &str) -> ReleaseRun {
        ReleaseRun {
            repo: repo.into(),
            run_id: id,
            workflow: workflow.into(),
            tag: Some(format!("v0.0.{id}")),
            title: None,
            status: status.into(),
            conclusion: Some(conclusion.into()).filter(|c: &String| !c.is_empty()),
            created_at: None,
            duration_secs: None,
            url: Some(format!("https://git.test/{repo}/actions/runs/{id}")),
            failure: None,
        }
    }

    #[test]
    fn only_the_newest_completed_run_per_repo_and_workflow_alerts() {
        let runs = vec![
            run(9, "o/a", "release.yml", "in_progress", ""),
            run(8, "o/a", "release.yml", "completed", "failure"),
            run(7, "o/a", "release.yml", "completed", "failure"),
            run(6, "o/b", "release.yml", "completed", "success"),
            run(5, "o/b", "release.yml", "completed", "failure"),
            run(4, "o/b", "release-draft.yml", "completed", "failure"),
        ];
        let ids: Vec<i64> = latest_failures(&runs).iter().map(|r| r.run_id).collect();
        assert_eq!(ids, vec![8, 4]);
    }

    #[test]
    fn run_alert_is_keyed_per_run_and_carries_step_and_log() {
        let mut r = run(
            7219,
            "argyle-labs/proxmox",
            "release.yml",
            "completed",
            "failure",
        );
        r.failure = Some(RunFailure {
            job: Some("build-aarch64-darwin".into()),
            job_id: Some(14648),
            stage: FailureStage::Setup,
            step: None,
            runner_name: Some("mint".into()),
            log_tail: vec!["##[error]git fetch failed".into()],
            url: Some("https://git.test/argyle-labs/proxmox/actions/runs/7219/jobs/14648".into()),
            error: None,
        });
        let a = run_alert("main", &r);
        assert_eq!(a.source_ref, "main:run:7219");
        assert_eq!(a.severity, Severity::Error);
        assert_eq!(a.title, "Release failed: argyle-labs/proxmox v0.0.7219");
        let body = a.body.unwrap();
        assert!(body.contains("job: build-aarch64-darwin"), "{body}");
        assert!(body.contains("step: setup"), "{body}");
        assert!(body.contains("runner: mint"), "{body}");
        assert!(body.ends_with("##[error]git fetch failed"), "{body}");
        assert_eq!(
            a.fix.unwrap().url.as_deref(),
            Some("https://git.test/argyle-labs/proxmox/actions/runs/7219/jobs/14648")
        );
    }

    #[test]
    fn drafts_alert_only_once_stale_and_link_the_publish_page() {
        let d = |tag: &str, age: i64| ReleaseView {
            repo: "o/r".into(),
            tag: tag.into(),
            name: None,
            kind: ReleaseKind::Rc,
            draft: true,
            prerelease: true,
            created_at: Timestamp::from_unix_seconds(1_000),
            age_secs: Some(age),
            url: Some(format!("https://git.test/o/r/releases/tag/{tag}")),
            publish_url: Some(format!("https://git.test/o/r/releases/edit/{tag}")),
        };
        let drafts = vec![d("v1.0.0-rc.1", 90_000), d("v1.0.0-rc.2", 60)];
        let stale = stale_drafts(&drafts, STALE_DRAFT_SECS);
        assert_eq!(stale.len(), 1);
        let a = draft_alert("main", stale[0]);
        assert_eq!(a.source_ref, "main:draft:o/r:v1.0.0-rc.1");
        assert_eq!(a.severity, Severity::Warn);
        assert_eq!(
            a.fix.unwrap().url.as_deref(),
            Some("https://git.test/o/r/releases/edit/v1.0.0-rc.1")
        );
    }

    #[test]
    fn dispatcher_answers_only_its_prefix() {
        assert!(dispatcher("gitea.release.list", Value::Null).is_none());
        assert_eq!(
            dispatcher("gitea.__notification_source.dismiss_at_source", Value::Null),
            Some(Ok(Value::Null))
        );
        assert!(matches!(
            dispatcher("gitea.__notification_source.bogus", Value::Null),
            Some(Err(_))
        ));
        let def = backend_def();
        assert_eq!(def.domain, "notification_source");
        assert_eq!(def.invoke_prefix, PREFIX);
    }
}
