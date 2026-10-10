//! `gitea.signing` / `gitea.signing.status`: give the Gitea server an SSH
//! signing key so the commits it authors (web merges, "Update branch",
//! squash merges, web edits, wiki edits) are signed.
//!
//! Both verbs act on the orca system they run on, which must be the Gitea
//! host: they read and edit its `app.ini` and restart its service.
//!
//! The private key lives in orca secrets (`gitea.<endpoint>.signing_key`) and
//! in the key file Gitea reads; it is never part of any output.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use plugin_toolkit::contract::plan::{ExecutionPlan, PlannedChange};
use plugin_toolkit::prelude::*;

use crate::Config;
use crate::runner::api::{instance_url, verified_client};
use crate::runner::exec::{chown, write_atomic};
use crate::runner::host::{LocalHost, lookup_user};
use crate::runner::layout::Init;
use crate::runner::tools::authorize_execute;

pub const SECTION: &str = "repository.signing";
const DEFAULT_APP_INI: &str = "/etc/gitea/app.ini";
const DEFAULT_KEY_PATH: &str = "/var/lib/gitea/signing/gitea_signing_ed25519";
const DEFAULT_RUN_USER: &str = "git";
/// Cap on `--verify-secs`. The verify actually gets less when the run's
/// deadline must still fit a rollback (see [`verify_budget`]).
const DEFAULT_VERIFY_SECS: u64 = 20;
/// After a rollback restart, how long to wait for Gitea to answer HTTP at all.
const ROLLBACK_UP_SECS: u64 = 10;
/// Whole `gitea.signing` execute, under orca's 35s plugin-call timeout.
const RUN_SECS: u64 = 30;
/// Each service restart; a hung restart counts as failed.
const RESTART_SECS: u64 = 8;
/// Least verify worth starting; below it a correct config would just roll back.
const MIN_VERIFY_SECS: u64 = 3;
/// Each HTTP attempt inside `verify` / `wait_up`.
const REQUEST_SECS: u64 = 5;
/// Total budget of one `gitea.update_style` call, under orca's 35s timeout.
const UPDATE_STYLE_SECS: u64 = 25;

fn secret_name(endpoint: &str) -> String {
    plugin_toolkit::secrets::scoped_name("gitea", endpoint, "signing_key")
}

/// A verb that needs admin to execute needs it to dry-run too: the plan
/// reveals paths, the service account and the repo list.
fn require_admin(tool: &str, ctx: &ToolCtx) -> Result<()> {
    authorize_execute(tool, ctx.caller().as_ref())
}

// ── app.ini ─────────────────────────────────────────────────────────────────

/// Value of `key` in `section` (`""` = the global, pre-section part).
/// Section and key names compare case-insensitively, as Gitea's loader does.
pub fn ini_get(ini: &str, section: &str, key: &str) -> Option<String> {
    let mut current = String::new();
    for line in ini.lines() {
        let t = line.trim();
        if let Some(name) = section_name(t) {
            current = name;
            continue;
        }
        if !current.eq_ignore_ascii_case(section) {
            continue;
        }
        if let Some((k, v)) = key_value(t)
            && k.eq_ignore_ascii_case(key)
        {
            return Some(unquote(v).to_string());
        }
    }
    None
}

fn section_name(t: &str) -> Option<String> {
    t.strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .map(|s| s.trim().to_string())
}

fn key_value(t: &str) -> Option<(&str, &str)> {
    if t.starts_with(';') || t.starts_with('#') {
        return None;
    }
    let (k, v) = t.split_once('=')?;
    Some((k.trim(), v.trim()))
}

fn unquote(v: &str) -> &str {
    v.strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .or_else(|| v.strip_prefix('`').and_then(|s| s.strip_suffix('`')))
        .unwrap_or(v)
}

/// `ini` with every `(key, value)` set in `section`: existing keys are
/// rewritten in place, missing ones appended to the section, and the section
/// appended if absent. Everything else is left byte-for-byte.
pub fn ini_set(ini: &str, section: &str, settings: &[(&str, String)]) -> String {
    let mut lines: Vec<String> = ini.lines().map(str::to_string).collect();
    let mut done = vec![false; settings.len()];
    let mut current = String::new();
    let mut section_end: Option<usize> = None;
    for (i, line) in lines.iter_mut().enumerate() {
        let t = line.trim().to_string();
        if let Some(name) = section_name(&t) {
            current = name;
            continue;
        }
        if !current.eq_ignore_ascii_case(section) {
            continue;
        }
        if !t.is_empty() {
            section_end = Some(i);
        }
        if let Some((k, _)) = key_value(&t)
            && let Some(j) = settings
                .iter()
                .position(|(sk, _)| sk.eq_ignore_ascii_case(k))
        {
            *line = format!("{} = {}", settings[j].0, settings[j].1);
            done[j] = true;
        }
    }
    let missing: Vec<String> = settings
        .iter()
        .zip(&done)
        .filter(|(_, d)| !**d)
        .map(|((k, v), _)| format!("{k} = {v}"))
        .collect();
    let has_section = ini
        .lines()
        .filter_map(|l| section_name(l.trim()))
        .any(|n| n.eq_ignore_ascii_case(section));
    if has_section {
        let at = section_end.map(|i| i + 1).unwrap_or_else(|| {
            lines
                .iter()
                .position(|l| {
                    section_name(l.trim()).is_some_and(|n| n.eq_ignore_ascii_case(section))
                })
                .map(|i| i + 1)
                .unwrap_or(lines.len())
        });
        lines.splice(at..at, missing);
    } else {
        if lines.last().is_some_and(|l| !l.trim().is_empty()) {
            lines.push(String::new());
        }
        lines.push(format!("[{section}]"));
        lines.extend(missing);
    }
    let mut out = lines.join("\n");
    out.push('\n');
    out
}

/// The `[repository.signing]` settings this verb owns. With
/// `SIGNING_FORMAT = ssh`, `SIGNING_KEY` names the PUBLIC key file and Gitea
/// reads the private key beside it, the same path without `.pub`
/// (https://docs.gitea.com/administration/signing).
pub fn signing_settings(key_path: &Path, name: &str, email: &str) -> Vec<(&'static str, String)> {
    vec![
        ("SIGNING_FORMAT", "ssh".to_string()),
        ("SIGNING_KEY", pub_path(key_path).display().to_string()),
        ("SIGNING_NAME", name.to_string()),
        ("SIGNING_EMAIL", email.to_string()),
        ("INITIAL_COMMIT", "always".to_string()),
        ("CRUD_ACTIONS", "always".to_string()),
        ("WIKI", "always".to_string()),
        ("MERGES", "always".to_string()),
    ]
}

fn pub_path(key_path: &Path) -> PathBuf {
    let mut p = key_path.as_os_str().to_owned();
    p.push(".pub");
    PathBuf::from(p)
}

// ── plan ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeySource {
    /// Neither orca secrets nor the host has a key.
    Generate,
    /// The host has a key orca secrets lacks: store it.
    Adopt,
    /// orca secrets has the key; write it to the host.
    Install,
    /// Both have one; execute checks they are the same key.
    CheckMatch,
}

impl KeySource {
    pub fn decide(in_secrets: bool, on_host: bool) -> Self {
        match (in_secrets, on_host) {
            (false, false) => KeySource::Generate,
            (false, true) => KeySource::Adopt,
            (true, false) => KeySource::Install,
            (true, true) => KeySource::CheckMatch,
        }
    }
}

#[derive(Debug, Clone)]
pub enum Step {
    Key {
        source: KeySource,
        key_path: PathBuf,
        owner: String,
        secret: String,
        comment: String,
    },
    WriteIni {
        path: PathBuf,
        contents: String,
    },
    Restart {
        argv: Vec<String>,
    },
    Verify {
        url: String,
        wait_secs: u64,
    },
}

impl Step {
    pub fn to_change(&self) -> PlannedChange {
        match self {
            Step::Key {
                source,
                key_path,
                owner,
                secret,
                ..
            } => {
                let (action, detail) = match source {
                    KeySource::Generate => (
                        "generate-key",
                        format!("new ed25519 key; private half stored in orca secret '{secret}' and written 0600 owned by '{owner}'"),
                    ),
                    KeySource::Adopt => (
                        "adopt-key",
                        format!("store the existing key in orca secret '{secret}'; fix mode 0600 and owner '{owner}'"),
                    ),
                    KeySource::Install => (
                        "install-key",
                        format!("write the key from orca secret '{secret}', 0600 owned by '{owner}'"),
                    ),
                    KeySource::CheckMatch => (
                        "check-key",
                        format!("host key must match orca secret '{secret}'; fix mode 0600 and owner '{owner}'"),
                    ),
                };
                PlannedChange::new(key_path.display().to_string(), action).with_detail(detail)
            }
            Step::WriteIni { path, .. } => PlannedChange::new(path.display().to_string(), "write")
                .with_detail(format!("set [{SECTION}]: SSH signing for initial commits, web edits, wiki and merges; OVERWRITES any custom SIGNING_*, INITIAL_COMMIT, CRUD_ACTIONS, WIKI and MERGES values, and inline comments on those lines")),
            Step::Restart { argv } => PlannedChange::new(argv.join(" "), "restart").with_detail(
                "Gitea is DOWN while it restarts: expect about 5-30s of failed web, API and git requests",
            ),
            Step::Verify { url, wait_secs } => PlannedChange::new(url.clone(), "verify")
                .with_detail(format!("wait up to {wait_secs}s for it to serve the new public key; on failure restore the previous app.ini and restart")),
        }
    }
}

fn restart_argv(init: Init, service: &str) -> Result<Vec<String>> {
    Ok(match init {
        Init::Systemd => vec!["systemctl".into(), "restart".into(), service.into()],
        Init::Openrc => vec!["rc-service".into(), service.into(), "restart".into()],
        Init::Launchd => bail!("gitea.signing manages a Linux Gitea host (systemd or OpenRC)"),
    })
}

/// What the plan needs from the host, the secret store and Gitea.
pub struct Facts {
    pub ini: String,
    pub init: Init,
    pub key_on_host: bool,
    pub key_in_secrets: bool,
}

pub fn plan(args: &SigningArgs, facts: &Facts, instance: &str) -> Result<Vec<Step>> {
    let owner = ini_get(&facts.ini, "", "RUN_USER").unwrap_or_else(|| DEFAULT_RUN_USER.into());
    let email = match &args.signing_email {
        Some(e) => e.clone(),
        None => match ini_get(&facts.ini, "server", "DOMAIN") {
            Some(d) if !d.is_empty() => format!("gitea@{d}"),
            _ => bail!("app.ini has no [server] DOMAIN; pass --signing-email"),
        },
    };
    let key_path = PathBuf::from(&args.key_path);
    let mut steps = vec![Step::Key {
        source: KeySource::decide(facts.key_in_secrets, facts.key_on_host),
        key_path: key_path.clone(),
        owner,
        secret: secret_name(&args.endpoint),
        comment: email.clone(),
    }];
    let ini = ini_set(
        &facts.ini,
        SECTION,
        &signing_settings(&key_path, &args.signing_name, &email),
    );
    let ini_changed = ini != facts.ini;
    if ini_changed {
        steps.push(Step::WriteIni {
            path: PathBuf::from(&args.app_ini),
            contents: ini,
        });
    }
    // A new or replaced key file needs a restart too: Gitea reads it at start.
    if ini_changed || !facts.key_on_host {
        steps.push(Step::Restart {
            argv: restart_argv(facts.init, &args.service)?,
        });
    }
    steps.push(Step::Verify {
        url: format!("{}/api/v1/signing-key.pub", instance.trim_end_matches('/')),
        wait_secs: args.verify_secs.clamp(1, DEFAULT_VERIFY_SECS),
    });
    Ok(steps)
}

// ── execute ─────────────────────────────────────────────────────────────────

async fn ssh_keygen(host: &LocalHost, args: &[&str]) -> Result<String> {
    let mut argv = vec!["ssh-keygen".to_string()];
    argv.extend(args.iter().map(|s| s.to_string()));
    let out = host.run(&argv, None).await?;
    if !out.ok {
        // stderr of ssh-keygen never carries key material.
        bail!("ssh-keygen failed (exit {:?}): {}", out.code, out.stderr);
    }
    Ok(out.stdout)
}

/// The public half of the key at `key_path`, as `type base64` (no comment).
async fn public_of(host: &LocalHost, key_path: &Path) -> Result<String> {
    let line = ssh_keygen(host, &["-y", "-f", &key_path.to_string_lossy()]).await?;
    Ok(key_body(&line))
}

/// `type base64` of an OpenSSH public key line, dropping any comment.
pub fn key_body(line: &str) -> String {
    line.split_whitespace()
        .take(2)
        .collect::<Vec<_>>()
        .join(" ")
}

/// Ensure the key's directory exists; `true` when this call created it, so
/// only then may its mode and owner be changed. An existing directory must
/// be dedicated to the key: holding nothing but the key and its `.pub`.
fn prepare_key_dir(key_path: &Path) -> Result<bool> {
    let dir = key_path
        .parent()
        .ok_or_else(|| anyhow!("{} has no parent", key_path.display()))?;
    if !dir.exists() {
        std::fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))?;
        return Ok(true);
    }
    let pub_file = pub_path(key_path);
    let allowed = [key_path.file_name(), pub_file.file_name()];
    for entry in std::fs::read_dir(dir).with_context(|| format!("read {}", dir.display()))? {
        let name = entry?.file_name();
        if !allowed.contains(&Some(name.as_os_str())) {
            bail!(
                "{} already exists and holds {:?}, so it is not a dedicated key directory; pass a --key-path in a new or key-only directory",
                dir.display(),
                name
            );
        }
    }
    Ok(false)
}

async fn apply_key(
    host: &LocalHost,
    source: &KeySource,
    key_path: &Path,
    owner: &str,
    secret: &str,
    comment: &str,
) -> Result<String> {
    let (uid, gid) = lookup_user(owner)?
        .ok_or_else(|| anyhow!("Gitea's RUN_USER '{owner}' does not exist on this host"))?;
    let dir = key_path
        .parent()
        .ok_or_else(|| anyhow!("{} has no parent", key_path.display()))?;
    if prepare_key_dir(key_path)? {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
            .with_context(|| format!("chmod {}", dir.display()))?;
        chown(dir, Some(uid), gid, false)?;
    }
    let read_private = || {
        std::fs::read_to_string(key_path).with_context(|| format!("read {}", key_path.display()))
    };
    match source {
        KeySource::Generate => {
            ssh_keygen(
                host,
                &[
                    "-q",
                    "-t",
                    "ed25519",
                    "-N",
                    "",
                    "-C",
                    comment,
                    "-f",
                    &key_path.to_string_lossy(),
                ],
            )
            .await?;
            plugin_toolkit::secrets::set(
                secret,
                &read_private()?,
                Some("Gitea server commit-signing key"),
            )?;
        }
        KeySource::Adopt => {
            plugin_toolkit::secrets::set(
                secret,
                &read_private()?,
                Some("Gitea server commit-signing key"),
            )?;
        }
        KeySource::Install => {
            let private = plugin_toolkit::secrets::get_required(secret)?;
            write_atomic(key_path, private.as_bytes(), 0o600)?;
        }
        KeySource::CheckMatch => {
            let private = plugin_toolkit::secrets::get_required(secret)?;
            if private.trim() != read_private()?.trim() {
                bail!(
                    "{} differs from orca secret '{secret}'; refusing to choose one. Remove the stale copy and re-run",
                    key_path.display()
                );
            }
        }
    }
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(key_path, std::fs::Permissions::from_mode(0o600))
            .with_context(|| format!("chmod {}", key_path.display()))?;
    }
    chown(key_path, Some(uid), gid, false)?;
    let public = public_of(host, key_path).await?;
    let pub_file = pub_path(key_path);
    write_atomic(&pub_file, format!("{public} {comment}\n").as_bytes(), 0o644)?;
    chown(&pub_file, Some(uid), gid, false)?;
    Ok(public)
}

/// Rewrite app.ini keeping its mode and owner: Gitea must still read it.
fn write_ini(path: &Path, contents: &str) -> Result<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let meta = std::fs::metadata(path).with_context(|| format!("stat {}", path.display()))?;
    write_atomic(
        path,
        contents.as_bytes(),
        meta.permissions().mode() & 0o7777,
    )?;
    chown(path, Some(meta.uid()), meta.gid(), false)
}

async fn fetch_public_key(cfg: &Config, url: &str) -> Result<String> {
    let resp = verified_client(cfg)?
        .get(url)
        .send()
        .await
        .map_err(|e| anyhow!("GET {url}: {e}"))?;
    let status = resp.status().as_u16();
    let body = resp.text().await.unwrap_or_default();
    if !(200..300).contains(&status) {
        bail!(
            "GET {url}: HTTP {status}: {}",
            body.trim().chars().take(200).collect::<String>()
        );
    }
    Ok(key_body(&body))
}

fn left(deadline: Instant) -> Duration {
    deadline.saturating_duration_since(Instant::now())
}

/// Await `fut` for at most `REQUEST_SECS`, and never past `deadline`.
async fn attempt<T>(deadline: Instant, fut: impl Future<Output = Result<T>>) -> Result<T> {
    let limit = left(deadline).min(Duration::from_secs(REQUEST_SECS));
    plugin_toolkit::time::timeout(limit, fut)
        .await
        .unwrap_or_else(|| Err(anyhow!("no answer within {}s", limit.as_secs())))
}

/// Sleep 2s between attempts, cut short at `deadline`.
async fn pause(deadline: Instant) {
    plugin_toolkit::time::sleep(left(deadline).min(Duration::from_secs(2))).await;
}

async fn verify(cfg: &Config, url: &str, expected: &str, wait_secs: u64) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(wait_secs);
    loop {
        let last = match attempt(deadline, fetch_public_key(cfg, url)).await {
            Ok(got) if got == expected => return Ok(()),
            Ok(got) => format!("it serves a different key ({got})"),
            Err(e) => format!("{e:#}"),
        };
        if left(deadline).is_zero() {
            bail!("Gitea did not serve the new signing key within {wait_secs}s: {last}");
        }
        pause(deadline).await;
    }
}

/// PATCH each repo until `deadline`. Returns the repos set, the failures
/// (each with its HTTP status or transport error), and the repos never reached.
async fn set_update_style(
    cfg: &Config,
    style: &str,
    repos: &[String],
    deadline: &plugin_toolkit::time::Deadline,
) -> Result<(Vec<String>, Vec<String>, Vec<String>)> {
    let client = verified_client(cfg)?;
    let mut updated = Vec::new();
    let mut failed = Vec::new();
    for (i, full) in repos.iter().enumerate() {
        if deadline.reached() {
            return Ok((updated, failed, repos[i..].to_vec()));
        }
        let url = format!("{}/repos/{full}", cfg.base_url.trim_end_matches('/'));
        match client
            .patch(url)
            .json(&json!({ "default_update_style": style }))
            .send()
            .await
        {
            Ok(r) if r.status().is_success() => updated.push(full.clone()),
            Ok(r) => failed.push(format!("{full} (HTTP {})", r.status().as_u16())),
            Err(e) => failed.push(format!("{full} ({e})")),
        }
    }
    Ok((updated, failed, vec![]))
}

/// `owner/name` of every repo whose `default_update_style` is not `style`.
/// An admin token's search sees every repo on the instance.
async fn repos_to_restyle(
    cfg: &Config,
    style: &str,
    deadline: &plugin_toolkit::time::Deadline,
) -> Result<Vec<String>> {
    #[derive(Deserialize)]
    struct Page {
        data: Vec<Repo>,
    }
    #[derive(Deserialize)]
    struct Repo {
        full_name: String,
        #[serde(default)]
        default_update_style: Option<String>,
    }
    let client = verified_client(cfg)?;
    let mut out = Vec::new();
    for page in 1.. {
        if deadline.reached() {
            bail!(
                "listing repos did not finish within {UPDATE_STYLE_SECS}s ({} found so far)",
                out.len()
            );
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
            bail!("search repos: HTTP {status}");
        }
        let page: Page = plugin_toolkit::serde_json::from_str(&body)
            .map_err(|e| anyhow!("search repos: {e}"))?;
        if page.data.is_empty() {
            break;
        }
        out.extend(
            page.data
                .into_iter()
                .filter(|r| r.default_update_style.as_deref() != Some(style))
                .map(|r| r.full_name),
        );
    }
    Ok(out)
}

// ═══════════════════════════════════════════════════════════════════════════
// gitea.signing
// ═══════════════════════════════════════════════════════════════════════════

fn default_app_ini() -> String {
    DEFAULT_APP_INI.into()
}
fn default_key_path() -> String {
    DEFAULT_KEY_PATH.into()
}
fn default_service() -> String {
    "gitea".into()
}
fn default_signing_name() -> String {
    "Gitea".into()
}
fn default_verify_secs() -> u64 {
    DEFAULT_VERIFY_SECS
}

#[derive(clap::Args, Serialize, Deserialize, JsonSchema)]
pub struct SigningArgs {
    /// Registered Gitea endpoint served from this host.
    #[arg(long)]
    pub endpoint: String,
    #[arg(long, default_value = DEFAULT_APP_INI)]
    #[serde(default = "default_app_ini")]
    pub app_ini: String,
    /// Private key path; the public key is written beside it as `.pub`.
    #[arg(long, default_value = DEFAULT_KEY_PATH)]
    #[serde(default = "default_key_path")]
    pub key_path: String,
    /// Service to restart.
    #[arg(long, default_value = "gitea")]
    #[serde(default = "default_service")]
    pub service: String,
    #[arg(long, default_value = "Gitea")]
    #[serde(default = "default_signing_name")]
    pub signing_name: String,
    /// Defaults to `gitea@<[server] DOMAIN>`.
    #[arg(long)]
    #[serde(default)]
    pub signing_email: Option<String>,
    /// How long to wait after the restart for Gitea to serve the new key;
    /// capped at the default.
    #[arg(long, default_value_t = DEFAULT_VERIFY_SECS)]
    #[serde(default = "default_verify_secs")]
    pub verify_secs: u64,
    /// Apply. Omitted, returns the plan and changes nothing.
    #[arg(long)]
    #[serde(default)]
    pub execute: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct SigningOutput {
    pub dry_run: bool,
    pub plan: ExecutionPlan,
    /// What each executed step did; empty on a dry run.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub applied: Vec<String>,
    /// Add to `allowed_signers` and any signature-requiring branch
    /// protection. Known on a dry run only when the key already exists.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
}

fn validate_style(style: &str) -> Result<()> {
    match style {
        "merge" | "rebase" => Ok(()),
        other => bail!("default_update_style must be 'merge' or 'rebase', not '{other}'"),
    }
}

fn read_ini(path: &str) -> Result<String> {
    std::fs::read_to_string(path).with_context(|| format!("read {path}"))
}

/// Give the Gitea server an SSH signing key and make it sign initial commits,
/// web edits, wiki edits and merges. Restarts Gitea.
#[orca_tool(
    domain = "gitea",
    verb = "signing",
    role = "admin",
    execute_gated = false
)]
pub async fn gitea_signing(args: SigningArgs, ctx: &ToolCtx) -> Result<SigningOutput> {
    const TOOL: &str = "gitea.signing";
    let budget = Budget::live();
    require_admin(TOOL, ctx)?;
    let host = LocalHost::current()?;
    let cfg = crate::tools::resolve_config(&args.endpoint).await?;
    let secret = secret_name(&args.endpoint);
    let key_path = PathBuf::from(&args.key_path);
    let facts = Facts {
        ini: read_ini(&args.app_ini)?,
        init: host.init,
        key_on_host: key_path.exists(),
        key_in_secrets: plugin_toolkit::secrets::get(&secret)?.is_some(),
    };
    let steps = plan(&args, &facts, &instance_url(&cfg))?;
    let execution_plan = to_plan(TOOL, &args, &steps)?;
    if !args.execute {
        let public_key = if facts.key_on_host {
            public_of(&host, &key_path).await.ok()
        } else {
            None
        };
        return Ok(SigningOutput {
            dry_run: true,
            plan: execution_plan,
            applied: vec![],
            public_key,
            notes: vec![],
        });
    }
    let live = Live {
        host: &host,
        cfg: &cfg,
        instance: instance_url(&cfg),
    };
    let (applied, public_key) = run(&live, &steps, budget).await?;
    Ok(SigningOutput {
        dry_run: false,
        plan: execution_plan,
        applied,
        public_key: Some(public_key),
        notes: vec![],
    })
}

fn to_plan(tool: &str, args: &SigningArgs, steps: &[Step]) -> Result<ExecutionPlan> {
    let inputs = plugin_toolkit::serde_json::to_value(args)?;
    let summary = format!(
        "sign Gitea-authored commits with an SSH key at {}{}",
        args.key_path,
        if steps.iter().any(|s| matches!(s, Step::Restart { .. })) {
            "; RESTARTS Gitea (brief downtime)"
        } else {
            "; already configured, no restart"
        }
    );
    Ok(ExecutionPlan::generic(tool, inputs.into())
        .detailed(summary, steps.iter().map(Step::to_change).collect()))
}

/// The parts of a run that touch the live service.
trait Service {
    async fn apply_key(
        &self,
        source: &KeySource,
        key_path: &Path,
        owner: &str,
        secret: &str,
        comment: &str,
    ) -> Result<String>;
    async fn restart(&self, argv: &[String]) -> Result<()>;
    async fn verify(&self, url: &str, expected: &str, wait_secs: u64) -> Result<()>;
    /// Gitea answers HTTP at all (any status) within `wait_secs`.
    async fn wait_up(&self, wait_secs: u64) -> Result<()>;
}

struct Live<'a> {
    host: &'a LocalHost,
    cfg: &'a Config,
    instance: String,
}

impl Service for Live<'_> {
    async fn apply_key(
        &self,
        source: &KeySource,
        key_path: &Path,
        owner: &str,
        secret: &str,
        comment: &str,
    ) -> Result<String> {
        apply_key(self.host, source, key_path, owner, secret, comment).await
    }
    async fn restart(&self, argv: &[String]) -> Result<()> {
        run_ok(self.host, argv).await
    }
    async fn verify(&self, url: &str, expected: &str, wait_secs: u64) -> Result<()> {
        verify(self.cfg, url, expected, wait_secs).await
    }
    async fn wait_up(&self, wait_secs: u64) -> Result<()> {
        let client = verified_client(self.cfg)?;
        let deadline = Instant::now() + Duration::from_secs(wait_secs);
        loop {
            let send = async { Ok(client.get(&self.instance).send().await?) };
            let last = match attempt(deadline, send).await {
                Ok(_) => return Ok(()),
                Err(e) => format!("{e:#}"),
            };
            if left(deadline).is_zero() {
                bail!(
                    "no HTTP answer from {} within {wait_secs}s: {last}",
                    self.instance
                );
            }
            pause(deadline).await;
        }
    }
}

/// Time limits of one run: its overall deadline and each restart's cap.
#[derive(Clone, Copy)]
struct Budget {
    deadline: Instant,
    restart: Duration,
}

impl Budget {
    fn live() -> Self {
        Budget {
            deadline: Instant::now() + Duration::from_secs(RUN_SECS),
            restart: Duration::from_secs(RESTART_SECS),
        }
    }

    /// Time that must remain at WriteIni: restart, a minimal verify, then a
    /// rollback restart and its wait.
    fn reserve(&self) -> Duration {
        self.restart * 2 + Duration::from_secs(MIN_VERIFY_SECS + ROLLBACK_UP_SECS)
    }

    /// What the key step may take so `reserve` still fits.
    fn key_limit(&self) -> Duration {
        left(self.deadline).saturating_sub(self.reserve())
    }
}

/// Seconds the verify may take: at most `wanted`, and short enough that a
/// rollback restart plus its `ROLLBACK_UP_SECS` wait still fit in `remaining`.
fn verify_budget(wanted: u64, remaining: Duration, restart: Duration) -> u64 {
    let reserve = restart + Duration::from_secs(ROLLBACK_UP_SECS);
    wanted.min(remaining.saturating_sub(reserve).as_secs())
}

async fn restart_within(svc: &impl Service, argv: &[String], limit: Duration) -> Result<()> {
    plugin_toolkit::time::timeout(limit, svc.restart(argv))
        .await
        .unwrap_or_else(|| {
            Err(anyhow!(
                "`{}` did not finish within {}s",
                argv.join(" "),
                limit.as_secs()
            ))
        })
}

/// After a failed restart or verify: put the previous app.ini back, restart,
/// and wait for Gitea to answer HTTP. Returns `cause` with what happened.
async fn roll_back(
    svc: &impl Service,
    previous_ini: &Option<(PathBuf, String)>,
    argv: &[String],
    budget: Budget,
    cause: anyhow::Error,
) -> anyhow::Error {
    let Some((path, old)) = previous_ini else {
        return cause;
    };
    let result = async {
        write_ini(path, old).context("restore app.ini")?;
        restart_within(svc, argv, budget.restart)
            .await
            .context("restart")?;
        svc.wait_up(ROLLBACK_UP_SECS).await
    }
    .await;
    match result {
        Ok(()) => cause.context(format!(
            "restored the previous {} and restarted Gitea; it answers HTTP",
            path.display()
        )),
        Err(r) => {
            let in_place = if std::fs::read_to_string(path).is_ok_and(|now| &now == old) {
                "the PREVIOUS app.ini is in place"
            } else {
                "the NEW (signing) app.ini is still in place"
            };
            cause.context(format!(
                "ROLLBACK FAILED, Gitea may be DOWN: {r:#}. At {}, {in_place}",
                path.display()
            ))
        }
    }
}

/// Run `steps`; a failure names what already ran. If the restart or the
/// verify fails, the previous app.ini is put back and Gitea restarted. The
/// verify is shortened so the rollback still finishes by `budget.deadline`.
async fn run(svc: &impl Service, steps: &[Step], budget: Budget) -> Result<(Vec<String>, String)> {
    let mut done = Vec::new();
    let mut public = None;
    let mut previous_ini: Option<(PathBuf, String)> = None;
    let mut restart: Option<Vec<String>> = None;
    for step in steps {
        let result: Result<()> = async {
            match step {
                Step::Key {
                    source,
                    key_path,
                    owner,
                    secret,
                    comment,
                } => {
                    let limit = budget.key_limit();
                    let key = svc.apply_key(source, key_path, owner, secret, comment);
                    public = Some(
                        plugin_toolkit::time::timeout(limit, key)
                            .await
                            .unwrap_or_else(|| {
                                Err(anyhow!(
                                    "key step did not finish within {}s",
                                    limit.as_secs()
                                ))
                            })?,
                    );
                }
                Step::WriteIni { path, contents } => {
                    if left(budget.deadline) < budget.reserve() {
                        bail!(
                            "too little time left to write, restart, verify and roll back; \
                             {} and the service are unchanged (rerun to finish)",
                            path.display()
                        );
                    }
                    previous_ini = Some((path.clone(), std::fs::read_to_string(path)?));
                    write_ini(path, contents)?;
                }
                Step::Restart { argv } => {
                    restart = Some(argv.clone());
                    if let Err(e) = restart_within(svc, argv, budget.restart).await {
                        return Err(roll_back(svc, &previous_ini, argv, budget, e).await);
                    }
                }
                Step::Verify { url, wait_secs } => {
                    let expected = public
                        .as_deref()
                        .ok_or_else(|| anyhow!("no key to verify"))?;
                    let secs = verify_budget(*wait_secs, left(budget.deadline), budget.restart);
                    if let Err(e) = svc.verify(url, expected, secs).await {
                        return Err(match &restart {
                            Some(argv) => roll_back(svc, &previous_ini, argv, budget, e).await,
                            None => e,
                        });
                    }
                }
            }
            Ok(())
        }
        .await;
        let change = step.to_change();
        if let Err(e) = result {
            bail!(
                "gitea.signing failed at `{} {}`: {e:#}. Already applied: [{}]",
                change.action,
                change.target,
                done.join("; ")
            );
        }
        done.push(format!("{} {}", change.action, change.target));
    }
    let public = public.ok_or_else(|| anyhow!("no key step ran"))?;
    Ok((done, public))
}

async fn run_ok(host: &LocalHost, argv: &[String]) -> Result<()> {
    let out = host.run(argv, None).await?;
    if !out.ok {
        bail!(
            "`{}` failed (exit {:?}): {}",
            argv.join(" "),
            out.code,
            out.stderr
        );
    }
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════
// gitea.update_style
// ═══════════════════════════════════════════════════════════════════════════

#[derive(clap::Args, Serialize, Deserialize, JsonSchema)]
pub struct UpdateStyleArgs {
    /// Registered Gitea endpoint.
    #[arg(long)]
    pub endpoint: String,
    /// Every repo's "update PR branch" default: `rebase` (no merge commit)
    /// or `merge`.
    #[arg(long)]
    pub style: String,
    /// Apply. Omitted, returns the plan and changes nothing.
    #[arg(long)]
    #[serde(default)]
    pub execute: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct UpdateStyleOutput {
    pub dry_run: bool,
    pub plan: ExecutionPlan,
    /// Repos set; empty on a dry run.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub updated: Vec<String>,
    /// `owner/name (HTTP status or error)` of each repo that refused.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub failed: Vec<String>,
    /// Repos not attempted before the time budget ran out; re-run to finish.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unreached: Vec<String>,
}

/// Set every repo's default "update PR branch" style. Never restarts Gitea.
#[orca_tool(
    domain = "gitea",
    verb = "update_style",
    role = "admin",
    execute_gated = false
)]
pub async fn gitea_update_style(args: UpdateStyleArgs, ctx: &ToolCtx) -> Result<UpdateStyleOutput> {
    const TOOL: &str = "gitea.update_style";
    require_admin(TOOL, ctx)?;
    validate_style(&args.style)?;
    let deadline =
        plugin_toolkit::time::Deadline::after(std::time::Duration::from_secs(UPDATE_STYLE_SECS));
    let cfg = crate::tools::resolve_config(&args.endpoint).await?;
    let repos = repos_to_restyle(&cfg, &args.style, &deadline).await?;
    let change = PlannedChange::new(
        format!("{} repo(s)", repos.len()),
        "set-default-update-style",
    )
    .with_detail(format!(
        "default_update_style = {} (replacing each repo's current value, custom ones included): {}",
        args.style,
        repos.join(", ")
    ));
    let plan = ExecutionPlan::generic(TOOL, plugin_toolkit::serde_json::to_value(&args)?.into())
        .detailed(
            format!(
                "set default_update_style = {} on {} repo(s)",
                args.style,
                repos.len()
            ),
            vec![change],
        );
    if !args.execute {
        return Ok(UpdateStyleOutput {
            dry_run: true,
            plan,
            updated: vec![],
            failed: vec![],
            unreached: vec![],
        });
    }
    let (updated, failed, unreached) =
        set_update_style(&cfg, &args.style, &repos, &deadline).await?;
    Ok(UpdateStyleOutput {
        dry_run: false,
        plan,
        updated,
        failed,
        unreached,
    })
}

// ═══════════════════════════════════════════════════════════════════════════
// gitea.signing.status
// ═══════════════════════════════════════════════════════════════════════════

#[derive(clap::Args, Serialize, Deserialize, JsonSchema)]
pub struct SigningStatusArgs {
    /// Registered Gitea endpoint.
    #[arg(long)]
    pub endpoint: String,
    /// Read when this system is the Gitea host; skipped if unreadable.
    #[arg(long, default_value = DEFAULT_APP_INI)]
    #[serde(default = "default_app_ini")]
    pub app_ini: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct SigningStatus {
    /// Gitea serves a signing public key.
    pub key_served: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub served_error: Option<String>,
    /// `[repository.signing]` as app.ini sets it; `None` if app.ini is unreadable here.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config: Option<std::collections::BTreeMap<String, String>>,
    /// Actions configured to sign (`INITIAL_COMMIT`, `CRUD_ACTIONS`, `WIKI`, `MERGES`)
    /// with a setting other than `never`.
    pub signing_actions: Vec<String>,
}

pub fn signing_config(ini: &str) -> std::collections::BTreeMap<String, String> {
    [
        "SIGNING_FORMAT",
        "SIGNING_KEY",
        "SIGNING_NAME",
        "SIGNING_EMAIL",
        "INITIAL_COMMIT",
        "CRUD_ACTIONS",
        "WIKI",
        "MERGES",
    ]
    .into_iter()
    .filter_map(|k| ini_get(ini, SECTION, k).map(|v| (k.to_string(), v)))
    .collect()
}

pub fn signing_actions(config: &std::collections::BTreeMap<String, String>) -> Vec<String> {
    if config.get("SIGNING_KEY").is_some_and(|k| k == "none") {
        return vec![];
    }
    ["INITIAL_COMMIT", "CRUD_ACTIONS", "WIKI", "MERGES"]
        .into_iter()
        .filter(|k| config.get(*k).is_some_and(|v| v != "never"))
        .map(str::to_string)
        .collect()
}

/// Is a signing key configured and served, and which actions sign.
#[orca_tool(domain = "gitea", verb = "signing.status", role = "admin")]
pub async fn gitea_signing_status(args: SigningStatusArgs, ctx: &ToolCtx) -> Result<SigningStatus> {
    require_admin("gitea.signing.status", ctx)?;
    let cfg = crate::tools::resolve_config(&args.endpoint).await?;
    let url = format!("{}/api/v1/signing-key.pub", instance_url(&cfg));
    let (public_key, served_error) = match fetch_public_key(&cfg, &url).await {
        Ok(k) if !k.is_empty() => (Some(k), None),
        Ok(_) => (None, Some("empty response".to_string())),
        Err(e) => (None, Some(format!("{e:#}"))),
    };
    let config = std::fs::read_to_string(&args.app_ini)
        .ok()
        .map(|i| signing_config(&i));
    Ok(SigningStatus {
        key_served: public_key.is_some(),
        public_key,
        served_error,
        signing_actions: config.as_ref().map(signing_actions).unwrap_or_default(),
        config,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(execute: bool) -> SigningArgs {
        SigningArgs {
            endpoint: "home".into(),
            app_ini: "/tmp/none.ini".into(),
            key_path: DEFAULT_KEY_PATH.into(),
            service: "gitea".into(),
            signing_name: "Gitea".into(),
            signing_email: None,
            verify_secs: DEFAULT_VERIFY_SECS,
            execute,
        }
    }

    const INI: &str = "APP_NAME = Gitea\nRUN_USER = gitea\n\n[server]\nDOMAIN = git.example\n\n[repository.signing]\n; keep me\nSIGNING_KEY = default\n\n[log]\nMODE = console\n";

    fn facts(ini: &str, on_host: bool, in_secrets: bool) -> Facts {
        Facts {
            ini: ini.into(),
            init: Init::Systemd,
            key_on_host: on_host,
            key_in_secrets: in_secrets,
        }
    }

    #[test]
    fn ini_set_rewrites_in_place_appends_missing_and_keeps_the_rest() {
        let out = ini_set(
            INI,
            SECTION,
            &signing_settings(Path::new("/k/key"), "Gitea", "g@x"),
        );
        assert!(
            out.contains("; keep me\nSIGNING_KEY = /k/key.pub\n"),
            "{out}"
        );
        assert!(
            out.contains("MERGES = always\n\n[log]\nMODE = console\n"),
            "{out}"
        );
        assert_eq!(out.matches("SIGNING_KEY").count(), 1);
        assert_eq!(
            ini_get(&out, SECTION, "signing_format").as_deref(),
            Some("ssh")
        );
        assert_eq!(ini_get(&out, "log", "MODE").as_deref(), Some("console"));
        let again = ini_set(
            &out,
            SECTION,
            &signing_settings(Path::new("/k/key"), "Gitea", "g@x"),
        );
        assert_eq!(again, out, "second apply must be a no-op");
    }

    #[test]
    fn ini_set_adds_a_missing_section() {
        let out = ini_set(
            "[server]\nDOMAIN = a\n",
            SECTION,
            &[("MERGES", "always".into())],
        );
        assert_eq!(
            out,
            "[server]\nDOMAIN = a\n\n[repository.signing]\nMERGES = always\n"
        );
    }

    #[test]
    fn plan_generates_a_key_writes_the_ini_restarts_and_verifies() {
        let steps = plan(
            &args(false),
            &facts(INI, false, false),
            "https://git.example",
        )
        .unwrap();
        let actions: Vec<_> = steps.iter().map(|s| s.to_change().action).collect();
        assert_eq!(actions, ["generate-key", "write", "restart", "verify"]);
        let Step::Key {
            owner,
            comment,
            secret,
            ..
        } = &steps[0]
        else {
            panic!()
        };
        assert_eq!(
            (owner.as_str(), comment.as_str()),
            ("gitea", "gitea@git.example")
        );
        assert_eq!(secret, "gitea.home.signing_key");
        let restart = steps[2].to_change();
        assert_eq!(restart.target, "systemctl restart gitea");
        assert!(restart.detail.unwrap().contains("DOWN"));
        assert_eq!(
            steps[3].to_change().target,
            "https://git.example/api/v1/signing-key.pub"
        );
    }

    #[test]
    fn configured_server_only_rechecks_the_key_and_verifies() {
        let done = ini_set(
            INI,
            SECTION,
            &signing_settings(Path::new(DEFAULT_KEY_PATH), "Gitea", "gitea@git.example"),
        );
        let steps = plan(&args(false), &facts(&done, true, true), "https://g").unwrap();
        let actions: Vec<_> = steps.iter().map(|s| s.to_change().action).collect();
        assert_eq!(actions, ["check-key", "verify"]);
    }

    #[test]
    fn key_source_covers_every_case() {
        assert_eq!(KeySource::decide(false, false), KeySource::Generate);
        assert_eq!(KeySource::decide(false, true), KeySource::Adopt);
        assert_eq!(KeySource::decide(true, false), KeySource::Install);
        assert_eq!(KeySource::decide(true, true), KeySource::CheckMatch);
    }

    #[test]
    fn plan_needs_an_email_when_app_ini_has_no_domain() {
        let err = plan(
            &args(false),
            &facts("[server]\n", false, false),
            "https://g",
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("--signing-email"), "{err}");
    }

    #[test]
    fn update_style_accepts_only_merge_or_rebase() {
        assert!(validate_style("rebase").is_ok());
        assert!(validate_style("merge").is_ok());
        assert!(validate_style("squash").is_err());
    }

    #[test]
    fn verify_secs_is_clamped_to_the_default() {
        let mut a = args(false);
        a.verify_secs = 600;
        let steps = plan(&a, &facts(INI, false, false), "https://g").unwrap();
        let Some(Step::Verify { wait_secs, .. }) = steps.last() else {
            panic!()
        };
        assert_eq!(*wait_secs, DEFAULT_VERIFY_SECS);
        a.verify_secs = 0;
        let steps = plan(&a, &facts(INI, false, false), "https://g").unwrap();
        let Some(Step::Verify { wait_secs, .. }) = steps.last() else {
            panic!()
        };
        assert_eq!(*wait_secs, 1);
    }

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("gitea-signing-{name}-{}", std::process::id()));
        std::fs::remove_dir_all(&dir).ok();
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn key_dir_is_created_or_must_be_dedicated() {
        let dir = scratch("keydir");
        let key = dir.join("new").join("k");
        assert!(prepare_key_dir(&key).unwrap(), "created");
        std::fs::write(dir.join("new").join("k.pub"), "x").unwrap();
        assert!(!prepare_key_dir(&key).unwrap(), "key-only dir is reused");
        std::fs::write(dir.join("other"), "x").unwrap();
        let err = prepare_key_dir(&dir.join("k")).unwrap_err().to_string();
        assert!(err.contains("not a dedicated key directory"), "{err}");
        std::fs::remove_dir_all(&dir).ok();
    }

    struct Fake {
        restarts: std::cell::RefCell<std::collections::VecDeque<bool>>,
        hang_first_restart: std::cell::Cell<bool>,
        key_delay: std::cell::Cell<Option<Duration>>,
        verify_ok: bool,
        up_ok: bool,
        calls: std::cell::RefCell<Vec<&'static str>>,
    }

    impl Fake {
        fn new(restarts: &[bool], verify_ok: bool, up_ok: bool) -> Self {
            Fake {
                restarts: std::cell::RefCell::new(restarts.iter().copied().collect()),
                hang_first_restart: Default::default(),
                key_delay: Default::default(),
                verify_ok,
                up_ok,
                calls: Default::default(),
            }
        }
    }

    impl Service for Fake {
        async fn apply_key(
            &self,
            _: &KeySource,
            _: &Path,
            _: &str,
            _: &str,
            _: &str,
        ) -> Result<String> {
            if let Some(d) = self.key_delay.get() {
                tokio::time::sleep(d).await;
            }
            Ok("ssh-ed25519 AAAA".into())
        }
        async fn restart(&self, _: &[String]) -> Result<()> {
            self.calls.borrow_mut().push("restart");
            if self.hang_first_restart.replace(false) {
                std::future::pending::<()>().await;
            }
            if self.restarts.borrow_mut().pop_front().unwrap() {
                Ok(())
            } else {
                bail!("restart exploded")
            }
        }
        async fn verify(&self, _: &str, _: &str, _: u64) -> Result<()> {
            self.calls.borrow_mut().push("verify");
            if self.verify_ok {
                Ok(())
            } else {
                bail!("wrong key")
            }
        }
        async fn wait_up(&self, _: u64) -> Result<()> {
            self.calls.borrow_mut().push("wait_up");
            if self.up_ok {
                Ok(())
            } else {
                bail!("no answer")
            }
        }
    }

    fn test_budget() -> Budget {
        Budget {
            deadline: Instant::now() + Duration::from_secs(RUN_SECS),
            restart: Duration::from_millis(50),
        }
    }

    #[test]
    fn verify_leaves_room_for_the_rollback() {
        let restart = Duration::from_secs(RESTART_SECS);
        let reserve = RESTART_SECS + ROLLBACK_UP_SECS;
        assert_eq!(
            verify_budget(20, Duration::from_secs(RUN_SECS), restart),
            RUN_SECS - reserve
        );
        assert_eq!(verify_budget(3, Duration::from_secs(RUN_SECS), restart), 3);
        assert_eq!(verify_budget(20, Duration::from_secs(reserve), restart), 0);
        assert_eq!(verify_budget(20, Duration::from_secs(5), restart), 0);
        const { assert!(RUN_SECS < 35) };
    }

    #[test]
    fn reserve_covers_restart_verify_and_rollback() {
        let b = Budget::live();
        assert_eq!(
            b.reserve(),
            Duration::from_secs(2 * RESTART_SECS + MIN_VERIFY_SECS + ROLLBACK_UP_SECS)
        );
        assert!(b.key_limit() <= Duration::from_secs(RUN_SECS) - b.reserve());
        let spent = Budget {
            deadline: Instant::now(),
            restart: b.restart,
        };
        assert_eq!(spent.key_limit(), Duration::ZERO);
        const { assert!(2 * RESTART_SECS + MIN_VERIFY_SECS + ROLLBACK_UP_SECS < RUN_SECS) };
    }

    #[tokio::test]
    async fn a_slow_key_step_refuses_before_writing_app_ini() {
        let dir = scratch("slowkey");
        let ini = dir.join("app.ini");
        std::fs::write(&ini, INI).unwrap();
        let fake = Fake::new(&[true, true], true, true);
        fake.key_delay.set(Some(Duration::from_millis(300)));
        let mut budget = test_budget();
        budget.deadline = Instant::now() + budget.reserve() + Duration::from_millis(100);
        let err = run(&fake, &run_steps(&ini), budget)
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("key step did not finish"), "{err}");
        assert_eq!(std::fs::read_to_string(&ini).unwrap(), INI);
        assert!(fake.calls.borrow().is_empty());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn too_little_time_at_write_ini_leaves_app_ini_unchanged() {
        let dir = scratch("late");
        let ini = dir.join("app.ini");
        std::fs::write(&ini, INI).unwrap();
        let fake = Fake::new(&[true, true], true, true);
        let mut budget = test_budget();
        budget.deadline = Instant::now() + budget.reserve() - Duration::from_millis(1);
        let err = run(&fake, &run_steps(&ini)[1..], budget)
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("unchanged"), "{err}");
        assert_eq!(std::fs::read_to_string(&ini).unwrap(), INI);
        assert!(fake.calls.borrow().is_empty());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn a_hung_restart_times_out_and_rolls_back() {
        let dir = scratch("hung");
        let ini = dir.join("app.ini");
        std::fs::write(&ini, INI).unwrap();
        let fake = Fake::new(&[true, true], true, true);
        fake.hang_first_restart.set(true);
        let err = run(&fake, &run_steps(&ini), test_budget())
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("did not finish within"), "{err}");
        assert!(err.contains("restored the previous"), "{err}");
        assert_eq!(std::fs::read_to_string(&ini).unwrap(), INI);
        assert_eq!(*fake.calls.borrow(), ["restart", "restart", "wait_up"]);
        std::fs::remove_dir_all(&dir).ok();
    }

    fn run_steps(ini: &Path) -> Vec<Step> {
        vec![
            Step::Key {
                source: KeySource::CheckMatch,
                key_path: "/k".into(),
                owner: "git".into(),
                secret: "s".into(),
                comment: "c".into(),
            },
            Step::WriteIni {
                path: ini.to_path_buf(),
                contents: "NEW\n".into(),
            },
            Step::Restart {
                argv: vec!["systemctl".into(), "restart".into(), "gitea".into()],
            },
            Step::Verify {
                url: "https://g/api/v1/signing-key.pub".into(),
                wait_secs: 1,
            },
        ]
    }

    #[tokio::test]
    async fn a_failed_restart_restores_app_ini_and_waits_for_gitea() {
        let dir = scratch("restart");
        let ini = dir.join("app.ini");
        std::fs::write(&ini, INI).unwrap();
        let fake = Fake::new(&[false, true], true, true);
        let err = run(&fake, &run_steps(&ini), test_budget())
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("restored the previous"), "{err}");
        assert_eq!(std::fs::read_to_string(&ini).unwrap(), INI);
        assert_eq!(*fake.calls.borrow(), ["restart", "restart", "wait_up"]);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn a_failed_verify_restores_app_ini_and_waits_for_gitea() {
        let dir = scratch("verify");
        let ini = dir.join("app.ini");
        std::fs::write(&ini, INI).unwrap();
        let fake = Fake::new(&[true, true], false, true);
        let err = run(&fake, &run_steps(&ini), test_budget())
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("restored the previous"), "{err}");
        assert_eq!(std::fs::read_to_string(&ini).unwrap(), INI);
        assert_eq!(
            *fake.calls.borrow(),
            ["restart", "verify", "restart", "wait_up"]
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn a_failed_rollback_says_gitea_may_be_down_and_which_ini_is_in_place() {
        let dir = scratch("rollback");
        let ini = dir.join("app.ini");
        std::fs::write(&ini, INI).unwrap();
        let fake = Fake::new(&[false, false], true, true);
        let err = run(&fake, &run_steps(&ini), test_budget())
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("Gitea may be DOWN"), "{err}");
        assert!(err.contains("PREVIOUS app.ini is in place"), "{err}");
        let fake = Fake::new(&[true, true], false, false);
        let err = run(&fake, &run_steps(&ini), test_budget())
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("Gitea may be DOWN"), "{err}");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn launchd_hosts_are_refused() {
        let mut f = facts(INI, false, false);
        f.init = Init::Launchd;
        assert!(plan(&args(false), &f, "https://g").is_err());
    }

    #[test]
    fn plan_output_never_contains_key_material() {
        let steps = plan(&args(false), &facts(INI, false, false), "https://g").unwrap();
        let p = to_plan("gitea.signing", &args(false), &steps).unwrap();
        let text = plugin_toolkit::serde_json::to_string(&p).unwrap();
        assert!(!text.contains("PRIVATE KEY"), "{text}");
    }

    #[tokio::test]
    async fn dry_run_without_an_admin_caller_is_refused_and_touches_nothing() {
        let dir = std::env::temp_dir().join(format!("gitea-signing-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let ini = dir.join("app.ini");
        std::fs::write(&ini, INI).unwrap();
        let ctx = plugin_toolkit::tool_manifest::minimal_ctx();
        for execute in [false, true] {
            let err = plugin_toolkit::dispatch::dispatch(
                "gitea.signing",
                json!({"endpoint": "home", "app_ini": ini, "key_path": dir.join("k"), "execute": execute}),
                &ctx,
            )
            .await
            .unwrap_err()
            .to_string();
            assert!(err.contains("no caller identity"), "{err}");
            let err = plugin_toolkit::dispatch::dispatch(
                "gitea.update_style",
                json!({"endpoint": "home", "style": "rebase", "execute": execute}),
                &ctx,
            )
            .await
            .unwrap_err()
            .to_string();
            assert!(err.contains("no caller identity"), "{err}");
        }
        let err = plugin_toolkit::dispatch::dispatch(
            "gitea.signing.status",
            json!({"endpoint": "home", "app_ini": ini}),
            &ctx,
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(err.contains("no caller identity"), "{err}");
        assert_eq!(std::fs::read_to_string(&ini).unwrap(), INI);
        assert!(!dir.join("k").exists());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn status_lists_the_signing_actions() {
        let done = ini_set(
            INI,
            SECTION,
            &signing_settings(Path::new("/k"), "Gitea", "g@x"),
        );
        let cfg = signing_config(&done);
        assert_eq!(
            signing_actions(&cfg),
            ["INITIAL_COMMIT", "CRUD_ACTIONS", "WIKI", "MERGES"]
        );
        assert!(signing_actions(&signing_config(INI)).is_empty());
    }

    #[test]
    fn verbs_have_their_roles() {
        assert_eq!(
            plugin_toolkit::dispatch::required_role("gitea.signing"),
            Some("admin")
        );
        assert_eq!(
            plugin_toolkit::dispatch::required_role("gitea.signing.status"),
            Some("admin")
        );
        assert_eq!(
            plugin_toolkit::dispatch::required_role("gitea.update_style"),
            Some("admin")
        );
    }

    #[test]
    fn key_body_drops_the_comment() {
        assert_eq!(key_body("ssh-ed25519 AAAA gitea@x\n"), "ssh-ed25519 AAAA");
    }
}
