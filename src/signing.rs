//! `gitea.signing.key` / `gitea.signing` / `gitea.signing.status`: give the
//! Gitea server an SSH signing key so the commits it authors (web merges,
//! "Update branch", squash merges, web edits, wiki edits) are signed.
//!
//! `gitea.signing.key` provisions the key file only. `gitea.signing` then
//! points app.ini at it, restarts Gitea and verifies, rolling back on failure;
//! it refuses to run until the key is in place.
//!
//! All verbs act on the orca system they run on, which must be the Gitea
//! host: they read its key and `app.ini`, and `gitea.signing` restarts it.
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
const ROLLBACK_UP_SECS: u64 = 7;
/// Whole `gitea.signing` call, under orca's 35s plugin-call timeout.
const RUN_SECS: u64 = 30;
/// Each service restart; a hung restart counts as failed.
const RESTART_SECS: u64 = 8;
/// Least verify worth starting; below it a correct config would just roll back.
const MIN_VERIFY_SECS: u64 = 3;
/// Each HTTP attempt inside `verify` / `wait_up`.
const REQUEST_SECS: u64 = 5;
/// Reading the key Gitea serves, carved out of setup before the other steps.
const SERVED_KEY_SECS: u64 = 2;
/// Whole `gitea.signing.key` call, under orca's 35s plugin-call timeout.
const KEY_SECS: u64 = 30;
/// Total budget of one `gitea.update_style` call, under orca's 35s timeout.
const UPDATE_STYLE_SECS: u64 = 25;
const RUN_KEY_FIRST: &str = "run `gitea.signing.key` first";

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

    pub fn to_change(&self, key_path: &Path, owner: &str, secret: &str) -> PlannedChange {
        let (action, detail) = match self {
            KeySource::Generate => (
                "generate-key",
                format!(
                    "new ed25519 key; private half stored in orca secret '{secret}' and written 0600 owned by '{owner}'"
                ),
            ),
            KeySource::Adopt => (
                "adopt-key",
                format!(
                    "validate the existing key, store it in orca secret '{secret}'; fix mode 0600 and owner '{owner}'"
                ),
            ),
            KeySource::Install => (
                "install-key",
                format!(
                    "validate and write the key from orca secret '{secret}', 0600 owned by '{owner}'"
                ),
            ),
            KeySource::CheckMatch => (
                "check-key",
                format!(
                    "host key must be valid and match orca secret '{secret}'; fix mode 0600 and owner '{owner}'"
                ),
            ),
        };
        PlannedChange::new(key_path.display().to_string(), action).with_detail(detail)
    }
}

#[derive(Debug, Clone)]
pub enum Step {
    WriteIni { path: PathBuf, contents: String },
    Restart { argv: Vec<String> },
    Verify { url: String, wait_secs: u64 },
}

impl Step {
    pub fn to_change(&self) -> PlannedChange {
        match self {
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

fn run_user(ini: &str) -> String {
    ini_get(ini, "", "RUN_USER").unwrap_or_else(|| DEFAULT_RUN_USER.into())
}

fn signing_email(explicit: &Option<String>, ini: &str) -> Result<String> {
    match explicit {
        Some(e) => Ok(e.clone()),
        None => match ini_get(ini, "server", "DOMAIN") {
            Some(d) if !d.is_empty() => Ok(format!("gitea@{d}")),
            _ => bail!("app.ini has no [server] DOMAIN; pass --signing-email"),
        },
    }
}

/// What the plan needs from the host and Gitea.
pub struct Facts {
    pub ini: String,
    pub init: Init,
    /// Public key on the host, already checked against orca secrets.
    pub public_key: String,
    /// What Gitea serves now, or why it could not be read.
    pub served_key: std::result::Result<String, String>,
}

pub fn plan(args: &SigningArgs, facts: &Facts, instance: &str) -> Result<Vec<Step>> {
    let email = signing_email(&args.signing_email, &facts.ini)?;
    let key_path = PathBuf::from(&args.key_path);
    let mut steps = Vec::new();
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
    // Gitea reads the key at start, so a key it does not serve yet needs one.
    // An unreadable served key is no evidence of that: it must not restart.
    let stale = matches!(&facts.served_key, Ok(k) if *k != facts.public_key);
    if args.force_restart || ini_changed || stale {
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
/// Fails unless the file is a readable, unencrypted private key.
async fn public_of(host: &LocalHost, key_path: &Path) -> Result<String> {
    let line = ssh_keygen(host, &["-y", "-P", "", "-f", &key_path.to_string_lossy()]).await?;
    let body = key_body(&line);
    if body.split_whitespace().count() != 2 {
        bail!(
            "ssh-keygen printed no public key for {}",
            key_path.display()
        );
    }
    Ok(body)
}

/// `type base64` of an OpenSSH public key line, dropping any comment.
pub fn key_body(line: &str) -> String {
    line.split_whitespace()
        .take(2)
        .collect::<Vec<_>>()
        .join(" ")
}

/// Run blocking `f` off the async runtime, giving up after `limit`.
async fn blocking<T: Send + 'static>(
    limit: Duration,
    what: &str,
    f: impl FnOnce() -> Result<T> + Send + 'static,
) -> Result<T> {
    match plugin_toolkit::time::timeout(limit, tokio::task::spawn_blocking(f)).await {
        Some(joined) => joined.map_err(|e| anyhow!("{what}: {e}"))?,
        None => bail!("{what} did not finish within {}s", limit.as_secs()),
    }
}

async fn secret_get(limit: Duration, secret: &str) -> Result<Option<String>> {
    let name = secret.to_string();
    blocking(limit, "read orca secret", move || {
        plugin_toolkit::secrets::get(&name)
    })
    .await
}

async fn secret_set(limit: Duration, secret: &str, value: &str) -> Result<()> {
    let (name, value) = (secret.to_string(), value.to_string());
    blocking(limit, "store orca secret", move || {
        plugin_toolkit::secrets::set(&name, &value, Some("Gitea server commit-signing key"))
            .map(|_| ())
    })
    .await
}

/// Where a new key is built before it is renamed over `key_path`.
fn temp_key_path(key_path: &Path) -> PathBuf {
    let mut name = std::ffi::OsString::from(".");
    name.push(key_path.file_name().unwrap_or_default());
    name.push(".orca-new");
    key_path.with_file_name(name)
}

/// Ensure the key's directory exists; `true` when this call created it, so
/// only then may its mode and owner be changed. An existing directory must
/// be dedicated to the key: holding nothing but the key, its `.pub` and a
/// leftover temp key from an interrupted run.
fn prepare_key_dir(key_path: &Path) -> Result<bool> {
    let dir = key_path
        .parent()
        .ok_or_else(|| anyhow!("{} has no parent", key_path.display()))?;
    if !dir.exists() {
        std::fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))?;
        return Ok(true);
    }
    let tmp = temp_key_path(key_path);
    let allowed = [
        key_path.to_path_buf(),
        pub_path(key_path),
        tmp.clone(),
        pub_path(&tmp),
    ];
    for entry in std::fs::read_dir(dir).with_context(|| format!("read {}", dir.display()))? {
        let name = entry?.file_name();
        if !allowed
            .iter()
            .any(|a| a.file_name() == Some(name.as_os_str()))
        {
            bail!(
                "{} already exists and holds {:?}, so it is not a dedicated key directory; pass a --key-path in a new or key-only directory",
                dir.display(),
                name
            );
        }
    }
    Ok(false)
}

/// Through an `O_NOFOLLOW` fd, so a symlink swapped in at `path` (its dir is
/// owned by the service account) cannot redirect root's chmod/chown.
fn set_mode_owner(path: &Path, mode: u32, uid: u32, gid: u32) -> Result<()> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .with_context(|| format!("open {}", path.display()))?;
    file.set_permissions(std::fs::Permissions::from_mode(mode))
        .with_context(|| format!("chmod {}", path.display()))?;
    std::os::unix::fs::fchown(&file, Some(uid), Some(gid))
        .with_context(|| format!("chown {}", path.display()))
}

fn corrupt_host_key(key_path: &Path, e: anyhow::Error, remedy: &str) -> anyhow::Error {
    e.context(format!(
        "{} is not a valid unencrypted private key. Move it aside (`mv {0} {0}.bad`) and re-run `gitea.signing.key` to {remedy}",
        key_path.display()
    ))
}

/// Provision the key at `key_path` per `source`; returns its public half.
/// Nothing is stored or compared before `public_of` accepts it.
async fn provision_key(
    host: &LocalHost,
    source: &KeySource,
    key_path: &Path,
    owner: &str,
    secret: &str,
    comment: &str,
    deadline: Instant,
) -> Result<String> {
    let (uid, gid) = lookup_user(owner)?
        .ok_or_else(|| anyhow!("Gitea's RUN_USER '{owner}' does not exist on this host"))?;
    let dir = key_path
        .parent()
        .ok_or_else(|| anyhow!("{} has no parent", key_path.display()))?;
    if prepare_key_dir(key_path)? {
        set_mode_owner(dir, 0o700, uid, gid)?;
    }
    let read =
        |p: &Path| std::fs::read_to_string(p).with_context(|| format!("read {}", p.display()));
    let tmp = temp_key_path(key_path);
    let public = match source {
        KeySource::Generate | KeySource::Install => {
            std::fs::remove_file(&tmp).ok();
            std::fs::remove_file(pub_path(&tmp)).ok();
            let result = async {
                let public = if *source == KeySource::Generate {
                    let tmp_arg = tmp.to_string_lossy();
                    let argv = ["-q", "-t", "ed25519", "-N", "", "-C", comment, "-f", &tmp_arg];
                    ssh_keygen(host, &argv).await?;
                    let public = public_of(host, &tmp).await?;
                    let private = read(&tmp)?;
                    secret_set(left(deadline), secret, &private).await?;
                    let stored = secret_get(left(deadline), secret).await?;
                    if stored.as_deref().map(str::trim) != Some(private.trim()) {
                        bail!("orca secret '{secret}' does not read back as the key just stored");
                    }
                    public
                } else {
                    let private = secret_get(left(deadline), secret)
                        .await?
                        .ok_or_else(|| anyhow!("orca secret '{secret}' disappeared"))?;
                    write_atomic(&tmp, private.as_bytes(), 0o600)?;
                    public_of(host, &tmp).await.with_context(|| {
                        format!("orca secret '{secret}' does not hold a valid private key; delete it and re-run `gitea.signing.key` to generate one")
                    })?
                };
                set_mode_owner(&tmp, 0o600, uid, gid)?;
                std::fs::rename(&tmp, key_path).with_context(|| {
                    format!("rename {} to {}", tmp.display(), key_path.display())
                })?;
                Ok(public)
            }
            .await;
            std::fs::remove_file(&tmp).ok();
            std::fs::remove_file(pub_path(&tmp)).ok();
            result?
        }
        KeySource::Adopt => {
            let public = public_of(host, key_path)
                .await
                .map_err(|e| corrupt_host_key(key_path, e, "generate a new key"))?;
            let private = read(key_path)?;
            secret_set(left(deadline), secret, &private).await?;
            let stored = secret_get(left(deadline), secret).await?;
            if stored.as_deref().map(str::trim) != Some(private.trim()) {
                bail!("orca secret '{secret}' does not read back as the key just stored");
            }
            set_mode_owner(key_path, 0o600, uid, gid)?;
            public
        }
        KeySource::CheckMatch => {
            let public = public_of(host, key_path)
                .await
                .map_err(|e| corrupt_host_key(key_path, e, "reinstall it from orca secrets"))?;
            check_matches_secret(key_path, secret, left(deadline)).await?;
            set_mode_owner(key_path, 0o600, uid, gid)?;
            public
        }
    };
    let pub_file = pub_path(key_path);
    write_atomic(&pub_file, format!("{public} {comment}\n").as_bytes(), 0o644)?;
    chown(&pub_file, Some(uid), gid, false)?;
    Ok(public)
}

async fn check_matches_secret(key_path: &Path, secret: &str, limit: Duration) -> Result<()> {
    let stored = secret_get(limit, secret)
        .await?
        .ok_or_else(|| anyhow!("orca secret '{secret}' does not exist"))?;
    let on_host = std::fs::read_to_string(key_path)
        .with_context(|| format!("read {}", key_path.display()))?;
    if stored.trim() != on_host.trim() {
        bail!(
            "{} differs from orca secret '{secret}'; refusing to choose one. Move the stale copy aside and re-run",
            key_path.display()
        );
    }
    Ok(())
}

/// The key `gitea.signing` needs: on the host, a valid private key, and the
/// one in orca secrets. Returns its public half.
async fn existing_key(
    host: &LocalHost,
    key_path: &Path,
    secret: &str,
    deadline: Instant,
) -> Result<String> {
    if !key_path.exists() {
        bail!("no signing key at {}; {RUN_KEY_FIRST}", key_path.display());
    }
    let public =
        match plugin_toolkit::time::timeout(left(deadline), public_of(host, key_path)).await {
            Some(parsed) => parsed.with_context(|| {
                format!(
                    "{} is not a valid private key; {RUN_KEY_FIRST}",
                    key_path.display()
                )
            })?,
            None => bail!(
                "timed out reading the public half of {} with ssh-keygen",
                key_path.display()
            ),
        };
    check_matches_secret(key_path, secret, left(deadline))
        .await
        .context(RUN_KEY_FIRST)?;
    Ok(public)
}

/// Rewrite app.ini keeping its mode and owner: Gitea must still read it.
fn write_ini(path: &Path, contents: &str) -> Result<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let meta = std::fs::metadata(path).with_context(|| format!("stat {}", path.display()))?;
    let previous = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
    install_ini(
        path,
        contents.as_bytes(),
        &previous,
        meta.permissions().mode() & 0o7777,
        |p| chown(p, Some(meta.uid()), meta.gid(), false),
    )
}

/// Atomically install `contents`, then `finish` it (chown). If `finish`
/// fails, `previous` is put back; the error says which file is in place.
fn install_ini(
    path: &Path,
    contents: &[u8],
    previous: &[u8],
    mode: u32,
    finish: impl Fn(&Path) -> Result<()>,
) -> Result<()> {
    write_atomic(path, contents, mode)?;
    let Err(e) = finish(path) else {
        return Ok(());
    };
    let shown = path.display();
    Err(match write_atomic(path, previous, mode) {
        Err(r) => e.context(format!(
            "restoring the previous {shown} failed ({r:#}); the NEW app.ini is in place"
        )),
        Ok(()) => match finish(path) {
            Ok(()) => e.context(format!("the PREVIOUS {shown} is back in place")),
            Err(r) => e.context(format!(
                "the PREVIOUS {shown} is back in place, but its owner could not be restored ({r:#})"
            )),
        },
    })
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

/// Names the slow step when `e` came from setup running out of time.
fn setup_expired(e: anyhow::Error, setup: Instant, step: &str) -> anyhow::Error {
    if !left(setup).is_zero() {
        return e;
    }
    e.context(format!(
        "setup ran out of time while {step}; nothing was changed, retry the call"
    ))
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
    /// Key provisioned by `gitea.signing.key`.
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
    /// Restart Gitea even when app.ini and the served key look current.
    #[arg(long)]
    #[serde(default)]
    pub force_restart: bool,
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

/// Point app.ini at the key `gitea.signing.key` provisioned and make Gitea
/// sign initial commits, web edits, wiki edits and merges. Restarts Gitea.
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
    // Everything before WriteIni must leave `reserve` for restart, verify and rollback.
    let pre = Instant::now() + budget.pre_limit();
    let setup = pre - Duration::from_secs(SERVED_KEY_SECS);
    let endpoint = args.endpoint.clone();
    let runtime = tokio::runtime::Handle::current();
    let cfg = blocking(left(setup), "resolve the endpoint", move || {
        runtime.block_on(crate::tools::resolve_config(&endpoint))
    })
    .await
    .map_err(|e| setup_expired(e, setup, "resolving the endpoint"))?;
    let key_path = PathBuf::from(&args.key_path);
    let public_key = existing_key(&host, &key_path, &secret_name(&args.endpoint), setup)
        .await
        .map_err(|e| setup_expired(e, setup, "checking the key against the orca secret"))?;
    let instance = instance_url(&cfg);
    let served_url = format!("{}/api/v1/signing-key.pub", instance.trim_end_matches('/'));
    let facts = Facts {
        ini: read_ini(&args.app_ini)?,
        init: host.init,
        served_key: attempt(pre, fetch_public_key(&cfg, &served_url))
            .await
            .map_err(|e| format!("{e:#}")),
        public_key: public_key.clone(),
    };
    let steps = plan(&args, &facts, &instance)?;
    let execution_plan = to_plan(TOOL, &args, &steps)?;
    let notes = match &facts.served_key {
        Err(e) if !steps.iter().any(|s| matches!(s, Step::Restart { .. })) => {
            vec![format!("already configured; served key unreadable: {e}")]
        }
        _ => vec![],
    };
    if !args.execute {
        return Ok(SigningOutput {
            dry_run: true,
            plan: execution_plan,
            applied: vec![],
            public_key: Some(public_key),
            notes,
        });
    }
    let live = Live {
        host: &host,
        cfg: &cfg,
        instance,
    };
    let applied = run(&live, &steps, budget, &public_key).await?;
    Ok(SigningOutput {
        dry_run: false,
        plan: execution_plan,
        applied,
        public_key: Some(public_key),
        notes,
    })
}

fn to_plan(tool: &str, args: &SigningArgs, steps: &[Step]) -> Result<ExecutionPlan> {
    let inputs = plugin_toolkit::serde_json::to_value(args)?;
    let summary = format!(
        "sign Gitea-authored commits with the SSH key at {}{}",
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

    /// What setup may take: resolving the endpoint, checking the key and the
    /// `SERVED_KEY_SECS` served-key read. Live: 30s run - 26s reserve = 4s,
    /// of which 2s is the served-key read and 2s the rest of setup.
    fn pre_limit(&self) -> Duration {
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
async fn run(
    svc: &impl Service,
    steps: &[Step],
    budget: Budget,
    public: &str,
) -> Result<Vec<String>> {
    let mut done = Vec::new();
    let mut previous_ini: Option<(PathBuf, String)> = None;
    let mut restart: Option<Vec<String>> = None;
    for step in steps {
        let result: Result<()> = async {
            match step {
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
                    let secs = verify_budget(*wait_secs, left(budget.deadline), budget.restart);
                    if let Err(e) = svc.verify(url, public, secs).await {
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
    Ok(done)
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
// gitea.signing.key
// ═══════════════════════════════════════════════════════════════════════════

#[derive(clap::Args, Serialize, Deserialize, JsonSchema)]
pub struct SigningKeyArgs {
    /// Registered Gitea endpoint served from this host.
    #[arg(long)]
    pub endpoint: String,
    /// Read for RUN_USER (the key's owner) and [server] DOMAIN; never written.
    #[arg(long, default_value = DEFAULT_APP_INI)]
    #[serde(default = "default_app_ini")]
    pub app_ini: String,
    /// Private key path; the public key is written beside it as `.pub`.
    #[arg(long, default_value = DEFAULT_KEY_PATH)]
    #[serde(default = "default_key_path")]
    pub key_path: String,
    /// Key comment; defaults to `gitea@<[server] DOMAIN>`.
    #[arg(long)]
    #[serde(default)]
    pub signing_email: Option<String>,
    /// Apply. Omitted, returns the plan and changes nothing.
    #[arg(long)]
    #[serde(default)]
    pub execute: bool,
}

/// Provision the Gitea signing key on this host and in orca secrets. Never
/// touches app.ini or restarts Gitea; run `gitea.signing` afterwards.
#[orca_tool(
    domain = "gitea",
    verb = "signing.key",
    role = "admin",
    execute_gated = false
)]
pub async fn gitea_signing_key(args: SigningKeyArgs, ctx: &ToolCtx) -> Result<SigningOutput> {
    const TOOL: &str = "gitea.signing.key";
    let deadline = Instant::now() + Duration::from_secs(KEY_SECS);
    require_admin(TOOL, ctx)?;
    let host = LocalHost::current()?;
    let endpoint = args.endpoint.clone();
    blocking(left(deadline), "look up the endpoint", move || {
        crate::tools::endpoint_db::require(&endpoint).map(|_| ())
    })
    .await?;
    let secret = secret_name(&args.endpoint);
    let key_path = PathBuf::from(&args.key_path);
    let ini = read_ini(&args.app_ini)?;
    let owner = run_user(&ini);
    let comment = signing_email(&args.signing_email, &ini)?;
    let source = KeySource::decide(
        secret_get(left(deadline), &secret).await?.is_some(),
        key_path.exists(),
    );
    let execution_plan =
        ExecutionPlan::generic(TOOL, plugin_toolkit::serde_json::to_value(&args)?.into()).detailed(
            format!(
                "provision the Gitea signing key at {}; app.ini and the service are untouched",
                args.key_path
            ),
            vec![source.to_change(&key_path, &owner, &secret)],
        );
    let notes = vec!["then run `gitea.signing` to configure Gitea to sign with it".to_string()];
    if !args.execute {
        let public_key = if key_path.exists() {
            plugin_toolkit::time::timeout(left(deadline), public_of(&host, &key_path))
                .await
                .and_then(Result::ok)
        } else {
            None
        };
        return Ok(SigningOutput {
            dry_run: true,
            plan: execution_plan,
            applied: vec![],
            public_key,
            notes,
        });
    }
    let public = plugin_toolkit::time::timeout(
        left(deadline),
        provision_key(
            &host, &source, &key_path, &owner, &secret, &comment, deadline,
        ),
    )
    .await
    .unwrap_or_else(|| Err(anyhow!("did not finish within {KEY_SECS}s")))
    .with_context(|| format!("{TOOL} failed; app.ini and the service are unchanged"))?;
    let change = source.to_change(&key_path, &owner, &secret);
    Ok(SigningOutput {
        dry_run: false,
        plan: execution_plan,
        applied: vec![format!("{} {}", change.action, change.target)],
        public_key: Some(public),
        notes,
    })
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
            force_restart: false,
        }
    }

    const INI: &str = "APP_NAME = Gitea\nRUN_USER = gitea\n\n[server]\nDOMAIN = git.example\n\n[repository.signing]\n; keep me\nSIGNING_KEY = default\n\n[log]\nMODE = console\n";

    const PUBLIC: &str = "ssh-ed25519 AAAA";

    fn facts(ini: &str, served: Option<&str>) -> Facts {
        Facts {
            ini: ini.into(),
            init: Init::Systemd,
            public_key: PUBLIC.into(),
            served_key: served
                .map(str::to_string)
                .ok_or_else(|| "timed out".to_string()),
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
    fn plan_writes_the_ini_restarts_and_verifies() {
        let steps = plan(&args(false), &facts(INI, None), "https://git.example").unwrap();
        let actions: Vec<_> = steps.iter().map(|s| s.to_change().action).collect();
        assert_eq!(actions, ["write", "restart", "verify"]);
        let restart = steps[1].to_change();
        assert_eq!(restart.target, "systemctl restart gitea");
        assert!(restart.detail.unwrap().contains("DOWN"));
        assert_eq!(
            steps[2].to_change().target,
            "https://git.example/api/v1/signing-key.pub"
        );
    }

    #[test]
    fn configured_server_restarts_only_when_it_does_not_serve_the_key() {
        let done = ini_set(
            INI,
            SECTION,
            &signing_settings(Path::new(DEFAULT_KEY_PATH), "Gitea", "gitea@git.example"),
        );
        let actions = |served| -> Vec<String> {
            plan(&args(false), &facts(&done, served), "https://g")
                .unwrap()
                .iter()
                .map(|s| s.to_change().action)
                .collect()
        };
        assert_eq!(actions(Some(PUBLIC)), ["verify"]);
        assert_eq!(actions(Some("ssh-ed25519 OLD")), ["restart", "verify"]);
        assert_eq!(actions(None), ["verify"]);
    }

    #[test]
    fn force_restart_restarts_a_configured_server() {
        let done = ini_set(
            INI,
            SECTION,
            &signing_settings(Path::new(DEFAULT_KEY_PATH), "Gitea", "gitea@git.example"),
        );
        let mut a = args(false);
        a.force_restart = true;
        for served in [Some(PUBLIC), None] {
            let actions: Vec<_> = plan(&a, &facts(&done, served), "https://g")
                .unwrap()
                .iter()
                .map(|s| s.to_change().action)
                .collect();
            assert_eq!(actions, ["restart", "verify"]);
        }
    }

    #[test]
    fn key_source_covers_every_case() {
        let actions: Vec<_> = [
            KeySource::Generate,
            KeySource::Adopt,
            KeySource::Install,
            KeySource::CheckMatch,
        ]
        .iter()
        .map(|k| k.to_change(Path::new("/k"), "git", "s").action)
        .collect();
        assert_eq!(
            actions,
            ["generate-key", "adopt-key", "install-key", "check-key"]
        );
        assert_eq!(KeySource::decide(false, false), KeySource::Generate);
        assert_eq!(KeySource::decide(false, true), KeySource::Adopt);
        assert_eq!(KeySource::decide(true, false), KeySource::Install);
        assert_eq!(KeySource::decide(true, true), KeySource::CheckMatch);
    }

    #[test]
    fn plan_needs_an_email_when_app_ini_has_no_domain() {
        let err = plan(&args(false), &facts("[server]\n", None), "https://g")
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
        let steps = plan(&a, &facts(INI, None), "https://g").unwrap();
        let Some(Step::Verify { wait_secs, .. }) = steps.last() else {
            panic!()
        };
        assert_eq!(*wait_secs, DEFAULT_VERIFY_SECS);
        a.verify_secs = 0;
        let steps = plan(&a, &facts(INI, None), "https://g").unwrap();
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
        std::fs::write(temp_key_path(&key), "x").unwrap();
        assert!(
            !prepare_key_dir(&key).unwrap(),
            "a leftover temp key is allowed"
        );
        std::fs::write(dir.join("other"), "x").unwrap();
        let err = prepare_key_dir(&dir.join("k")).unwrap_err().to_string();
        assert!(err.contains("not a dedicated key directory"), "{err}");
        std::fs::remove_dir_all(&dir).ok();
    }

    struct Fake {
        restarts: std::cell::RefCell<std::collections::VecDeque<bool>>,
        hang_first_restart: std::cell::Cell<bool>,
        verify_ok: bool,
        up_ok: bool,
        calls: std::cell::RefCell<Vec<&'static str>>,
    }

    impl Fake {
        fn new(restarts: &[bool], verify_ok: bool, up_ok: bool) -> Self {
            Fake {
                restarts: std::cell::RefCell::new(restarts.iter().copied().collect()),
                hang_first_restart: Default::default(),
                verify_ok,
                up_ok,
                calls: Default::default(),
            }
        }
    }

    impl Service for Fake {
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
    fn setup_timeout_names_the_step_and_changes_nothing() {
        let e = setup_expired(anyhow!("slow"), Instant::now(), "resolving the endpoint");
        let msg = format!("{e:#}");
        assert!(msg.contains("resolving the endpoint"), "{msg}");
        assert!(msg.contains("nothing was changed"), "{msg}");
        let later = Instant::now() + Duration::from_secs(60);
        assert_eq!(
            format!("{:#}", setup_expired(anyhow!("bad key"), later, "x")),
            "bad key"
        );
    }

    #[test]
    fn reserve_covers_restart_verify_and_rollback() {
        let b = Budget::live();
        assert_eq!(
            b.reserve(),
            Duration::from_secs(2 * RESTART_SECS + MIN_VERIFY_SECS + ROLLBACK_UP_SECS)
        );
        assert!(b.pre_limit() <= Duration::from_secs(RUN_SECS) - b.reserve());
        assert!(b.pre_limit() > Duration::from_secs(3));
        const {
            assert!(
                RUN_SECS
                    - (2 * RESTART_SECS + MIN_VERIFY_SECS + ROLLBACK_UP_SECS)
                    - SERVED_KEY_SECS
                    >= 2
            )
        };
        // Worst path: pre-run checks, write, restart, verify, rollback restart, wait_up.
        const {
            assert!(
                (RUN_SECS - (2 * RESTART_SECS + MIN_VERIFY_SECS + ROLLBACK_UP_SECS))
                    + RESTART_SECS
                    + MIN_VERIFY_SECS
                    + RESTART_SECS
                    + ROLLBACK_UP_SECS
                    <= RUN_SECS
            )
        };
        let spent = Budget {
            deadline: Instant::now(),
            restart: b.restart,
        };
        assert_eq!(spent.pre_limit(), Duration::ZERO);
    }

    #[tokio::test]
    async fn too_little_time_at_write_ini_leaves_app_ini_unchanged() {
        let dir = scratch("late");
        let ini = dir.join("app.ini");
        std::fs::write(&ini, INI).unwrap();
        let fake = Fake::new(&[true, true], true, true);
        let mut budget = test_budget();
        budget.deadline = Instant::now() + budget.reserve() - Duration::from_millis(1);
        let err = run(&fake, &run_steps(&ini), budget, PUBLIC)
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
        let err = run(&fake, &run_steps(&ini), test_budget(), PUBLIC)
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
        let err = run(&fake, &run_steps(&ini), test_budget(), PUBLIC)
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
        let err = run(&fake, &run_steps(&ini), test_budget(), PUBLIC)
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
        let err = run(&fake, &run_steps(&ini), test_budget(), PUBLIC)
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("Gitea may be DOWN"), "{err}");
        assert!(err.contains("PREVIOUS app.ini is in place"), "{err}");
        let fake = Fake::new(&[true, true], false, false);
        let err = run(&fake, &run_steps(&ini), test_budget(), PUBLIC)
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("Gitea may be DOWN"), "{err}");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn launchd_hosts_are_refused() {
        let mut f = facts(INI, None);
        f.init = Init::Launchd;
        assert!(plan(&args(false), &f, "https://g").is_err());
    }

    #[test]
    fn plan_output_never_contains_key_material() {
        let steps = plan(&args(false), &facts(INI, None), "https://g").unwrap();
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
                "gitea.signing.key",
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
            plugin_toolkit::dispatch::required_role("gitea.signing.key"),
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
    fn a_failed_chown_after_install_restores_the_previous_app_ini() {
        let dir = scratch("chown");
        let ini = dir.join("app.ini");
        std::fs::write(&ini, INI).unwrap();
        let calls = std::cell::Cell::new(0);
        let finish = |_: &Path| {
            calls.set(calls.get() + 1);
            if calls.get() == 1 {
                bail!("chown refused")
            }
            Ok(())
        };
        let err = install_ini(&ini, b"NEW\n", INI.as_bytes(), 0o640, finish)
            .unwrap_err()
            .to_string();
        assert!(err.contains("PREVIOUS"), "{err}");
        assert_eq!(std::fs::read_to_string(&ini).unwrap(), INI);
        let err = install_ini(&ini, b"NEW\n", INI.as_bytes(), 0o640, |_| bail!("no"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("owner could not be restored"), "{err}");
        assert_eq!(std::fs::read_to_string(&ini).unwrap(), INI);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// `existing_key` only spawns ssh-keygen, so the init system is irrelevant;
    /// `LocalHost::current` would fail on hosts without a service manager.
    fn keygen_host(home: &Path) -> LocalHost {
        LocalHost {
            init: Init::Systemd,
            home: home.to_path_buf(),
            uid: 501,
        }
    }

    #[tokio::test]
    async fn apply_refuses_until_the_key_is_provisioned() {
        let dir = scratch("nokey");
        let host = keygen_host(&dir);
        let deadline = Instant::now() + Duration::from_secs(5);
        let err = existing_key(&host, &dir.join("k"), "s", deadline)
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains(RUN_KEY_FIRST), "{err}");
        std::fs::write(dir.join("garbage"), "not a key").unwrap();
        let err = format!(
            "{:#}",
            existing_key(&host, &dir.join("garbage"), "s", deadline)
                .await
                .unwrap_err()
        );
        assert!(err.contains("not a valid private key"), "{err}");
        assert!(err.contains(RUN_KEY_FIRST), "{err}");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn apply_reports_a_key_check_timeout_as_a_timeout() {
        let dir = scratch("keytimeout");
        let host = keygen_host(&dir);
        std::fs::write(dir.join("k"), "not a key").unwrap();
        let err = format!(
            "{:#}",
            existing_key(&host, &dir.join("k"), "s", Instant::now())
                .await
                .unwrap_err()
        );
        assert!(err.contains("timed out"), "{err}");
        assert!(!err.contains("not a valid private key"), "{err}");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn key_body_drops_the_comment() {
        assert_eq!(key_body("ssh-ed25519 AAAA gitea@x\n"), "ssh-ed25519 AAAA");
    }
}
