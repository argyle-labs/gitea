use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use plugin_toolkit::contract::plan::{ExecutionPlan, PlannedChange};
use plugin_toolkit::prelude::*;
use plugin_toolkit::secrets::SecretRef;
use plugin_toolkit::url::encode;

use crate::Config;
use crate::runner::api::{status_error, verified_client};
use crate::runner::host::LocalHost;
use crate::runner::layout::Init;
use crate::runner::tools::authorize_execute;
use crate::signing::ini_get;

const DEFAULT_APP_INI: &str = "/etc/gitea/app.ini";
const DEFAULT_RUN_USER: &str = "git";
const SYSTEMD_UNITS: &[&str] = &[
    "/etc/systemd/system/gitea.service",
    "/lib/systemd/system/gitea.service",
    "/usr/lib/systemd/system/gitea.service",
];
const OPENRC_SCRIPT: &str = "/etc/init.d/gitea";
const TEAM_MARKER: &str = "[managed by orca gitea.bot.create]";
const TEAM_UNITS: &[&str] = &[
    "repo.code",
    "repo.issues",
    "repo.ext_issues",
    "repo.pulls",
    "repo.releases",
    "repo.wiki",
    "repo.ext_wiki",
    "repo.projects",
    "repo.packages",
    "repo.actions",
];
const FORBIDDEN_SCOPES: &[&str] = &["all", "write:admin", "read:admin", "sudo"];

pub fn scrub(text: &str) -> String {
    plugin_toolkit::scrub::scrub_line(text).into_owned()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Launch {
    pub binary: PathBuf,
    pub app_ini: PathBuf,
}

fn unquote(s: &str) -> &str {
    s.trim_matches(|c| c == '"' || c == '\'')
}

fn config_flag(words: &[&str]) -> Option<String> {
    words.iter().enumerate().find_map(|(i, w)| {
        let w = unquote(w);
        if let Some(v) = w
            .strip_prefix("--config=")
            .or_else(|| w.strip_prefix("-c="))
        {
            return Some(v.to_string());
        }
        (w == "--config" || w == "-c")
            .then(|| words.get(i + 1).map(|v| unquote(v).to_string()))
            .flatten()
    })
}

pub fn parse_systemd_exec(unit: &str) -> Option<Launch> {
    let line = unit
        .lines()
        .map(str::trim)
        .find_map(|l| l.strip_prefix("ExecStart="))?;
    let words: Vec<&str> = line
        .trim_start_matches(['-', '@', '+', '!', ':'])
        .split_whitespace()
        .collect();
    let binary = unquote(words.first()?);
    Some(Launch {
        binary: PathBuf::from(binary),
        app_ini: PathBuf::from(config_flag(&words).unwrap_or_else(|| DEFAULT_APP_INI.into())),
    })
}

pub fn parse_openrc_script(script: &str) -> Option<Launch> {
    let value = |key: &str| {
        script.lines().map(str::trim).find_map(|l| {
            l.strip_prefix(key)
                .and_then(|v| v.strip_prefix('='))
                .map(|v| unquote(v.trim()).to_string())
        })
    };
    let binary = value("command")?;
    let args = value("command_args").unwrap_or_default();
    let words: Vec<&str> = args.split_whitespace().collect();
    Some(Launch {
        binary: PathBuf::from(binary),
        app_ini: PathBuf::from(config_flag(&words).unwrap_or_else(|| DEFAULT_APP_INI.into())),
    })
}

fn discover_launch(init: Init) -> Result<Launch> {
    let found = match init {
        Init::Systemd => SYSTEMD_UNITS.iter().find_map(|p| {
            std::fs::read_to_string(p)
                .ok()
                .and_then(|u| parse_systemd_exec(&u))
        }),
        Init::Openrc => std::fs::read_to_string(OPENRC_SCRIPT)
            .ok()
            .and_then(|s| parse_openrc_script(&s)),
        Init::Launchd => None,
    };
    found.ok_or_else(|| anyhow!("no gitea systemd unit or OpenRC script found on this host"))
}

pub fn check_binary_trust(path: &Path, uid: u32, mode: u32) -> Result<()> {
    if !path.is_absolute() {
        bail!("gitea binary {} is not an absolute path", path.display());
    }
    if uid != 0 {
        bail!("gitea binary {} is not owned by root", path.display());
    }
    if mode & 0o022 != 0 {
        bail!(
            "gitea binary {} is writable by group or others",
            path.display()
        );
    }
    Ok(())
}

pub fn check_run_user(run_user: &str) -> Result<()> {
    if run_user == "root" {
        bail!("app.ini RUN_USER is root; refusing to run the gitea CLI as root");
    }
    Ok(())
}

pub struct GiteaCli {
    pub binary: String,
    pub app_ini: String,
    pub run_user: String,
    pub as_root: bool,
}

impl GiteaCli {
    fn discover(host: &LocalHost) -> Result<Self> {
        use std::os::unix::fs::MetadataExt;
        let launch = discover_launch(host.init)?;
        let meta = std::fs::metadata(&launch.binary)
            .with_context(|| format!("stat {}", launch.binary.display()))?;
        check_binary_trust(&launch.binary, meta.uid(), meta.mode())?;
        let ini = std::fs::read_to_string(&launch.app_ini)
            .with_context(|| format!("read {}", launch.app_ini.display()))?;
        let run_user = ini_get(&ini, "", "RUN_USER").unwrap_or_else(|| DEFAULT_RUN_USER.into());
        check_run_user(&run_user)?;
        Ok(Self {
            binary: launch.binary.display().to_string(),
            app_ini: launch.app_ini.display().to_string(),
            run_user,
            as_root: host.is_root(),
        })
    }

    pub fn argv(&self, args: &[String]) -> Vec<String> {
        let mut argv = Vec::new();
        if self.as_root {
            argv.extend([
                "runuser".into(),
                "-u".into(),
                self.run_user.clone(),
                "--".into(),
            ]);
        }
        argv.extend([self.binary.clone(), "--config".into(), self.app_ini.clone()]);
        argv.extend(args.iter().cloned());
        argv
    }

    async fn run(&self, host: &LocalHost, args: &[String]) -> Result<String> {
        let argv = self.argv(args);
        let out = host.run(&argv, None).await?;
        if !out.ok {
            bail!(
                "`gitea {}` failed (exit {:?}): {}",
                args.iter().take(3).cloned().collect::<Vec<_>>().join(" "),
                out.code,
                scrub(&out.stderr)
            );
        }
        Ok(out.stdout)
    }
}

pub fn validate_username(name: &str) -> Result<()> {
    let special = |c: char| matches!(c, '-' | '.' | '_');
    let ok = name.len() <= 40
        && name
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphanumeric())
        && name
            .chars()
            .last()
            .is_some_and(|c| c.is_ascii_alphanumeric())
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || special(c))
        && !name
            .chars()
            .zip(name.chars().skip(1))
            .any(|(a, b)| special(a) && special(b));
    if !ok {
        bail!("invalid Gitea username '{name}'");
    }
    Ok(())
}

pub fn validate_email(email: &str) -> Result<()> {
    let ok = !email.starts_with('-')
        && email.len() <= 254
        && !email.chars().any(|c| c.is_whitespace() || c.is_control())
        && email
            .split_once('@')
            .is_some_and(|(l, d)| !l.is_empty() && d.contains('.') && !d.contains('@'));
    if !ok {
        bail!("invalid email '{email}'");
    }
    Ok(())
}

pub fn validate_token_name(name: &str) -> Result<()> {
    let ok = !name.is_empty()
        && name.len() <= 64
        && !name.starts_with('-')
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_'));
    if !ok {
        bail!("invalid token name '{name}': use [A-Za-z0-9._-], not starting with '-'");
    }
    Ok(())
}

pub fn create_user_args(username: &str, email: &str) -> Vec<String> {
    vec![
        "admin".into(),
        "user".into(),
        "create".into(),
        "--username".into(),
        username.into(),
        "--email".into(),
        email.into(),
        "--user-type".into(),
        "bot".into(),
        "--random-password".into(),
        "--must-change-password=false".into(),
    ]
}

pub fn generate_token_args(username: &str, token_name: &str, scopes: &[String]) -> Vec<String> {
    vec![
        "admin".into(),
        "user".into(),
        "generate-access-token".into(),
        "--username".into(),
        username.into(),
        "--token-name".into(),
        token_name.into(),
        "--scopes".into(),
        scopes.join(","),
        "--raw".into(),
    ]
}

pub fn change_password_args(username: &str, password: &str) -> Vec<String> {
    vec![
        "admin".into(),
        "user".into(),
        "change-password".into(),
        "--username".into(),
        username.into(),
        "--password".into(),
        password.into(),
        "--must-change-password=false".into(),
    ]
}

pub fn minted_name(token_name: &str, unix_secs: u64) -> String {
    format!("{token_name}-{unix_secs}")
}

pub fn parse_raw_token(out: &str) -> Result<String> {
    let token = out
        .lines()
        .map(str::trim)
        .rfind(|l| !l.is_empty())
        .unwrap_or("");
    if token.len() < 20 || !token.chars().all(|c| c.is_ascii_alphanumeric()) {
        bail!("gitea printed no access token");
    }
    Ok(token.to_string())
}

pub fn parse_units(units: &[String]) -> Result<BTreeMap<String, String>> {
    units
        .iter()
        .map(|u| {
            let (unit, access) = u
                .split_once('=')
                .ok_or_else(|| anyhow!("team unit '{u}' must be <unit>=<access>"))?;
            let unit = unit.trim();
            if !TEAM_UNITS.contains(&unit) {
                bail!("team unit '{unit}' is not one of {}", TEAM_UNITS.join(", "));
            }
            match access {
                "none" | "read" | "write" => {}
                other => bail!("team unit access must be none|read|write, not '{other}'"),
            }
            Ok((unit.to_string(), access.to_string()))
        })
        .collect()
}

pub fn validate_scopes(scopes: &[String]) -> Result<()> {
    if scopes.is_empty() {
        bail!("at least one scope is required");
    }
    for s in scopes {
        if s.is_empty() || s.contains(',') || s.contains(char::is_whitespace) {
            bail!("invalid scope '{s}'");
        }
        if FORBIDDEN_SCOPES.contains(&s.as_str()) {
            bail!("scope '{s}' is not allowed for bot tokens");
        }
    }
    Ok(())
}

pub fn token_secret_name(endpoint: &str, username: &str, token_name: &str) -> String {
    plugin_toolkit::secrets::scoped_name("gitea", endpoint, &format!("{username}.{token_name}"))
}

fn minted_secret_name(secret: &str) -> String {
    format!("{secret}.minted")
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct GiteaUser {
    #[serde(default, rename = "type")]
    pub kind: String,
    #[serde(default)]
    pub is_admin: bool,
}

pub fn require_bot(username: &str, user: &GiteaUser) -> Result<()> {
    if user.is_admin {
        bail!("'{username}' is a site admin; only non-admin bot users are allowed");
    }
    if user.kind != "bot" {
        bail!(
            "'{username}' is a '{}' user, not a bot; only bot users are allowed",
            user.kind
        );
    }
    Ok(())
}

async fn send(what: &str, req: plugin_toolkit::reqwest::RequestBuilder) -> Result<String> {
    let resp = req.send().await.map_err(|e| anyhow!("{what}: {e}"))?;
    let status = resp.status().as_u16();
    let body = resp.text().await.unwrap_or_default();
    if !(200..300).contains(&status) {
        return Err(status_error(what, status, &scrub(&body)));
    }
    Ok(body)
}

async fn fetch_user(cfg: &Config, username: &str) -> Result<Option<GiteaUser>> {
    let url = format!(
        "{}/users/{}",
        cfg.base_url.trim_end_matches('/'),
        encode(username)
    );
    let resp = verified_client(cfg)?
        .get(url)
        .send()
        .await
        .map_err(|e| anyhow!("get user: {e}"))?;
    let status = resp.status().as_u16();
    let body = resp.text().await.unwrap_or_default();
    match status {
        404 => Ok(None),
        200..=299 => Ok(Some(plugin_toolkit::serde_json::from_str(&body)?)),
        _ => Err(status_error("get user", status, &scrub(&body))),
    }
}

async fn require_bot_user(cfg: &Config, username: &str) -> Result<()> {
    let user = fetch_user(cfg, username)
        .await?
        .ok_or_else(|| anyhow!("Gitea user '{username}' does not exist"))?;
    require_bot(username, &user)
}

pub fn team_search_url(base_url: &str, org: &str, team: &str) -> String {
    format!(
        "{}/orgs/{}/teams/search?q={}&limit=50",
        base_url.trim_end_matches('/'),
        encode(org),
        encode(team)
    )
}

pub fn team_member_url(base_url: &str, team_id: i64, username: &str) -> String {
    format!(
        "{}/teams/{team_id}/members/{}",
        base_url.trim_end_matches('/'),
        encode(username)
    )
}

pub fn delete_token_url(base_url: &str, username: &str, token_name: &str) -> String {
    format!(
        "{}/users/{}/tokens/{}",
        base_url.trim_end_matches('/'),
        encode(username),
        encode(token_name)
    )
}

pub fn require_secure_url(url: &str) -> Result<()> {
    if url.starts_with("https://") {
        return Ok(());
    }
    let host = url
        .strip_prefix("http://")
        .and_then(|rest| rest.split(['/', '?']).next())
        .map(|authority| match authority.strip_prefix('[') {
            Some(v6) => v6.split(']').next().unwrap_or(""),
            None => authority.rsplit_once(':').map_or(authority, |(h, _)| h),
        })
        .unwrap_or("");
    let loopback = host == "localhost"
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback());
    if !loopback {
        bail!("refusing to send credentials to non-https, non-loopback {url}");
    }
    Ok(())
}

pub fn basic_auth(username: &str, password: &str) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let bytes = format!("{username}:{password}").into_bytes();
    let mut out = String::from("Basic ");
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(ALPHABET[(n >> (18 - 6 * i) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

fn random_password() -> Result<String> {
    use std::io::Read;
    let mut buf = [0u8; 24];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut buf))
        .context("read /dev/urandom")?;
    Ok(buf.iter().map(|b| format!("{b:02x}")).collect())
}

async fn set_password(cli: &GiteaCli, host: &LocalHost, username: &str) -> Result<String> {
    let password = random_password()?;
    cli.run(host, &change_password_args(username, &password))
        .await
        .map_err(|e| anyhow!("{}", format!("{e:#}").replace(&password, "<redacted>")))?;
    Ok(password)
}

async fn revoke_token(
    cli: &GiteaCli,
    host: &LocalHost,
    cfg: &Config,
    username: &str,
    token_name: &str,
) -> Result<()> {
    let url = delete_token_url(&cfg.base_url, username, token_name);
    require_secure_url(&url)?;
    let password = set_password(cli, host, username).await?;
    let deleted = async {
        let client = plugin_toolkit::api_client::ApiClientBuilder::new()
            .header("authorization", basic_auth(username, &password))
            .and_then(|b| b.insecure(false).build())?;
        let resp = client
            .delete(url)
            .send()
            .await
            .map_err(|e| anyhow!("delete token: {e}"))?;
        let status = resp.status().as_u16();
        if !(200..300).contains(&status) && status != 404 {
            let body = resp.text().await.unwrap_or_default();
            return Err(status_error("delete token", status, &scrub(&body)));
        }
        Ok(())
    }
    .await;
    let rerolled = set_password(cli, host, username).await;
    deleted?;
    rerolled.map(|_| ())
}

async fn secret_get(name: &str) -> Result<Option<String>> {
    let name = name.to_string();
    tokio::task::spawn_blocking(move || plugin_toolkit::secrets::get(&name)).await?
}

async fn secret_set(name: &str, value: &str, desc: &str) -> Result<SecretRef> {
    let (name, value, desc) = (name.to_string(), value.to_string(), desc.to_string());
    tokio::task::spawn_blocking(move || plugin_toolkit::secrets::set(&name, &value, Some(&desc)))
        .await?
}

#[derive(clap::Args, Serialize, Deserialize, JsonSchema)]
pub struct BotCreateArgs {
    #[arg(long)]
    pub endpoint: String,
    #[arg(long)]
    pub username: String,
    #[arg(long)]
    pub email: String,
    #[arg(long)]
    #[serde(default)]
    pub org: Option<String>,
    #[arg(long)]
    #[serde(default)]
    pub team: Option<String>,
    #[arg(long = "team-unit")]
    #[serde(default)]
    pub team_units: Vec<String>,
    #[arg(long)]
    #[serde(default)]
    pub dry_run: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct BotCreateOutput {
    pub dry_run: bool,
    pub plan: ExecutionPlan,
    pub username: String,
    pub user_existed: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub applied: Vec<String>,
}

#[derive(Deserialize)]
struct Team {
    id: i64,
    name: String,
    #[serde(default)]
    description: Option<String>,
}

pub fn team_is_managed(description: Option<&str>) -> bool {
    description.is_some_and(|d| d.contains(TEAM_MARKER))
}

async fn find_team(cfg: &Config, org: &str, team: &str) -> Result<Option<Team>> {
    #[derive(Deserialize)]
    struct Search {
        data: Vec<Team>,
    }
    let body = send(
        "search teams",
        verified_client(cfg)?.get(team_search_url(&cfg.base_url, org, team)),
    )
    .await?;
    let found: Search = plugin_toolkit::serde_json::from_str(&body)?;
    Ok(found
        .data
        .into_iter()
        .find(|t| t.name.eq_ignore_ascii_case(team)))
}

pub fn team_body(
    team: &str,
    units: &BTreeMap<String, String>,
) -> plugin_toolkit::serde_json::Value {
    json!({
        "name": team,
        "description": TEAM_MARKER,
        "permission": "read",
        "includes_all_repositories": false,
        "can_create_org_repo": false,
        "units": units.keys().collect::<Vec<_>>(),
        "units_map": units,
    })
}

async fn ensure_team(
    cfg: &Config,
    org: &str,
    team: &str,
    units: &BTreeMap<String, String>,
) -> Result<(i64, String)> {
    let client = verified_client(cfg)?;
    let base = cfg.base_url.trim_end_matches('/');
    let body = team_body(team, units);
    match find_team(cfg, org, team).await? {
        Some(t) if team_is_managed(t.description.as_deref()) && !units.is_empty() => {
            send(
                "update team",
                client.patch(format!("{base}/teams/{}", t.id)).json(&body),
            )
            .await?;
            Ok((t.id, format!("team {org}/{team} units set")))
        }
        Some(t) if team_is_managed(t.description.as_deref()) => {
            Ok((t.id, format!("team {org}/{team} unchanged")))
        }
        Some(t) => Ok((
            t.id,
            format!("team {org}/{team} is not orca-managed; units left unchanged"),
        )),
        None => {
            let created = send(
                "create team",
                client
                    .post(format!("{base}/orgs/{}/teams", encode(org)))
                    .json(&body),
            )
            .await?;
            let t: Team = plugin_toolkit::serde_json::from_str(&created)?;
            Ok((t.id, format!("created team {org}/{team}")))
        }
    }
}

#[orca_tool(
    domain = "gitea",
    verb = "bot.create",
    role = "admin",
    execute_gated = false
)]
pub async fn gitea_bot_create(args: BotCreateArgs, ctx: &ToolCtx) -> Result<BotCreateOutput> {
    const TOOL: &str = "gitea.bot.create";
    authorize_execute(TOOL, ctx.caller().as_ref())?;
    validate_username(&args.username)?;
    validate_email(&args.email)?;
    let units = parse_units(&args.team_units)?;
    let team = match (&args.org, &args.team) {
        (Some(o), Some(t)) => Some((o.clone(), t.clone())),
        (None, None) if units.is_empty() => None,
        _ => bail!("org and team go together, and team units need both"),
    };
    let host = LocalHost::current()?;
    let cli = GiteaCli::discover(&host)?;
    let cfg = crate::tools::resolve_config(&args.endpoint).await?;
    let existing = fetch_user(&cfg, &args.username).await?;
    if let Some(user) = &existing {
        require_bot(&args.username, user)?;
    }
    let existed = existing.is_some();
    let mut changes = Vec::new();
    if !existed {
        changes.push(
            PlannedChange::new(format!("user {}", args.username), "create").with_detail(format!(
                "non-admin bot user, random password, no forced change; runs `{}`",
                cli.argv(&create_user_args(&args.username, &args.email))
                    .join(" ")
            )),
        );
    }
    if let Some((org, t)) = &team {
        changes.push(
            PlannedChange::new(format!("team {org}/{t}"), "ensure-member").with_detail(format!(
                "create the team with units {units:?} (or update it if orca created it) and add {}",
                args.username
            )),
        );
    }
    let plan = ExecutionPlan::generic(TOOL, plugin_toolkit::serde_json::to_value(&args)?.into())
        .detailed(format!("ensure Gitea bot user {}", args.username), changes);
    if args.dry_run {
        return Ok(BotCreateOutput {
            dry_run: true,
            plan,
            username: args.username,
            user_existed: existed,
            applied: vec![],
        });
    }
    let mut applied = Vec::new();
    if !existed {
        cli.run(&host, &create_user_args(&args.username, &args.email))
            .await?;
        applied.push(format!("created bot user {}", args.username));
    }
    if let Some((org, t)) = &team {
        let (id, did) = ensure_team(&cfg, org, t, &units).await?;
        applied.push(did);
        send(
            "add team member",
            verified_client(&cfg)?.put(team_member_url(&cfg.base_url, id, &args.username)),
        )
        .await?;
        applied.push(format!("{} is a member of {org}/{t}", args.username));
    }
    Ok(BotCreateOutput {
        dry_run: false,
        plan,
        username: args.username,
        user_existed: existed,
        applied,
    })
}

#[derive(clap::Args, Serialize, Deserialize, JsonSchema)]
pub struct TokenCreateArgs {
    #[arg(long)]
    pub endpoint: String,
    #[arg(long)]
    pub username: String,
    #[arg(long)]
    pub token_name: String,
    #[arg(long = "scope", required = true)]
    pub scopes: Vec<String>,
    #[arg(long)]
    #[serde(default)]
    pub rotate: bool,
    #[arg(long)]
    #[serde(default)]
    pub dry_run: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct TokenCreateOutput {
    pub dry_run: bool,
    pub plan: ExecutionPlan,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret: Option<SecretRef>,
    pub created: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gitea_token_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked: Option<String>,
}

#[orca_tool(
    domain = "gitea",
    verb = "token.create",
    role = "admin",
    execute_gated = false
)]
pub async fn gitea_token_create(args: TokenCreateArgs, ctx: &ToolCtx) -> Result<TokenCreateOutput> {
    const TOOL: &str = "gitea.token.create";
    authorize_execute(TOOL, ctx.caller().as_ref())?;
    validate_username(&args.username)?;
    validate_token_name(&args.token_name)?;
    validate_scopes(&args.scopes)?;
    let host = LocalHost::current()?;
    let cli = GiteaCli::discover(&host)?;
    let cfg = crate::tools::resolve_config(&args.endpoint).await?;
    require_bot_user(&cfg, &args.username).await?;
    let secret = token_secret_name(&args.endpoint, &args.username, &args.token_name);
    let minted_secret = minted_secret_name(&secret);
    let existing = secret_get(&secret).await?.is_some();
    let previous = secret_get(&minted_secret).await?;
    let keep = existing && !args.rotate;
    let change = if keep {
        PlannedChange::new(format!("secret {secret}"), "keep")
            .with_detail("orca secret already holds a token; nothing is created")
    } else {
        PlannedChange::new(
            format!("token {}/{}-<unix time>", args.username, args.token_name),
            if args.rotate { "rotate" } else { "create" },
        )
        .with_detail(format!(
            "scopes {}; value stored only in orca secret '{secret}'{}",
            args.scopes.join(","),
            previous
                .as_deref()
                .map(|p| format!(", then previous token '{p}' revoked"))
                .unwrap_or_default()
        ))
    };
    let plan = ExecutionPlan::generic(TOOL, plugin_toolkit::serde_json::to_value(&args)?.into())
        .detailed(
            format!("access token for Gitea bot user {}", args.username),
            vec![change],
        );
    if args.dry_run || keep {
        return Ok(TokenCreateOutput {
            dry_run: args.dry_run,
            plan,
            secret: existing.then(|| SecretRef(secret.clone())),
            created: false,
            gitea_token_name: previous,
            revoked: None,
        });
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    let minted = minted_name(&args.token_name, now);
    let out = cli
        .run(
            &host,
            &generate_token_args(&args.username, &minted, &args.scopes),
        )
        .await?;
    let token = parse_raw_token(&out)?;
    let desc = format!(
        "Gitea access token {}/{minted} (gitea.token.create)",
        args.username
    );
    let stored = secret_set(&secret, &token, &desc).await?;
    secret_set(&minted_secret, &minted, &desc).await?;
    let revoked = match previous.filter(|p| *p != minted) {
        Some(prev) => {
            revoke_token(&cli, &host, &cfg, &args.username, &prev)
                .await
                .with_context(|| {
                    format!(
                        "new token '{minted}' is stored in '{secret}', but revoking previous token '{prev}' failed"
                    )
                })?;
            Some(prev)
        }
        None => None,
    };
    Ok(TokenCreateOutput {
        dry_run: false,
        plan,
        secret: Some(stored),
        created: true,
        gitea_token_name: Some(minted),
        revoked,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cli(as_root: bool) -> GiteaCli {
        GiteaCli {
            binary: "/usr/local/bin/gitea".into(),
            app_ini: "/etc/gitea/app.ini".into(),
            run_user: "git".into(),
            as_root,
        }
    }

    #[test]
    fn discovers_launch_from_systemd_unit() {
        let unit =
            "[Service]\nUser=git\nExecStart=/usr/local/bin/gitea web --config /etc/gitea/app.ini\n";
        assert_eq!(
            parse_systemd_exec(unit),
            Some(Launch {
                binary: "/usr/local/bin/gitea".into(),
                app_ini: "/etc/gitea/app.ini".into()
            })
        );
        let unit = "ExecStart=-/opt/gitea/gitea web -c=/srv/gitea.ini";
        assert_eq!(
            parse_systemd_exec(unit).unwrap().app_ini,
            PathBuf::from("/srv/gitea.ini")
        );
        assert_eq!(
            parse_systemd_exec("ExecStart=/usr/bin/gitea web")
                .unwrap()
                .app_ini,
            PathBuf::from(DEFAULT_APP_INI)
        );
        assert!(parse_systemd_exec("[Unit]").is_none());
    }

    #[test]
    fn discovers_launch_from_openrc_script() {
        let script =
            "command=\"/usr/bin/gitea\"\ncommand_args=\"web --config /etc/gitea/app.ini\"\n";
        assert_eq!(
            parse_openrc_script(script),
            Some(Launch {
                binary: "/usr/bin/gitea".into(),
                app_ini: "/etc/gitea/app.ini".into()
            })
        );
    }

    #[test]
    fn binary_must_be_root_owned_and_not_writable() {
        let p = Path::new("/usr/local/bin/gitea");
        assert!(check_binary_trust(p, 0, 0o100755).is_ok());
        assert!(check_binary_trust(p, 1000, 0o100755).is_err());
        assert!(check_binary_trust(p, 0, 0o100775).is_err());
        assert!(check_binary_trust(p, 0, 0o100757).is_err());
        assert!(check_binary_trust(Path::new("gitea"), 0, 0o100755).is_err());
    }

    #[test]
    fn refuses_root_run_user() {
        assert!(check_run_user("root").is_err());
        assert!(check_run_user("git").is_ok());
    }

    #[test]
    fn root_runs_cli_as_run_user() {
        let args = ["admin".to_string()];
        assert_eq!(
            cli(true).argv(&args).join(" "),
            "runuser -u git -- /usr/local/bin/gitea --config /etc/gitea/app.ini admin"
        );
        assert_eq!(
            cli(false).argv(&args).join(" "),
            "/usr/local/bin/gitea --config /etc/gitea/app.ini admin"
        );
    }

    #[test]
    fn create_user_is_non_admin_bot_with_random_password() {
        let a = create_user_args("pkg-bot", "pkg-bot@x.test").join(" ");
        assert_eq!(
            a,
            "admin user create --username pkg-bot --email pkg-bot@x.test --user-type bot --random-password --must-change-password=false"
        );
        assert!(!a.contains("--admin"));
    }

    #[test]
    fn token_args_join_scopes_and_print_raw() {
        let a = generate_token_args(
            "pkg-bot",
            "ci-1700000000",
            &["read:package".into(), "read:user".into()],
        );
        assert_eq!(
            a.join(" "),
            "admin user generate-access-token --username pkg-bot --token-name ci-1700000000 --scopes read:package,read:user --raw"
        );
        assert_eq!(minted_name("ci", 1700000000), "ci-1700000000");
    }

    #[test]
    fn parses_raw_token_and_rejects_noise() {
        let t = "0123456789abcdef0123456789abcdef01234567";
        assert_eq!(parse_raw_token(&format!("{t}\n")).unwrap(), t);
        assert!(parse_raw_token("").is_err());
        assert!(parse_raw_token("access token was successfully created").is_err());
    }

    #[test]
    fn team_units_are_allowlisted_and_never_admin() {
        let u = parse_units(&["repo.packages=read".into()]).unwrap();
        assert_eq!(u.get("repo.packages").map(String::as_str), Some("read"));
        assert!(parse_units(&["repo.packages".into()]).is_err());
        assert!(parse_units(&["repo.packages=admin".into()]).is_err());
        assert!(parse_units(&["repo.packages=owner".into()]).is_err());
        assert!(parse_units(&["repo.settings=read".into()]).is_err());
        let body = team_body("readers", &u);
        assert_eq!(body["units_map"]["repo.packages"], "read");
        assert_eq!(body["units"][0], "repo.packages");
        assert_eq!(body["includes_all_repositories"], false);
        assert_eq!(body["description"], TEAM_MARKER);
    }

    #[test]
    fn only_marked_teams_are_managed() {
        assert!(team_is_managed(Some(TEAM_MARKER)));
        assert!(team_is_managed(Some(&format!("readers {TEAM_MARKER}"))));
        assert!(!team_is_managed(Some("Owners")));
        assert!(!team_is_managed(None));
    }

    #[test]
    fn scopes_are_validated_and_admin_scopes_refused() {
        assert!(validate_scopes(&[]).is_err());
        assert!(validate_scopes(&["read:package,write:user".into()]).is_err());
        for bad in ["all", "write:admin", "read:admin"] {
            assert!(validate_scopes(&[bad.into()]).is_err(), "{bad}");
        }
        assert!(validate_scopes(&["read:package".into()]).is_ok());
    }

    #[test]
    fn only_non_admin_bots_pass() {
        let user = |kind: &str, is_admin| GiteaUser {
            kind: kind.into(),
            is_admin,
        };
        assert!(require_bot("b", &user("bot", false)).is_ok());
        assert!(require_bot("b", &user("bot", true)).is_err());
        assert!(require_bot("b", &user("user", false)).is_err());
        assert!(require_bot("b", &user("", false)).is_err());
        let parsed: GiteaUser =
            plugin_toolkit::serde_json::from_str(r#"{"login":"b","type":"bot","is_admin":false}"#)
                .unwrap();
        assert_eq!(parsed, user("bot", false));
    }

    #[test]
    fn validates_usernames_emails_and_token_names() {
        for ok in ["pkg-bot", "a", "bot.1", "ci_bot"] {
            assert!(validate_username(ok).is_ok(), "{ok}");
        }
        for bad in ["-bot", "bot-", "a--b", "a b", "", "a/b", "--admin"] {
            assert!(validate_username(bad).is_err(), "{bad}");
        }
        assert!(validate_email("b@x.test").is_ok());
        for bad in ["-b@x.test", "b x@y.z", "bx.test", "b@x"] {
            assert!(validate_email(bad).is_err(), "{bad}");
        }
        assert!(validate_token_name("ci.pull_1").is_ok());
        for bad in ["-ci", "", "a b", "a/b"] {
            assert!(validate_token_name(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn secret_name_is_namespaced() {
        let s = token_secret_name("home", "pkg-bot", "ci");
        assert_eq!(s, "gitea.home.pkg-bot.ci");
        assert_eq!(minted_secret_name(&s), "gitea.home.pkg-bot.ci.minted");
    }

    #[test]
    fn url_path_segments_are_encoded() {
        assert_eq!(
            team_search_url("https://g.test/api/v1", "ar gyle", "pkg readers&x=1"),
            "https://g.test/api/v1/orgs/ar%20gyle/teams/search?q=pkg%20readers%26x%3D1&limit=50"
        );
        assert_eq!(
            team_member_url("https://g.test/api/v1/", 3, "a/b"),
            "https://g.test/api/v1/teams/3/members/a%2Fb"
        );
        assert_eq!(
            delete_token_url("https://g.test/api/v1/", "pkg-bot", "ci 1"),
            "https://g.test/api/v1/users/pkg-bot/tokens/ci%201"
        );
    }

    #[test]
    fn credentials_go_only_over_https_or_loopback() {
        assert!(require_secure_url("https://g.test/api/v1/x").is_ok());
        assert!(require_secure_url("http://127.0.0.1:3000/api/v1/x").is_ok());
        assert!(require_secure_url("http://localhost/api").is_ok());
        assert!(require_secure_url("http://[::1]:3000/api").is_ok());
        assert!(require_secure_url("http://g.test/api").is_err());
        assert!(require_secure_url("http://10.0.0.5:3000/api").is_err());
    }

    #[test]
    fn rotate_helpers() {
        assert_eq!(
            change_password_args("b", "pw").join(" "),
            "admin user change-password --username b --password pw --must-change-password=false"
        );
        assert_eq!(
            basic_auth("Aladdin", "open sesame"),
            "Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ=="
        );
        assert_eq!(basic_auth("a", "b"), "Basic YTpi");
        let pw = random_password().unwrap();
        assert_eq!(pw.len(), 48);
        assert_ne!(pw, random_password().unwrap());
    }

    #[test]
    fn errors_are_scrubbed() {
        let s = scrub("failed: Authorization: token 0123456789abcdef0123456789abcdef01234567");
        assert!(
            !s.contains("0123456789abcdef0123456789abcdef01234567"),
            "{s}"
        );
    }

    #[tokio::test]
    async fn dry_runs_without_admin_caller_are_refused() {
        let ctx = plugin_toolkit::tool_manifest::minimal_ctx();
        for (tool, args) in [
            (
                "gitea.bot.create",
                json!({"endpoint": "e", "username": "b", "email": "b@x.test", "dry_run": true}),
            ),
            (
                "gitea.token.create",
                json!({"endpoint": "e", "username": "b", "token_name": "t", "scopes": ["read:package"], "dry_run": true}),
            ),
        ] {
            let err = plugin_toolkit::dispatch::dispatch(tool, args, &ctx)
                .await
                .unwrap_err()
                .to_string();
            assert!(err.contains("caller identity"), "{err}");
        }
    }
}
