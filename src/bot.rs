use std::collections::BTreeMap;

use plugin_toolkit::contract::plan::{ExecutionPlan, PlannedChange};
use plugin_toolkit::prelude::*;
use plugin_toolkit::secrets::SecretRef;

use crate::Config;
use crate::runner::api::{status_error, verified_client};
use crate::runner::host::LocalHost;
use crate::runner::tools::authorize_execute;
use crate::signing::ini_get;

const DEFAULT_APP_INI: &str = "/etc/gitea/app.ini";
const DEFAULT_BINARY: &str = "gitea";
const DEFAULT_RUN_USER: &str = "git";

fn default_app_ini() -> String {
    DEFAULT_APP_INI.into()
}
fn default_binary() -> String {
    DEFAULT_BINARY.into()
}

pub struct GiteaCli {
    pub binary: String,
    pub app_ini: String,
    pub run_user: String,
    pub as_root: bool,
}

impl GiteaCli {
    fn load(binary: &str, app_ini: &str, host: &LocalHost) -> Result<Self> {
        let ini = std::fs::read_to_string(app_ini).with_context(|| format!("read {app_ini}"))?;
        Ok(Self {
            binary: binary.to_string(),
            app_ini: app_ini.to_string(),
            run_user: ini_get(&ini, "", "RUN_USER").unwrap_or_else(|| DEFAULT_RUN_USER.into()),
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
                out.stderr
            );
        }
        Ok(out.stdout)
    }
}

pub fn list_users_args() -> Vec<String> {
    ["admin", "user", "list"].map(String::from).to_vec()
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

pub fn listed_usernames(out: &str) -> Vec<String> {
    out.lines()
        .skip_while(|l| !l.trim_start().starts_with("ID"))
        .skip(1)
        .filter_map(|l| {
            let mut cols = l.split_whitespace();
            cols.next()?.parse::<i64>().ok()?;
            cols.next().map(str::to_string)
        })
        .collect()
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
            match access {
                "none" | "read" | "write" | "admin" => {}
                other => bail!("team unit access must be none|read|write|admin, not '{other}'"),
            }
            Ok((unit.trim().to_string(), access.to_string()))
        })
        .collect()
}

fn validate_scopes(scopes: &[String]) -> Result<()> {
    if scopes.is_empty() {
        bail!("at least one scope is required");
    }
    if let Some(bad) = scopes
        .iter()
        .find(|s| s.is_empty() || s.contains(',') || s.contains(char::is_whitespace))
    {
        bail!("invalid scope '{bad}'");
    }
    Ok(())
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
    #[arg(long, default_value = DEFAULT_APP_INI)]
    #[serde(default = "default_app_ini")]
    pub app_ini: String,
    #[arg(long, default_value = DEFAULT_BINARY)]
    #[serde(default = "default_binary")]
    pub binary: String,
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
}

async fn find_team(cfg: &Config, org: &str, team: &str) -> Result<Option<i64>> {
    #[derive(Deserialize)]
    struct Search {
        data: Vec<Team>,
    }
    let url = format!(
        "{}/orgs/{org}/teams/search?q={team}&limit=50",
        cfg.base_url.trim_end_matches('/')
    );
    let resp = verified_client(cfg)?
        .get(url)
        .send()
        .await
        .map_err(|e| anyhow!("search teams: {e}"))?;
    let status = resp.status().as_u16();
    let body = resp.text().await.unwrap_or_default();
    if !(200..300).contains(&status) {
        return Err(status_error("search teams", status, &body));
    }
    let found: Search = plugin_toolkit::serde_json::from_str(&body)?;
    Ok(found
        .data
        .into_iter()
        .find(|t| t.name.eq_ignore_ascii_case(team))
        .map(|t| t.id))
}

pub fn team_body(
    team: &str,
    units: &BTreeMap<String, String>,
) -> plugin_toolkit::serde_json::Value {
    json!({
        "name": team,
        "permission": "read",
        "includes_all_repositories": false,
        "can_create_org_repo": false,
        "units": units.keys().collect::<Vec<_>>(),
        "units_map": units,
    })
}

async fn send(what: &str, req: plugin_toolkit::reqwest::RequestBuilder) -> Result<String> {
    let resp = req.send().await.map_err(|e| anyhow!("{what}: {e}"))?;
    let status = resp.status().as_u16();
    let body = resp.text().await.unwrap_or_default();
    if !(200..300).contains(&status) {
        return Err(status_error(what, status, &body));
    }
    Ok(body)
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
        Some(id) => {
            if !units.is_empty() {
                send(
                    "update team",
                    client.patch(format!("{base}/teams/{id}")).json(&body),
                )
                .await?;
            }
            Ok((id, format!("team {org}/{team} units set")))
        }
        None => {
            let created = send(
                "create team",
                client.post(format!("{base}/orgs/{org}/teams")).json(&body),
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
    let units = parse_units(&args.team_units)?;
    let team = match (&args.org, &args.team) {
        (Some(o), Some(t)) => Some((o.clone(), t.clone())),
        (None, None) if units.is_empty() => None,
        _ => bail!("org and team go together, and team units need both"),
    };
    let host = LocalHost::current()?;
    let cli = GiteaCli::load(&args.binary, &args.app_ini, &host)?;
    let existed = listed_usernames(&cli.run(&host, &list_users_args()).await?)
        .iter()
        .any(|u| u.eq_ignore_ascii_case(&args.username));
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
                "create or update the team with units {units:?} and add {}",
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
        let cfg = crate::tools::resolve_config(&args.endpoint).await?;
        let (id, did) = ensure_team(&cfg, org, t, &units).await?;
        applied.push(did);
        let url = format!(
            "{}/teams/{id}/members/{}",
            cfg.base_url.trim_end_matches('/'),
            args.username
        );
        send("add team member", verified_client(&cfg)?.put(url)).await?;
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
    pub username: String,
    #[arg(long)]
    pub token_name: String,
    #[arg(long = "scope", required = true)]
    pub scopes: Vec<String>,
    #[arg(long)]
    pub secret_name: String,
    #[arg(long, default_value = DEFAULT_APP_INI)]
    #[serde(default = "default_app_ini")]
    pub app_ini: String,
    #[arg(long, default_value = DEFAULT_BINARY)]
    #[serde(default = "default_binary")]
    pub binary: String,
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
    validate_scopes(&args.scopes)?;
    let host = LocalHost::current()?;
    let cli = GiteaCli::load(&args.binary, &args.app_ini, &host)?;
    let secret_name = args.secret_name.clone();
    let existing = tokio::task::spawn_blocking(move || plugin_toolkit::secrets::get(&secret_name))
        .await??
        .is_some();
    let change = if existing {
        PlannedChange::new(format!("secret {}", args.secret_name), "keep")
            .with_detail("orca secret already holds a token; nothing is created")
    } else {
        PlannedChange::new(
            format!("token {}/{}", args.username, args.token_name),
            "create",
        )
        .with_detail(format!(
            "scopes {}; value stored only in orca secret '{}'",
            args.scopes.join(","),
            args.secret_name
        ))
    };
    let plan = ExecutionPlan::generic(TOOL, plugin_toolkit::serde_json::to_value(&args)?.into())
        .detailed(
            format!("access token for Gitea user {}", args.username),
            vec![change],
        );
    if args.dry_run || existing {
        return Ok(TokenCreateOutput {
            dry_run: args.dry_run,
            plan,
            secret: existing.then(|| SecretRef(args.secret_name.clone())),
            created: false,
        });
    }
    let out = cli
        .run(
            &host,
            &generate_token_args(&args.username, &args.token_name, &args.scopes),
        )
        .await?;
    let token = parse_raw_token(&out)?;
    let (name, desc) = (
        args.secret_name.clone(),
        format!("Gitea access token {}/{}", args.username, args.token_name),
    );
    let secret = tokio::task::spawn_blocking(move || {
        plugin_toolkit::secrets::set(&name, &token, Some(&desc))
    })
    .await??;
    Ok(TokenCreateOutput {
        dry_run: false,
        plan,
        secret: Some(secret),
        created: true,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cli(as_root: bool) -> GiteaCli {
        GiteaCli {
            binary: "gitea".into(),
            app_ini: "/etc/gitea/app.ini".into(),
            run_user: "git".into(),
            as_root,
        }
    }

    #[test]
    fn root_runs_cli_as_run_user() {
        assert_eq!(
            cli(true).argv(&list_users_args()).join(" "),
            "runuser -u git -- gitea --config /etc/gitea/app.ini admin user list"
        );
        assert_eq!(
            cli(false).argv(&list_users_args()).join(" "),
            "gitea --config /etc/gitea/app.ini admin user list"
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
            "ci",
            &["read:package".into(), "read:user".into()],
        );
        assert_eq!(
            a.join(" "),
            "admin user generate-access-token --username pkg-bot --token-name ci --scopes read:package,read:user --raw"
        );
    }

    #[test]
    fn parses_user_list_table() {
        let out = "ID   Username  Email           IsActive IsAdmin 2FA\n1    root      r@x.test        true     true    false\n7    pkg-bot   p@x.test        true     false   false";
        assert_eq!(listed_usernames(out), ["root", "pkg-bot"]);
        assert!(listed_usernames("").is_empty());
    }

    #[test]
    fn parses_raw_token_and_rejects_noise() {
        let t = "0123456789abcdef0123456789abcdef01234567";
        assert_eq!(parse_raw_token(&format!("{t}\n")).unwrap(), t);
        assert!(parse_raw_token("").is_err());
        assert!(parse_raw_token("access token was successfully created").is_err());
    }

    #[test]
    fn parses_team_units() {
        let u = parse_units(&["repo.packages=read".into()]).unwrap();
        assert_eq!(u.get("repo.packages").map(String::as_str), Some("read"));
        assert!(parse_units(&["repo.packages".into()]).is_err());
        assert!(parse_units(&["repo.packages=owner".into()]).is_err());
        let body = team_body("readers", &u);
        assert_eq!(body["units_map"]["repo.packages"], "read");
        assert_eq!(body["units"][0], "repo.packages");
    }

    #[test]
    fn rejects_bad_scopes() {
        assert!(validate_scopes(&[]).is_err());
        assert!(validate_scopes(&["read:package,write:user".into()]).is_err());
        assert!(validate_scopes(&["read:package".into()]).is_ok());
    }

    #[tokio::test]
    async fn dry_runs_without_admin_caller_are_refused() {
        let ctx = plugin_toolkit::tool_manifest::minimal_ctx();
        for (tool, args) in [
            (
                "gitea.bot.create",
                json!({"endpoint": "e", "username": "b", "email": "b@x", "dry_run": true}),
            ),
            (
                "gitea.token.create",
                json!({"username": "b", "token_name": "t", "scopes": ["read:package"], "secret_name": "s", "dry_run": true}),
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
