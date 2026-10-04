//! Gitea tool surface.
//!
//! Endpoint registry: `gitea.{list, detail, create, update, delete}` — generated
//! wholesale by `#[endpoint_resource]`. The macro emits the row struct, db
//! helpers (`endpoint_db::*`), schema fragment, args/output types, and the five
//! `#[orca_tool]`-annotated functions in one shot.
//!
//! [`make_client`] is the contract the auto-generated `gitea.*` surface calls:
//! every surfaced tool takes an `endpoint` arg and resolves it here into a ready
//! typed client.
//!
//! Imports flow through `plugin_toolkit::prelude::*` only.

use plugin_toolkit::prelude::*;

use crate::Config;
use crate::generated;

// ═══════════════════════════════════════════════════════════════════════════
// gitea.{list,detail,create,update,delete} — endpoint registry CRUD.
// ═══════════════════════════════════════════════════════════════════════════

// `routes` is a built-in column on every `#[endpoint_resource]` — an ordered
// fallback list (`--route kind=url`, repeatable) resolved by
// `route::resolve_reachable`. Each entry's free-form `kind` (`fqdn` / `lan` /
// `tailscale`) doubles as the locality class the fewest-hop router consumes.
#[endpoint_resource(plugin = "gitea")]
pub struct GiteaEndpoint {
    pub name: String,
    #[secret]
    pub token: String,
    pub insecure: bool,
    pub enabled: bool,
}

// ── secret resolution ──────────────────────────────────────────────────────

fn resolve_token(name: &str, row: &GiteaEndpoint) -> Result<String> {
    plugin_toolkit::secrets::resolve_scoped(
        "gitea",
        name,
        "token",
        (!row.token.is_empty()).then_some(row.token.as_str()),
    )
}

// ── client resolution ──────────────────────────────────────────────────────

/// Resolve a registered endpoint into a ready [`Config`]: the first reachable
/// base URL (`resolve_reachable` over the endpoint's `routes` fallback list)
/// promoted to the Gitea API root (`.../api/v1`), plus the secure-first token.
pub(crate) async fn resolve_config(name: &str) -> Result<Config> {
    let row = endpoint_db::require(name)?;
    let token = resolve_token(name, &row)?;
    let reachable = route::resolve_reachable(name, &row.routes, row.insecure).await?;
    let base_url = api_root(&reachable);
    Ok(Config::new(base_url, token).insecure(row.insecure))
}

/// `scheme://host[:port]` of every enabled route registered for endpoint `name`.
pub(crate) fn endpoint_route_urls(name: &str) -> Result<Vec<String>> {
    let row = endpoint_db::require(name)?;
    Ok(row.routes.enabled().filter_map(|r| r.base_url()).collect())
}

/// Promote a bare Gitea host URL to its REST API root (`.../api/v1`), leaving a
/// URL that already carries the suffix untouched.
fn api_root(base: &str) -> String {
    let trimmed = base.trim_end_matches('/');
    if trimmed.ends_with("/api/v1") {
        trimmed.to_string()
    } else {
        format!("{trimmed}/api/v1")
    }
}

/// The contract the auto-generated `gitea.*` surface calls: resolve an endpoint
/// name into a ready typed client.
pub(crate) async fn make_client(name: &str) -> Result<generated::Client> {
    Ok(resolve_config(name).await?.build_generated_client()?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn api_root_appends_suffix_once() {
        assert_eq!(api_root("https://gitea.test"), "https://gitea.test/api/v1");
        assert_eq!(api_root("https://gitea.test/"), "https://gitea.test/api/v1");
        assert_eq!(
            api_root("https://gitea.test/api/v1"),
            "https://gitea.test/api/v1"
        );
    }
}
