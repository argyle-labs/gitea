//! Dual-substrate Gitea deploy — the hard requirement.
//!
//! `gitea.deploy(substrate = "lxc" | "docker", spec)` dispatches to a
//! [`GiteaSubstrate`] provider:
//!   - **LXC** provider drives the proxmox plugin (create LXC, nesting) then
//!     configures Gitea + Postgres inside it.
//!   - **Docker** provider drives the docker/dockge plugin to bring up the
//!     `gitea/gitea` + `postgres` compose stack.
//!
//! Backup/restore is meant to funnel both substrates through the SAME
//! `gitea dump` so archives are portable and LXC↔Docker migration is a
//! backup+restore; it is not implemented yet (see [`crate::backup`]).
//!
//! Neither provider can run yet, so `gitea.deploy` refuses with a "not
//! implemented" error; the missing pieces are listed in [`LXC_MISSING`] and
//! [`DOCKER_MISSING`].

use plugin_toolkit::prelude::*;

const LXC_MISSING: &str = "plugin-toolkit has no seam for a plugin tool to invoke another \
     plugin's tools, so the proxmox plugin cannot be driven to create the LXC; \
     orca's lxc-exec seam does not allow the commands that set up Postgres and Gitea \
     (psql, useradd, the gitea binary), and its push seam caps a file at 8 MiB, too small \
     for the Gitea binary; nothing registers the new instance as an endpoint";

const DOCKER_MISSING: &str = "plugin-toolkit has no seam for a plugin tool to invoke another \
     plugin's tools, so the docker/dockge plugin cannot be driven to bring up the \
     gitea/gitea + postgres compose stack; nothing registers the new instance as an endpoint";

/// Which substrate hosts the Gitea application.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum Substrate {
    Lxc,
    Docker,
}

impl std::str::FromStr for Substrate {
    type Err = crate::GiteaError;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "lxc" | "container" | "pct" => Ok(Substrate::Lxc),
            "docker" | "compose" => Ok(Substrate::Docker),
            other => Err(crate::GiteaError::BadSubstrate(other.to_string())),
        }
    }
}

/// Declarative deploy spec — substrate-agnostic. The provider maps these onto
/// substrate-native primitives (pct create args / compose service env).
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct DeploySpec {
    /// Where the substrate itself lives — a proxmox node name (lxc) or a docker
    /// host / dockge endpoint (docker).
    pub host: String,
    /// Desired hostname / container name.
    #[serde(default = "default_name")]
    pub name: String,
    /// Static IP in CIDR form for the LXC substrate (ignored for docker, which
    /// uses the compose network).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip_cidr: Option<String>,
    /// Gitea `ROOT_URL` (e.g. `https://gitea.example/`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root_url: Option<String>,
    /// Gitea image/version tag to deploy (docker) or binary version (lxc).
    #[serde(default = "default_version")]
    pub version: String,
}

fn default_name() -> String {
    "gitea".to_string()
}
fn default_version() -> String {
    "latest".to_string()
}

/// Outcome of a deploy: what was created and where to reach it.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct DeployOutcome {
    pub substrate: String,
    pub host: String,
    pub name: String,
    /// Best-effort reachable base URL once the instance is up.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base_url: Option<String>,
    /// Human-readable steps taken / next steps.
    pub notes: Vec<String>,
}

/// The provider contract each substrate implements. Kept object-safe so
/// [`dispatch`] can hold a `Box<dyn GiteaSubstrate>`.
#[plugin_toolkit::async_trait::async_trait]
pub trait GiteaSubstrate: Send + Sync {
    fn kind(&self) -> Substrate;
    async fn provision(&self, spec: &DeploySpec) -> Result<DeployOutcome>;
}

/// LXC substrate — drives the proxmox plugin over the mesh.
pub struct LxcSubstrate;

#[plugin_toolkit::async_trait::async_trait]
impl GiteaSubstrate for LxcSubstrate {
    fn kind(&self) -> Substrate {
        Substrate::Lxc
    }
    async fn provision(&self, spec: &DeploySpec) -> Result<DeployOutcome> {
        bail!(
            "gitea.deploy lxc {} on {}: not implemented: {LXC_MISSING}",
            spec.name,
            spec.host
        )
    }
}

/// Docker substrate — drives the docker/dockge plugin over the mesh.
pub struct DockerSubstrate;

#[plugin_toolkit::async_trait::async_trait]
impl GiteaSubstrate for DockerSubstrate {
    fn kind(&self) -> Substrate {
        Substrate::Docker
    }
    async fn provision(&self, spec: &DeploySpec) -> Result<DeployOutcome> {
        bail!(
            "gitea.deploy docker {} on {}: not implemented: {DOCKER_MISSING}",
            spec.name,
            spec.host
        )
    }
}

/// Build the provider for a substrate.
pub fn provider_for(substrate: Substrate) -> Box<dyn GiteaSubstrate> {
    match substrate {
        Substrate::Lxc => Box::new(LxcSubstrate),
        Substrate::Docker => Box::new(DockerSubstrate),
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// gitea.deploy — substrate-agnostic deploy verb.
// ═══════════════════════════════════════════════════════════════════════════

#[derive(clap::Args, Serialize, Deserialize, JsonSchema)]
pub struct GiteaDeployArgs {
    /// Substrate to deploy on: `lxc` or `docker`.
    #[arg(long)]
    pub substrate: String,
    /// Substrate host — a proxmox node (lxc) or docker/dockge endpoint (docker).
    #[arg(long)]
    pub host: String,
    /// Instance name / hostname.
    #[arg(long, default_value = "gitea")]
    pub name: String,
    /// Static IP in CIDR form (lxc only).
    #[arg(long)]
    pub ip_cidr: Option<String>,
    /// Gitea ROOT_URL.
    #[arg(long)]
    pub root_url: Option<String>,
    /// Gitea version / image tag.
    #[arg(long, default_value = "latest")]
    pub version: String,
}

/// Deploy Gitea onto the chosen substrate. Always fails until the pieces in
/// [`LXC_MISSING`] / [`DOCKER_MISSING`] exist. `role = "admin"`.
#[orca_tool(
    domain = "gitea",
    verb = "deploy",
    data_mutation = true,
    role = "admin",
    // Ungated so a dry run errors instead of previewing a run that cannot
    // happen. Restore the gate once a provider is implemented.
    execute_gated = false
)]
pub async fn gitea_deploy(args: GiteaDeployArgs, _ctx: &ToolCtx) -> Result<DeployOutcome> {
    let substrate: Substrate = args.substrate.parse()?;
    let spec = DeploySpec {
        host: args.host,
        name: args.name,
        ip_cidr: args.ip_cidr,
        root_url: args.root_url,
        version: args.version,
    };
    provider_for(substrate).provision(&spec).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn substrate_parses_aliases() {
        assert_eq!("lxc".parse::<Substrate>().unwrap(), Substrate::Lxc);
        assert_eq!("pct".parse::<Substrate>().unwrap(), Substrate::Lxc);
        assert_eq!("docker".parse::<Substrate>().unwrap(), Substrate::Docker);
        assert_eq!("compose".parse::<Substrate>().unwrap(), Substrate::Docker);
        assert!("k8s".parse::<Substrate>().is_err());
    }

    async fn dispatch_err(args: plugin_toolkit::serde_json::Value) -> String {
        let ctx = plugin_toolkit::tool_manifest::minimal_ctx();
        match plugin_toolkit::dispatch::dispatch("gitea.deploy", args, &ctx).await {
            Ok(out) => panic!("gitea.deploy reported success without doing the work: {out}"),
            Err(e) => e.to_string(),
        }
    }

    #[tokio::test]
    async fn deploy_fails_honestly_on_every_substrate() {
        for (substrate, want) in [
            ("lxc", "gitea.deploy lxc"),
            ("docker", "gitea.deploy docker"),
        ] {
            for execute in [false, true] {
                let err = dispatch_err(plugin_toolkit::serde_json::json!({
                    "substrate": substrate,
                    "host": "pve",
                    "name": "gitea",
                    "root_url": "https://gitea.example/",
                    "version": "latest",
                    "execute": execute,
                }))
                .await;
                assert!(err.contains(want), "{err}");
                assert!(err.contains("not implemented"), "{err}");
            }
        }
    }

    #[tokio::test]
    async fn providers_never_return_ok() {
        let spec = DeploySpec {
            host: "pve".into(),
            name: "gitea".into(),
            ip_cidr: None,
            root_url: Some("https://gitea.example/".into()),
            version: "latest".into(),
        };
        for substrate in [Substrate::Lxc, Substrate::Docker] {
            let p = provider_for(substrate);
            assert_eq!(p.kind(), substrate);
            assert!(p.provision(&spec).await.is_err(), "{substrate:?}");
        }
    }

    #[test]
    fn deploy_requires_admin() {
        assert_eq!(
            plugin_toolkit::dispatch::required_role("gitea.deploy"),
            Some("admin")
        );
    }
}
