//! Dual-substrate Gitea deploy — the hard requirement.
//!
//! `gitea.deploy(substrate = "lxc" | "docker", spec)` dispatches to a
//! [`GiteaSubstrate`] provider:
//!   - **LXC** provider drives the proxmox plugin (create LXC, nesting) then
//!     configures Gitea + Postgres inside it.
//!   - **Docker** provider drives the docker/dockge plugin to bring up the
//!     `gitea/gitea` + `postgres` compose stack.
//!
//! Both funnel backup/restore through the SAME `gitea dump` (see
//! [`crate::backup`]) so archives are portable between substrates — which also
//! makes LXC↔Docker migration a backup+restore.
//!
//! This module defines the substrate abstraction and the `gitea.deploy` tool.
//! Provider internals that shell out to peer plugins are driven over the mesh
//! via `plugin.invoke` and are filled in incrementally; the trait + dispatch +
//! spec validation are the stable seam.

use plugin_toolkit::prelude::*;

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
        // Full implementation drives `proxmox.post_create_vm_nodes_node_lxc`
        // (nesting=1,keyctl=1) via `plugin.invoke`, then configures Gitea +
        // Postgres inside. Tracked as the next deploy milestone.
        Ok(DeployOutcome {
            substrate: "lxc".to_string(),
            host: spec.host.clone(),
            name: spec.name.clone(),
            base_url: spec.root_url.clone(),
            notes: vec![
                "lxc substrate selected".to_string(),
                "provision via proxmox plugin (pct create nesting) — pending wiring".to_string(),
            ],
        })
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
        // Full implementation deploys the `gitea/gitea` + `postgres` compose
        // stack via the dockge/docker plugin. Tracked as the next milestone.
        Ok(DeployOutcome {
            substrate: "docker".to_string(),
            host: spec.host.clone(),
            name: spec.name.clone(),
            base_url: spec.root_url.clone(),
            notes: vec![
                "docker substrate selected".to_string(),
                "deploy gitea+postgres compose via dockge plugin — pending wiring".to_string(),
            ],
        })
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

/// Deploy Gitea onto the chosen substrate. `role = "admin"` — this creates
/// infrastructure.
#[orca_tool(
    domain = "gitea",
    verb = "deploy",
    data_mutation = true,
    role = "admin"
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
}
