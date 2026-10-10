//! Dual-substrate Gitea deploy.
//!
//! `gitea.deploy(substrate = "lxc" | "docker", spec)` dispatches to a
//! [`GiteaSubstrate`] provider. The LXC provider is meant to drive the proxmox
//! plugin (create LXC, nesting) then configure Gitea + Postgres inside it; the
//! Docker provider is meant to drive the docker/dockge plugin to bring up the
//! `gitea/gitea` + `postgres` compose stack.
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
     (psql, useradd, the gitea binary); plugin-toolkit exposes no push seam, and orca's \
     caps a file at 8 MiB, too small for the Gitea binary; nothing registers the new instance as an endpoint";

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

impl DeploySpec {
    /// Reject a spec no provider could honor, before any provider runs.
    pub fn validate(&self, substrate: Substrate) -> Result<()> {
        if self.host.trim().is_empty() {
            bail!("host is empty");
        }
        let n = &self.name;
        let label_ok = (1..=63).contains(&n.len())
            && n.bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            && !n.starts_with('-')
            && !n.ends_with('-');
        if !label_ok {
            bail!(
                "name `{n}` is not a hostname label (1-63 of a-z, 0-9, '-'; no leading/trailing '-')"
            );
        }
        if self.version.trim().is_empty() || self.version.contains(char::is_whitespace) {
            bail!("version `{}` is empty or contains whitespace", self.version);
        }
        if let Some(url) = &self.root_url
            && (!(url.starts_with("https://") || url.starts_with("http://")) || !url.ends_with('/'))
        {
            bail!("root_url `{url}` must be http(s):// and end with '/'");
        }
        if let Some(cidr) = &self.ip_cidr {
            if substrate != Substrate::Lxc {
                bail!("ip_cidr applies to the lxc substrate only");
            }
            let (ip, prefix) = cidr
                .split_once('/')
                .ok_or_else(|| anyhow!("ip_cidr `{cidr}` has no /prefix"))?;
            let ip: std::net::IpAddr = ip
                .parse()
                .map_err(|_| anyhow!("ip_cidr `{cidr}`: `{ip}` is not an IP address"))?;
            let max = if ip.is_ipv4() { 32 } else { 128 };
            match prefix.parse::<u8>() {
                Ok(p) if p <= max => {}
                _ => bail!("ip_cidr `{cidr}`: prefix must be 0-{max}"),
            }
        }
        Ok(())
    }
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

/// LXC substrate. Not implemented; see [`LXC_MISSING`].
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

/// Docker substrate. Not implemented; see [`DOCKER_MISSING`].
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
    #[serde(default = "default_name")]
    pub name: String,
    /// Static IP in CIDR form (lxc only).
    #[arg(long)]
    pub ip_cidr: Option<String>,
    /// Gitea ROOT_URL.
    #[arg(long)]
    pub root_url: Option<String>,
    /// Gitea version / image tag.
    #[arg(long, default_value = "latest")]
    #[serde(default = "default_version")]
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
    // happen. Re-enable the gate once a provider is implemented.
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
    spec.validate(substrate)
        .with_context(|| format!("gitea.deploy {}: invalid spec", spec.name))?;
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

    fn spec() -> DeploySpec {
        DeploySpec {
            host: "pve".into(),
            name: "gitea".into(),
            ip_cidr: Some("10.0.0.5/24".into()),
            root_url: Some("https://gitea.example/".into()),
            version: "1.22.0".into(),
        }
    }

    #[test]
    fn valid_spec_passes() {
        spec().validate(Substrate::Lxc).unwrap();
        DeploySpec {
            ip_cidr: None,
            ..spec()
        }
        .validate(Substrate::Docker)
        .unwrap();
    }

    #[test]
    fn invalid_specs_are_rejected() {
        let bad = [
            DeploySpec {
                host: " ".into(),
                ..spec()
            },
            DeploySpec {
                name: "Gitea".into(),
                ..spec()
            },
            DeploySpec {
                name: "-gitea".into(),
                ..spec()
            },
            DeploySpec {
                name: "a".repeat(64),
                ..spec()
            },
            DeploySpec {
                version: "1.22 rc".into(),
                ..spec()
            },
            DeploySpec {
                root_url: Some("https://gitea.example".into()),
                ..spec()
            },
            DeploySpec {
                root_url: Some("gitea.example/".into()),
                ..spec()
            },
            DeploySpec {
                ip_cidr: Some("10.0.0.5".into()),
                ..spec()
            },
            DeploySpec {
                ip_cidr: Some("10.0.0.5/33".into()),
                ..spec()
            },
            DeploySpec {
                ip_cidr: Some("10.0.0.300/24".into()),
                ..spec()
            },
        ];
        for s in bad {
            assert!(s.validate(Substrate::Lxc).is_err(), "{s:?}");
        }
        assert!(
            spec().validate(Substrate::Docker).is_err(),
            "ip_cidr is lxc-only"
        );
    }

    #[tokio::test]
    async fn invalid_spec_fails_before_the_provider() {
        let err = dispatch_err(plugin_toolkit::serde_json::json!({
            "substrate": "lxc",
            "host": "pve",
            "name": "Bad_Name",
        }))
        .await;
        assert!(err.contains("invalid spec"), "{err}");
    }

    #[tokio::test]
    async fn json_callers_get_the_cli_defaults() {
        let err = dispatch_err(plugin_toolkit::serde_json::json!({
            "substrate": "docker",
            "host": "pve",
        }))
        .await;
        assert!(
            err.contains("gitea.deploy docker gitea on pve: not implemented"),
            "{err}"
        );
    }

    #[test]
    fn deploy_requires_admin() {
        assert_eq!(
            plugin_toolkit::dispatch::required_role("gitea.deploy"),
            Some("admin")
        );
    }
}
