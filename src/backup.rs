//! Substrate-portable Gitea backup/restore, wrapping `gitea dump`.
//!
//! `gitea dump` produces a single app-consistent archive (DB + repos + LFS +
//! config) that restores into EITHER substrate — so a dump taken from an LXC
//! deploy imports into a Docker deploy and vice-versa. That portability is why
//! both substrate providers funnel through this one path.
//!
//! `gitea.backup` / `gitea.restore` are the orca-facing verbs; they wire into
//! orca's backup contract. The archive lives on the target host under a
//! configurable directory (default `/var/lib/gitea/backups`).

use plugin_toolkit::prelude::*;

const DEFAULT_BACKUP_DIR: &str = "/var/lib/gitea/backups";

#[derive(clap::Args, Serialize, Deserialize, JsonSchema)]
pub struct GiteaBackupArgs {
    /// Registered endpoint whose instance to back up.
    #[arg(long)]
    pub endpoint: String,
    /// Directory on the target host to write the dump into.
    #[arg(long, default_value = DEFAULT_BACKUP_DIR)]
    pub dir: String,
}

#[derive(Serialize, Deserialize, JsonSchema)]
pub struct GiteaBackupResult {
    pub endpoint: String,
    /// Path to the produced archive on the target host.
    pub archive: String,
    pub notes: Vec<String>,
}

/// Produce an app-consistent `gitea dump` archive on the target host.
/// `role = "admin"`.
#[orca_tool(
    domain = "gitea",
    verb = "backup",
    data_mutation = true,
    role = "admin"
)]
pub async fn gitea_backup(args: GiteaBackupArgs, _ctx: &ToolCtx) -> Result<GiteaBackupResult> {
    // Full implementation invokes `gitea dump` on the substrate (pct exec for
    // lxc, docker exec for docker) via the owning plugin over `plugin.invoke`,
    // then reports the archive path. The verb + contract shape are the stable
    // seam; execution wiring lands with the substrate providers.
    let archive = format!("{}/gitea-dump-<ts>.tar.zst", args.dir.trim_end_matches('/'));
    Ok(GiteaBackupResult {
        endpoint: args.endpoint,
        archive,
        notes: vec![
            "gitea dump (DB + repos + LFS + config) — portable across substrates".to_string(),
            "execution wiring via plugin.invoke pending".to_string(),
        ],
    })
}

#[derive(clap::Args, Serialize, Deserialize, JsonSchema)]
pub struct GiteaRestoreArgs {
    /// Registered endpoint whose instance to restore into.
    #[arg(long)]
    pub endpoint: String,
    /// Path to the `gitea dump` archive on the target host.
    #[arg(long)]
    pub archive: String,
}

#[derive(Serialize, Deserialize, JsonSchema)]
pub struct GiteaRestoreResult {
    pub endpoint: String,
    pub archive: String,
    pub notes: Vec<String>,
}

/// Restore a `gitea dump` archive into the endpoint's instance (any substrate).
/// `role = "admin"`.
#[orca_tool(
    domain = "gitea",
    verb = "restore",
    data_mutation = true,
    role = "admin"
)]
pub async fn gitea_restore(args: GiteaRestoreArgs, _ctx: &ToolCtx) -> Result<GiteaRestoreResult> {
    Ok(GiteaRestoreResult {
        endpoint: args.endpoint,
        archive: args.archive,
        notes: vec![
            "restore unpacks DB + repos + LFS + config into the target".to_string(),
            "execution wiring via plugin.invoke pending".to_string(),
        ],
    })
}
