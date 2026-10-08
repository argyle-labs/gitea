//! `gitea.backup` / `gitea.restore` — app-consistent `gitea dump` backup and
//! restore, portable across the lxc and docker substrates.
//!
//! Neither verb can run yet, so both refuse with a "not implemented" error and
//! never report success or an archive path. Missing pieces (gitea#7, gitea#9):
//! - an endpoint → substrate binding: a registered endpoint is a URL + token,
//!   with no record of which LXC vmid or docker container runs the instance;
//! - in-guest exec of `gitea`: orca's privileged lxc-exec seam allowlists only
//!   package/service/read-only diagnostic commands, caps a run at 300s, and has
//!   no way to pull an archive out of the guest;
//! - a backup target: the plugin registers no `BackupKindPlugin`, so there is
//!   no off-rootfs destination to write the dump to, nor a stored sha256 to
//!   verify before a restore.

use plugin_toolkit::prelude::*;

const BACKUP_MISSING: &str = "no endpoint → substrate (LXC vmid / docker container) binding; \
     orca's lxc-exec seam does not allow `gitea dump` and cannot copy an archive out of the guest; \
     no `gitea` BackupKindPlugin to write the dump to a backup target with a sha256 checksum \
     (gitea#7, gitea#9)";

const RESTORE_MISSING: &str = "no endpoint → substrate (LXC vmid / docker container) binding; \
     no seam to push a dump archive into the guest and run the multi-step restore; \
     no `gitea` BackupKindPlugin holding a sha256 checksum to verify the archive against \
     (gitea#7, gitea#9)";

#[derive(clap::Args, Serialize, Deserialize, JsonSchema)]
pub struct GiteaBackupArgs {
    /// Registered endpoint whose instance to back up.
    #[arg(long)]
    pub endpoint: String,
}

#[derive(Serialize, Deserialize, JsonSchema)]
pub struct GiteaBackupResult {
    pub endpoint: String,
    /// Path to the produced archive on the backup target.
    pub archive: String,
}

/// Produce an app-consistent `gitea dump` archive. Always fails until the
/// pieces in [`BACKUP_MISSING`] exist. `role = "admin"`.
#[orca_tool(
    domain = "gitea",
    verb = "backup",
    data_mutation = true,
    role = "admin",
    // The default dry-run preview would say the verb "would run"; it cannot.
    execute_gated = false
)]
pub async fn gitea_backup(args: GiteaBackupArgs, _ctx: &ToolCtx) -> Result<GiteaBackupResult> {
    bail!(
        "gitea.backup {}: not implemented: {BACKUP_MISSING}",
        args.endpoint
    )
}

#[derive(clap::Args, Serialize, Deserialize, JsonSchema)]
pub struct GiteaRestoreArgs {
    /// Registered endpoint whose instance to restore into.
    #[arg(long)]
    pub endpoint: String,
    /// Path to the `gitea dump` archive on the backup target.
    #[arg(long)]
    pub archive: String,
}

#[derive(Serialize, Deserialize, JsonSchema)]
pub struct GiteaRestoreResult {
    pub endpoint: String,
    pub archive: String,
}

/// Restore a `gitea dump` archive into the endpoint's instance. Always fails
/// until the pieces in [`RESTORE_MISSING`] exist. `role = "admin"`.
#[orca_tool(
    domain = "gitea",
    verb = "restore",
    data_mutation = true,
    role = "admin",
    // The default dry-run preview would say the verb "would run"; it cannot.
    execute_gated = false
)]
pub async fn gitea_restore(args: GiteaRestoreArgs, _ctx: &ToolCtx) -> Result<GiteaRestoreResult> {
    bail!(
        "gitea.restore {}: not implemented: {RESTORE_MISSING}",
        args.endpoint
    )
}

#[cfg(test)]
mod tests {
    use plugin_toolkit::serde_json::json;

    async fn dispatch_err(tool: &str, args: plugin_toolkit::serde_json::Value) -> String {
        let ctx = plugin_toolkit::tool_manifest::minimal_ctx();
        match plugin_toolkit::dispatch::dispatch(tool, args, &ctx).await {
            Ok(out) => panic!("{tool} reported success without doing the work: {out}"),
            Err(e) => e.to_string(),
        }
    }

    #[tokio::test]
    async fn backup_fails_honestly_and_names_no_archive() {
        for args in [
            json!({"endpoint": "home"}),
            json!({"endpoint": "home", "execute": true}),
        ] {
            let err = dispatch_err("gitea.backup", args).await;
            assert!(err.contains("gitea.backup home: not implemented"), "{err}");
            assert!(!err.contains("gitea-dump"), "error names an archive: {err}");
        }
    }

    #[tokio::test]
    async fn restore_fails_honestly() {
        for args in [
            json!({"endpoint": "home", "archive": "/backups/gitea-dump.zip"}),
            json!({"endpoint": "home", "archive": "/backups/gitea-dump.zip", "execute": true}),
        ] {
            let err = dispatch_err("gitea.restore", args).await;
            assert!(err.contains("gitea.restore home: not implemented"), "{err}");
        }
    }

    #[test]
    fn backup_and_restore_require_admin() {
        for tool in ["gitea.backup", "gitea.restore"] {
            assert_eq!(
                plugin_toolkit::dispatch::required_role(tool),
                Some("admin"),
                "{tool}"
            );
        }
    }
}
