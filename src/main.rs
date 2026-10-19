//! Dynamic (subprocess) entrypoint for the gitea plugin.
//!
//! gitea is a tools-only plugin: the generated `gitea.*` REST surface plus the
//! hand-written `gitea.deploy` / `gitea.backup` / `gitea.restore` verbs and the
//! endpoint-registry CRUD, plus a `notification_source` backend for release
//! failures and stale drafts. Built on the typed [`Plugin`]
//! builder.
//!
//! `gitea::link_anchor()` force-links the `gitea` **lib** crate so its
//! `#[orca_tool]` inventory registers — a bin that never references the lib would
//! link none of it (empty tool surface).
plugin_toolkit::instrument::bootstrap!();
use plugin_toolkit::plugin::Plugin;

fn main() -> plugin_toolkit::anyhow::Result<()> {
    gitea::link_anchor();
    Plugin::named("gitea")
        .version(env!("CARGO_PKG_VERSION"))
        .tools(["gitea."])
        .backend(
            gitea::release_watch::backend_def(),
            Box::new(gitea::release_watch::dispatcher),
        )
        .serve()
}
