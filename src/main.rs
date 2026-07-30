//! Dynamic (subprocess) entrypoint for the gitea plugin.
//!
//! gitea is a tools-only plugin: the generated `gitea.*` REST surface plus the
//! hand-written `gitea.deploy` / `gitea.backup` / `gitea.restore` verbs and the
//! endpoint-registry CRUD. No domain backends yet.
//!
//! We call [`serve`] directly rather than via `serve_tool_plugin!{name,
//! target_compat}` because the `#[orca_tool]` inventory lives in the `gitea`
//! **lib** crate, and a bin that never references the lib would link none of it
//! (empty tool surface). Referencing [`gitea::link_anchor`] forces the lib into
//! the link so its inventory registers — the same reason every split lib/bin
//! plugin names a lib symbol in `main` (e.g. `adguard::AdguardBackend::new`).

use plugin_toolkit::serve::{PluginSpec, serve};

fn main() -> plugin_toolkit::anyhow::Result<()> {
    gitea::link_anchor();
    serve(PluginSpec {
        name: "gitea".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        prefixes: vec!["gitea.".to_string()],
        backends_json: plugin_toolkit::backend_def::EMPTY_BACKENDS.to_string(),
        schema_json: plugin_toolkit::backend_def::EMPTY_SCHEMAS.to_string(),
        backend_dispatch: None,
    })
}
