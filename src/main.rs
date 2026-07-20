//! Dynamic (subprocess) entrypoint for the gitea plugin.
//!
//! The toolkit's `serve_tool_plugin!` emits `fn main`, serving this plugin over
//! the orca socket. gitea is a tools-only plugin: the generated `gitea.*` REST
//! surface plus the hand-written `gitea.deploy` / `gitea.backup` /
//! `gitea.restore` verbs and the endpoint-registry CRUD. No domain backends yet
//! (a `unit` provider exposing repos as managed units can be added later).
plugin_toolkit::serve_tool_plugin! {
    name: "gitea",
    target_compat: ">=1.20",
}
