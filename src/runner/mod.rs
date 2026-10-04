//! Gitea Actions runner management: install, register, supervise, health-check,
//! self-heal, upgrade and remove act_runner on the orca host the call runs on.
//!
//! Verbs live in [`tools`]. Rendering, planning and health classification are
//! pure modules so every rule is unit-tested without a host or a Gitea.

pub mod api;
pub mod exec;
pub mod health;
pub mod host;
pub mod layout;
pub mod plan;
pub mod release;
pub mod render;
pub mod tools;
