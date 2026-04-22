//! Projection apply engine internals. [`project_one`] is the single entrypoint: it runs
//! dep checks, loads the projector's decision context, dispatches to the event-type
//! projector, executes returned [`WriteOp`]s, and kicks off the Kahn-style [`cascade`]
//! that unblocks dependent events. Split into [`backend`] (the SQL surface),
//! [`dispatch`] (projector lookup), [`stages`] (pipeline stages), and [`write_exec`]
//! (`WriteOp` → rusqlite) for testability.

mod backend;
mod cascade;
mod dispatch;
pub(crate) mod project_one;
mod stages;
mod write_exec;

pub(crate) use backend::{ProjectionApplyResult, ProjectionBackend, WriteCapability};
pub use project_one::project_one;
pub(crate) use stages::run_dep_and_projection_stages;

#[cfg(test)]
mod tests;
