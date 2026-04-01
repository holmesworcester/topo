mod backend;
mod cascade;
mod dispatch;
pub(crate) mod project_one;
mod stages;
mod write_exec;

pub(crate) use backend::{ProjectionApplyResult, ProjectionBackend};
pub use project_one::project_one;
pub(crate) use stages::run_dep_and_projection_stages;

#[cfg(test)]
mod tests;
