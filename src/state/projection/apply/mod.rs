mod backend;
mod cascade;
mod dispatch;
pub(crate) mod project_one;
mod stages;
mod write_exec;

pub(crate) use backend::{ProjectionApplyResult, ProjectionBackend};
pub use project_one::project_one;

#[cfg(test)]
mod tests;
