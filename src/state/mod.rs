//! Durable workspace state. [`db`] hosts the SQLite schema and per-table access modules,
//! [`pipeline`] ingests incoming blobs and drains the projection queue, [`projection`]
//! materializes events into tables via pure projectors, and [`subscriptions`] exposes a
//! local poll-based feed used by frontends. `shared_workspace_fanout` coordinates
//! tenant-scoped delivery when a single daemon hosts many workspaces.

pub mod db;
pub mod pipeline;
pub mod projection;
pub(crate) mod shared_workspace_fanout;
pub mod subscriptions;
