pub mod ingest_runtime;
pub mod sqlite_adapters;

pub use ingest_runtime::{batch_writer, drain_project_queue};

/// Re-export the canonical `IngestItem` from the contracts boundary.
pub use crate::contracts::event_runtime_contract::IngestItem;
