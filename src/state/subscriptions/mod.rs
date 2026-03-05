//! Local subscription engine: definitions, feed, state, and projection hook.
//!
//! Subscriptions are local-only (non-replicated). They match projected events
//! via event-module-owned subscription filters and populate a pull-based feed that CLI/RPC
//! consumers can poll.

pub mod engine;
pub mod filter;
pub mod queries;
pub mod schema;
pub mod types;

pub use engine::*;
pub use queries::*;
pub use schema::ensure_schema;
pub use types::*;
