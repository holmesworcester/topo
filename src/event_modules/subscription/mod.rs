//! Local subscription engine: definitions, feed, state, and projection hook.
//!
//! Subscriptions are local-only (non-replicated). They match projected events
//! via event-module-owned matchers and populate a pull-based feed that CLI/RPC
//! consumers can poll.

pub mod matcher;
pub mod queries;
pub mod schema;
pub mod types;

pub use queries::*;
pub use schema::ensure_schema;
pub use types::*;
