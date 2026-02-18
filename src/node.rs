//! Multi-tenant node daemon — composition root.
//!
//! Implementation has moved to `crate::network::runtime`.
//! This module re-exports `run_node` for backward compatibility.

pub use crate::network::runtime::{run_node, NodeRuntimeNetInfo};
