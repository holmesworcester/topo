//! Compatibility shim for the `replication` -> `sync` rename.
//!
//! New code should import from `crate::sync`.

pub use crate::sync::{PeerCoord, ReplicationSessionHandler};

pub mod session {
    pub use crate::sync::session::*;
}

pub mod session_handler {
    pub use crate::sync::session_handler::*;
}
