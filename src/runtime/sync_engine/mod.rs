//! Negentropy-based workspace sync engine: per-session range reconciliation between two
//! connected peers over an already-established transport session. [`session`] holds the
//! protocol state machine, [`session_handler`] is the entry point consumed by peering,
//! [`runtime`] wires it into the daemon, and [`negentropy_debug`] is an off-path
//! diagnostic surface.

pub mod negentropy_debug;
pub mod runtime;
pub mod session;
pub mod session_handler;

pub use session_handler::SyncConnectionHandler;
