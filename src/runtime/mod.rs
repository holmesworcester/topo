//! Runtime glue. Hosts the `topo` CLI/RPC surface ([`control`]), the peering orchestration
//! loops ([`peering`]), the negentropy sync engine ([`sync_engine`]), and the QUIC
//! [`transport`] layer. Everything in this tree is daemon-scoped; workspace-scoped state
//! lives under `state/`.

pub(crate) mod build_mismatch;
pub mod control;
pub mod key_repair;
pub mod memtrace;
pub mod peering;
pub(crate) mod repeated_warning;
pub mod sync_control;
pub mod sync_engine;
pub mod transport;

pub use sync_engine::runtime::SyncStats;
