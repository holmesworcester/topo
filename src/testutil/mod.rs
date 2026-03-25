pub mod bootstrap;

pub(crate) use std::net::SocketAddr;
use std::process::Child;
pub(crate) use std::sync::Arc;
pub(crate) use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// RAII guard that kills a daemon process on drop, preventing leaked processes
/// when tests panic before reaching manual cleanup.
pub struct DaemonGuard {
    child: Option<Child>,
}

impl DaemonGuard {
    /// Wrap an already-spawned daemon `Child` process.
    pub fn new(child: Child) -> Self {
        Self { child: Some(child) }
    }

    /// Access the underlying `Child` (e.g. for `try_wait` or `id`).
    pub fn child(&mut self) -> &mut Child {
        self.child.as_mut().expect("DaemonGuard already consumed")
    }

    /// Prevent Drop from touching a child that has already been reaped or
    /// transferred elsewhere.
    pub fn clear(&mut self) {
        self.child = None;
    }

    /// Take ownership of the underlying child process.
    pub fn take(&mut self) -> Option<Child> {
        self.child.take()
    }
}

impl Drop for DaemonGuard {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

pub(crate) use crate::crypto::{event_id_from_base64, event_id_to_base64, EventId};
pub(crate) use crate::db::{open_connection, schema::create_tables, store::insert_recorded_event};
pub(crate) use crate::event_modules::{
    AdminEvent, DeviceInviteEvent, FileEvent, FileSliceEvent, InviteAcceptedEvent, KeySecretEvent,
    KeySharedEvent, MessageDeletionEvent, MessageEvent, ParsedEvent, PeerSharedEvent,
    ReactionEvent, TenantEvent, UserEvent, UserInviteEvent, WorkspaceEvent,
};
pub(crate) use crate::peering::loops::{
    accept_loop, connect_loop, connect_loop_with_coordination_until_cancel,
    connect_loop_with_coordination_until_cancel_with_fallback_with_auth,
};
pub(crate) use crate::projection::apply::project_one;
pub(crate) use crate::projection::create::{
    create_encrypted_event_staged, create_encrypted_event_synchronous, create_event_staged,
    create_event_synchronous, create_signed_event_staged, create_signed_event_synchronous,
    event_id_or_blocked, CreateEventError,
};
pub(crate) use crate::state::db::queue::SQLITE_BUSY_RETRY_ATTEMPTS;
pub(crate) use crate::state::db::queue::SQLITE_BUSY_RETRY_BASE_MS;
pub(crate) use crate::transport::identity::{ensure_transport_peer_id, load_transport_cert};
pub(crate) use crate::transport::{
    create_dual_endpoint, create_dual_endpoint_dynamic, extract_spki_fingerprint,
    OutboundSessionAuthPlan,
};
pub(crate) use ed25519_dalek::SigningKey;
pub(crate) use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
pub(crate) use tokio_util::sync::CancellationToken;

/// No-op intro spawner for tests that don't need holepunch.
pub fn noop_intro_spawner(
    _conn: quinn::Connection,
    _db_path: String,
    _recorded_by: String,
    _peer_id: String,
    _endpoint: quinn::Endpoint,
    _client_config: Option<quinn::ClientConfig>,
) -> tokio::task::JoinHandle<()> {
    tokio::task::spawn_local(async {})
}

/// Convenience: production `IngestFns` for tests.
pub fn test_ingest_fns() -> crate::contracts::event_pipeline_contract::IngestFns {
    crate::contracts::event_pipeline_contract::IngestFns {
        batch_writer: crate::event_pipeline::batch_writer,
        drain_queue: crate::event_pipeline::drain_project_queue,
    }
}

pub(crate) const TESTUTIL_SQLITE_BUSY_RETRY_ATTEMPTS: usize = SQLITE_BUSY_RETRY_ATTEMPTS + 4;

pub(crate) fn current_timestamp_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

mod convergence;
mod fingerprint;
mod peer;
mod shared_db;
mod sync_harness;

pub use convergence::*;
pub use fingerprint::verify_projection_invariants;
pub use peer::*;
pub use shared_db::*;
pub use sync_harness::*;
