use std::sync::atomic::AtomicU64;
use std::sync::Arc;

use tokio::sync::mpsc;

use super::peering_contract::{PeerFingerprint, TenantId};

/// Ingest channel item: (event_id, blob, recorded_by_tenant_id).
///
/// Shared between peering, sync, and event_pipeline layers so that
/// callers never import event_pipeline internals directly.
pub type IngestItem = ([u8; 32], Vec<u8>, String);

/// Batch writer entry point.  Blocks the calling thread draining `rx` and
/// writing events to storage until the channel is closed.
pub type BatchWriterFn = fn(String, mpsc::Receiver<IngestItem>, Arc<AtomicU64>);

/// Drain pending project-queue items for a single tenant (startup recovery).
/// Returns the number of items successfully drained.
pub type DrainQueueFn = fn(&str, &str, usize) -> usize;

/// Bundled ingest function pointers for the peering layer.
/// Passed from the composition root to avoid leaking event-pipeline details.
#[derive(Clone, Copy)]
pub struct IngestFns {
    pub batch_writer: BatchWriterFn,
    pub drain_queue: DrainQueueFn,
}

#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum IngestError {
    #[error("event already ingested")]
    AlreadyExists,
    #[error("invalid event payload: {0}")]
    Invalid(String),
    #[error("ingest sink unavailable")]
    StoreUnavailable,
    #[error("ingest internal error: {0}")]
    Internal(String),
}

#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum StoreError {
    #[error("store unavailable")]
    Unavailable,
    #[error("store internal error: {0}")]
    Internal(String),
}

pub trait IngestSink: Send + Sync {
    fn ingest_event(
        &self,
        tenant: &TenantId,
        event_id: [u8; 32],
        blob: Vec<u8>,
    ) -> Result<(), IngestError>;
}

pub trait SyncStore: Send + Sync {
    fn enqueue_outbound(&self, peer: &PeerFingerprint, ids: &[[u8; 32]]) -> Result<(), StoreError>;

    fn claim_outbound(
        &self,
        peer: &PeerFingerprint,
        limit: usize,
    ) -> Result<Vec<[u8; 32]>, StoreError>;

    fn load_shared_blob(&self, event_id: &[u8; 32]) -> Result<Option<Vec<u8>>, StoreError>;
}
