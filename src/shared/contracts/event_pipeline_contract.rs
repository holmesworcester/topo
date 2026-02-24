use std::sync::atomic::AtomicU64;
use std::sync::Arc;

use tokio::sync::mpsc;

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
