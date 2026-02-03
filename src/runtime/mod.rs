pub mod jobs;

use std::time::Duration;

/// Sync statistics
#[derive(Debug, Default, Clone)]
pub struct SyncStats {
    pub events_sent: u64,
    pub events_received: u64,
    pub neg_rounds: u64,
}

/// Runtime configuration
#[derive(Debug, Clone)]
pub struct RuntimeConfig {
    pub ingest_batch_size: usize,
    pub ingest_interval_ms: u64,
    pub run_duration: Duration,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            ingest_batch_size: 100,
            ingest_interval_ms: 10,
            run_duration: Duration::from_secs(30),
        }
    }
}
