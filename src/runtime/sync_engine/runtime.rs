/// Sync statistics
#[allow(dead_code)]
#[derive(Debug, Default, Clone)]
pub struct SyncStats {
    pub events_sent: u64,
    pub events_received: u64,
    pub neg_rounds: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub duration_ms: u128,
}
