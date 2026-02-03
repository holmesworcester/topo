/// Sync statistics
#[derive(Debug, Default, Clone)]
pub struct SyncStats {
    pub events_sent: u64,
    pub events_received: u64,
    pub neg_rounds: u64,
}
