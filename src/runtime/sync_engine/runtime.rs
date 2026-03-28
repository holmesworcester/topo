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

/// Dependency-session statistics used for simulator calibration.
#[allow(dead_code)]
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct DependencySessionStats {
    pub control_frames_sent: u64,
    pub control_frames_received: u64,
    pub control_bytes_sent: u64,
    pub control_bytes_received: u64,
    pub request_ids_sent: u64,
    pub request_ids_received: u64,
    pub data_frames_sent: u64,
    pub data_frames_received: u64,
    pub data_bytes_sent: u64,
    pub data_bytes_received: u64,
    pub response_events_sent: u64,
    pub response_events_received: u64,
    pub response_payload_bytes_sent: u64,
    pub response_payload_bytes_received: u64,
    pub duration_ms: u128,
}

#[allow(dead_code)]
impl DependencySessionStats {
    pub fn total_bytes_sent(&self) -> u64 {
        self.control_bytes_sent.saturating_add(self.data_bytes_sent)
    }

    pub fn total_bytes_received(&self) -> u64 {
        self.control_bytes_received
            .saturating_add(self.data_bytes_received)
    }
}
