use super::network_contract::{PeerFingerprint, TenantId};

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

pub trait ReplicationStore: Send + Sync {
    fn enqueue_outbound(&self, peer: &PeerFingerprint, ids: &[[u8; 32]]) -> Result<(), StoreError>;

    fn claim_outbound(
        &self,
        peer: &PeerFingerprint,
        limit: usize,
    ) -> Result<Vec<[u8; 32]>, StoreError>;

    fn load_shared_blob(&self, event_id: &[u8; 32]) -> Result<Option<Vec<u8>>, StoreError>;
}
