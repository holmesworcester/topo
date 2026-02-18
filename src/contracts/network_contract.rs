use async_trait::async_trait;
use std::net::SocketAddr;
use tokio_util::sync::CancellationToken;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TenantId(pub String);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PeerFingerprint(pub [u8; 32]);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionDirection {
    Inbound,
    Outbound,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionMeta {
    pub session_id: u64,
    pub tenant: TenantId,
    pub peer: PeerFingerprint,
    pub remote_addr: SocketAddr,
    pub direction: SessionDirection,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustDecision {
    Allow,
    Deny,
}

#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum TrustError {
    #[error("trust store unavailable")]
    StoreUnavailable,
    #[error("trust oracle internal error: {0}")]
    Internal(String),
}

#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum SessionIoError {
    #[error("connection lost")]
    ConnectionLost,
    #[error("frame too large: len={len}, max={max}")]
    FrameTooLarge { len: usize, max: usize },
    #[error("peer violated protocol: {0}")]
    PeerViolation(String),
    #[error("session timed out")]
    Timeout,
    #[error("session io internal error: {0}")]
    Internal(String),
}

#[async_trait]
pub trait TrustOracle: Send + Sync {
    async fn check(
        &self,
        tenant: &TenantId,
        peer: &PeerFingerprint,
    ) -> Result<TrustDecision, TrustError>;
}

#[async_trait]
pub trait SessionIo: Send {
    fn session_id(&self) -> u64;
    fn into_any(self: Box<Self>) -> Box<dyn std::any::Any + Send>;
    fn max_frame_size(&self) -> usize;
    async fn poll_send_ready(&mut self) -> Result<(), SessionIoError>;
    async fn recv_control(&mut self) -> Result<Vec<u8>, SessionIoError>;
    async fn send_control(&mut self, frame: &[u8]) -> Result<(), SessionIoError>;
    async fn recv_data(&mut self) -> Result<Vec<u8>, SessionIoError>;
    async fn send_data(&mut self, frame: &[u8]) -> Result<(), SessionIoError>;
    async fn close_session(&mut self, code: u32, reason: &[u8]) -> Result<(), SessionIoError>;
}

#[async_trait(?Send)]
pub trait SessionHandler: Send + Sync {
    async fn on_session(
        &self,
        meta: SessionMeta,
        io: Box<dyn SessionIo>,
        cancel: CancellationToken,
    ) -> Result<(), String>;
}
