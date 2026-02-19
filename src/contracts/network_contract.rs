use std::sync::atomic::{AtomicU64, Ordering};

use async_trait::async_trait;
use std::net::SocketAddr;
use tokio_util::sync::CancellationToken;

static NEXT_SESSION_ID: AtomicU64 = AtomicU64::new(1);

/// Allocate a monotonically increasing session ID.
pub fn next_session_id() -> u64 {
    NEXT_SESSION_ID.fetch_add(1, Ordering::Relaxed)
}

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

/// Control stream: bidirectional (send + recv) for negentropy and protocol messages.
#[async_trait]
pub trait ControlIo: Send {
    async fn recv(&mut self) -> Result<Vec<u8>, SessionIoError>;
    async fn send(&mut self, frame: &[u8]) -> Result<(), SessionIoError>;
    async fn flush(&mut self) -> Result<(), SessionIoError>;
}

/// Data send stream: outbound event blobs.
#[async_trait]
pub trait DataSendIo: Send {
    async fn send(&mut self, frame: &[u8]) -> Result<(), SessionIoError>;
    async fn flush(&mut self) -> Result<(), SessionIoError>;
}

/// Data receive stream: inbound event blobs.  Must be `'static` so it can be
/// sent to a spawned task.
#[async_trait]
pub trait DataRecvIo: Send + 'static {
    async fn recv(&mut self) -> Result<Vec<u8>, SessionIoError>;
}

/// Split session IO parts returned by [`SessionIo::split`].
pub struct SessionIoParts {
    pub control: Box<dyn ControlIo>,
    pub data_send: Box<dyn DataSendIo>,
    pub data_recv: Box<dyn DataRecvIo>,
}

#[async_trait]
pub trait SessionIo: Send {
    fn session_id(&self) -> u64;
    fn max_frame_size(&self) -> usize;
    /// Split into independent control, data-send, and data-recv handles.
    /// Consuming `self` allows the data-recv handle to be moved to a spawned task.
    fn split(self: Box<Self>) -> SessionIoParts;

    // -- Direct frame methods (backward compatibility) --
    // These exist for unit tests in transport/session_io.rs that exercise
    // the pre-split code path. Production code should use `split()` instead.
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
