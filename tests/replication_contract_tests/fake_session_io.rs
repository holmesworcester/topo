//! FakeSessionIo: channel-backed implementation of the SessionIo contract
//! for deterministic, transport-free replication testing.
//!
//! Models:
//! - frame delivery via bounded tokio mpsc channels,
//! - half-close via channel drop,
//! - abrupt close via explicit error injection,
//! - frame-size enforcement,
//! - delayed delivery (optional per-frame delay),
//! - out-of-order data frame reordering.
//!
//! The `fake_session_io_pair` constructor returns a `FakeSessionIo` (for the
//! handler under test) and a `FakePeerSide` (for the test harness to script
//! the other end of the conversation).

use async_trait::async_trait;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;

use topo::contracts::network_contract::{
    ControlIo, DataRecvIo, DataSendIo, SessionIo, SessionIoError, SessionIoParts,
};
use topo::sync::{encode_sync_message, parse_sync_message, SyncMessage};

/// Default max frame size for tests (4 MiB + 5-byte header).
pub const TEST_MAX_FRAME_SIZE: usize = (4 * 1024 * 1024) + 5;

/// Channel capacity for test IO channels.
const CHANNEL_CAP: usize = 256;

// ---------------------------------------------------------------------------
// FakeIoConfig: configurable failure modes for FakeSessionIo
// ---------------------------------------------------------------------------

/// Configuration for FakeSessionIo failure-mode simulation.
///
/// Controls frame-size enforcement, per-frame delivery delay, and
/// data-frame reordering. Use `Default::default()` for standard behavior.
#[derive(Clone, Debug)]
pub struct FakeIoConfig {
    /// If set, sleep this duration before delivering each received frame.
    /// Simulates network latency / delayed delivery.
    pub frame_delay: Option<Duration>,
    /// Maximum frame size enforced on send operations. Frames exceeding this
    /// limit will produce `SessionIoError::FrameTooLarge`.
    pub max_frame_size: usize,
    /// When true, data frames received via `FakeDataRecvIo` are buffered and
    /// delivered in reversed order (simulates out-of-order delivery).
    pub reorder_data_frames: bool,
}

impl Default for FakeIoConfig {
    fn default() -> Self {
        Self {
            frame_delay: None,
            max_frame_size: TEST_MAX_FRAME_SIZE,
            reorder_data_frames: false,
        }
    }
}

// ---------------------------------------------------------------------------
// FakeSessionIo: implements SessionIo for injection into SessionHandler
// ---------------------------------------------------------------------------

pub struct FakeSessionIo {
    session_id: u64,
    max_frame_size: usize,
    config: FakeIoConfig,
    closed: Arc<AtomicBool>,
    // Control: handler receives from ctrl_in_rx, sends to ctrl_out_tx
    ctrl_in_rx: Option<mpsc::Receiver<Vec<u8>>>,
    ctrl_out_tx: Option<mpsc::Sender<Vec<u8>>>,
    // Data: handler sends to data_out_tx, receives from data_in_rx
    data_out_tx: Option<mpsc::Sender<Vec<u8>>>,
    data_in_rx: Option<mpsc::Receiver<Vec<u8>>>,
}

/// The test harness side: send frames to and receive frames from the handler.
pub struct FakePeerSide {
    /// Send control frames to the handler (handler's control recv).
    pub control_send: mpsc::Sender<Vec<u8>>,
    /// Receive control frames from the handler (handler's control send).
    pub control_recv: mpsc::Receiver<Vec<u8>>,
    /// Send data frames to the handler (handler's data recv).
    pub data_send: mpsc::Sender<Vec<u8>>,
    /// Receive data frames from the handler (handler's data send).
    pub data_recv: mpsc::Receiver<Vec<u8>>,
    /// Shared closed flag for simulating abrupt close.
    pub closed: Arc<AtomicBool>,
}

/// Create a paired FakeSessionIo + FakePeerSide for testing.
pub fn fake_session_io_pair(session_id: u64) -> (FakeSessionIo, FakePeerSide) {
    fake_session_io_pair_with_config(session_id, FakeIoConfig::default())
}

#[allow(dead_code)]
pub fn fake_session_io_pair_with_capacity(
    session_id: u64,
    cap: usize,
) -> (FakeSessionIo, FakePeerSide) {
    build_fake_session_io(session_id, cap, FakeIoConfig::default())
}

/// Create a paired FakeSessionIo + FakePeerSide with custom failure-mode config.
pub fn fake_session_io_pair_with_config(
    session_id: u64,
    config: FakeIoConfig,
) -> (FakeSessionIo, FakePeerSide) {
    build_fake_session_io(session_id, CHANNEL_CAP, config)
}

fn build_fake_session_io(
    session_id: u64,
    cap: usize,
    config: FakeIoConfig,
) -> (FakeSessionIo, FakePeerSide) {
    let (ctrl_to_handler_tx, ctrl_to_handler_rx) = mpsc::channel(cap);
    let (ctrl_from_handler_tx, ctrl_from_handler_rx) = mpsc::channel(cap);
    let (data_to_handler_tx, data_to_handler_rx) = mpsc::channel(cap);
    let (data_from_handler_tx, data_from_handler_rx) = mpsc::channel(cap);
    let closed = Arc::new(AtomicBool::new(false));

    let io = FakeSessionIo {
        session_id,
        max_frame_size: config.max_frame_size,
        config,
        closed: closed.clone(),
        ctrl_in_rx: Some(ctrl_to_handler_rx),
        ctrl_out_tx: Some(ctrl_from_handler_tx),
        data_out_tx: Some(data_from_handler_tx),
        data_in_rx: Some(data_to_handler_rx),
    };

    let peer = FakePeerSide {
        control_send: ctrl_to_handler_tx,
        control_recv: ctrl_from_handler_rx,
        data_send: data_to_handler_tx,
        data_recv: data_from_handler_rx,
        closed,
    };

    (io, peer)
}

// ---------------------------------------------------------------------------
// Split adapters: channel-backed ControlIo / DataSendIo / DataRecvIo
// ---------------------------------------------------------------------------

struct FakeControlIo {
    rx: mpsc::Receiver<Vec<u8>>,
    tx: mpsc::Sender<Vec<u8>>,
    closed: Arc<AtomicBool>,
    max_frame_size: usize,
    frame_delay: Option<Duration>,
}

#[async_trait]
impl ControlIo for FakeControlIo {
    async fn recv(&mut self) -> Result<Vec<u8>, SessionIoError> {
        if self.closed.load(Ordering::Acquire) {
            return Err(SessionIoError::ConnectionLost);
        }
        if let Some(delay) = self.frame_delay {
            tokio::time::sleep(delay).await;
        }
        self.rx
            .recv()
            .await
            .ok_or(SessionIoError::ConnectionLost)
    }

    async fn send(&mut self, frame: &[u8]) -> Result<(), SessionIoError> {
        if self.closed.load(Ordering::Acquire) {
            return Err(SessionIoError::ConnectionLost);
        }
        if frame.len() > self.max_frame_size {
            return Err(SessionIoError::FrameTooLarge {
                len: frame.len(),
                max: self.max_frame_size,
            });
        }
        self.tx
            .send(frame.to_vec())
            .await
            .map_err(|_| SessionIoError::ConnectionLost)
    }

    async fn flush(&mut self) -> Result<(), SessionIoError> {
        Ok(()) // channels are unbuffered from the sender's perspective
    }
}

struct FakeDataSendIo {
    tx: mpsc::Sender<Vec<u8>>,
    closed: Arc<AtomicBool>,
    max_frame_size: usize,
}

#[async_trait]
impl DataSendIo for FakeDataSendIo {
    async fn send(&mut self, frame: &[u8]) -> Result<(), SessionIoError> {
        if self.closed.load(Ordering::Acquire) {
            return Err(SessionIoError::ConnectionLost);
        }
        if frame.len() > self.max_frame_size {
            return Err(SessionIoError::FrameTooLarge {
                len: frame.len(),
                max: self.max_frame_size,
            });
        }
        self.tx
            .send(frame.to_vec())
            .await
            .map_err(|_| SessionIoError::ConnectionLost)
    }

    async fn flush(&mut self) -> Result<(), SessionIoError> {
        Ok(())
    }
}

struct FakeDataRecvIo {
    rx: mpsc::Receiver<Vec<u8>>,
    closed: Arc<AtomicBool>,
    frame_delay: Option<Duration>,
    reorder: bool,
    /// Buffer for reordering: frames accumulate here until the channel closes,
    /// then are delivered in reverse order.
    reorder_buf: Vec<Vec<u8>>,
    /// True once the underlying channel has been drained for reordering.
    reorder_drained: bool,
}

#[async_trait]
impl DataRecvIo for FakeDataRecvIo {
    async fn recv(&mut self) -> Result<Vec<u8>, SessionIoError> {
        if self.closed.load(Ordering::Acquire) {
            return Err(SessionIoError::ConnectionLost);
        }
        if let Some(delay) = self.frame_delay {
            tokio::time::sleep(delay).await;
        }
        if self.reorder {
            // In reorder mode, buffer all frames from the channel first,
            // then pop them in reverse order.
            if !self.reorder_drained {
                // Drain all available frames from the channel.
                loop {
                    match self.rx.recv().await {
                        Some(frame) => self.reorder_buf.push(frame),
                        None => break,
                    }
                }
                // Buffer now holds [A, B, C]. pop() yields C, B, A (reversed).
                self.reorder_drained = true;
            }
            self.reorder_buf
                .pop()
                .ok_or(SessionIoError::ConnectionLost)
        } else {
            self.rx
                .recv()
                .await
                .ok_or(SessionIoError::ConnectionLost)
        }
    }
}

// ---------------------------------------------------------------------------
// SessionIo implementation
// ---------------------------------------------------------------------------

#[async_trait]
impl SessionIo for FakeSessionIo {
    fn session_id(&self) -> u64 {
        self.session_id
    }

    fn max_frame_size(&self) -> usize {
        self.max_frame_size
    }

    fn split(self: Box<Self>) -> SessionIoParts {
        let config = &self.config;
        SessionIoParts {
            control: Box::new(FakeControlIo {
                rx: self.ctrl_in_rx.expect("split called twice"),
                tx: self.ctrl_out_tx.expect("split called twice"),
                closed: self.closed.clone(),
                max_frame_size: config.max_frame_size,
                frame_delay: config.frame_delay,
            }),
            data_send: Box::new(FakeDataSendIo {
                tx: self.data_out_tx.expect("split called twice"),
                closed: self.closed.clone(),
                max_frame_size: config.max_frame_size,
            }),
            data_recv: Box::new(FakeDataRecvIo {
                rx: self.data_in_rx.expect("split called twice"),
                closed: self.closed.clone(),
                frame_delay: config.frame_delay,
                reorder: config.reorder_data_frames,
                reorder_buf: Vec::new(),
                reorder_drained: false,
            }),
        }
    }

    async fn poll_send_ready(&mut self) -> Result<(), SessionIoError> {
        Ok(())
    }

    async fn recv_control(&mut self) -> Result<Vec<u8>, SessionIoError> {
        if let Some(rx) = &mut self.ctrl_in_rx {
            if let Some(delay) = self.config.frame_delay {
                tokio::time::sleep(delay).await;
            }
            rx.recv().await.ok_or(SessionIoError::ConnectionLost)
        } else {
            Err(SessionIoError::Internal("already split".into()))
        }
    }

    async fn send_control(&mut self, frame: &[u8]) -> Result<(), SessionIoError> {
        if frame.len() > self.config.max_frame_size {
            return Err(SessionIoError::FrameTooLarge {
                len: frame.len(),
                max: self.config.max_frame_size,
            });
        }
        if let Some(tx) = &self.ctrl_out_tx {
            tx.send(frame.to_vec())
                .await
                .map_err(|_| SessionIoError::ConnectionLost)
        } else {
            Err(SessionIoError::Internal("already split".into()))
        }
    }

    async fn recv_data(&mut self) -> Result<Vec<u8>, SessionIoError> {
        if let Some(rx) = &mut self.data_in_rx {
            if let Some(delay) = self.config.frame_delay {
                tokio::time::sleep(delay).await;
            }
            rx.recv().await.ok_or(SessionIoError::ConnectionLost)
        } else {
            Err(SessionIoError::Internal("already split".into()))
        }
    }

    async fn send_data(&mut self, frame: &[u8]) -> Result<(), SessionIoError> {
        if frame.len() > self.config.max_frame_size {
            return Err(SessionIoError::FrameTooLarge {
                len: frame.len(),
                max: self.config.max_frame_size,
            });
        }
        if let Some(tx) = &self.data_out_tx {
            tx.send(frame.to_vec())
                .await
                .map_err(|_| SessionIoError::ConnectionLost)
        } else {
            Err(SessionIoError::Internal("already split".into()))
        }
    }

    async fn close_session(&mut self, _code: u32, _reason: &[u8]) -> Result<(), SessionIoError> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Helpers for test harness
// ---------------------------------------------------------------------------

impl FakePeerSide {
    /// Send a SyncMessage (encoded) on the control channel.
    pub async fn send_control_msg(&self, msg: &SyncMessage) {
        let frame = encode_sync_message(msg);
        self.control_send
            .send(frame)
            .await
            .expect("control channel closed");
    }

    /// Send a SyncMessage (encoded) on the data channel.
    pub async fn send_data_msg(&self, msg: &SyncMessage) {
        let frame = encode_sync_message(msg);
        self.data_send
            .send(frame)
            .await
            .expect("data channel closed");
    }

    /// Receive and decode a SyncMessage from the control channel.
    #[allow(dead_code)]
    pub async fn recv_control_msg(&mut self) -> Option<SyncMessage> {
        let frame = self.control_recv.recv().await?;
        let (msg, _) = parse_sync_message(&frame).expect("invalid frame from handler");
        Some(msg)
    }

    /// Receive and decode a SyncMessage from the data channel.
    #[allow(dead_code)]
    pub async fn recv_data_msg(&mut self) -> Option<SyncMessage> {
        let frame = self.data_recv.recv().await?;
        let (msg, _) = parse_sync_message(&frame).expect("invalid frame from handler");
        Some(msg)
    }

    /// Receive and decode a SyncMessage from the control channel with timeout.
    pub async fn recv_control_msg_timeout(
        &mut self,
        timeout: std::time::Duration,
    ) -> Option<SyncMessage> {
        match tokio::time::timeout(timeout, self.control_recv.recv()).await {
            Ok(Some(frame)) => {
                let (msg, _) = parse_sync_message(&frame).expect("invalid frame from handler");
                Some(msg)
            }
            _ => None,
        }
    }

    /// Receive and decode a SyncMessage from the data channel with timeout.
    pub async fn recv_data_msg_timeout(
        &mut self,
        timeout: std::time::Duration,
    ) -> Option<SyncMessage> {
        match tokio::time::timeout(timeout, self.data_recv.recv()).await {
            Ok(Some(frame)) => {
                let (msg, _) = parse_sync_message(&frame).expect("invalid frame from handler");
                Some(msg)
            }
            _ => None,
        }
    }

    /// Simulate abrupt connection close.
    pub fn force_close(&self) {
        self.closed.store(true, Ordering::Release);
    }
}

// ---------------------------------------------------------------------------
// Negentropy helper: create an empty negentropy for test harness responses
// ---------------------------------------------------------------------------

/// Create a sealed empty negentropy storage and return it.
/// The caller must keep the storage alive while the Negentropy is in use.
pub fn empty_negentropy_storage() -> negentropy::NegentropyStorageVector {
    let mut storage = negentropy::NegentropyStorageVector::with_capacity(0);
    storage.seal().expect("seal empty storage");
    storage
}

// ---------------------------------------------------------------------------
// Test database helper
// ---------------------------------------------------------------------------

/// Create a minimal test database with schema tables initialized.
/// Returns (db_path, tempdir_guard).
pub fn create_test_db(tenant_id: &str) -> (String, tempfile::TempDir) {
    let tmpdir = tempfile::tempdir().expect("failed to create tempdir");
    let db_path = tmpdir.path().join("test.db");
    let db_path_str = db_path.to_str().unwrap().to_string();

    let conn = topo::db::open_connection(&db_path_str).expect("open db");
    topo::db::schema::create_tables(&conn).expect("create tables");

    // Insert a trust anchor so lookup_workspace_id works
    conn.execute(
        "INSERT OR IGNORE INTO trust_anchors (peer_id, workspace_id) VALUES (?1, ?2)",
        rusqlite::params![tenant_id, format!("ws-{}", tenant_id)],
    )
    .expect("insert trust anchor");

    drop(conn);
    (db_path_str, tmpdir)
}

/// No-op batch writer for tests that don't need event ingestion.
pub fn noop_batch_writer(
    _db_path: String,
    mut rx: tokio::sync::mpsc::Receiver<topo::contracts::event_runtime_contract::IngestItem>,
    _events_received: std::sync::Arc<std::sync::atomic::AtomicU64>,
) {
    // Drain the channel so senders don't block
    while rx.blocking_recv().is_some() {}
}

/// Build a SessionMeta for testing.
pub fn test_session_meta(
    direction: topo::contracts::network_contract::SessionDirection,
) -> topo::contracts::network_contract::SessionMeta {
    use topo::contracts::network_contract::*;
    SessionMeta {
        session_id: next_session_id(),
        tenant: TenantId("test-tenant".into()),
        peer: PeerFingerprint([0xABu8; 32]),
        remote_addr: "127.0.0.1:9999".parse().unwrap(),
        direction,
    }
}

/// Run a !Send future on a LocalSet (needed because SessionHandler is ?Send).
pub async fn run_local<F, T>(fut: F) -> T
where
    F: std::future::Future<Output = T> + 'static,
    T: 'static,
{
    let local = tokio::task::LocalSet::new();
    local.run_until(fut).await
}
