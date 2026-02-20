//! FakeTransportSessionIo: channel-backed implementation of the TransportSessionIo contract
//! for deterministic, transport-free sync testing.
//!
//! Models:
//! - frame delivery via bounded tokio mpsc channels,
//! - half-close via channel drop,
//! - abrupt close via explicit error injection,
//! - frame-size enforcement,
//! - delayed delivery (optional per-frame delay),
//! - out-of-order data frame reordering,
//! - transport-layer frame fragmentation,
//! - deterministic peer-protocol violations.
//!
//! The `fake_session_io_pair` constructor returns a `FakeTransportSessionIo` (for the
//! handler under test) and a `FakePeerSide` (for the test harness to script
//! the other end of the conversation).

use async_trait::async_trait;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;

use topo::contracts::peering_contract::{
    ControlIo, DataRecvIo, DataSendIo, TransportSessionIo, TransportSessionIoError, TransportSessionIoParts,
};
use topo::protocol::{encode_frame, parse_frame, Frame};

/// Default max frame size for tests (4 MiB + 5-byte header).
pub const TEST_MAX_FRAME_SIZE: usize = (4 * 1024 * 1024) + 5;

/// Channel capacity for test IO channels.
const CHANNEL_CAP: usize = 256;

// ---------------------------------------------------------------------------
// FakeIoConfig: configurable failure modes for FakeTransportSessionIo
// ---------------------------------------------------------------------------

/// Deterministic peer-protocol violations that can be injected into a session.
///
/// Each variant causes the harness to inject a specific protocol-level error
/// at the appropriate point during the session, allowing tests to verify that
/// the handler correctly rejects or handles malformed peer behavior.
#[derive(Clone, Debug)]
pub enum ProtocolViolation {
    /// Inject random garbage bytes as a control frame. The handler should
    /// fail with a parse error when it tries to decode the invalid frame.
    GarbageControlFrame,
    /// Send the `Done` control message twice. The handler should detect the
    /// duplicate and either ignore it or error out.
    DuplicateDone,
}

/// Configuration for FakeTransportSessionIo failure-mode simulation.
///
/// Controls frame-size enforcement, per-frame delivery delay,
/// data-frame reordering, transport-layer fragmentation, and
/// deterministic protocol violations.
/// Use `Default::default()` for standard behavior.
#[derive(Clone, Debug)]
pub struct FakeIoConfig {
    /// If set, sleep this duration before delivering each received frame.
    /// Simulates network latency / delayed delivery.
    pub frame_delay: Option<Duration>,
    /// Maximum frame size enforced on send operations. Frames exceeding this
    /// limit will produce `TransportSessionIoError::FrameTooLarge`.
    pub max_frame_size: usize,
    /// When true, data frames received via `FakeDataRecvIo` are buffered and
    /// delivered in reversed order (simulates out-of-order delivery).
    pub reorder_data_frames: bool,
    /// When true, each data frame received from the peer is split into 2+
    /// smaller chunks before delivery to the handler's `DataRecvIo`.
    /// Simulates transport-layer fragmentation where a single logical frame
    /// arrives as multiple smaller reads.
    pub fragment_data_frames: bool,
    /// If set, inject a deterministic protocol violation during the session.
    /// The violation is injected on the control channel at an appropriate
    /// point (e.g., as the first control frame for `GarbageControlFrame`,
    /// or after a legitimate `Done` for `DuplicateDone`).
    pub inject_protocol_violation: Option<ProtocolViolation>,
}

impl Default for FakeIoConfig {
    fn default() -> Self {
        Self {
            frame_delay: None,
            max_frame_size: TEST_MAX_FRAME_SIZE,
            reorder_data_frames: false,
            fragment_data_frames: false,
            inject_protocol_violation: None,
        }
    }
}

// ---------------------------------------------------------------------------
// FakeTransportSessionIo: implements TransportSessionIo for injection into SessionHandler
// ---------------------------------------------------------------------------

pub struct FakeTransportSessionIo {
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

/// Create a paired FakeTransportSessionIo + FakePeerSide for testing.
pub fn fake_session_io_pair(session_id: u64) -> (FakeTransportSessionIo, FakePeerSide) {
    fake_session_io_pair_with_config(session_id, FakeIoConfig::default())
}

#[allow(dead_code)]
pub fn fake_session_io_pair_with_capacity(
    session_id: u64,
    cap: usize,
) -> (FakeTransportSessionIo, FakePeerSide) {
    build_fake_session_io(session_id, cap, FakeIoConfig::default())
}

/// Create a paired FakeTransportSessionIo + FakePeerSide with custom failure-mode config.
pub fn fake_session_io_pair_with_config(
    session_id: u64,
    config: FakeIoConfig,
) -> (FakeTransportSessionIo, FakePeerSide) {
    build_fake_session_io(session_id, CHANNEL_CAP, config)
}

fn build_fake_session_io(
    session_id: u64,
    cap: usize,
    config: FakeIoConfig,
) -> (FakeTransportSessionIo, FakePeerSide) {
    let (ctrl_to_handler_tx, ctrl_to_handler_rx) = mpsc::channel(cap);
    let (ctrl_from_handler_tx, ctrl_from_handler_rx) = mpsc::channel(cap);
    let (data_to_handler_tx, data_to_handler_rx) = mpsc::channel(cap);
    let (data_from_handler_tx, data_from_handler_rx) = mpsc::channel(cap);
    let closed = Arc::new(AtomicBool::new(false));

    let io = FakeTransportSessionIo {
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
    violation: Option<ProtocolViolation>,
    /// Number of frames delivered so far (for injection timing).
    recv_count: u64,
    /// Pending frame to re-deliver (used by DuplicateDone).
    pending_duplicate: Option<Vec<u8>>,
}

/// Garbage bytes that cannot be parsed as any valid Frame.
/// Uses 0xFF as the message type byte, which is not a known type.
const GARBAGE_CONTROL_FRAME: &[u8] = &[0xFF, 0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x42];

#[async_trait]
impl ControlIo for FakeControlIo {
    async fn recv(&mut self) -> Result<Vec<u8>, TransportSessionIoError> {
        if self.closed.load(Ordering::Acquire) {
            return Err(TransportSessionIoError::ConnectionLost);
        }
        if let Some(delay) = self.frame_delay {
            tokio::time::sleep(delay).await;
        }

        // DuplicateDone: if we have a pending duplicate, deliver it first.
        if let Some(dup) = self.pending_duplicate.take() {
            self.recv_count += 1;
            return Ok(dup);
        }

        // GarbageControlFrame: inject garbage as the very first control frame.
        if self.recv_count == 0 {
            if let Some(ProtocolViolation::GarbageControlFrame) = &self.violation {
                self.recv_count += 1;
                return Ok(GARBAGE_CONTROL_FRAME.to_vec());
            }
        }

        let frame = self.rx
            .recv()
            .await
            .ok_or(TransportSessionIoError::ConnectionLost)?;

        // DuplicateDone: when we see a Done frame, queue a duplicate.
        if let Some(ProtocolViolation::DuplicateDone) = &self.violation {
            // Done is encoded as a single byte (MSG_TYPE_DONE = 0x20).
            if frame.len() == 1 && frame[0] == 0x20 {
                self.pending_duplicate = Some(frame.clone());
            }
        }

        self.recv_count += 1;
        Ok(frame)
    }

    async fn send(&mut self, frame: &[u8]) -> Result<(), TransportSessionIoError> {
        if self.closed.load(Ordering::Acquire) {
            return Err(TransportSessionIoError::ConnectionLost);
        }
        if frame.len() > self.max_frame_size {
            return Err(TransportSessionIoError::FrameTooLarge {
                len: frame.len(),
                max: self.max_frame_size,
            });
        }
        self.tx
            .send(frame.to_vec())
            .await
            .map_err(|_| TransportSessionIoError::ConnectionLost)
    }

    async fn flush(&mut self) -> Result<(), TransportSessionIoError> {
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
    async fn send(&mut self, frame: &[u8]) -> Result<(), TransportSessionIoError> {
        if self.closed.load(Ordering::Acquire) {
            return Err(TransportSessionIoError::ConnectionLost);
        }
        if frame.len() > self.max_frame_size {
            return Err(TransportSessionIoError::FrameTooLarge {
                len: frame.len(),
                max: self.max_frame_size,
            });
        }
        self.tx
            .send(frame.to_vec())
            .await
            .map_err(|_| TransportSessionIoError::ConnectionLost)
    }

    async fn flush(&mut self) -> Result<(), TransportSessionIoError> {
        Ok(())
    }
}

struct FakeDataRecvIo {
    rx: mpsc::Receiver<Vec<u8>>,
    closed: Arc<AtomicBool>,
    frame_delay: Option<Duration>,
    reorder: bool,
    fragment: bool,
    /// Buffer for reordering: frames accumulate here until the channel closes,
    /// then are delivered in reverse order.
    reorder_buf: Vec<Vec<u8>>,
    /// True once the underlying channel has been drained for reordering.
    reorder_drained: bool,
    /// Buffer for fragmentation: when a frame is split into chunks, the
    /// remaining chunks are stored here and delivered on subsequent recv calls.
    fragment_buf: std::collections::VecDeque<Vec<u8>>,
}

#[async_trait]
impl DataRecvIo for FakeDataRecvIo {
    async fn recv(&mut self) -> Result<Vec<u8>, TransportSessionIoError> {
        if self.closed.load(Ordering::Acquire) {
            return Err(TransportSessionIoError::ConnectionLost);
        }
        if let Some(delay) = self.frame_delay {
            tokio::time::sleep(delay).await;
        }

        // If we have buffered fragments from a previous frame, deliver them first.
        if let Some(chunk) = self.fragment_buf.pop_front() {
            return Ok(chunk);
        }

        let frame = if self.reorder {
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
                .ok_or(TransportSessionIoError::ConnectionLost)?
        } else {
            self.rx
                .recv()
                .await
                .ok_or(TransportSessionIoError::ConnectionLost)?
        };

        // Apply fragmentation: split the frame into 2 chunks at the midpoint.
        if self.fragment && frame.len() > 1 {
            let mid = frame.len() / 2;
            let first = frame[..mid].to_vec();
            let second = frame[mid..].to_vec();
            self.fragment_buf.push_back(second);
            Ok(first)
        } else {
            Ok(frame)
        }
    }
}

// ---------------------------------------------------------------------------
// TransportSessionIo implementation
// ---------------------------------------------------------------------------

#[async_trait]
impl TransportSessionIo for FakeTransportSessionIo {
    fn session_id(&self) -> u64 {
        self.session_id
    }

    fn max_frame_size(&self) -> usize {
        self.max_frame_size
    }

    fn split(self: Box<Self>) -> TransportSessionIoParts {
        let config = &self.config;
        TransportSessionIoParts {
            control: Box::new(FakeControlIo {
                rx: self.ctrl_in_rx.expect("split called twice"),
                tx: self.ctrl_out_tx.expect("split called twice"),
                closed: self.closed.clone(),
                max_frame_size: config.max_frame_size,
                frame_delay: config.frame_delay,
                violation: config.inject_protocol_violation.clone(),
                recv_count: 0,
                pending_duplicate: None,
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
                fragment: config.fragment_data_frames,
                reorder_buf: Vec::new(),
                reorder_drained: false,
                fragment_buf: VecDeque::new(),
            }),
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers for test harness
// ---------------------------------------------------------------------------

impl FakePeerSide {
    /// Send a Frame (encoded) on the control channel.
    pub async fn send_control_msg(&self, msg: &Frame) {
        let frame = encode_frame(msg);
        self.control_send
            .send(frame)
            .await
            .expect("control channel closed");
    }

    /// Send a Frame (encoded) on the data channel.
    pub async fn send_data_msg(&self, msg: &Frame) {
        let frame = encode_frame(msg);
        self.data_send
            .send(frame)
            .await
            .expect("data channel closed");
    }

    /// Receive and decode a Frame from the control channel.
    #[allow(dead_code)]
    pub async fn recv_control_msg(&mut self) -> Option<Frame> {
        let frame = self.control_recv.recv().await?;
        let (msg, _) = parse_frame(&frame).expect("invalid frame from handler");
        Some(msg)
    }

    /// Receive and decode a Frame from the data channel.
    #[allow(dead_code)]
    pub async fn recv_data_msg(&mut self) -> Option<Frame> {
        let frame = self.data_recv.recv().await?;
        let (msg, _) = parse_frame(&frame).expect("invalid frame from handler");
        Some(msg)
    }

    /// Receive and decode a Frame from the control channel with timeout.
    pub async fn recv_control_msg_timeout(
        &mut self,
        timeout: std::time::Duration,
    ) -> Option<Frame> {
        match tokio::time::timeout(timeout, self.control_recv.recv()).await {
            Ok(Some(frame)) => {
                let (msg, _) = parse_frame(&frame).expect("invalid frame from handler");
                Some(msg)
            }
            _ => None,
        }
    }

    /// Receive and decode a Frame from the data channel with timeout.
    pub async fn recv_data_msg_timeout(
        &mut self,
        timeout: std::time::Duration,
    ) -> Option<Frame> {
        match tokio::time::timeout(timeout, self.data_recv.recv()).await {
            Ok(Some(frame)) => {
                let (msg, _) = parse_frame(&frame).expect("invalid frame from handler");
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
    mut rx: tokio::sync::mpsc::Receiver<topo::contracts::event_pipeline_contract::IngestItem>,
    _events_received: std::sync::Arc<std::sync::atomic::AtomicU64>,
) {
    // Drain the channel so senders don't block
    while rx.blocking_recv().is_some() {}
}

/// Build a SessionMeta for testing.
pub fn test_session_meta(
    direction: topo::contracts::peering_contract::SessionDirection,
) -> topo::contracts::peering_contract::SessionMeta {
    use topo::contracts::peering_contract::*;
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
