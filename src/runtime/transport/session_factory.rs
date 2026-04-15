//! Session factory: opens QUIC streams and wraps them into contract-level
//! `TransportSessionIo`. This is the sole owner of stream wiring; peering
//! callers receive ready-to-use session IO without touching QUIC stream types.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::contracts::peering_contract::{next_session_id, TransportSessionIo};

use super::connection::{Connection, RecvConnection, SendConnection};
use super::{DualConnection, QuicTransportSessionIo};

const SESSION_STREAM_HEADER_MAGIC: [u8; 4] = *b"P7SS";
const SESSION_STREAM_HEADER_VERSION: u8 = 3;
// v3 header: [4 magic][1 version][1 class][1 kind][8 session_id][8 commit_hash] = 23 bytes
const SESSION_STREAM_HEADER_LEN: usize = 23;
const BUILD_MISMATCH_PREFIX: &str =
    "Version negotiation is out of scope for this PoC -- builds must be from the same commit.";
const CONNECTION_CLOSE_REASON_LIMIT: usize = 900;

/// Transport connection operations needed by session setup.
#[async_trait]
pub trait SessionCarrier: Clone + Send + Sync + 'static {
    type BiSend: AsyncWrite + Unpin + Send + 'static;
    type BiRecv: AsyncRead + Unpin + Send + 'static;

    async fn open_bi(&self) -> Result<(Self::BiSend, Self::BiRecv), String>;
    async fn accept_bi(&self) -> Result<(Self::BiSend, Self::BiRecv), String>;
    fn close_with_reason(&self, error_code: u32, reason: &[u8]);
}

/// Build commit hash embedded at compile time (8 ASCII hex chars, zero-padded).
fn local_commit_hash() -> [u8; 8] {
    let hash_str = local_commit_hash_str();
    let mut buf = [0u8; 8];
    let bytes = hash_str.as_bytes();
    let len = bytes.len().min(8);
    buf[..len].copy_from_slice(&bytes[..len]);
    buf
}

pub(crate) fn local_commit_hash_str() -> &'static str {
    env!("TOPO_GIT_HASH")
}

pub(crate) fn local_commit_subject() -> &'static str {
    env!("TOPO_GIT_SUBJECT")
}

fn format_build_label(hash: &str, subject: &str) -> String {
    if subject.is_empty() || subject == "unknown" {
        hash.to_string()
    } else {
        format!(r#"{hash} "{subject}""#)
    }
}

fn local_build_label() -> String {
    format_build_label(local_commit_hash_str(), local_commit_subject())
}

fn build_mismatch_reason_remote_protocol(remote_version: u8) -> String {
    format!(
        "{BUILD_MISMATCH_PREFIX} Local build: {}. Remote protocol version: v{}.",
        local_build_label(),
        remote_version
    )
}

fn build_mismatch_reason_remote_hash(remote_hash: &str) -> String {
    format!(
        "{BUILD_MISMATCH_PREFIX} Local build: {}. Remote build: {}.",
        local_build_label(),
        remote_hash
    )
}

pub(crate) fn extract_build_mismatch_reason(message: &str) -> Option<&str> {
    message
        .find(BUILD_MISMATCH_PREFIX)
        .map(|idx| &message[idx..])
}

fn connection_close_reason(reason: &str) -> Vec<u8> {
    let bytes = reason.as_bytes();
    if bytes.len() <= CONNECTION_CLOSE_REASON_LIMIT {
        return bytes.to_vec();
    }

    let mut end = CONNECTION_CLOSE_REASON_LIMIT.saturating_sub(3);
    while !reason.is_char_boundary(end) && end > 0 {
        end -= 1;
    }
    let mut truncated = reason[..end].to_string();
    truncated.push_str("...");
    truncated.into_bytes()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SessionStreamKind {
    Control,
    Data,
}

impl SessionStreamKind {
    fn to_byte(self) -> u8 {
        match self {
            Self::Control => 0,
            Self::Data => 1,
        }
    }

    fn from_byte(value: u8) -> Result<Self, SessionOpenError> {
        match value {
            0 => Ok(Self::Control),
            1 => Ok(Self::Data),
            other => Err(SessionOpenError::Protocol(format!(
                "invalid session stream kind {other}"
            ))),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionClass {
    Range,
}

impl SessionClass {
    fn to_byte(self) -> u8 {
        match self {
            Self::Range => 0,
        }
    }

    fn from_byte(value: u8) -> Result<Self, SessionOpenError> {
        match value {
            0 => Ok(Self::Range),
            other => Err(SessionOpenError::Protocol(format!(
                "invalid session class {other}"
            ))),
        }
    }
}

type BiStream<S, R> = (S, R);

struct PendingInboundSession<S, R> {
    class: Option<SessionClass>,
    control: Option<BiStream<S, R>>,
    data: Option<BiStream<S, R>>,
}

pub struct InboundSessionState<S, R> {
    pending: Arc<Mutex<HashMap<u64, PendingInboundSession<S, R>>>>,
}

impl<S, R> Default for PendingInboundSession<S, R> {
    fn default() -> Self {
        Self {
            class: None,
            control: None,
            data: None,
        }
    }
}

impl<S, R> Default for InboundSessionState<S, R> {
    fn default() -> Self {
        Self {
            pending: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

impl<S, R> Clone for InboundSessionState<S, R> {
    fn clone(&self) -> Self {
        Self {
            pending: Arc::clone(&self.pending),
        }
    }
}

/// Error from session stream opening.
#[derive(Debug)]
pub enum SessionOpenError {
    /// The QUIC connection dropped while opening streams.
    ConnectionLost(String),
    /// The peer opened streams that do not form a valid sync session.
    Protocol(String),
}

impl std::fmt::Display for SessionOpenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SessionOpenError::ConnectionLost(e) => write!(f, "connection lost: {}", e),
            SessionOpenError::Protocol(e) => write!(f, "protocol error: {}", e),
        }
    }
}

impl std::error::Error for SessionOpenError {}

async fn write_session_stream_header<W>(
    send: &mut W,
    session_id: u64,
    class: SessionClass,
    kind: SessionStreamKind,
) -> Result<(), SessionOpenError>
where
    W: AsyncWrite + Unpin + Send,
{
    let mut header = [0u8; SESSION_STREAM_HEADER_LEN];
    header[..4].copy_from_slice(&SESSION_STREAM_HEADER_MAGIC);
    header[4] = SESSION_STREAM_HEADER_VERSION;
    header[5] = class.to_byte();
    header[6] = kind.to_byte();
    header[7..15].copy_from_slice(&session_id.to_be_bytes());
    header[15..23].copy_from_slice(&local_commit_hash());
    send.write_all(&header)
        .await
        .map_err(|e| SessionOpenError::ConnectionLost(format!("write session header: {e}")))?;
    send.flush()
        .await
        .map_err(|e| SessionOpenError::ConnectionLost(format!("flush session header: {e}")))?;
    Ok(())
}

async fn read_session_stream_header<R>(
    recv: &mut R,
) -> Result<(u64, SessionClass, SessionStreamKind), SessionOpenError>
where
    R: AsyncRead + Unpin + Send,
{
    // Read first 7 bytes to check magic + version before committing to full read.
    let mut prefix = [0u8; 7];
    recv.read_exact(&mut prefix)
        .await
        .map_err(|e| SessionOpenError::ConnectionLost(format!("read session header: {e}")))?;
    if prefix[..4] != SESSION_STREAM_HEADER_MAGIC {
        return Err(SessionOpenError::Protocol(
            "missing session stream magic".to_string(),
        ));
    }
    let remote_version = prefix[4];
    if remote_version != SESSION_STREAM_HEADER_VERSION {
        return Err(SessionOpenError::Protocol(
            build_mismatch_reason_remote_protocol(remote_version),
        ));
    }
    let class = SessionClass::from_byte(prefix[5])?;
    let kind = SessionStreamKind::from_byte(prefix[6])?;

    // Read remaining 16 bytes: [8 session_id][8 commit_hash]
    let mut rest = [0u8; 16];
    recv.read_exact(&mut rest)
        .await
        .map_err(|e| SessionOpenError::ConnectionLost(format!("read session header: {e}")))?;
    let mut session_id_bytes = [0u8; 8];
    session_id_bytes.copy_from_slice(&rest[..8]);

    // Check commit hash match
    let local_hash = local_commit_hash();
    let remote_hash = &rest[8..16];
    if remote_hash != &local_hash {
        let remote_str = String::from_utf8_lossy(remote_hash);
        return Err(SessionOpenError::Protocol(
            build_mismatch_reason_remote_hash(remote_str.trim_end_matches('\0')),
        ));
    }

    Ok((u64::from_be_bytes(session_id_bytes), class, kind))
}

struct CompletedInboundSession<S, R> {
    session_id: u64,
    class: SessionClass,
    control: BiStream<S, R>,
    data: BiStream<S, R>,
}

fn insert_pending_stream<S, R>(
    state: &InboundSessionState<S, R>,
    session_id: u64,
    class: SessionClass,
    kind: SessionStreamKind,
    send: S,
    recv: R,
) -> Result<Option<CompletedInboundSession<S, R>>, SessionOpenError> {
    let mut pending = state
        .pending
        .lock()
        .map_err(|_| SessionOpenError::Protocol("pending session state poisoned".to_string()))?;
    let entry = pending.entry(session_id).or_default();
    match entry.class {
        Some(existing) if existing != class => {
            return Err(SessionOpenError::Protocol(format!(
                "mismatched session class for session {}",
                session_id
            )))
        }
        None => entry.class = Some(class),
        Some(_) => {}
    }
    let slot = match kind {
        SessionStreamKind::Control => &mut entry.control,
        SessionStreamKind::Data => &mut entry.data,
    };
    if slot.is_some() {
        return Err(SessionOpenError::Protocol(format!(
            "duplicate {:?} stream for session {}",
            kind, session_id
        )));
    }
    *slot = Some((send, recv));

    if entry.control.is_some() && entry.data.is_some() {
        let complete = pending.remove(&session_id).expect("pending entry exists");
        Ok(Some(CompletedInboundSession {
            session_id,
            class: complete.class.expect("session class present"),
            control: complete.control.expect("control stream present"),
            data: complete.data.expect("data stream present"),
        }))
    } else {
        Ok(None)
    }
}

pub async fn open_session_io_for_class<C>(
    conn: &C,
    class: SessionClass,
) -> Result<(u64, Box<dyn TransportSessionIo>), SessionOpenError>
where
    C: SessionCarrier,
{
    let session_id = next_session_id();
    let (mut ctrl_send, ctrl_recv) = conn
        .open_bi()
        .await
        .map_err(SessionOpenError::ConnectionLost)?;
    write_session_stream_header(
        &mut ctrl_send,
        session_id,
        class,
        SessionStreamKind::Control,
    )
    .await?;
    let (mut data_send, data_recv) = conn
        .open_bi()
        .await
        .map_err(SessionOpenError::ConnectionLost)?;
    write_session_stream_header(&mut data_send, session_id, class, SessionStreamKind::Data).await?;
    let dual = DualConnection::from_parts(
        Connection::new(ctrl_send, ctrl_recv),
        SendConnection::new(data_send),
        RecvConnection::new(data_recv),
    );
    let io = QuicTransportSessionIo::new(session_id, dual);
    Ok((session_id, Box::new(io)))
}

/// Open two bidirectional streams (control + data) as a range session.
pub async fn open_range_session_io<C>(
    conn: &C,
) -> Result<(u64, Box<dyn TransportSessionIo>), SessionOpenError>
where
    C: SessionCarrier,
{
    open_session_io_for_class(conn, SessionClass::Range).await
}

/// Accept two bidirectional streams (control + data) as responder and wrap
/// into a `TransportSessionIo`. Returns `(session_id, class, io)`.
pub async fn accept_session_io<C>(
    conn: &C,
    state: &InboundSessionState<C::BiSend, C::BiRecv>,
) -> Result<(u64, SessionClass, Box<dyn TransportSessionIo>), SessionOpenError>
where
    C: SessionCarrier,
{
    loop {
        let (send, mut recv) = conn
            .accept_bi()
            .await
            .map_err(SessionOpenError::ConnectionLost)?;
        let (session_id, class, kind) = match read_session_stream_header(&mut recv).await {
            Ok(header) => header,
            Err(SessionOpenError::Protocol(message))
                if extract_build_mismatch_reason(&message).is_some() =>
            {
                let reason = connection_close_reason(&message);
                conn.close_with_reason(1, &reason);
                return Err(SessionOpenError::Protocol(message));
            }
            Err(err) => return Err(err),
        };
        if let Some(complete) = insert_pending_stream(state, session_id, class, kind, send, recv)? {
            let dual = DualConnection::from_parts(
                Connection::new(complete.control.0, complete.control.1),
                SendConnection::new(complete.data.0),
                RecvConnection::new(complete.data.1),
            );
            let io = QuicTransportSessionIo::new(complete.session_id, dual);
            return Ok((complete.session_id, complete.class, Box::new(io)));
        }
    }
}

#[cfg(all(test, feature = "iroh-transport"))]
mod tests {
    use tokio::io::AsyncWriteExt;

    use crate::protocol::{encode_frame, parse_frame, Frame};
    use crate::transport::{
        accept_daemon_connection, create_runtime_endpoint_for_tenants, dial_daemon_connection,
        load_daemon_identity_from_db, multi_workspace::transport_sni, TransportConnection,
        TransportEndpoint,
    };

    use super::{
        accept_session_io, local_commit_hash_str, local_commit_subject, open_range_session_io,
        write_session_stream_header, InboundSessionState, SessionCarrier, SessionClass,
        SessionOpenError, SessionStreamKind, BUILD_MISMATCH_PREFIX, SESSION_STREAM_HEADER_LEN,
        SESSION_STREAM_HEADER_MAGIC, SESSION_STREAM_HEADER_VERSION,
    };

    async fn connected_pair() -> Result<
        (
            tempfile::TempDir,
            TransportEndpoint,
            TransportConnection,
            TransportEndpoint,
            TransportConnection,
        ),
        Box<dyn std::error::Error + Send + Sync>,
    > {
        let temp = tempfile::tempdir()?;
        let server_db = temp.path().join("server.sqlite3");
        let client_db = temp.path().join("client.sqlite3");
        let server_ep = create_runtime_endpoint_for_tenants(
            "127.0.0.1:0".parse().unwrap(),
            server_db.to_str().unwrap(),
        )
        .await?;
        let client_ep = create_runtime_endpoint_for_tenants(
            "127.0.0.1:0".parse().unwrap(),
            client_db.to_str().unwrap(),
        )
        .await?;

        let server_addr = server_ep.local_addr()?;
        let server_peer_id = load_daemon_identity_from_db(server_db.to_str().unwrap())?.0;
        let server_sni = transport_sni(&server_peer_id);

        let (server_conn_res, client_conn_res) = tokio::join!(
            accept_daemon_connection(&server_ep),
            dial_daemon_connection(&client_ep, server_addr, &server_sni)
        );
        let server_conn = server_conn_res?
            .expect("server accepted connection")
            .connection();
        let client_conn = client_conn_res?.connection();

        Ok((temp, server_ep, server_conn, client_ep, client_conn))
    }

    #[tokio::test]
    async fn open_session_io_succeeds_when_peer_accepts_streams() {
        let (_temp, _server_ep, server_conn, _client_ep, client_conn) =
            connected_pair().await.expect("connected pair");

        let server_accept_task = tokio::task::spawn(async move {
            server_conn
                .accept_bi()
                .await
                .map_err(|e| format!("control accept: {e}"))?;
            server_conn
                .accept_bi()
                .await
                .map_err(|e| format!("data accept: {e}"))?;
            Ok::<(), String>(())
        });

        let (client_session_id, client_io) = open_range_session_io(&client_conn)
            .await
            .expect("open_range_session_io");
        assert!(client_session_id > 0);
        drop(client_io);

        server_accept_task
            .await
            .expect("server accept task join")
            .expect("server accepted two streams");
    }

    #[tokio::test]
    async fn accept_session_io_succeeds_when_peer_preopens_streams() {
        let (_temp, _server_ep, server_conn, _client_ep, client_conn) =
            connected_pair().await.expect("connected pair");
        let inbound_state = InboundSessionState::default();

        // Pre-open the two bi streams the responder expects.
        let session_id = 77;
        let (mut ctrl_send, _ctrl_recv) =
            client_conn.inner.open_bi().await.expect("open control bi");
        write_session_stream_header(
            &mut ctrl_send,
            session_id,
            SessionClass::Range,
            SessionStreamKind::Control,
        )
        .await
        .expect("write control header");
        let (mut data_send, _data_recv) = client_conn.inner.open_bi().await.expect("open data bi");
        write_session_stream_header(
            &mut data_send,
            session_id,
            SessionClass::Range,
            SessionStreamKind::Data,
        )
        .await
        .expect("write data header");

        let (server_session_id, server_class, server_io) =
            accept_session_io(&server_conn, &inbound_state)
                .await
                .expect("accept_session_io");
        assert_eq!(server_session_id, session_id);
        assert_eq!(server_class, SessionClass::Range);
        drop(server_io);
    }

    #[tokio::test]
    async fn accept_session_io_pairs_interleaved_streams_by_session_header() {
        let (_temp, _server_ep, server_conn, _client_ep, client_conn) =
            connected_pair().await.expect("connected pair");
        let inbound_state = InboundSessionState::default();

        let session_a = 1001;
        let session_b = 2002;
        let control_a = Frame::NegOpen { msg: vec![0x0a] };
        let control_b = Frame::NegOpen { msg: vec![0x0b] };
        let data_a = Frame::Event { blob: vec![0xa1] };
        let data_b = Frame::Event { blob: vec![0xb2] };

        let (mut ctrl_a_send, _ctrl_a_recv) =
            client_conn.inner.open_bi().await.expect("open ctrl a");
        write_session_stream_header(
            &mut ctrl_a_send,
            session_a,
            SessionClass::Range,
            SessionStreamKind::Control,
        )
        .await
        .expect("write ctrl a header");
        ctrl_a_send
            .write_all(&encode_frame(&control_a))
            .await
            .expect("write ctrl a frame");
        ctrl_a_send.flush().await.expect("flush ctrl a frame");

        let (mut ctrl_b_send, _ctrl_b_recv) =
            client_conn.inner.open_bi().await.expect("open ctrl b");
        write_session_stream_header(
            &mut ctrl_b_send,
            session_b,
            SessionClass::Range,
            SessionStreamKind::Control,
        )
        .await
        .expect("write ctrl b header");
        ctrl_b_send
            .write_all(&encode_frame(&control_b))
            .await
            .expect("write ctrl b frame");
        ctrl_b_send.flush().await.expect("flush ctrl b frame");

        let (mut data_a_send, _data_a_recv) =
            client_conn.inner.open_bi().await.expect("open data a");
        write_session_stream_header(
            &mut data_a_send,
            session_a,
            SessionClass::Range,
            SessionStreamKind::Data,
        )
        .await
        .expect("write data a header");
        data_a_send
            .write_all(&encode_frame(&data_a))
            .await
            .expect("write data a frame");
        data_a_send.flush().await.expect("flush data a frame");

        let (mut data_b_send, _data_b_recv) =
            client_conn.inner.open_bi().await.expect("open data b");
        write_session_stream_header(
            &mut data_b_send,
            session_b,
            SessionClass::Range,
            SessionStreamKind::Data,
        )
        .await
        .expect("write data b header");
        data_b_send
            .write_all(&encode_frame(&data_b))
            .await
            .expect("write data b frame");
        data_b_send.flush().await.expect("flush data b frame");

        let (accepted_a_id, accepted_a_class, accepted_a_io) =
            accept_session_io(&server_conn, &inbound_state)
                .await
                .expect("accept first session");
        assert_eq!(accepted_a_id, session_a);
        assert_eq!(accepted_a_class, SessionClass::Range);
        let mut accepted_a = accepted_a_io.split();
        let accepted_a_control = accepted_a.control.recv().await.expect("recv control a");
        let accepted_a_data = accepted_a.data_recv.recv().await.expect("recv data a");
        assert_eq!(
            parse_frame(&accepted_a_control).expect("parse control a").0,
            control_a
        );
        assert_eq!(
            parse_frame(&accepted_a_data).expect("parse data a").0,
            data_a
        );

        let (accepted_b_id, accepted_b_class, accepted_b_io) =
            accept_session_io(&server_conn, &inbound_state)
                .await
                .expect("accept second session");
        assert_eq!(accepted_b_id, session_b);
        assert_eq!(accepted_b_class, SessionClass::Range);
        let mut accepted_b = accepted_b_io.split();
        let accepted_b_control = accepted_b.control.recv().await.expect("recv control b");
        let accepted_b_data = accepted_b.data_recv.recv().await.expect("recv data b");
        assert_eq!(
            parse_frame(&accepted_b_control).expect("parse control b").0,
            control_b
        );
        assert_eq!(
            parse_frame(&accepted_b_data).expect("parse data b").0,
            data_b
        );
    }

    #[tokio::test]
    async fn open_session_io_returns_error_after_connection_close() {
        let (_temp, _server_ep, _server_conn, _client_ep, client_conn) =
            connected_pair().await.expect("connected pair");
        client_conn.close(0u32.into(), b"test-close");
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;

        let err = match open_range_session_io(&client_conn).await {
            Ok(_) => panic!("expected stream open failure after close"),
            Err(err) => err,
        };
        match err {
            super::SessionOpenError::ConnectionLost(msg) => {
                assert!(!msg.is_empty(), "error message should be populated");
            }
            super::SessionOpenError::Protocol(msg) => {
                panic!("expected connection-lost error after close, got protocol error: {msg}");
            }
        }
    }

    #[cfg(feature = "iroh-transport")]
    #[tokio::test]
    async fn accept_session_io_reports_build_mismatch_and_closes_with_reason() {
        let (_temp, _server_ep, server_conn, _client_ep, client_conn) =
            connected_pair().await.expect("connected pair");
        let inbound_state = InboundSessionState::default();

        let remote_hash = if local_commit_hash_str() == "deadbeef" {
            *b"badc0ffe"
        } else {
            *b"deadbeef"
        };

        let (mut ctrl_send, _ctrl_recv) =
            client_conn.inner.open_bi().await.expect("open control bi");
        let mut header = [0u8; SESSION_STREAM_HEADER_LEN];
        header[..4].copy_from_slice(&SESSION_STREAM_HEADER_MAGIC);
        header[4] = SESSION_STREAM_HEADER_VERSION;
        header[5] = SessionClass::Range.to_byte();
        header[6] = SessionStreamKind::Control.to_byte();
        header[7..15].copy_from_slice(&77u64.to_be_bytes());
        header[15..23].copy_from_slice(&remote_hash);
        ctrl_send
            .write_all(&header)
            .await
            .expect("write mismatched control header");
        ctrl_send
            .flush()
            .await
            .expect("flush mismatched control header");

        let err = match accept_session_io(&server_conn, &inbound_state).await {
            Ok(_) => panic!("accept should reject mismatched build"),
            Err(err) => err,
        };
        let message = match err {
            SessionOpenError::Protocol(message) => message,
            other => panic!("expected protocol error, got {other}"),
        };
        assert!(
            message.contains(BUILD_MISMATCH_PREFIX),
            "expected human-readable build mismatch message: {message}"
        );
        assert!(
            message.contains(local_commit_hash_str()),
            "expected local commit hash in mismatch message: {message}"
        );
        assert!(
            message.contains(local_commit_subject()),
            "expected local commit subject in mismatch message: {message}"
        );
        assert!(
            message.contains("deadbeef") || message.contains("badc0ffe"),
            "expected remote hash in mismatch message: {message}"
        );

        let closed = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            client_conn.inner.closed(),
        )
        .await
        .expect("client should observe connection close");
        match closed {
            iroh::endpoint::ConnectionError::ApplicationClosed(close) => {
                let reason = String::from_utf8_lossy(close.reason.as_ref());
                assert!(
                    reason.contains(BUILD_MISMATCH_PREFIX),
                    "expected propagated close reason, got {reason}"
                );
                assert!(
                    reason.contains(local_commit_hash_str()),
                    "expected local build hash in close reason, got {reason}"
                );
            }
            other => panic!("expected application close, got {other}"),
        }
    }
}
