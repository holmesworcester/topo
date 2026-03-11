//! Session factory: opens QUIC streams and wraps them into contract-level
//! `TransportSessionIo`. This is the sole owner of stream wiring; peering
//! callers receive ready-to-use session IO without touching QUIC stream types.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use tokio::io::AsyncWriteExt;

use crate::contracts::peering_contract::{next_session_id, TransportSessionIo};

use super::{DualConnection, QuicTransportSessionIo};

const SESSION_STREAM_HEADER_MAGIC: [u8; 4] = *b"P7SS";
const SESSION_STREAM_HEADER_VERSION: u8 = 1;
const SESSION_STREAM_HEADER_LEN: usize = 14;

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

type BiStream = (quinn::SendStream, quinn::RecvStream);

#[derive(Default)]
struct PendingInboundSession {
    control: Option<BiStream>,
    data: Option<BiStream>,
}

#[derive(Default, Clone)]
pub struct InboundSessionState {
    pending: Arc<Mutex<HashMap<u64, PendingInboundSession>>>,
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

async fn write_session_stream_header(
    send: &mut quinn::SendStream,
    session_id: u64,
    kind: SessionStreamKind,
) -> Result<(), SessionOpenError> {
    let mut header = [0u8; SESSION_STREAM_HEADER_LEN];
    header[..4].copy_from_slice(&SESSION_STREAM_HEADER_MAGIC);
    header[4] = SESSION_STREAM_HEADER_VERSION;
    header[5] = kind.to_byte();
    header[6..].copy_from_slice(&session_id.to_be_bytes());
    send.write_all(&header)
        .await
        .map_err(|e| SessionOpenError::ConnectionLost(format!("write session header: {e}")))?;
    send.flush()
        .await
        .map_err(|e| SessionOpenError::ConnectionLost(format!("flush session header: {e}")))?;
    Ok(())
}

async fn read_session_stream_header(
    recv: &mut quinn::RecvStream,
) -> Result<(u64, SessionStreamKind), SessionOpenError> {
    let mut header = [0u8; SESSION_STREAM_HEADER_LEN];
    recv.read_exact(&mut header)
        .await
        .map_err(|e| SessionOpenError::ConnectionLost(format!("read session header: {e}")))?;
    if header[..4] != SESSION_STREAM_HEADER_MAGIC {
        return Err(SessionOpenError::Protocol(
            "missing session stream magic".to_string(),
        ));
    }
    if header[4] != SESSION_STREAM_HEADER_VERSION {
        return Err(SessionOpenError::Protocol(format!(
            "unsupported session stream version {}",
            header[4]
        )));
    }
    let kind = SessionStreamKind::from_byte(header[5])?;
    let mut session_id_bytes = [0u8; 8];
    session_id_bytes.copy_from_slice(&header[6..]);
    Ok((u64::from_be_bytes(session_id_bytes), kind))
}

struct CompletedInboundSession {
    session_id: u64,
    control: BiStream,
    data: BiStream,
}

fn insert_pending_stream(
    state: &InboundSessionState,
    session_id: u64,
    kind: SessionStreamKind,
    send: quinn::SendStream,
    recv: quinn::RecvStream,
) -> Result<Option<CompletedInboundSession>, SessionOpenError> {
    let mut pending = state
        .pending
        .lock()
        .map_err(|_| SessionOpenError::Protocol("pending session state poisoned".to_string()))?;
    let entry = pending.entry(session_id).or_default();
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
            control: complete.control.expect("control stream present"),
            data: complete.data.expect("data stream present"),
        }))
    } else {
        Ok(None)
    }
}

/// Open two bidirectional streams (control + data) as initiator and wrap
/// into a `TransportSessionIo`. Returns `(session_id, io)`.
pub async fn open_session_io(
    conn: &quinn::Connection,
) -> Result<(u64, Box<dyn TransportSessionIo>), SessionOpenError> {
    let session_id = next_session_id();
    let (mut ctrl_send, ctrl_recv) = conn
        .open_bi()
        .await
        .map_err(|e| SessionOpenError::ConnectionLost(format!("control open: {e}")))?;
    write_session_stream_header(&mut ctrl_send, session_id, SessionStreamKind::Control).await?;
    let (mut data_send, data_recv) = conn
        .open_bi()
        .await
        .map_err(|e| SessionOpenError::ConnectionLost(format!("data open: {e}")))?;
    write_session_stream_header(&mut data_send, session_id, SessionStreamKind::Data).await?;
    let dual = DualConnection::new(ctrl_send, ctrl_recv, data_send, data_recv);
    let io = QuicTransportSessionIo::new(session_id, dual);
    Ok((session_id, Box::new(io)))
}

/// Accept two bidirectional streams (control + data) as responder and wrap
/// into a `TransportSessionIo`. Returns `(session_id, io)`.
pub async fn accept_session_io(
    conn: &quinn::Connection,
    state: &InboundSessionState,
) -> Result<(u64, Box<dyn TransportSessionIo>), SessionOpenError> {
    loop {
        let (send, mut recv) = conn
            .accept_bi()
            .await
            .map_err(|e| SessionOpenError::ConnectionLost(format!("stream accept: {e}")))?;
        let (session_id, kind) = read_session_stream_header(&mut recv).await?;
        if let Some(complete) = insert_pending_stream(state, session_id, kind, send, recv)? {
            let dual = DualConnection::new(
                complete.control.0,
                complete.control.1,
                complete.data.0,
                complete.data.1,
            );
            let io = QuicTransportSessionIo::new(complete.session_id, dual);
            return Ok((complete.session_id, Box::new(io)));
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use tokio::io::AsyncWriteExt;

    use crate::protocol::{encode_frame, parse_frame, Frame};
    use crate::transport::{
        create_dual_endpoint, extract_spki_fingerprint, generate_self_signed_cert, AllowedPeers,
    };

    use super::{
        accept_session_io, open_session_io, write_session_stream_header, InboundSessionState,
        SessionStreamKind,
    };

    async fn connected_pair() -> Result<
        (
            quinn::Endpoint,
            quinn::Connection,
            quinn::Endpoint,
            quinn::Connection,
        ),
        Box<dyn std::error::Error + Send + Sync>,
    > {
        let (server_cert, server_key) = generate_self_signed_cert()?;
        let server_fp = extract_spki_fingerprint(server_cert.as_ref())?;
        let (client_cert, client_key) = generate_self_signed_cert()?;
        let client_fp = extract_spki_fingerprint(client_cert.as_ref())?;

        let server_allowed = Arc::new(AllowedPeers::from_fingerprints(vec![client_fp]));
        let client_allowed = Arc::new(AllowedPeers::from_fingerprints(vec![server_fp]));

        let server_ep = create_dual_endpoint(
            "127.0.0.1:0".parse().unwrap(),
            server_cert,
            server_key,
            server_allowed,
        )?;
        let client_ep = create_dual_endpoint(
            "127.0.0.1:0".parse().unwrap(),
            client_cert,
            client_key,
            client_allowed,
        )?;

        let server_addr = server_ep.local_addr()?;
        let server_ep_accept = server_ep.clone();
        let server_accept = async move {
            let incoming = server_ep_accept
                .accept()
                .await
                .ok_or_else(|| "server endpoint closed unexpectedly".to_string())?;
            let conn = incoming.await?;
            Ok::<quinn::Connection, Box<dyn std::error::Error + Send + Sync>>(conn)
        };

        let client_ep_connect = client_ep.clone();
        let client_connect = async move {
            let connecting = client_ep_connect.connect(server_addr, "localhost")?;
            let conn = connecting.await?;
            Ok::<quinn::Connection, Box<dyn std::error::Error + Send + Sync>>(conn)
        };

        let (server_conn_res, client_conn_res) = tokio::join!(server_accept, client_connect);
        let server_conn = server_conn_res?;
        let client_conn = client_conn_res?;

        Ok((server_ep, server_conn, client_ep, client_conn))
    }

    #[tokio::test]
    async fn open_session_io_succeeds_when_peer_accepts_streams() {
        let (_server_ep, server_conn, _client_ep, client_conn) =
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

        let (client_session_id, client_io) = open_session_io(&client_conn)
            .await
            .expect("open_session_io");
        assert!(client_session_id > 0);
        let mut parts = client_io.split();
        let marker = encode_frame(&Frame::HaveList { ids: vec![] });
        parts
            .control
            .send(&marker)
            .await
            .expect("send control marker");
        parts
            .data_send
            .send(&marker)
            .await
            .expect("send data marker");
        parts.control.flush().await.expect("flush control marker");
        parts.data_send.flush().await.expect("flush data marker");

        server_accept_task
            .await
            .expect("server accept task join")
            .expect("server accepted two streams");
    }

    #[tokio::test]
    async fn accept_session_io_succeeds_when_peer_preopens_streams() {
        let (_server_ep, server_conn, _client_ep, client_conn) =
            connected_pair().await.expect("connected pair");
        let inbound_state = InboundSessionState::default();

        // Pre-open the two bi streams the responder expects.
        let session_id = 77;
        let (mut ctrl_send, _ctrl_recv) = client_conn.open_bi().await.expect("open control bi");
        write_session_stream_header(&mut ctrl_send, session_id, SessionStreamKind::Control)
            .await
            .expect("write control header");
        let (mut data_send, _data_recv) = client_conn.open_bi().await.expect("open data bi");
        write_session_stream_header(&mut data_send, session_id, SessionStreamKind::Data)
            .await
            .expect("write data header");
        let marker = encode_frame(&Frame::HaveList { ids: vec![] });
        ctrl_send
            .write_all(&marker)
            .await
            .expect("write control marker");
        ctrl_send.flush().await.expect("flush control marker");
        data_send
            .write_all(&marker)
            .await
            .expect("write data marker");
        data_send.flush().await.expect("flush data marker");

        let (server_session_id, server_io) = accept_session_io(&server_conn, &inbound_state)
            .await
            .expect("accept_session_io");
        assert_eq!(server_session_id, session_id);

        let mut server_parts = server_io.split();
        let recv = server_parts
            .control
            .recv()
            .await
            .expect("recv control frame");
        let (parsed, consumed) = parse_frame(&recv).expect("parse recv frame");
        assert_eq!(consumed, recv.len());
        match parsed {
            Frame::HaveList { ids } => assert!(ids.is_empty()),
            other => panic!("expected HaveList marker, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn accept_session_io_pairs_interleaved_streams_by_session_header() {
        let (_server_ep, server_conn, _client_ep, client_conn) =
            connected_pair().await.expect("connected pair");
        let inbound_state = InboundSessionState::default();

        let session_a = 1001;
        let session_b = 2002;
        let control_a = Frame::NegOpen { msg: vec![0x0a] };
        let control_b = Frame::NegOpen { msg: vec![0x0b] };
        let data_a = Frame::Event { blob: vec![0xa1] };
        let data_b = Frame::Event { blob: vec![0xb2] };

        let (mut ctrl_a_send, _ctrl_a_recv) = client_conn.open_bi().await.expect("open ctrl a");
        write_session_stream_header(&mut ctrl_a_send, session_a, SessionStreamKind::Control)
            .await
            .expect("write ctrl a header");
        ctrl_a_send
            .write_all(&encode_frame(&control_a))
            .await
            .expect("write ctrl a frame");
        ctrl_a_send.flush().await.expect("flush ctrl a frame");

        let (mut ctrl_b_send, _ctrl_b_recv) = client_conn.open_bi().await.expect("open ctrl b");
        write_session_stream_header(&mut ctrl_b_send, session_b, SessionStreamKind::Control)
            .await
            .expect("write ctrl b header");
        ctrl_b_send
            .write_all(&encode_frame(&control_b))
            .await
            .expect("write ctrl b frame");
        ctrl_b_send.flush().await.expect("flush ctrl b frame");

        let (mut data_a_send, _data_a_recv) = client_conn.open_bi().await.expect("open data a");
        write_session_stream_header(&mut data_a_send, session_a, SessionStreamKind::Data)
            .await
            .expect("write data a header");
        data_a_send
            .write_all(&encode_frame(&data_a))
            .await
            .expect("write data a frame");
        data_a_send.flush().await.expect("flush data a frame");

        let (mut data_b_send, _data_b_recv) = client_conn.open_bi().await.expect("open data b");
        write_session_stream_header(&mut data_b_send, session_b, SessionStreamKind::Data)
            .await
            .expect("write data b header");
        data_b_send
            .write_all(&encode_frame(&data_b))
            .await
            .expect("write data b frame");
        data_b_send.flush().await.expect("flush data b frame");

        let (accepted_a_id, accepted_a_io) = accept_session_io(&server_conn, &inbound_state)
            .await
            .expect("accept first session");
        assert_eq!(accepted_a_id, session_a);
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

        let (accepted_b_id, accepted_b_io) = accept_session_io(&server_conn, &inbound_state)
            .await
            .expect("accept second session");
        assert_eq!(accepted_b_id, session_b);
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
        let (_server_ep, _server_conn, _client_ep, client_conn) =
            connected_pair().await.expect("connected pair");
        client_conn.close(0u32.into(), b"test-close");
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;

        let err = match open_session_io(&client_conn).await {
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
}
