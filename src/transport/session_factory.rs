//! Session factory: opens QUIC streams and wraps them into contract-level
//! `TransportSessionIo`. This is the sole owner of stream wiring; peering
//! callers receive ready-to-use session IO without touching QUIC stream types.

use crate::contracts::peering_contract::{next_session_id, TransportSessionIo};
use crate::protocol::{parse_frame, Frame};

use super::{DualConnection, QuicTransportSessionIo};

/// Error from session stream opening.
#[derive(Debug)]
pub enum SessionOpenError {
    /// The QUIC connection dropped while opening streams.
    ConnectionLost(String),
}

impl std::fmt::Display for SessionOpenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SessionOpenError::ConnectionLost(e) => write!(f, "connection lost: {}", e),
        }
    }
}

impl std::error::Error for SessionOpenError {}

/// Open two bidirectional streams (control + data) as initiator and wrap
/// into a `TransportSessionIo`. Returns `(session_id, io)`.
pub async fn open_session_io(
    conn: &quinn::Connection,
) -> Result<(u64, Box<dyn TransportSessionIo>), SessionOpenError> {
    let (ctrl_send, ctrl_recv) = conn
        .open_bi()
        .await
        .map_err(|e| SessionOpenError::ConnectionLost(format!("control open: {e}")))?;
    let (data_send, data_recv) = conn
        .open_bi()
        .await
        .map_err(|e| SessionOpenError::ConnectionLost(format!("data open: {e}")))?;
    let dual = DualConnection::new(ctrl_send, ctrl_recv, data_send, data_recv);
    let session_id = next_session_id();
    let io = QuicTransportSessionIo::new(session_id, dual);
    Ok((session_id, Box::new(io)))
}

/// Accept two bidirectional streams (control + data) as responder and wrap
/// into a `TransportSessionIo`. Returns `(session_id, io)`.
pub async fn accept_session_io(
    conn: &quinn::Connection,
) -> Result<(u64, Box<dyn TransportSessionIo>), SessionOpenError> {
    let (ctrl_send, ctrl_recv) = conn
        .accept_bi()
        .await
        .map_err(|e| SessionOpenError::ConnectionLost(format!("control accept: {e}")))?;
    let (data_send, data_recv) = conn
        .accept_bi()
        .await
        .map_err(|e| SessionOpenError::ConnectionLost(format!("data accept: {e}")))?;
    let dual = DualConnection::new(ctrl_send, ctrl_recv, data_send, data_recv);
    let session_id = next_session_id();
    let io = QuicTransportSessionIo::new(session_id, dual);
    Ok((session_id, Box::new(io)))
}

/// Accept a unidirectional stream from a QUIC connection and read an
/// IntroOffer message. Returns `None` if the connection was closed (normal
/// shutdown), `Err` for read/parse failures, or `Ok(Some(frame))` on success.
pub async fn accept_and_read_intro(
    conn: &quinn::Connection,
) -> Result<Option<Frame>, Box<dyn std::error::Error + Send + Sync>> {
    let mut recv = match conn.accept_uni().await {
        Ok(r) => r,
        Err(_) => return Ok(None),
    };
    // IntroOffer is a fixed 88 bytes on the wire
    let mut buf = vec![0u8; 88];
    recv.read_exact(&mut buf).await?;
    let (msg, _) = parse_frame(&buf)?;
    Ok(Some(msg))
}
