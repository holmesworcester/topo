//! Session factory: opens QUIC streams and wraps them into contract-level
//! `TransportSessionIo`. This is the sole owner of stream wiring; peering
//! callers receive ready-to-use session IO without touching QUIC stream types.

use crate::contracts::peering_contract::{next_session_id, TransportSessionIo};

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

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::protocol::{encode_frame, parse_frame, Frame};
    use crate::transport::{
        create_dual_endpoint, extract_spki_fingerprint, generate_self_signed_cert, AllowedPeers,
    };

    use super::{accept_session_io, open_session_io};

    async fn connected_pair(
    ) -> Result<
        (quinn::Endpoint, quinn::Connection, quinn::Endpoint, quinn::Connection),
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

        let (client_session_id, client_io) =
            open_session_io(&client_conn).await.expect("open_session_io");
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

        // Pre-open the two bi streams the responder expects.
        let (mut ctrl_send, _ctrl_recv) = client_conn.open_bi().await.expect("open control bi");
        let (mut data_send, _data_recv) = client_conn.open_bi().await.expect("open data bi");
        let marker = encode_frame(&Frame::HaveList { ids: vec![] });
        ctrl_send
            .write_all(&marker)
            .await
            .expect("write control marker");
        data_send
            .write_all(&marker)
            .await
            .expect("write data marker");

        let (server_session_id, server_io) =
            accept_session_io(&server_conn).await.expect("accept_session_io");
        assert!(server_session_id > 0);

        let mut server_parts = server_io.split();
        let recv = server_parts.control.recv().await.expect("recv control frame");
        let (parsed, consumed) = parse_frame(&recv).expect("parse recv frame");
        assert_eq!(consumed, recv.len());
        match parsed {
            Frame::HaveList { ids } => assert!(ids.is_empty()),
            other => panic!("expected HaveList marker, got {:?}", other),
        }
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
        }
    }
}
