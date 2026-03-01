//! Intro uni-stream I/O helpers.
//!
//! Keeps intro frame receive/parsing separate from the session stream factory
//! so transport boundaries stay explicit:
//! - `session_factory`: sync control/data bi-stream wiring only
//! - `intro_io`: intro offer uni-stream receive path

use crate::protocol::{parse_frame, Frame};

/// IntroOffer fixed wire size:
/// type(1) + intro_id(16) + other_peer_id(32) + family(1) + ip(16)
/// + port(2) + observed_at_ms(8) + expires_at_ms(8) + attempt_window_ms(4).
pub const INTRO_OFFER_WIRE_BYTES: usize = 88;

/// Accept one uni stream and parse one IntroOffer-sized frame.
///
/// Returns:
/// - `Ok(Some(frame))`: parsed frame
/// - `Ok(None)`: connection closed while waiting for a uni stream
/// - `Err(_)`: read/parse failure
pub async fn accept_and_read_intro(
    conn: &quinn::Connection,
) -> Result<Option<Frame>, Box<dyn std::error::Error + Send + Sync>> {
    let mut recv = match conn.accept_uni().await {
        Ok(r) => r,
        Err(_) => return Ok(None),
    };

    let mut buf = vec![0u8; INTRO_OFFER_WIRE_BYTES];
    recv.read_exact(&mut buf).await?;
    let (msg, _) = parse_frame(&buf)?;
    Ok(Some(msg))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::protocol::{encode_frame, Frame};
    use crate::transport::{
        create_dual_endpoint, extract_spki_fingerprint, generate_self_signed_cert, AllowedPeers,
    };

    use super::accept_and_read_intro;

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
    async fn accept_and_read_intro_roundtrip_intro_offer() {
        let (_server_ep, server_conn, _client_ep, client_conn) =
            connected_pair().await.expect("connected pair");

        let intro = Frame::IntroOffer {
            intro_id: [0x11; 16],
            other_peer_id: [0x22; 32],
            origin_family: 4,
            origin_ip: [0; 16],
            origin_port: 4433,
            observed_at_ms: 1000,
            expires_at_ms: 5000,
            attempt_window_ms: 1200,
        };

        let mut uni = client_conn.open_uni().await.expect("open uni");
        uni.write_all(&encode_frame(&intro))
            .await
            .expect("write intro frame");
        uni.finish().expect("finish uni stream");

        let read = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            accept_and_read_intro(&server_conn),
        )
        .await
        .expect("timeout waiting intro")
        .expect("read intro")
        .expect("intro frame present");

        assert_eq!(read, intro);
    }

    #[tokio::test]
    async fn accept_and_read_intro_returns_none_when_connection_closed() {
        let (_server_ep, server_conn, _client_ep, _client_conn) =
            connected_pair().await.expect("connected pair");
        server_conn.close(0u32.into(), b"test-close");

        let read = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            accept_and_read_intro(&server_conn),
        )
        .await
        .expect("timeout waiting close result")
        .expect("accept/read result");

        assert!(
            read.is_none(),
            "closed connection should return Ok(None), got {:?}",
            read
        );
    }
}
