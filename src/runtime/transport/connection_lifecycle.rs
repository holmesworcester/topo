//! Connection lifecycle helpers shared by peering loops/workflows.
//!
//! Keeps QUIC dial/accept + peer identity extraction in transport so peering
//! can focus on orchestration/retry logic.

use std::net::SocketAddr;

use thiserror::Error;

use crate::transport::peer_identity_from_connection;
use super::TRUST_REJECTION_MARKER;

/// A successful transport connection with verified peer identity.
pub struct ConnectedPeer {
    pub connection: quinn::Connection,
    /// Hex-encoded peer certificate SPKI fingerprint (transport identity).
    pub peer_id: String,
}

impl ConnectedPeer {
    /// Canonical transport-facing name for `peer_id`.
    pub fn transport_fingerprint(&self) -> &str {
        &self.peer_id
    }
}

#[derive(Debug, Error)]
pub enum ConnectionLifecycleError {
    #[error("dial failed: {0}")]
    Dial(String),
    #[error("dial rejected by trust policy: {0}")]
    DialTrustRejected(String),
    #[error("accept failed: {0}")]
    Accept(String),
    #[error("missing peer identity from TLS session")]
    MissingPeerIdentity,
}

fn into_connected_peer(
    connection: quinn::Connection,
) -> Result<ConnectedPeer, ConnectionLifecycleError> {
    let transport_fingerprint = peer_identity_from_connection(&connection)
        .ok_or(ConnectionLifecycleError::MissingPeerIdentity)?;
    Ok(ConnectedPeer {
        connection,
        peer_id: transport_fingerprint,
    })
}

/// Dial a remote endpoint and return a connection with extracted peer identity.
pub async fn dial_peer(
    endpoint: &quinn::Endpoint,
    remote: SocketAddr,
    sni: &str,
    client_config: Option<&quinn::ClientConfig>,
) -> Result<ConnectedPeer, ConnectionLifecycleError> {
    let connecting = if let Some(cfg) = client_config {
        endpoint.connect_with(cfg.clone(), remote, sni)
    } else {
        endpoint.connect(remote, sni)
    }
    .map_err(|e| ConnectionLifecycleError::Dial(format!("initiate to {remote}: {e}")))?;

    let connection = connecting.await.map_err(|e| {
        let msg = format!("handshake to {remote}: {e}");
        if msg.contains(TRUST_REJECTION_MARKER) {
            ConnectionLifecycleError::DialTrustRejected(msg)
        } else {
            ConnectionLifecycleError::Dial(msg)
        }
    })?;

    into_connected_peer(connection)
}

/// Accept the next inbound connection and extract peer identity.
///
/// Returns `Ok(None)` when the endpoint is closed.
pub async fn accept_peer(
    endpoint: &quinn::Endpoint,
) -> Result<Option<ConnectedPeer>, ConnectionLifecycleError> {
    let incoming = match endpoint.accept().await {
        Some(incoming) => incoming,
        None => return Ok(None),
    };
    let connection = incoming
        .await
        .map_err(|e| ConnectionLifecycleError::Accept(e.to_string()))?;
    Ok(Some(into_connected_peer(connection)?))
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::time::Duration;

    use super::{accept_peer, dial_peer};
    use crate::transport::{
        create_dual_endpoint, extract_spki_fingerprint, generate_self_signed_cert, AllowedPeers,
    };

    async fn endpoint_pair() -> Result<
        (quinn::Endpoint, quinn::Endpoint, SocketAddr, String, String),
        Box<dyn std::error::Error + Send + Sync>,
    > {
        let (server_cert, server_key) = generate_self_signed_cert()?;
        let (client_cert, client_key) = generate_self_signed_cert()?;

        let server_fp = extract_spki_fingerprint(server_cert.as_ref())?;
        let client_fp = extract_spki_fingerprint(client_cert.as_ref())?;

        let server_ep = create_dual_endpoint(
            "127.0.0.1:0".parse().unwrap(),
            server_cert,
            server_key,
            Arc::new(AllowedPeers::from_fingerprints(vec![client_fp])),
        )?;
        let client_ep = create_dual_endpoint(
            "127.0.0.1:0".parse().unwrap(),
            client_cert,
            client_key,
            Arc::new(AllowedPeers::from_fingerprints(vec![server_fp])),
        )?;
        let server_addr = server_ep.local_addr()?;
        Ok((
            server_ep,
            client_ep,
            server_addr,
            hex::encode(server_fp),
            hex::encode(client_fp),
        ))
    }

    #[tokio::test]
    async fn dial_and_accept_extract_expected_peer_ids() {
        let (server_ep, client_ep, server_addr, server_peer_id, client_peer_id) =
            endpoint_pair().await.expect("endpoint pair");

        let (accepted_res, dialed_res) = tokio::join!(
            accept_peer(&server_ep),
            dial_peer(&client_ep, server_addr, "localhost", None)
        );

        let accepted = accepted_res
            .expect("accept_peer")
            .expect("accepted connection");
        let dialed = dialed_res.expect("dial_peer");

        assert_eq!(accepted.peer_id, client_peer_id);
        assert_eq!(dialed.peer_id, server_peer_id);
    }

    #[tokio::test]
    async fn accept_peer_returns_none_when_endpoint_closed() {
        let (server_ep, _client_ep, _server_addr, _server_peer_id, _client_peer_id) =
            endpoint_pair().await.expect("endpoint pair");
        server_ep.close(0u32.into(), b"test-close");

        let result = tokio::time::timeout(Duration::from_secs(1), accept_peer(&server_ep))
            .await
            .expect("accept timeout")
            .expect("accept result");

        assert!(
            result.is_none(),
            "closed endpoint should return None, got {:?}",
            result.as_ref().map(|p| &p.peer_id)
        );
    }
}
