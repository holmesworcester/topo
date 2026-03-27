//! Connection lifecycle helpers shared by peering loops/workflows.
//!
//! Keeps QUIC dial/accept + peer identity extraction in transport so peering
//! can focus on orchestration/retry logic.

use std::net::SocketAddr;

use thiserror::Error;

use super::TRUST_REJECTION_MARKER;
use crate::transport::peer_identity_from_connection;

/// A successful transport connection with verified peer identity.
pub struct ConnectedDaemon {
    pub connection: quinn::Connection,
    /// Hex-encoded daemon certificate SPKI fingerprint.
    pub daemon_peer_id: String,
}

impl ConnectedDaemon {
    pub fn remote_daemon_peer_id(&self) -> &str {
        &self.daemon_peer_id
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

fn into_connected_daemon(
    connection: quinn::Connection,
) -> Result<ConnectedDaemon, ConnectionLifecycleError> {
    let daemon_peer_id = peer_identity_from_connection(&connection)
        .ok_or(ConnectionLifecycleError::MissingPeerIdentity)?;
    Ok(ConnectedDaemon {
        connection,
        daemon_peer_id,
    })
}

/// Dial a remote endpoint and return a connection with extracted peer identity.
pub async fn dial_daemon(
    endpoint: &quinn::Endpoint,
    remote: SocketAddr,
    sni: &str,
    client_config: Option<&quinn::ClientConfig>,
) -> Result<ConnectedDaemon, ConnectionLifecycleError> {
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

    into_connected_daemon(connection)
}

/// Accept the next inbound connection and extract peer identity.
///
/// Returns `Ok(None)` when the endpoint is closed.
pub async fn accept_daemon(
    endpoint: &quinn::Endpoint,
) -> Result<Option<ConnectedDaemon>, ConnectionLifecycleError> {
    let incoming = match endpoint.accept().await {
        Some(incoming) => incoming,
        None => return Ok(None),
    };
    let connection = incoming
        .await
        .map_err(|e| ConnectionLifecycleError::Accept(e.to_string()))?;
    Ok(Some(into_connected_daemon(connection)?))
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::time::Duration;

    use super::{accept_daemon, dial_daemon};
    use crate::transport::{
        create_dual_endpoint, extract_spki_fingerprint, generate_self_signed_cert,
        multi_workspace::transport_sni,
    };

    async fn endpoint_pair() -> Result<
        (quinn::Endpoint, quinn::Endpoint, SocketAddr, String, String),
        Box<dyn std::error::Error + Send + Sync>,
    > {
        let (server_cert, server_key) = generate_self_signed_cert()?;
        let (client_cert, client_key) = generate_self_signed_cert()?;

        let server_fp = extract_spki_fingerprint(server_cert.as_ref())?;
        let client_fp = extract_spki_fingerprint(client_cert.as_ref())?;
        let server_peer_id = hex::encode(server_fp);
        let client_peer_id = hex::encode(client_fp);

        let allow_client: Arc<crate::transport::DynamicAllowFn> =
            Arc::new(move |candidate| Ok(candidate == &client_fp));
        let allow_server: Arc<crate::transport::DynamicAllowFn> =
            Arc::new(move |candidate| Ok(candidate == &server_fp));

        let server_ep = create_dual_endpoint(
            "127.0.0.1:0".parse().unwrap(),
            server_cert,
            server_key,
            allow_client,
        )?;
        let client_ep = create_dual_endpoint(
            "127.0.0.1:0".parse().unwrap(),
            client_cert,
            client_key,
            allow_server,
        )?;
        let server_addr = server_ep.local_addr()?;
        Ok((
            server_ep,
            client_ep,
            server_addr,
            server_peer_id,
            client_peer_id,
        ))
    }

    #[tokio::test]
    async fn dial_and_accept_extract_expected_peer_ids() {
        let (server_ep, client_ep, server_addr, server_peer_id, client_peer_id) =
            endpoint_pair().await.expect("endpoint pair");
        let server_sni = transport_sni(&server_peer_id);

        let (accepted_res, dialed_res) = tokio::join!(
            accept_daemon(&server_ep),
            dial_daemon(&client_ep, server_addr, &server_sni, None)
        );

        let accepted = accepted_res
            .expect("accept_daemon")
            .expect("accepted connection");
        let dialed = dialed_res.expect("dial_daemon");

        assert_eq!(accepted.daemon_peer_id, client_peer_id);
        assert_eq!(dialed.daemon_peer_id, server_peer_id);
    }

    #[tokio::test]
    async fn accept_peer_returns_none_when_endpoint_closed() {
        let (server_ep, _client_ep, _server_addr, _server_peer_id, _client_peer_id) =
            endpoint_pair().await.expect("endpoint pair");
        server_ep.close(0u32.into(), b"test-close");

        let result = tokio::time::timeout(Duration::from_secs(1), accept_daemon(&server_ep))
            .await
            .expect("accept timeout")
            .expect("accept result");

        assert!(
            result.is_none(),
            "closed endpoint should return None, got {:?}",
            result.as_ref().map(|p| &p.daemon_peer_id)
        );
    }
}
