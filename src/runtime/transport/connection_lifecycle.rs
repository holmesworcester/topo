//! Connection lifecycle helpers shared by peering loops/workflows.
//!
//! Keeps QUIC dial/accept + peer identity extraction in transport so peering
//! can focus on orchestration/retry logic.

use std::net::SocketAddr;

use thiserror::Error;

use super::{TransportConnection, TransportEndpoint, TOPO_ALPN};

/// A successful transport connection with verified peer identity.
pub struct ConnectedDaemon {
    pub connection: TransportConnection,
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
    #[error("accept failed: {0}")]
    Accept(String),
    #[error("missing peer identity from transport session")]
    MissingPeerIdentity,
}

fn endpoint_id_from_target(target: &str) -> Result<iroh::EndpointId, ConnectionLifecycleError> {
    let endpoint_id_hex = super::multi_workspace::parse_transport_sni(target)
        .map(|parsed| parsed.transport_peer_id)
        .unwrap_or_else(|| target.to_ascii_lowercase());
    let mut bytes = [0u8; 32];
    hex::decode_to_slice(&endpoint_id_hex, &mut bytes).map_err(|_| {
        ConnectionLifecycleError::Dial(format!(
            "invalid remote daemon id '{endpoint_id_hex}': expected 32-byte hex"
        ))
    })?;
    iroh::EndpointId::from_bytes(&bytes).map_err(|_| {
        ConnectionLifecycleError::Dial(format!(
            "invalid remote daemon id '{endpoint_id_hex}': not a valid iroh endpoint id"
        ))
    })
}

fn connection_socket_addr(connection: &iroh::endpoint::Connection) -> Option<SocketAddr> {
    if let Some(path) = connection.to_info().selected_path() {
        if let iroh::TransportAddr::Ip(addr) = path.remote_addr() {
            return Some(*addr);
        }
    }
    for path in connection.paths() {
        if let iroh::TransportAddr::Ip(addr) = path.remote_addr() {
            return Some(*addr);
        }
    }
    None
}

fn into_connected_daemon(
    connection: TransportConnection,
) -> Result<ConnectedDaemon, ConnectionLifecycleError> {
    let daemon_peer_id = hex::encode(connection.inner.remote_id().as_bytes());
    Ok(ConnectedDaemon {
        connection,
        daemon_peer_id,
    })
}

/// Dial a remote endpoint and return a connection with extracted peer identity.
pub async fn dial_daemon(
    endpoint: &TransportEndpoint,
    remote: Option<SocketAddr>,
    relay_url: Option<&str>,
    sni: &str,
) -> Result<ConnectedDaemon, ConnectionLifecycleError> {
    let endpoint_id = endpoint_id_from_target(sni)?;
    let relay_url_str = relay_url;
    let relay_url = relay_url_str
        .map(|relay_url| relay_url.parse::<iroh::RelayUrl>())
        .transpose()
        .map_err(|e| {
            ConnectionLifecycleError::Dial(format!("invalid relay url '{relay_url_str:?}': {e}"))
        })?;
    let target = match (remote, relay_url.as_ref()) {
        (Some(remote), Some(relay_url)) => format!("{remote} via {relay_url}"),
        (Some(remote), None) => remote.to_string(),
        (None, Some(relay_url)) => {
            format!("{} via {relay_url}", hex::encode(endpoint_id.as_bytes()))
        }
        (None, None) => hex::encode(endpoint_id.as_bytes()),
    };
    let mut transport_addrs = Vec::new();
    if let Some(remote) = remote {
        transport_addrs.push(iroh::TransportAddr::Ip(remote));
    }
    if let Some(relay_url) = relay_url {
        transport_addrs.push(iroh::TransportAddr::Relay(relay_url));
    }
    let endpoint_addr = if transport_addrs.is_empty() {
        endpoint_id.into()
    } else {
        iroh::EndpointAddr::from_parts(endpoint_id, transport_addrs)
    };
    let connection = endpoint
        .inner
        .connect(endpoint_addr, TOPO_ALPN)
        .await
        .map_err(|e| ConnectionLifecycleError::Dial(format!("connect to {target}: {e}")))?;
    let remote_addr = connection_socket_addr(&connection);
    into_connected_daemon(TransportConnection::new(connection, remote_addr))
}

/// Accept the next inbound connection and extract peer identity.
///
/// Returns `Ok(None)` when the endpoint is closed.
pub async fn accept_daemon(
    endpoint: &TransportEndpoint,
) -> Result<Option<ConnectedDaemon>, ConnectionLifecycleError> {
    let Some(incoming) = endpoint.inner.accept().await else {
        return Ok(None);
    };
    let connection = incoming
        .await
        .map_err(|e| ConnectionLifecycleError::Accept(e.to_string()))?;
    let remote_addr = connection_socket_addr(&connection);
    Ok(Some(into_connected_daemon(TransportConnection::new(
        connection,
        remote_addr,
    ))?))
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::time::Duration;

    use super::{accept_daemon, dial_daemon};
    use crate::transport::{
        create_runtime_endpoint_for_tenants, load_daemon_identity_from_db,
        multi_workspace::transport_sni, TransportEndpoint,
    };

    async fn endpoint_pair() -> Result<
        (
            tempfile::TempDir,
            TransportEndpoint,
            TransportEndpoint,
            SocketAddr,
            String,
            String,
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
        let client_peer_id = load_daemon_identity_from_db(client_db.to_str().unwrap())?.0;
        Ok((
            temp,
            server_ep,
            client_ep,
            server_addr,
            server_peer_id,
            client_peer_id,
        ))
    }

    #[tokio::test]
    async fn dial_and_accept_extract_expected_peer_ids() {
        let (_temp, server_ep, client_ep, server_addr, server_peer_id, client_peer_id) =
            endpoint_pair().await.expect("endpoint pair");
        let server_sni = transport_sni(&server_peer_id);

        let (accepted_res, dialed_res) = tokio::join!(
            accept_daemon(&server_ep),
            dial_daemon(&client_ep, Some(server_addr), None, &server_sni)
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
        let (_temp, server_ep, _client_ep, _server_addr, _server_peer_id, _client_peer_id) =
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

    #[tokio::test]
    async fn dial_daemon_rejects_invalid_remote_daemon_id() {
        let (_temp, _server_ep, client_ep, _server_addr, _server_peer_id, _client_peer_id) =
            endpoint_pair().await.expect("endpoint pair");

        let err = match dial_daemon(&client_ep, None, None, "not-a-valid-endpoint-id").await {
            Ok(_) => panic!("invalid target should fail before dialing"),
            Err(err) => err,
        };

        match err {
            super::ConnectionLifecycleError::Dial(message) => {
                assert!(
                    message.contains("invalid remote daemon id"),
                    "unexpected dial error: {message}"
                );
            }
            other => panic!("expected dial error, got {other:?}"),
        }
    }
}
