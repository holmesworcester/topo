//! Connection lifecycle helpers shared by peering loops/workflows.
//!
//! The Tor backend authenticates the remote daemon on an initial signed hello
//! stream, then reuses the daemon peer id as the stable connection identity.

use std::net::SocketAddr;

use thiserror::Error;
use tracing::debug;

use super::{TransportConnection, TransportEndpoint, TOPO_ALPN};

/// A successful transport connection with verified peer identity.
pub struct ConnectedDaemon {
    pub connection: TransportConnection,
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

fn endpoint_id_from_target(target: &str) -> Result<String, ConnectionLifecycleError> {
    let endpoint_id_hex = super::multi_workspace::parse_transport_sni(target)
        .map(|parsed| parsed.transport_peer_id)
        .unwrap_or_else(|| target.to_ascii_lowercase());
    let mut bytes = [0u8; 32];
    hex::decode_to_slice(&endpoint_id_hex, &mut bytes).map_err(|_| {
        ConnectionLifecycleError::Dial(format!(
            "invalid remote daemon id '{endpoint_id_hex}': expected 32-byte hex"
        ))
    })?;
    Ok(endpoint_id_hex)
}

fn short_peer_id(peer_id: &str) -> &str {
    &peer_id[..16.min(peer_id.len())]
}

/// Dial a remote endpoint and return a connection with extracted peer identity.
pub async fn dial_daemon(
    endpoint: &TransportEndpoint,
    remote: Option<SocketAddr>,
    relay_url: Option<&str>,
    sni: &str,
) -> Result<ConnectedDaemon, ConnectionLifecycleError> {
    let remote_daemon_peer_id = endpoint_id_from_target(sni)?;
    let target = match (remote, relay_url) {
        (Some(remote), Some(relay_url)) => format!("{remote} via {relay_url}"),
        (Some(remote), None) => remote.to_string(),
        (None, Some(relay_url)) => {
            format!("{remote_daemon_peer_id} via {relay_url}")
        }
        (None, None) => remote_daemon_peer_id.clone(),
    };
    debug!(
        target: "topo::connection",
        alpn = ?TOPO_ALPN,
        "dial_daemon start target={} sni={}",
        target,
        sni,
    );
    endpoint
        .send_hello(&remote_daemon_peer_id)
        .await
        .map_err(|e| ConnectionLifecycleError::Dial(format!("connect to {target}: {e}")))?;
    let connected = ConnectedDaemon {
        connection: TransportConnection::new(endpoint.clone(), remote_daemon_peer_id.clone()),
        daemon_peer_id: remote_daemon_peer_id,
    };
    debug!(
        target: "topo::connection",
        "dial_daemon success daemon={} remote_addr={:?}",
        short_peer_id(&connected.daemon_peer_id),
        connected.connection.remote_address(),
    );
    Ok(connected)
}

/// Accept the next inbound connection and extract peer identity.
///
/// Returns `Ok(None)` when the endpoint is closed.
pub async fn accept_daemon(
    endpoint: &TransportEndpoint,
) -> Result<Option<ConnectedDaemon>, ConnectionLifecycleError> {
    let Some(connected) = endpoint.accept_connection_notice().await else {
        return Ok(None);
    };
    let daemon_peer_id = connected.remote_daemon_peer_id;
    let connected = ConnectedDaemon {
        connection: TransportConnection::new(endpoint.clone(), daemon_peer_id.clone()),
        daemon_peer_id,
    };
    debug!(
        target: "topo::connection",
        "accept_daemon success daemon={} remote_addr={:?}",
        short_peer_id(&connected.daemon_peer_id),
        connected.connection.remote_address(),
    );
    Ok(Some(connected))
}

#[cfg(test)]
mod tests {
    use super::{endpoint_id_from_target, ConnectionLifecycleError};
    use crate::transport::multi_workspace::transport_sni;

    #[test]
    fn tor_transport_endpoint_id_from_target_accepts_raw_hex_ids() {
        let peer_id = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        assert_eq!(
            endpoint_id_from_target(peer_id).expect("raw hex peer id should parse"),
            peer_id
        );
    }

    #[test]
    fn tor_transport_endpoint_id_from_target_accepts_transport_sni() {
        let peer_id = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let sni = transport_sni(peer_id);
        assert_eq!(
            endpoint_id_from_target(&sni).expect("transport sni should parse"),
            peer_id
        );
    }

    #[test]
    fn tor_transport_endpoint_id_from_target_rejects_invalid_ids() {
        let err = endpoint_id_from_target("not-a-valid-endpoint-id")
            .expect_err("invalid target should fail");
        match err {
            ConnectionLifecycleError::Dial(message) => {
                assert!(
                    message.contains("invalid remote daemon id"),
                    "unexpected error message: {message}"
                );
            }
            other => panic!("expected dial error, got {other:?}"),
        }
    }
}
