//! Daemon-target SNI helpers.
//!
//! The daemon-scoped `iroh` runtime no longer serves per-tenant TLS certs, but
//! a few caller-facing transport helpers still use the existing SNI encoding to
//! name a remote daemon endpoint.

/// Parsed exact transport-target SNI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransportSniTarget {
    pub transport_peer_id: String,
}

/// Convert a full 32-byte hex peer_id to a DNS-safe peer-specific SNI suffix.
///
/// SNI labels are capped at 63 characters, so split the 64-char hex peer id
/// across two labels.
pub fn peer_sni(peer_id_hex: &str) -> String {
    if peer_id_hex.len() == 64 && peer_id_hex.chars().all(|c| c.is_ascii_hexdigit()) {
        format!("p7-{}.{}", &peer_id_hex[..32], &peer_id_hex[32..])
    } else {
        peer_id_hex
            .replace('/', "-")
            .replace('+', "0")
            .replace('=', "")
    }
}

/// Build an SNI hostname that addresses one exact daemon endpoint id.
pub fn transport_sni(transport_peer_id_hex: &str) -> String {
    peer_sni(transport_peer_id_hex)
}

/// Parse an exact transport-target SNI.
pub fn parse_transport_sni(sni: &str) -> Option<TransportSniTarget> {
    let mut parts = sni.split('.');
    let first_peer = parts.next()?;
    let second_peer = parts.next()?;
    if parts.next().is_some() {
        return None;
    }
    let peer_prefix = first_peer.strip_prefix("p7-")?;
    if peer_prefix.len() != 32
        || second_peer.len() != 32
        || !peer_prefix.chars().all(|c| c.is_ascii_hexdigit())
        || !second_peer.chars().all(|c| c.is_ascii_hexdigit())
    {
        return None;
    }
    Some(TransportSniTarget {
        transport_peer_id: format!("{peer_prefix}{second_peer}").to_ascii_lowercase(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_peer_sni_splits_full_peer_id() {
        let peer_id = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let sni = peer_sni(peer_id);
        assert_eq!(
            sni,
            "p7-0123456789abcdef0123456789abcdef.0123456789abcdef0123456789abcdef"
        );
    }

    #[test]
    fn test_transport_sni_round_trips() {
        let peer_id = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let sni = transport_sni(peer_id);
        assert_eq!(
            parse_transport_sni(&sni),
            Some(TransportSniTarget {
                transport_peer_id: peer_id.to_string(),
            })
        );
    }

    #[test]
    fn test_parse_transport_sni_ignores_workspace_only_values() {
        assert_eq!(parse_transport_sni("workspace-only"), None);
    }
}
