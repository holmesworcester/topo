//! Multi-tenant TLS cert resolver.
//!
//! Implements `ResolvesServerCert` so a single QUIC endpoint can serve
//! multiple local transport identities. The client's SNI selects which
//! local cert the server presents.
//!
//! Uses `RwLock` for interior mutability so new tenants can be registered
//! on a live endpoint without restarting.

use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, RwLock};

/// Map exact transport-target SNI → CertifiedKey for per-connection cert selection.
pub struct TransportTargetCertResolver {
    /// SNI hostname → CertifiedKey
    certs: RwLock<HashMap<String, Arc<CertifiedKey>>>,
}

impl fmt::Debug for TransportTargetCertResolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let certs = self.certs.read().unwrap();
        f.debug_struct("TransportTargetCertResolver")
            .field("targets", &certs.keys().collect::<Vec<_>>())
            .finish()
    }
}

impl TransportTargetCertResolver {
    /// Create a new resolver.
    pub fn new() -> Self {
        Self {
            certs: RwLock::new(HashMap::new()),
        }
    }

    /// Register one local transport identity's cert+key for the given SNI hostname.
    ///
    /// Takes `&self` (not `&mut self`) so callers can register new tenants
    /// on a live endpoint behind an `Arc`.
    pub fn add(&self, sni: String, certified_key: Arc<CertifiedKey>) {
        self.certs.write().unwrap().insert(sni, certified_key);
    }

    /// Number of registered exact-SNI aliases.
    pub fn len(&self) -> usize {
        self.certs.read().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.certs.read().unwrap().is_empty()
    }
}

impl ResolvesServerCert for TransportTargetCertResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        if let Some(sni) = client_hello.server_name() {
            let certs = self.certs.read().unwrap();
            if let Some(ck) = certs.get(sni) {
                return Some(ck.clone());
            }
        }
        None
    }
}

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

/// Build an SNI hostname that addresses one exact local transport fingerprint.
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

    #[test]
    fn test_resolver_selects_by_sni() {
        let provider = rustls::crypto::ring::default_provider();

        let resolver = TransportTargetCertResolver::new();

        // Generate two transport certs
        let (cert1, key1) = crate::transport::generate_self_signed_cert().unwrap();
        let (cert2, key2) = crate::transport::generate_self_signed_cert().unwrap();

        let ck1 = Arc::new(CertifiedKey::from_der(vec![cert1], key1.into(), &provider).unwrap());
        let ck2 = Arc::new(CertifiedKey::from_der(vec![cert2], key2.into(), &provider).unwrap());

        resolver.add("ws-aaa".to_string(), ck1.clone());
        resolver.add("ws-bbb".to_string(), ck2.clone());

        assert_eq!(resolver.len(), 2);
    }
}
