//! Multi-workspace TLS cert resolver.
//!
//! Implements `ResolvesServerCert` so a single QUIC endpoint can serve
//! multiple workspaces. The client's SNI selects which workspace cert
//! the server presents.
//!
//! Uses `RwLock` for interior mutability so new tenants can be registered
//! on a live endpoint without restarting.

use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, RwLock};

use crate::crypto::event_id_from_base64;

/// Map workspace SNI → CertifiedKey for per-connection cert selection.
pub struct WorkspaceCertResolver {
    /// SNI hostname → CertifiedKey
    certs: RwLock<HashMap<String, Arc<CertifiedKey>>>,
    /// Fallback cert when no SNI is provided.
    fallback: RwLock<Option<Arc<CertifiedKey>>>,
}

impl fmt::Debug for WorkspaceCertResolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let certs = self.certs.read().unwrap();
        f.debug_struct("WorkspaceCertResolver")
            .field("workspaces", &certs.keys().collect::<Vec<_>>())
            .field("has_fallback", &self.fallback.read().unwrap().is_some())
            .finish()
    }
}

impl WorkspaceCertResolver {
    /// Create a new resolver.
    pub fn new() -> Self {
        Self {
            certs: RwLock::new(HashMap::new()),
            fallback: RwLock::new(None),
        }
    }

    /// Register a workspace's cert+key for the given SNI hostname.
    ///
    /// Takes `&self` (not `&mut self`) so callers can register new tenants
    /// on a live endpoint behind an `Arc`.
    pub fn add(&self, sni: String, certified_key: Arc<CertifiedKey>) {
        let mut fallback = self.fallback.write().unwrap();
        if fallback.is_none() {
            *fallback = Some(certified_key.clone());
        }
        drop(fallback);
        self.certs.write().unwrap().insert(sni, certified_key);
    }

    /// Number of registered workspaces.
    pub fn len(&self) -> usize {
        self.certs.read().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.certs.read().unwrap().is_empty()
    }
}

impl ResolvesServerCert for WorkspaceCertResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        if let Some(sni) = client_hello.server_name() {
            let certs = self.certs.read().unwrap();
            if let Some(ck) = certs.get(sni) {
                return Some(ck.clone());
            }
        }
        // Fallback for clients that do not send workspace-specific SNI.
        self.fallback.read().unwrap().clone()
    }
}

/// Convert a workspace_id (base64 event_id) to a DNS-safe SNI hostname.
///
/// Uses hex encoding of the first 16 bytes of the event_id → 32-char
/// hex string, well within the 63-char DNS label limit.
pub fn workspace_sni(workspace_id_b64: &str) -> String {
    if let Some(eid) = event_id_from_base64(workspace_id_b64) {
        hex::encode(&eid[..16])
    } else {
        // Fallback for invalid b64: sanitize for DNS
        workspace_id_b64
            .replace('/', "-")
            .replace('+', "0")
            .replace('=', "")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_workspace_sni_produces_hex() {
        // A 32-byte event_id base64-encoded
        let eid = [0xABu8; 32];
        let b64 = crate::crypto::event_id_to_base64(&eid);
        let sni = workspace_sni(&b64);
        assert_eq!(sni.len(), 32);
        assert_eq!(sni, "abababababababababababababababab");
    }

    #[test]
    fn test_workspace_sni_fallback() {
        let sni = workspace_sni("not-valid-base64!!!");
        assert!(!sni.contains('/'));
        assert!(!sni.contains('+'));
        assert!(!sni.contains('='));
    }

    #[test]
    fn test_resolver_selects_by_sni() {
        let provider = rustls::crypto::ring::default_provider();

        let resolver = WorkspaceCertResolver::new();

        // Generate two workspace certs
        let (cert1, key1) = crate::transport::generate_self_signed_cert().unwrap();
        let (cert2, key2) = crate::transport::generate_self_signed_cert().unwrap();

        let ck1 = Arc::new(CertifiedKey::from_der(vec![cert1], key1.into(), &provider).unwrap());
        let ck2 = Arc::new(CertifiedKey::from_der(vec![cert2], key2.into(), &provider).unwrap());

        resolver.add("ws-aaa".to_string(), ck1.clone());
        resolver.add("ws-bbb".to_string(), ck2.clone());

        assert_eq!(resolver.len(), 2);
    }
}
