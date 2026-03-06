//! Concrete `TransportIdentityAdapter` implementation.
//!
//! This is the **sole** module that calls raw transport identity install
//! functions (`install_peer_key_transport_identity`). All other code
//! (service, projection, event_modules) must go through the adapter trait.

use rusqlite::Connection;
use rusqlite::OptionalExtension;

use crate::contracts::transport_identity_contract::{
    TransportIdentityAdapter, TransportIdentityError, TransportIdentityIntent,
};

/// Production adapter backed by `transport::identity` install functions.
pub struct ConcreteTransportIdentityAdapter;

fn parse_signing_key(
    key_bytes: Vec<u8>,
) -> Result<ed25519_dalek::SigningKey, TransportIdentityError> {
    if key_bytes.len() != 32 {
        return Err(TransportIdentityError::InvalidKeyMaterial(format!(
            "expected 32 bytes, got {}",
            key_bytes.len()
        )));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&key_bytes);
    Ok(ed25519_dalek::SigningKey::from_bytes(&arr))
}

impl TransportIdentityAdapter for ConcreteTransportIdentityAdapter {
    fn apply_intent(
        &self,
        conn: &Connection,
        intent: TransportIdentityIntent,
    ) -> Result<String, TransportIdentityError> {
        match intent {
            TransportIdentityIntent::InstallBootstrapIdentityFromInviteKey {
                invite_private_key,
            } => {
                let signing_key = ed25519_dalek::SigningKey::from_bytes(&invite_private_key);
                crate::transport::identity::install_invite_bootstrap_transport_identity(
                    conn,
                    &signing_key,
                )
                .map_err(|e| TransportIdentityError::InstallFailed(e.to_string()))
            }
            TransportIdentityIntent::InstallBootstrapIdentityFromInviteSecret {
                recorded_by,
                invite_event_id,
            } => {
                let invite_eid_b64 = crate::crypto::event_id_to_base64(&invite_event_id);
                let key_bytes: Option<Vec<u8>> = conn
                    .query_row(
                        "SELECT private_key FROM invite_secrets
                         WHERE recorded_by = ?1
                           AND invite_event_id = ?2
                         ORDER BY created_at DESC, event_id DESC
                         LIMIT 1",
                        rusqlite::params![recorded_by, invite_eid_b64],
                        |row| row.get(0),
                    )
                    .optional()
                    .map_err(|e| TransportIdentityError::InstallFailed(e.to_string()))?
                    .flatten();

                let key_bytes =
                    key_bytes.ok_or_else(|| TransportIdentityError::InviteSecretNotFound {
                        recorded_by: recorded_by.clone(),
                        invite_event_id: invite_eid_b64.clone(),
                    })?;
                let signing_key = parse_signing_key(key_bytes)?;
                crate::transport::identity::install_invite_bootstrap_transport_identity(
                    conn,
                    &signing_key,
                )
                .map_err(|e| TransportIdentityError::InstallFailed(e.to_string()))
            }
            TransportIdentityIntent::InstallPeerSharedIdentityFromSigner {
                recorded_by,
                signer_event_id,
            } => {
                // Load peer_shared private key from peer_secrets
                let signer_eid_b64 = crate::crypto::event_id_to_base64(&signer_event_id);
                let key_bytes: Option<Vec<u8>> = conn
                    .query_row(
                        "SELECT private_key FROM peer_secrets
                         WHERE recorded_by = ?1
                           AND signer_event_id = ?2
                         ORDER BY created_at DESC, event_id DESC
                         LIMIT 1",
                        rusqlite::params![recorded_by, signer_eid_b64],
                        |row| row.get(0),
                    )
                    .optional()
                    .map_err(|e| TransportIdentityError::InstallFailed(e.to_string()))?
                    .flatten();

                let key_bytes =
                    key_bytes.ok_or_else(|| TransportIdentityError::SignerKeyNotFound {
                        recorded_by: recorded_by.clone(),
                    })?;

                let signing_key = parse_signing_key(key_bytes)?;

                crate::transport::identity::install_peer_key_transport_identity(conn, &signing_key)
                    .map_err(|e| TransportIdentityError::InstallFailed(e.to_string()))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::open_in_memory;
    use crate::db::schema::create_tables;
    use crate::transport::identity::install_peer_key_transport_identity;

    #[test]
    fn bootstrap_install_sets_bootstrap_source() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();
        let adapter = ConcreteTransportIdentityAdapter;

        let result = adapter.apply_intent(
            &conn,
            TransportIdentityIntent::InstallBootstrapIdentityFromInviteKey {
                invite_private_key: [7u8; 32],
            },
        );
        assert!(result.is_ok(), "bootstrap install should succeed");

        let source: String = conn
            .query_row(
                "SELECT source FROM local_transport_creds LIMIT 1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(source, "bootstrap");
    }

    #[test]
    fn bootstrap_install_rejected_after_peershared_for_same_peer() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();
        let adapter = ConcreteTransportIdentityAdapter;

        let same_key = [9u8; 32];
        let peer_key = ed25519_dalek::SigningKey::from_bytes(&same_key);
        install_peer_key_transport_identity(&conn, &peer_key).unwrap();

        let result = adapter.apply_intent(
            &conn,
            TransportIdentityIntent::InstallBootstrapIdentityFromInviteKey {
                invite_private_key: same_key,
            },
        );
        assert!(
            matches!(
                result.as_ref().map(|_| ()),
                Err(TransportIdentityError::InstallFailed(_))
            ),
            "expected bootstrap install failure for same peer, got: {:?}",
            result
        );
    }

    #[test]
    fn bootstrap_install_allowed_when_other_peer_has_peershared() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();
        let adapter = ConcreteTransportIdentityAdapter;

        let peer_key = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
        install_peer_key_transport_identity(&conn, &peer_key).unwrap();

        // Different key => different transport peer_id, allowed in multi-tenant mode.
        let result = adapter.apply_intent(
            &conn,
            TransportIdentityIntent::InstallBootstrapIdentityFromInviteKey {
                invite_private_key: [11u8; 32],
            },
        );
        assert!(
            result.is_ok(),
            "bootstrap install should succeed for other peer"
        );
    }
}
