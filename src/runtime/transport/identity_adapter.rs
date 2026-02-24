//! Concrete `TransportIdentityAdapter` implementation.
//!
//! This is the **sole** module that calls raw transport identity install
//! functions (`install_peer_key_transport_identity`,
//! `install_invite_bootstrap_transport_identity_conn`). All other code
//! (service, projection, event_modules) must go through the adapter trait.

use rusqlite::Connection;
use rusqlite::OptionalExtension;

use crate::contracts::transport_identity_contract::{
    TransportIdentityAdapter, TransportIdentityError, TransportIdentityIntent,
};

/// Production adapter backed by `transport::identity` install functions.
pub struct ConcreteTransportIdentityAdapter;

impl TransportIdentityAdapter for ConcreteTransportIdentityAdapter {
    fn apply_intent(
        &self,
        conn: &Connection,
        intent: TransportIdentityIntent,
    ) -> Result<String, TransportIdentityError> {
        match intent {
            TransportIdentityIntent::InstallInviteBootstrapIdentity {
                invite_private_key,
            } => {
                let signing_key = ed25519_dalek::SigningKey::from_bytes(&invite_private_key);
                crate::transport::identity::install_invite_bootstrap_transport_identity_conn(
                    conn,
                    &signing_key,
                )
                .map_err(|e| TransportIdentityError::InstallFailed(e.to_string()))
            }
            TransportIdentityIntent::InstallPeerSharedIdentityFromSigner {
                recorded_by,
                signer_event_id,
            } => {
                // Load peer_shared private key from local_signer_material
                let signer_eid_b64 = crate::crypto::event_id_to_base64(&signer_event_id);
                let key_bytes: Option<Vec<u8>> = conn
                    .query_row(
                        "SELECT private_key FROM local_signer_material
                         WHERE recorded_by = ?1 AND signer_kind = 3
                         AND signer_event_id = ?2
                         LIMIT 1",
                        rusqlite::params![recorded_by, signer_eid_b64],
                        |row| row.get(0),
                    )
                    .optional()
                    .map_err(|e| TransportIdentityError::InstallFailed(e.to_string()))?
                    .flatten();

                let key_bytes = key_bytes.ok_or_else(|| TransportIdentityError::SignerKeyNotFound {
                    recorded_by: recorded_by.clone(),
                })?;

                if key_bytes.len() != 32 {
                    return Err(TransportIdentityError::InvalidKeyMaterial(format!(
                        "expected 32 bytes, got {}",
                        key_bytes.len()
                    )));
                }

                let mut arr = [0u8; 32];
                arr.copy_from_slice(&key_bytes);
                let signing_key = ed25519_dalek::SigningKey::from_bytes(&arr);

                crate::transport::identity::install_peer_key_transport_identity(conn, &signing_key)
                    .map_err(|e| TransportIdentityError::InstallFailed(e.to_string()))
            }
        }
    }
}
