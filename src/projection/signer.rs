use rusqlite::Connection;

use crate::crypto::event_id_to_base64;
use crate::events::{self, ParsedEvent};

/// Distinguishes content errors (malformed/unsupported signer data, terminal reject)
/// from infrastructure errors (DB failures, retriable).
#[derive(Debug)]
pub enum SignerError {
    /// Content error: unsupported signer type, wrong event kind, parse failure.
    /// Should map to ProjectionDecision::Reject.
    ContentError(String),
    /// Infrastructure error: DB failure, etc. Should propagate as hard Err.
    InfraError(Box<dyn std::error::Error>),
}

impl std::fmt::Display for SignerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SignerError::ContentError(msg) => write!(f, "signer content error: {}", msg),
            SignerError::InfraError(e) => write!(f, "signer infra error: {}", e),
        }
    }
}

impl std::error::Error for SignerError {}

/// Resolve the public key for a signer event.
/// For signer_type=0 (peer), loads the event blob, parses as PeerKeyEvent,
/// and returns the public key. Returns None if the event is not found.
///
/// Returns `SignerError::ContentError` for unsupported signer types or
/// malformed signer events (should map to Reject).
/// Returns `SignerError::InfraError` for DB failures (should propagate as Err).
pub fn resolve_signer_key(
    conn: &Connection,
    signer_type: u8,
    signer_event_id: &[u8; 32],
) -> Result<Option<[u8; 32]>, SignerError> {
    match signer_type {
        0 => {
            // Peer signer: load from events table
            let eid_b64 = event_id_to_base64(signer_event_id);
            let blob: Vec<u8> = match conn.query_row(
                "SELECT blob FROM events WHERE event_id = ?1",
                rusqlite::params![&eid_b64],
                |row| row.get(0),
            ) {
                Ok(b) => b,
                Err(rusqlite::Error::QueryReturnedNoRows) => return Ok(None),
                Err(e) => return Err(SignerError::InfraError(e.into())),
            };

            let parsed = match events::parse_event(&blob) {
                Ok(p) => p,
                Err(e) => return Err(SignerError::ContentError(
                    format!("signer event parse error: {}", e)
                )),
            };
            match parsed {
                ParsedEvent::PeerKey(pk) => Ok(Some(pk.public_key)),
                other => Err(SignerError::ContentError(format!(
                    "signer event is not a PeerKeyEvent, got type_code={}",
                    other.event_type_code()
                ))),
            }
        }
        _ => Err(SignerError::ContentError(
            format!("unsupported signer_type: {}", signer_type)
        )),
    }
}

/// Verify an Ed25519 signature over the given message bytes.
pub fn verify_ed25519_signature(public_key: &[u8; 32], message: &[u8], signature: &[u8]) -> bool {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    let vk = match VerifyingKey::from_bytes(public_key) {
        Ok(k) => k,
        Err(_) => return false,
    };

    let sig = match Signature::from_slice(signature) {
        Ok(s) => s,
        Err(_) => return false,
    };

    vk.verify(message, &sig).is_ok()
}

/// Sign bytes with an Ed25519 signing key, returning a 64-byte signature.
pub fn sign_event_bytes(signing_key: &ed25519_dalek::SigningKey, signing_bytes: &[u8]) -> [u8; 64] {
    use ed25519_dalek::Signer;
    let sig = signing_key.sign(signing_bytes);
    sig.to_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::hash_event;
    use crate::db::{open_in_memory, schema::create_tables};
    use crate::events::{PeerKeyEvent, ParsedEvent, encode_event};
    use ed25519_dalek::SigningKey;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn now_ms() -> u64 {
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64
    }

    fn setup() -> rusqlite::Connection {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();
        conn
    }

    fn insert_event_blob(conn: &rusqlite::Connection, blob: &[u8]) -> [u8; 32] {
        let event_id = hash_event(blob);
        let event_id_b64 = event_id_to_base64(&event_id);
        let ts = now_ms() as i64;
        conn.execute(
            "INSERT OR IGNORE INTO events (event_id, event_type, blob, share_scope, created_at, inserted_at)
             VALUES (?1, ?2, ?3, 'shared', ?4, ?5)",
            rusqlite::params![&event_id_b64, "peer_key", blob, ts, ts],
        ).unwrap();
        event_id
    }

    #[test]
    fn test_verify_valid_signature() {
        let mut rng = rand::thread_rng();
        let signing_key = SigningKey::generate(&mut rng);
        let public_key = signing_key.verifying_key().to_bytes();
        let message = b"hello world";
        let sig = sign_event_bytes(&signing_key, message);
        assert!(verify_ed25519_signature(&public_key, message, &sig));
    }

    #[test]
    fn test_verify_invalid_signature() {
        let mut rng = rand::thread_rng();
        let signing_key = SigningKey::generate(&mut rng);
        let wrong_key = SigningKey::generate(&mut rng);
        let wrong_pubkey = wrong_key.verifying_key().to_bytes();
        let message = b"hello world";
        let sig = sign_event_bytes(&signing_key, message);
        assert!(!verify_ed25519_signature(&wrong_pubkey, message, &sig));
    }

    #[test]
    fn test_verify_tampered_message() {
        let mut rng = rand::thread_rng();
        let signing_key = SigningKey::generate(&mut rng);
        let public_key = signing_key.verifying_key().to_bytes();
        let message = b"hello world";
        let sig = sign_event_bytes(&signing_key, message);
        assert!(!verify_ed25519_signature(&public_key, b"tampered", &sig));
    }

    #[test]
    fn test_resolve_signer_key_found() {
        let conn = setup();
        let mut rng = rand::thread_rng();
        let signing_key = SigningKey::generate(&mut rng);
        let public_key = signing_key.verifying_key().to_bytes();

        let pk_event = ParsedEvent::PeerKey(PeerKeyEvent {
            created_at_ms: now_ms(),
            public_key,
        });
        let blob = encode_event(&pk_event).unwrap();
        let event_id = insert_event_blob(&conn, &blob);

        let result = resolve_signer_key(&conn, 0, &event_id).unwrap();
        assert_eq!(result, Some(public_key));
    }

    #[test]
    fn test_resolve_signer_key_not_found() {
        let conn = setup();
        let fake_id = [99u8; 32];
        let result = resolve_signer_key(&conn, 0, &fake_id).unwrap();
        assert_eq!(result, None);
    }

    #[test]
    fn test_resolve_signer_key_wrong_event_type() {
        let conn = setup();
        use crate::events::MessageEvent;
        let msg = ParsedEvent::Message(MessageEvent {
            created_at_ms: now_ms(),
            channel_id: [1u8; 32],
            author_id: [2u8; 32],
            content: "not a key".to_string(),
        });
        let blob = encode_event(&msg).unwrap();
        let event_id = hash_event(&blob);
        let event_id_b64 = event_id_to_base64(&event_id);
        let ts = now_ms() as i64;
        conn.execute(
            "INSERT OR IGNORE INTO events (event_id, event_type, blob, share_scope, created_at, inserted_at)
             VALUES (?1, ?2, ?3, 'shared', ?4, ?5)",
            rusqlite::params![&event_id_b64, "message", &blob, ts, ts],
        ).unwrap();

        let result = resolve_signer_key(&conn, 0, &event_id);
        assert!(result.is_err());
        match result.unwrap_err() {
            SignerError::ContentError(msg) => {
                assert!(msg.contains("not a PeerKeyEvent"), "msg: {}", msg);
            }
            other => panic!("expected ContentError, got: {}", other),
        }
    }
}
