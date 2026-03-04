use rusqlite::Connection;

use crate::crypto::event_id_to_base64;
pub use crate::crypto::{sign_event_bytes, verify_ed25519_signature};

/// Result of resolving a signer key from the database.
#[derive(Debug, PartialEq)]
pub enum SignerResolution {
    /// Key successfully resolved.
    Found([u8; 32]),
    /// Signer event not found (or not valid for this tenant).
    NotFound,
    /// Signer data is invalid (unsupported type, wrong event type, parse error).
    Invalid(String),
}

/// Resolve the public key for a signer event, scoped to the given tenant.
///
/// Returns `Err` only for real DB errors. Data-level problems (unsupported
/// signer_type, missing event, wrong event type, parse failures) are
/// returned as `SignerResolution::Invalid` or `SignerResolution::NotFound`.
pub fn resolve_signer_key(
    conn: &Connection,
    recorded_by: &str,
    signer_type: u8,
    signer_event_id: &[u8; 32],
) -> Result<SignerResolution, Box<dyn std::error::Error>> {
    // Valid type codes for each signer_type
    let valid_type_codes: &[u8] = match signer_type {
        1 => &[8],  // Workspace
        2 => &[10], // UserInvite
        3 => &[12], // DeviceInvite
        4 => &[14], // User
        5 => &[16], // PeerShared
        _ => {
            return Ok(SignerResolution::Invalid(format!(
                "unsupported signer_type: {}",
                signer_type
            )));
        }
    };

    let eid_b64 = event_id_to_base64(signer_event_id);
    let blob: Vec<u8> = match conn.query_row(
        "SELECT e.blob FROM events e
         INNER JOIN valid_events v ON e.event_id = v.event_id
         WHERE v.peer_id = ?1 AND e.event_id = ?2",
        rusqlite::params![recorded_by, &eid_b64],
        |row| row.get(0),
    ) {
        Ok(b) => b,
        Err(rusqlite::Error::QueryReturnedNoRows) => return Ok(SignerResolution::NotFound),
        Err(e) => return Err(e.into()),
    };

    // All signer key events have public_key at blob[9..41].
    // Minimum blob size for key extraction: 41 bytes.
    if blob.len() < 41 {
        return Ok(SignerResolution::Invalid(format!(
            "signer blob too short: {} bytes",
            blob.len()
        )));
    }

    let actual_type_code = blob[0];
    if !valid_type_codes.contains(&actual_type_code) {
        return Ok(SignerResolution::Invalid(format!(
            "signer event type_code={} not valid for signer_type={}",
            actual_type_code, signer_type
        )));
    }

    let mut public_key = [0u8; 32];
    public_key.copy_from_slice(&blob[9..41]);
    Ok(SignerResolution::Found(public_key))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::hash_event;
    use crate::db::{
        open_in_memory,
        schema::create_tables,
        store::{insert_event, insert_recorded_event},
    };
    use crate::event_modules::{encode_event, ParsedEvent, PeerSharedEvent};
    use ed25519_dalek::SigningKey;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn now_ms() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64
    }

    fn setup() -> rusqlite::Connection {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();
        conn
    }

    /// Insert a blob into events + valid_events + recorded_events for the given tenant.
    fn insert_event_blob(conn: &rusqlite::Connection, recorded_by: &str, blob: &[u8]) -> [u8; 32] {
        let event_id = hash_event(blob);
        let event_id_b64 = event_id_to_base64(&event_id);
        let type_code = blob[0];
        let type_name = crate::event_modules::registry()
            .lookup(type_code)
            .map(|m| m.type_name)
            .unwrap_or("unknown");
        let ts = now_ms() as i64;
        insert_event(
            conn,
            &event_id,
            type_name,
            blob,
            crate::event_modules::ShareScope::Shared,
            ts,
            ts,
        )
        .unwrap();
        conn.execute(
            "INSERT OR IGNORE INTO valid_events (peer_id, event_id) VALUES (?1, ?2)",
            rusqlite::params![recorded_by, &event_id_b64],
        )
        .unwrap();
        insert_recorded_event(conn, recorded_by, &event_id, ts, "test").unwrap();
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
        let recorded_by = "peer1";
        let mut rng = rand::thread_rng();
        let signing_key = SigningKey::generate(&mut rng);
        let public_key = signing_key.verifying_key().to_bytes();

        let signer_event = ParsedEvent::PeerShared(PeerSharedEvent {
            created_at_ms: now_ms(),
            public_key,
            user_event_id: [0u8; 32],
            device_name: "test-device".to_string(),
            signed_by: [1u8; 32],
            signer_type: 5,
            signature: [0u8; 64],
        });
        let blob = encode_event(&signer_event).unwrap();
        let event_id = insert_event_blob(&conn, recorded_by, &blob);

        let result = resolve_signer_key(&conn, recorded_by, 5, &event_id).unwrap();
        assert_eq!(result, SignerResolution::Found(public_key));
    }

    #[test]
    fn test_resolve_signer_key_not_found() {
        let conn = setup();
        let recorded_by = "peer1";
        let fake_id = [99u8; 32];
        let result = resolve_signer_key(&conn, recorded_by, 5, &fake_id).unwrap();
        assert_eq!(result, SignerResolution::NotFound);
    }

    #[test]
    fn test_resolve_signer_key_wrong_event_type() {
        let conn = setup();
        let recorded_by = "peer1";
        use crate::event_modules::MessageEvent;
        let msg = ParsedEvent::Message(MessageEvent {
            created_at_ms: now_ms(),
            workspace_id: [1u8; 32],
            author_id: [2u8; 32],
            content: "not a key".to_string(),
            signed_by: [0u8; 32],
            signer_type: 5,
            signature: [0u8; 64],
        });
        let blob = encode_event(&msg).unwrap();
        let event_id = insert_event_blob(&conn, recorded_by, &blob);

        let result = resolve_signer_key(&conn, recorded_by, 5, &event_id).unwrap();
        match result {
            SignerResolution::Invalid(msg) => {
                assert!(msg.contains("not valid for signer_type=5"), "msg: {}", msg);
            }
            other => panic!("expected Invalid, got {:?}", other),
        }
    }

    #[test]
    fn test_resolve_signer_key_unsupported_type() {
        let conn = setup();
        let recorded_by = "peer1";
        let fake_id = [1u8; 32];
        let result = resolve_signer_key(&conn, recorded_by, 255, &fake_id).unwrap();
        match result {
            SignerResolution::Invalid(msg) => {
                assert!(msg.contains("unsupported signer_type: 255"), "msg: {}", msg);
            }
            other => panic!("expected Invalid, got {:?}", other),
        }
    }

    #[test]
    fn test_resolve_signer_key_tenant_scoped() {
        let conn = setup();
        let tenant_a = "tenant_a";
        let tenant_b = "tenant_b";
        let mut rng = rand::thread_rng();
        let signing_key = SigningKey::generate(&mut rng);
        let public_key = signing_key.verifying_key().to_bytes();

        let signer_event = ParsedEvent::PeerShared(PeerSharedEvent {
            created_at_ms: now_ms(),
            public_key,
            user_event_id: [0u8; 32],
            device_name: "test-device".to_string(),
            signed_by: [1u8; 32],
            signer_type: 5,
            signature: [0u8; 64],
        });
        let blob = encode_event(&signer_event).unwrap();
        // Insert and validate for tenant_a only
        let event_id = insert_event_blob(&conn, tenant_a, &blob);

        // tenant_a should find it
        let result_a = resolve_signer_key(&conn, tenant_a, 5, &event_id).unwrap();
        assert_eq!(result_a, SignerResolution::Found(public_key));

        // tenant_b should NOT find it (not in valid_events for tenant_b)
        let result_b = resolve_signer_key(&conn, tenant_b, 5, &event_id).unwrap();
        assert_eq!(result_b, SignerResolution::NotFound);
    }
}
