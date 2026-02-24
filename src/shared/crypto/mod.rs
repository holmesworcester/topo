use blake2::{Blake2b, Digest};
use blake2::digest::consts::U32;

pub type EventId = [u8; 32];

type Blake2b256 = Blake2b<U32>;

/// Compute Blake2b-256 hash of data, returning 32-byte event ID
pub fn hash_event(data: &[u8]) -> EventId {
    let mut hasher = Blake2b256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut id = [0u8; 32];
    id.copy_from_slice(&result);
    id
}

/// Encode event ID as base64 for storage
pub fn event_id_to_base64(id: &EventId) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(id)
}

/// Decode event ID from base64
pub fn event_id_from_base64(s: &str) -> Option<EventId> {
    use base64::Engine;
    let bytes = base64::engine::general_purpose::STANDARD.decode(s).ok()?;
    if bytes.len() != 32 {
        return None;
    }
    let mut id = [0u8; 32];
    id.copy_from_slice(&bytes);
    Some(id)
}

/// Parse a hex-encoded event ID into a 32-byte array.
pub fn event_id_from_hex(hex_str: &str) -> Option<EventId> {
    let bytes = hex::decode(hex_str).ok()?;
    if bytes.len() != 32 {
        return None;
    }
    let mut id = [0u8; 32];
    id.copy_from_slice(&bytes);
    Some(id)
}

/// Convert a base64-encoded string to hex. Returns the original string on decode failure.
pub fn b64_to_hex(b64: &str) -> String {
    use base64::Engine;
    match base64::engine::general_purpose::STANDARD.decode(b64) {
        Ok(bytes) => hex::encode(bytes),
        Err(_) => b64.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_deterministic() {
        let data = b"hello world";
        let hash1 = hash_event(data);
        let hash2 = hash_event(data);
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_hash_different_inputs() {
        let hash1 = hash_event(b"hello");
        let hash2 = hash_event(b"world");
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_base64_roundtrip() {
        let id = hash_event(b"test data");
        let encoded = event_id_to_base64(&id);
        let decoded = event_id_from_base64(&encoded).unwrap();
        assert_eq!(id, decoded);
    }

    #[test]
    fn test_event_id_size() {
        let id = hash_event(b"test");
        assert_eq!(id.len(), 32);
    }

    #[test]
    fn test_event_id_from_hex_roundtrip() {
        let id = hash_event(b"hex test");
        let hex_str = hex::encode(id);
        let decoded = event_id_from_hex(&hex_str).unwrap();
        assert_eq!(id, decoded);
    }

    #[test]
    fn test_event_id_from_hex_invalid() {
        assert!(event_id_from_hex("not-hex").is_none());
        assert!(event_id_from_hex("aabb").is_none()); // too short
    }

    #[test]
    fn test_b64_to_hex() {
        let id = hash_event(b"b64 test");
        let b64 = event_id_to_base64(&id);
        let hex_str = b64_to_hex(&b64);
        assert_eq!(hex_str, hex::encode(id));
    }

    #[test]
    fn test_b64_to_hex_invalid() {
        assert_eq!(b64_to_hex("not-valid-b64!!!"), "not-valid-b64!!!");
    }
}
