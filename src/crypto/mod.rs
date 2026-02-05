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
#[cfg(test)]
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
}
