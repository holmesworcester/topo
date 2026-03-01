use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use blake2::digest::consts::U32;
use blake2::{Blake2b, Digest};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

pub type EventId = [u8; 32];

mod allowed_peers;
mod spki;

pub use allowed_peers::AllowedPeers;
pub use spki::spki_fingerprint_from_ed25519_pubkey;

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

/// Encrypt a plaintext blob using AES-256-GCM with a random nonce.
/// Returns (nonce, ciphertext, auth_tag).
pub fn encrypt_event_blob(
    key: &[u8; 32],
    plaintext: &[u8],
) -> Result<([u8; 12], Vec<u8>, [u8; 16]), Box<dyn std::error::Error>> {
    use rand::RngCore;

    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| format!("aes-gcm key init: {}", e))?;

    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext_with_tag = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| format!("aes-gcm encrypt: {}", e))?;

    // aes-gcm appends the 16-byte tag to the ciphertext
    let tag_start = ciphertext_with_tag.len() - 16;
    let ciphertext = ciphertext_with_tag[..tag_start].to_vec();
    let mut auth_tag = [0u8; 16];
    auth_tag.copy_from_slice(&ciphertext_with_tag[tag_start..]);

    Ok((nonce_bytes, ciphertext, auth_tag))
}

/// Decrypt an AES-256-GCM encrypted blob represented as nonce + ciphertext + auth_tag.
pub fn decrypt_event_blob(
    key: &[u8; 32],
    nonce: &[u8; 12],
    ciphertext: &[u8],
    auth_tag: &[u8; 16],
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| format!("aes-gcm key init: {}", e))?;
    let nonce_obj = Nonce::from_slice(nonce);

    let mut ct_with_tag = Vec::with_capacity(ciphertext.len() + 16);
    ct_with_tag.extend_from_slice(ciphertext);
    ct_with_tag.extend_from_slice(auth_tag);

    let plaintext = cipher
        .decrypt(nonce_obj, ct_with_tag.as_slice())
        .map_err(|e| format!("aes-gcm decrypt: {}", e))?;
    Ok(plaintext)
}

/// Verify an Ed25519 signature over the given message bytes.
pub fn verify_ed25519_signature(public_key: &[u8; 32], message: &[u8], signature: &[u8]) -> bool {
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
pub fn sign_event_bytes(signing_key: &SigningKey, signing_bytes: &[u8]) -> [u8; 64] {
    let sig = signing_key.sign(signing_bytes);
    sig.to_bytes()
}

/// Derive a 32-byte shared wrap key from a local Ed25519 private key and
/// a remote Ed25519 public key via X25519 Diffie-Hellman.
fn derive_wrap_key(local_private: &SigningKey, remote_public: &VerifyingKey) -> [u8; 32] {
    // Convert Ed25519 keys to X25519 (Montgomery form)
    let local_scalar = local_private.to_scalar();
    let remote_point = remote_public.to_montgomery();

    // X25519 DH: shared_point = local_scalar * remote_montgomery_point
    let shared_point = &remote_point * &local_scalar;

    // Hash to uniform 32-byte key with domain separation
    let mut hasher = Blake2b256::new();
    hasher.update(b"poc7-key-wrap-v1");
    hasher.update(shared_point.as_bytes());
    let hash = hasher.finalize();

    let mut key = [0u8; 32];
    key.copy_from_slice(&hash);
    key
}

/// Wrap a 32-byte secret key for a recipient identified by their Ed25519 public key.
///
/// Simplified wrap for POC: XOR plaintext key with a derived wrap key.
/// Authentication is provided by the SecretShared event signature.
pub fn wrap_key_for_recipient(
    sender_private: &SigningKey,
    recipient_public: &VerifyingKey,
    plaintext_key: &[u8; 32],
) -> [u8; 32] {
    let wrap_key = derive_wrap_key(sender_private, recipient_public);
    let mut wrapped = [0u8; 32];
    for i in 0..32 {
        wrapped[i] = plaintext_key[i] ^ wrap_key[i];
    }
    wrapped
}

/// Unwrap a 32-byte wrapped key using the recipient's private key and sender's public key.
///
/// Mirror of `wrap_key_for_recipient`: derives the same wrap key and XORs
/// to recover the plaintext key.
pub fn unwrap_key_from_sender(
    recipient_private: &SigningKey,
    sender_public: &VerifyingKey,
    wrapped_key: &[u8; 32],
) -> [u8; 32] {
    let wrap_key = derive_wrap_key(recipient_private, sender_public);
    let mut plaintext = [0u8; 32];
    for i in 0..32 {
        plaintext[i] = wrapped_key[i] ^ wrap_key[i];
    }
    plaintext
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

    #[test]
    fn test_encrypt_decrypt_event_blob_roundtrip() {
        let key = [0xCC; 32];
        let plaintext = b"hello world, this is a test payload!";
        let (nonce, ciphertext, auth_tag) = encrypt_event_blob(&key, plaintext).unwrap();
        let decrypted = decrypt_event_blob(&key, &nonce, &ciphertext, &auth_tag).unwrap();
        assert_eq!(decrypted.as_slice(), plaintext);
    }

    #[test]
    fn test_sign_verify_roundtrip() {
        let mut rng = rand::thread_rng();
        let signing_key = SigningKey::generate(&mut rng);
        let message = b"hello";
        let signature = sign_event_bytes(&signing_key, message);
        let public_key = signing_key.verifying_key().to_bytes();
        assert!(verify_ed25519_signature(&public_key, message, &signature));
    }

    #[test]
    fn test_wrap_unwrap_roundtrip() {
        let mut rng = rand::thread_rng();
        let sender_key = SigningKey::generate(&mut rng);
        let recipient_key = SigningKey::generate(&mut rng);
        let plaintext_key = [0x42u8; 32];
        let wrapped =
            wrap_key_for_recipient(&sender_key, &recipient_key.verifying_key(), &plaintext_key);
        let unwrapped =
            unwrap_key_from_sender(&recipient_key, &sender_key.verifying_key(), &wrapped);
        assert_eq!(unwrapped, plaintext_key);
    }
}
