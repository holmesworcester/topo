pub use crate::crypto::{
    decrypt_event_blob, encrypt_event_blob, unwrap_key_from_sender, wrap_key_for_recipient,
};
// Encrypted wrapper handling now lives inside the shared projection pipeline
// recursion in `apply/stages.rs`. This module only exposes the crypto helpers
// reused by projection, creation, runtime control, and tests.

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    #[test]
    fn test_wrap_unwrap_roundtrip() {
        let mut rng = rand::thread_rng();
        let sender_key = SigningKey::generate(&mut rng);
        let recipient_key = SigningKey::generate(&mut rng);

        let plaintext_key = [0x42u8; 32];

        let wrapped =
            wrap_key_for_recipient(&sender_key, &recipient_key.verifying_key(), &plaintext_key);

        // Wrapped key should differ from plaintext
        assert_ne!(wrapped, plaintext_key);

        let unwrapped =
            unwrap_key_from_sender(&recipient_key, &sender_key.verifying_key(), &wrapped);

        assert_eq!(unwrapped, plaintext_key);
    }

    #[test]
    fn test_wrap_wrong_recipient_fails() {
        let mut rng = rand::thread_rng();
        let sender_key = SigningKey::generate(&mut rng);
        let recipient_key = SigningKey::generate(&mut rng);
        let wrong_key = SigningKey::generate(&mut rng);

        let plaintext_key = [0xAB; 32];

        let wrapped =
            wrap_key_for_recipient(&sender_key, &recipient_key.verifying_key(), &plaintext_key);

        // Wrong recipient cannot unwrap
        let bad_unwrap = unwrap_key_from_sender(&wrong_key, &sender_key.verifying_key(), &wrapped);
        assert_ne!(bad_unwrap, plaintext_key);
    }

    #[test]
    fn test_wrap_different_keys_produce_different_wrapped() {
        let mut rng = rand::thread_rng();
        let sender_key = SigningKey::generate(&mut rng);
        let recipient_key = SigningKey::generate(&mut rng);

        let key_a = [0x11u8; 32];
        let key_b = [0x22u8; 32];

        let wrapped_a = wrap_key_for_recipient(&sender_key, &recipient_key.verifying_key(), &key_a);
        let wrapped_b = wrap_key_for_recipient(&sender_key, &recipient_key.verifying_key(), &key_b);

        assert_ne!(wrapped_a, wrapped_b);
    }

    #[test]
    fn test_encrypt_decrypt_event_blob_roundtrip() {
        let key = [0xCC; 32];
        let plaintext = b"hello world, this is a test payload!";

        let (nonce, ciphertext, auth_tag) = encrypt_event_blob(&key, plaintext).unwrap();
        let decrypted = decrypt_event_blob(&key, &nonce, &ciphertext, &auth_tag).unwrap();

        assert_eq!(decrypted.as_slice(), plaintext);
    }
}
