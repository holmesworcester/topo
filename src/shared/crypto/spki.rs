/// Compute the SPKI fingerprint (BLAKE3) from raw Ed25519 public key bytes.
///
/// Constructs the DER-encoded SubjectPublicKeyInfo for Ed25519 and hashes it.
pub fn spki_fingerprint_from_ed25519_pubkey(pubkey: &[u8; 32]) -> [u8; 32] {
    // Ed25519 SubjectPublicKeyInfo DER encoding:
    //   SEQUENCE { SEQUENCE { OID 1.3.101.112 }, BIT STRING { 0x00, <32 key bytes> } }
    let mut spki = Vec::with_capacity(44);
    spki.extend_from_slice(&[
        0x30, 0x2a, // SEQUENCE (42 bytes)
        0x30, 0x05, // SEQUENCE (5 bytes) - AlgorithmIdentifier
        0x06, 0x03, // OID (3 bytes)
        0x2b, 0x65, 0x70, // 1.3.101.112 = Ed25519
        0x03, 0x21, // BIT STRING (33 bytes)
        0x00, // unused bits = 0
    ]);
    spki.extend_from_slice(pubkey);

    *blake3::hash(&spki).as_bytes()
}

#[cfg(test)]
mod tests {
    use super::spki_fingerprint_from_ed25519_pubkey;
    use ed25519_dalek::SigningKey;
    use std::collections::HashSet;

    #[test]
    fn spki_fingerprints_are_unique_for_distinct_generated_keys() {
        // Exercises AXIOM_SPKI_COLLISION_RESISTANCE by checking that
        // generated Ed25519 keys produce distinct SPKI fingerprints.
        let mut rng = rand::thread_rng();
        let mut fingerprints = HashSet::with_capacity(1000);

        for _ in 0..1000 {
            let signing_key = SigningKey::generate(&mut rng);
            let fp = spki_fingerprint_from_ed25519_pubkey(&signing_key.verifying_key().to_bytes());
            assert!(
                fingerprints.insert(fp),
                "duplicate SPKI fingerprint observed during 1000-key generation run"
            );
        }

        assert_eq!(fingerprints.len(), 1000);
    }
}
