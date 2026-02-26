use blake2::digest::consts::U32;
use blake2::{Blake2b, Digest};

/// Compute the SPKI fingerprint (BLAKE2b-256) from raw Ed25519 public key bytes.
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

    let mut hasher = Blake2b::<U32>::new();
    hasher.update(&spki);
    let result = hasher.finalize();
    let mut fp = [0u8; 32];
    fp.copy_from_slice(&result);
    fp
}

