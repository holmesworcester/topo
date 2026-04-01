//! BLAKE3 verified streaming for file slices using bao.
//!
//! Computes a root hash over file plaintext at send time, extracts per-slice
//! proofs, and verifies incoming slices independently (in any order) at
//! receive time.

use std::io::{self, Cursor, Read, Write};

/// Compute the bao root hash and outboard for given data.
/// Returns (root_hash, outboard_bytes).
pub fn compute_outboard(data: &[u8]) -> io::Result<([u8; 32], Vec<u8>)> {
    let mut outboard = Vec::new();
    let mut encoder = bao::encode::Encoder::new_outboard(Cursor::new(&mut outboard));
    encoder.write_all(data)?;
    let hash = encoder.finalize()?;
    Ok((*hash.as_bytes(), outboard))
}

/// Compute the bao root hash by streaming from a reader.
///
/// Reads in 64 KiB chunks to keep memory bounded.  The outboard is built
/// in memory but is much smaller than the data (~0.4% overhead), so for a
/// 100 MiB file the outboard is only ~400 KiB.
pub fn compute_root_hash_streaming(reader: &mut impl Read) -> io::Result<[u8; 32]> {
    let mut outboard = Vec::new();
    let mut encoder = bao::encode::Encoder::new_outboard(Cursor::new(&mut outboard));
    let mut buf = [0u8; 65536];
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        encoder.write_all(&buf[..n])?;
    }
    let hash = encoder.finalize()?;
    Ok(*hash.as_bytes())
}

/// Extract a bao slice proof for the given byte range.
pub fn extract_slice_proof(
    data: &[u8],
    outboard: &[u8],
    slice_start: u64,
    slice_len: u64,
) -> io::Result<Vec<u8>> {
    let mut extractor = bao::encode::SliceExtractor::new_outboard(
        Cursor::new(data),
        Cursor::new(outboard),
        slice_start,
        slice_len,
    );
    let mut proof = Vec::new();
    extractor.read_to_end(&mut proof)?;
    Ok(proof)
}

/// Verify a bao slice proof against a root hash.
/// Returns the verified plaintext bytes.
pub fn verify_slice(
    root_hash: &[u8; 32],
    proof: &[u8],
    slice_start: u64,
    slice_len: u64,
) -> io::Result<Vec<u8>> {
    let hash = bao::Hash::from(*root_hash);
    let mut decoder = bao::decode::SliceDecoder::new(
        Cursor::new(proof),
        &hash,
        slice_start,
        slice_len,
    );
    let mut output = Vec::new();
    decoder.read_to_end(&mut output)?;
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_single_slice() {
        let data = b"hello world, this is a test of bao verified streaming";
        let (root_hash, outboard) = compute_outboard(data).unwrap();

        let proof = extract_slice_proof(data, &outboard, 0, data.len() as u64).unwrap();
        let verified = verify_slice(&root_hash, &proof, 0, data.len() as u64).unwrap();
        assert_eq!(verified, data);
    }

    #[test]
    fn roundtrip_multi_slice() {
        // 4 KiB of data, sliced into 1 KiB chunks
        let data: Vec<u8> = (0..4096).map(|i| (i % 256) as u8).collect();
        let (root_hash, outboard) = compute_outboard(&data).unwrap();

        for i in 0..4 {
            let start = i * 1024;
            let len = 1024u64;
            let proof = extract_slice_proof(&data, &outboard, start, len).unwrap();
            let verified = verify_slice(&root_hash, &proof, start, len).unwrap();
            assert_eq!(verified, &data[start as usize..(start + len) as usize]);
        }
    }

    #[test]
    fn tampered_proof_fails() {
        let data = b"some important data that must be verified";
        let (root_hash, outboard) = compute_outboard(data).unwrap();
        let mut proof = extract_slice_proof(data, &outboard, 0, data.len() as u64).unwrap();

        // Tamper with the proof
        if let Some(last) = proof.last_mut() {
            *last ^= 1;
        }

        let result = verify_slice(&root_hash, &proof, 0, data.len() as u64);
        assert!(result.is_err(), "tampered proof should fail verification");
    }

    #[test]
    fn wrong_hash_fails() {
        let data = b"data for wrong hash test";
        let (_root_hash, outboard) = compute_outboard(data).unwrap();
        let proof = extract_slice_proof(data, &outboard, 0, data.len() as u64).unwrap();

        let wrong_hash = [0xFFu8; 32];
        let result = verify_slice(&wrong_hash, &proof, 0, data.len() as u64);
        assert!(result.is_err(), "wrong hash should fail verification");
    }

    #[test]
    fn measure_proof_overhead() {
        use crate::event_modules::file_slice::wire::{BAO_PLAINTEXT_CAPACITY, FILE_SLICE_CIPHERTEXT_BYTES};

        // Test with various file sizes to measure overhead scaling
        for file_size in [1_000_000usize, 10_000_000, 100_000_000] {
            let file_data: Vec<u8> = (0..file_size).map(|i| (i % 251) as u8).collect();
            let (_, outboard) = compute_outboard(&file_data).unwrap();

            let chunk = BAO_PLAINTEXT_CAPACITY;
            let len = file_data.len().min(chunk);
            let proof = extract_slice_proof(&file_data, &outboard, 0, len as u64).unwrap();
            let overhead = proof.len() - len;
            let fits = proof.len() <= FILE_SLICE_CIPHERTEXT_BYTES - 4;
            eprintln!(
                "  file={:.0}MB chunk={} proof={} overhead={} fits={}",
                file_size as f64 / 1e6, chunk, proof.len(), overhead, fits
            );
            assert!(fits, "bao encoding must fit in payload field for {}MB file", file_size / 1_000_000);
        }
    }

    #[test]
    fn roundtrip_packed_payload() {
        // Simulate the real send/receive flow: file data → outboard → per-slice
        // bao encoding → pack into 262144-byte payload → unpack → verify.
        use crate::event_modules::file_slice::wire::*;

        let eff_cap = BAO_PLAINTEXT_CAPACITY;
        let file_data: Vec<u8> = (0..600_000).map(|i| (i % 251) as u8).collect();
        let file_size = file_data.len();
        let (root_hash, outboard) = compute_outboard(&file_data).unwrap();

        let num_slices = file_size.div_ceil(eff_cap);

        for i in 0..num_slices {
            let data_start = i * eff_cap;
            let bytes_this = (file_size - data_start).min(eff_cap);
            // Extract bao slice encoding (contains data + tree nodes)
            let encoding = extract_slice_proof(
                &file_data,
                &outboard,
                data_start as u64,
                bytes_this as u64,
            )
            .unwrap();
            let plaintext = &file_data[data_start..data_start + bytes_this];

            // Pack into fixed-size field
            let packed = pack_bao_payload(&encoding, plaintext);
            assert_eq!(packed.len(), FILE_SLICE_CIPHERTEXT_BYTES);

            // Unpack and verify (mirrors the projector + save path)
            let (enc_out, _) = unpack_bao_payload(&packed);
            assert!(!enc_out.is_empty(), "slice {} should have bao encoding", i);
            let verified = verify_slice(
                &root_hash,
                &enc_out,
                data_start as u64,
                bytes_this as u64,
            )
            .unwrap();
            assert_eq!(
                &verified, plaintext,
                "slice {} verified data mismatch",
                i
            );
        }
    }

    #[test]
    fn empty_data() {
        let data = b"";
        let (root_hash, outboard) = compute_outboard(data).unwrap();
        let proof = extract_slice_proof(data, &outboard, 0, 0).unwrap();
        let verified = verify_slice(&root_hash, &proof, 0, 0).unwrap();
        assert!(verified.is_empty());
    }
}
