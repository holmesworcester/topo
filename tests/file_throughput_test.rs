//! File attachment throughput benchmarks.
//!
//! Measures encode + store + project throughput for file slices.
//!
//! Run default tests: cargo test --release --test file_throughput_test -- --nocapture
//! Run all (incl. ignored): cargo test --release --test file_throughput_test -- --nocapture --include-ignored

use std::time::Instant;

use topo::crypto::event_id_to_base64;
use topo::db::open_connection;
use topo::event_modules::{
    file_slice::{FILE_SLICE_CIPHERTEXT_BYTES, FILE_SLICE_DATA_BYTES},
    FileEvent, FileSliceEvent, ParsedEvent,
};
use topo::projection::create::create_encrypted_event_synchronous;
use topo::testutil::Peer;

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

fn run_file_throughput(file_size_bytes: usize) {
    let peer = Peer::new_with_identity("file-throughput");
    let conn = open_connection(&peer.db_path).unwrap();
    let recorded_by = peer.identity.as_str();
    let sk_eid = peer.create_key_secret([0xBB; 32]);
    let msg_eid = peer.create_encrypted_message(&sk_eid, "file parent");
    let signer_eid = peer
        .peer_shared_event_id
        .expect("peer should have peer_shared signer");
    let signing_key = peer
        .peer_shared_signing_key
        .as_ref()
        .expect("peer should have peer_shared signing key")
        .clone();

    // Each file slice carries 256 KiB of logical file data in a larger fixed payload.
    let slice_size = FILE_SLICE_DATA_BYTES;
    let total_slices = (file_size_bytes + slice_size - 1) / slice_size;
    let file_id = [0xF0; 32];

    // Create and project encrypted file descriptor first (required for file_slice auth).
    let att_eid = create_encrypted_event_synchronous(
        &conn,
        recorded_by,
        &sk_eid,
        &ParsedEvent::File(FileEvent {
            created_at_ms: now_ms(),
            message_id: msg_eid,
            file_id,
            blob_bytes: file_size_bytes as u64,
            total_slices: total_slices as u32,
            slice_bytes: slice_size as u32,
            root_hash: [0u8; 32],
            key_event_id: sk_eid,
            filename: "bench.bin".to_string(),
            mime_type: "application/octet-stream".to_string(),
        }),
        Some((&signer_eid, &signing_key)),
    )
    .unwrap();

    // Pre-generate ciphertext for slices (canonical fixed size)
    let ciphertext_template: Vec<u8> = vec![0xAB; FILE_SLICE_CIPHERTEXT_BYTES];

    let start = Instant::now();

    // Encode + encrypt + store + project all file slices.
    for i in 0..total_slices as u32 {
        create_encrypted_event_synchronous(
            &conn,
            recorded_by,
            &sk_eid,
            &ParsedEvent::FileSlice(FileSliceEvent {
                created_at_ms: now_ms(),
                file_id,
                slice_number: i,
                ciphertext: ciphertext_template.clone(),
            }),
            Some((&signer_eid, &signing_key)),
        )
        .unwrap_or_else(|err| panic!("slice {} failed: {:?}", i, err));
    }

    let elapsed = start.elapsed();

    // Verify
    let file_id_b64 = event_id_to_base64(&file_id);
    let slice_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM file_slices WHERE recorded_by = ?1 AND file_id = ?2",
            rusqlite::params![recorded_by, &file_id_b64],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(slice_count, total_slices as i64);

    let att_b64 = event_id_to_base64(&att_eid);
    let att_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM files WHERE recorded_by = ?1 AND event_id = ?2",
            rusqlite::params![recorded_by, &att_b64],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(att_count, 1);

    let secs = elapsed.as_secs_f64();
    let mb = file_size_bytes as f64 / (1024.0 * 1024.0);
    let mb_per_sec = mb / secs.max(0.001);

    eprintln!();
    eprintln!(
        "=== File throughput: {:.1} MB in {} slices ({} B/slice) ===",
        mb, total_slices, slice_size
    );
    eprintln!("  Wall time:  {:.3}s", secs);
    eprintln!("  Throughput: {:.1} MB/s", mb_per_sec);
    eprintln!("  Slices/s:   {:.0}", total_slices as f64 / secs.max(0.001));
    eprintln!();
}

#[test]
fn test_file_throughput_200kb() {
    run_file_throughput(256 * 1024); // 1 canonical slice
}

#[test]
fn test_file_throughput_10mb() {
    run_file_throughput(10 * 1024 * 1024); // 40 slices @ 256 KiB each
}

#[test]
#[ignore]
fn test_file_throughput_100mb() {
    run_file_throughput(100 * 1024 * 1024); // 400 slices
}

#[test]
#[ignore]
fn test_file_throughput_1gb() {
    run_file_throughput(1024 * 1024 * 1024); // 4,096 slices
}
