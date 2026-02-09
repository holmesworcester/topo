//! File attachment throughput benchmarks.
//!
//! Measures encode + store + project throughput for file slices.
//!
//! Run default tests: cargo test --release --test file_throughput -- --nocapture
//! Run all (incl. ignored): cargo test --release --test file_throughput -- --nocapture --include-ignored

use std::time::Instant;

use ed25519_dalek::SigningKey;
use poc_7::crypto::{event_id_to_base64, hash_event, EventId};
use poc_7::db::{open_connection, schema::create_tables};
use poc_7::events::{
    self, FileSliceEvent, MessageAttachmentEvent, MessageEvent, ParsedEvent, PeerKeyEvent,
    SecretKeyEvent,
};
use poc_7::projection::pipeline::project_one;
use poc_7::projection::signer::sign_event_bytes;
use rusqlite::Connection;
use tempfile::NamedTempFile;

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

fn setup() -> (Connection, NamedTempFile) {
    let tmp = NamedTempFile::new().unwrap();
    let conn = open_connection(tmp.path()).unwrap();
    create_tables(&conn).unwrap();
    (conn, tmp)
}

/// Insert a blob into events + neg_items + recorded_events.
fn insert_event_raw(conn: &Connection, recorded_by: &str, blob: &[u8]) -> EventId {
    let event_id = hash_event(blob);
    let event_id_b64 = event_id_to_base64(&event_id);
    let ts = now_ms();
    let type_code = blob[0];
    let type_name = events::registry()
        .lookup(type_code)
        .map(|m| m.type_name)
        .unwrap_or("unknown");

    conn.execute(
        "INSERT OR IGNORE INTO events (event_id, event_type, blob, share_scope, created_at, inserted_at)
         VALUES (?1, ?2, ?3, 'shared', ?4, ?5)",
        rusqlite::params![&event_id_b64, type_name, blob, ts as i64, ts as i64],
    )
    .unwrap();
    conn.execute(
        "INSERT OR IGNORE INTO neg_items (ts, id) VALUES (?1, ?2)",
        rusqlite::params![ts as i64, event_id.as_slice()],
    )
    .unwrap();
    conn.execute(
        "INSERT OR IGNORE INTO recorded_events (peer_id, event_id, recorded_at, source)
         VALUES (?1, ?2, ?3, 'test')",
        rusqlite::params![recorded_by, &event_id_b64, ts as i64],
    )
    .unwrap();

    event_id
}

/// Create prerequisite events (message, secret key, peer key) and return their IDs + signing key.
fn create_prereqs(
    conn: &Connection,
    recorded_by: &str,
) -> (EventId, EventId, EventId, SigningKey) {
    // Message
    let msg = ParsedEvent::Message(MessageEvent {
        created_at_ms: now_ms(),
        channel_id: [1u8; 32],
        author_id: [2u8; 32],
        content: "file parent".to_string(),
    });
    let msg_blob = events::encode_event(&msg).unwrap();
    let msg_eid = insert_event_raw(conn, recorded_by, &msg_blob);
    project_one(conn, recorded_by, &msg_eid).unwrap();

    // Secret key (for attachment key_event_id dep)
    let sk = ParsedEvent::SecretKey(SecretKeyEvent {
        created_at_ms: now_ms(),
        key_bytes: [0xBB; 32],
    });
    let sk_blob = events::encode_event(&sk).unwrap();
    let sk_eid = insert_event_raw(conn, recorded_by, &sk_blob);
    project_one(conn, recorded_by, &sk_eid).unwrap();

    // Peer key for signing
    let mut rng = rand::thread_rng();
    let signing_key = SigningKey::generate(&mut rng);
    let public_key = signing_key.verifying_key().to_bytes();

    let pk = ParsedEvent::PeerKey(PeerKeyEvent {
        created_at_ms: now_ms(),
        public_key,
    });
    let pk_blob = events::encode_event(&pk).unwrap();
    let pk_eid = insert_event_raw(conn, recorded_by, &pk_blob);
    project_one(conn, recorded_by, &pk_eid).unwrap();

    (msg_eid, sk_eid, pk_eid, signing_key)
}

fn run_file_throughput(file_size_bytes: usize, slice_size: usize) {
    let (conn, _tmp) = setup();
    let recorded_by = "peer1";

    let (msg_eid, sk_eid, pk_eid, signing_key) = create_prereqs(&conn, recorded_by);

    let total_slices = (file_size_bytes + slice_size - 1) / slice_size;
    let file_id = [0xF0; 32];

    // Pre-generate ciphertext for slices (reuse one buffer)
    let ciphertext_template: Vec<u8> = vec![0xAB; slice_size];

    let start = Instant::now();

    // Encode + store + project all file slices
    for i in 0..total_slices as u32 {
        let ct_len = if (i as usize + 1) * slice_size > file_size_bytes {
            file_size_bytes - (i as usize) * slice_size
        } else {
            slice_size
        };

        let fs = FileSliceEvent {
            created_at_ms: now_ms(),
            file_id,
            slice_number: i,
            ciphertext: ciphertext_template[..ct_len].to_vec(),
            signed_by: pk_eid,
            signer_type: 0,
            signature: [0u8; 64],
        };
        let event = ParsedEvent::FileSlice(fs);
        let mut blob = events::encode_event(&event).unwrap();

        // Sign
        let sig_len = 64;
        let blob_len = blob.len();
        let signing_bytes = &blob[..blob_len - sig_len];
        let sig = sign_event_bytes(&signing_key, signing_bytes);
        blob[blob_len - sig_len..].copy_from_slice(&sig);

        let eid = insert_event_raw(&conn, recorded_by, &blob);
        let result = project_one(&conn, recorded_by, &eid).unwrap();
        assert!(
            matches!(
                result,
                poc_7::projection::decision::ProjectionDecision::Valid
            ),
            "slice {} failed: {:?}",
            i,
            result
        );
    }

    // Create and project message_attachment
    let att = ParsedEvent::MessageAttachment(MessageAttachmentEvent {
        created_at_ms: now_ms(),
        message_id: msg_eid,
        file_id,
        blob_bytes: file_size_bytes as u64,
        total_slices: total_slices as u32,
        slice_bytes: slice_size as u32,
        root_hash: [0xAA; 32],
        key_event_id: sk_eid,
        filename: "bench.bin".to_string(),
        mime_type: "application/octet-stream".to_string(),
    });
    let att_blob = events::encode_event(&att).unwrap();
    let att_eid = insert_event_raw(&conn, recorded_by, &att_blob);
    project_one(&conn, recorded_by, &att_eid).unwrap();

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
            "SELECT COUNT(*) FROM message_attachments WHERE recorded_by = ?1 AND event_id = ?2",
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
    run_file_throughput(200 * 1024, 65536); // ~4 slices
}

#[test]
fn test_file_throughput_10mb() {
    run_file_throughput(10 * 1024 * 1024, 65536); // 160 slices
}

#[test]
#[ignore]
fn test_file_throughput_100mb() {
    run_file_throughput(100 * 1024 * 1024, 65536); // 1,600 slices
}

#[test]
#[ignore]
fn test_file_throughput_1gb() {
    run_file_throughput(1024 * 1024 * 1024, 65536); // 16,384 slices
}
