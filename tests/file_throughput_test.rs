//! File attachment throughput benchmarks.
//!
//! Measures encode + store + project throughput for file slices.
//!
//! Run default tests: cargo test --release --test file_throughput_test -- --nocapture
//! Run all (incl. ignored): cargo test --release --test file_throughput_test -- --nocapture --include-ignored

use std::time::Instant;

use ed25519_dalek::SigningKey;
use rusqlite::Connection;
use tempfile::NamedTempFile;
use topo::crypto::{event_id_to_base64, hash_event, EventId};
use topo::db::{open_connection, schema::create_tables};
use topo::event_modules::{
    self as events,
    file_slice::{FILE_SLICE_CIPHERTEXT_BYTES, FILE_SLICE_DATA_BYTES},
    FileEvent, FileSliceEvent, KeySecretEvent, MessageEvent, ParsedEvent, PeerSharedEvent,
    UserEvent, WorkspaceEvent,
};
use topo::projection::apply::project_one;
use topo::projection::create::create_encrypted_event_synchronous;

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

/// Insert a blob into events + optional shared_event_index + recorded_events.
fn insert_event_raw(
    conn: &Connection,
    recorded_by: &str,
    blob: &[u8],
    workspace_id: Option<&str>,
) -> EventId {
    let event_id = hash_event(blob);
    let event_id_b64 = event_id_to_base64(&event_id);
    let ts = now_ms();
    let type_code = blob[0];
    let meta = events::registry()
        .lookup(type_code)
        .expect("unknown event type for raw insert");

    conn.execute(
        "INSERT OR IGNORE INTO events (event_id, event_type, blob, share_scope, created_at, inserted_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        rusqlite::params![
            &event_id_b64,
            meta.type_name,
            blob,
            meta.share_scope.as_str(),
            ts as i64,
            ts as i64
        ],
    )
    .unwrap();
    if meta.share_scope == events::ShareScope::Shared {
        let ws_id = if meta.type_name == "workspace" {
            event_id_b64.as_str()
        } else {
            workspace_id.expect("shared event insert requires workspace_id")
        };
        conn.execute(
            "INSERT OR IGNORE INTO shared_event_index (workspace_id, ts, shard_u8, id) VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![ws_id, ts as i64, i64::from(event_id[0]), event_id.as_slice()],
        )
        .unwrap();
    }
    conn.execute(
        "INSERT OR IGNORE INTO recorded_events (peer_id, event_id, recorded_at, source)
         VALUES (?1, ?2, ?3, 'test')",
        rusqlite::params![recorded_by, &event_id_b64, ts as i64],
    )
    .unwrap();

    event_id
}

/// Bootstrap a minimal workspace bootstrap path. Returns
/// (peer_shared_id, peer_shared_key, user_id, workspace_id).
fn make_identity_chain(
    conn: &Connection,
    recorded_by: &str,
) -> (EventId, SigningKey, EventId, EventId) {
    let mut rng = rand::thread_rng();

    let workspace_key = SigningKey::generate(&mut rng);
    let net = ParsedEvent::Workspace(WorkspaceEvent {
        created_at_ms: now_ms(),
        public_key: workspace_key.verifying_key().to_bytes(),
        name: "bench".to_string(),
    });
    let net_blob = events::encode_event(&net).unwrap();
    let net_eid = hash_event(&net_blob);
    let workspace_id_b64 = event_id_to_base64(&net_eid);
    let net_eid = insert_event_raw(conn, recorded_by, &net_blob, Some(&workspace_id_b64));
    let workspace_id = net_eid;

    let user_key = SigningKey::generate(&mut rng);
    let ub = ParsedEvent::User(UserEvent {
        created_at_ms: now_ms(),
        public_key: user_key.verifying_key().to_bytes(),
        username: "bench-user".to_string(),
    });
    let ub_blob = events::encode_event(&ub).unwrap();
    let ub_eid = insert_event_raw(conn, recorded_by, &ub_blob, Some(&workspace_id_b64));
    project_one(conn, recorded_by, &ub_eid).unwrap();

    let endpoint_key = SigningKey::generate(&mut rng);
    let endpoint_event = topo::event_modules::endpoint_shared::deterministic_endpoint_shared_event(
        endpoint_key.to_bytes(),
    );
    let endpoint_id = hex::encode(endpoint_key.verifying_key().to_bytes());
    let endpoint_blob = events::encode_event(&endpoint_event).unwrap();
    let endpoint_eid =
        insert_event_raw(conn, &endpoint_id, &endpoint_blob, Some(&workspace_id_b64));
    project_one(conn, &endpoint_id, &endpoint_eid).unwrap();

    let peer_shared_key = SigningKey::generate(&mut rng);
    let psf = ParsedEvent::PeerShared(PeerSharedEvent {
        created_at_ms: now_ms(),
        public_key: peer_shared_key.verifying_key().to_bytes(),
        user_event_id: ub_eid,
        endpoint_shared_event_id: endpoint_eid,
        device_name: "bench-device".to_string(),
    });
    let psf_blob = events::encode_event(&psf).unwrap();
    let psf_eid = insert_event_raw(conn, recorded_by, &psf_blob, Some(&workspace_id_b64));
    project_one(conn, recorded_by, &psf_eid).unwrap();

    (psf_eid, peer_shared_key, ub_eid, workspace_id)
}

/// Create prerequisite events (identity chain, signed message, secret key) and return IDs + signing key.
fn create_prereqs(conn: &Connection, recorded_by: &str) -> (EventId, EventId, EventId, SigningKey) {
    let (signer_eid, signing_key, _user_event_id, workspace_id) =
        make_identity_chain(conn, recorded_by);

    // Secret key (for attachment key_event_id dep)
    let sk = ParsedEvent::KeySecret(KeySecretEvent {
        created_at_ms: now_ms(),
        key_bytes: [0xBB; 32],
    });
    let sk_blob = events::encode_event(&sk).unwrap();
    let sk_eid = insert_event_raw(conn, recorded_by, &sk_blob, None);
    project_one(conn, recorded_by, &sk_eid).unwrap();

    // Signed message inside the current encrypted-wrapper path.
    let msg_eid = create_encrypted_event_synchronous(
        conn,
        recorded_by,
        &sk_eid,
        &ParsedEvent::Message(MessageEvent {
            created_at_ms: now_ms(),
            workspace_id,
            author_id: signer_eid,
            content: "file parent".to_string(),
        }),
        Some((&signer_eid, &signing_key)),
    )
    .unwrap();

    // Return signer_eid from the PeerShared chain.
    (msg_eid, sk_eid, signer_eid, signing_key)
}

fn run_file_throughput(file_size_bytes: usize) {
    let (conn, _tmp) = setup();
    let recorded_by = "peer1";

    let (msg_eid, sk_eid, signer_eid, signing_key) = create_prereqs(&conn, recorded_by);

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
