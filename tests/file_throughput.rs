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
    self, FileSliceEvent, MessageAttachmentEvent, MessageEvent, ParsedEvent,
    SecretKeyEvent, WorkspaceEvent, InviteAcceptedEvent, UserInviteBootEvent,
    UserBootEvent, DeviceInviteFirstEvent, PeerSharedFirstEvent,
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

/// Helper: sign a blob in-place (overwrite last 64 bytes with Ed25519 signature).
fn sign_blob(key: &SigningKey, blob: &mut Vec<u8>) {
    let len = blob.len();
    let sig = sign_event_bytes(key, &blob[..len - 64]);
    blob[len - 64..].copy_from_slice(&sig);
}

/// Bootstrap a full identity chain: Workspace → InviteAccepted → UserInviteBoot →
/// UserBoot → DeviceInviteFirst → PeerSharedFirst. Returns (peer_shared_eid, signing_key).
fn make_identity_chain(conn: &Connection, recorded_by: &str) -> (EventId, SigningKey) {
    let mut rng = rand::thread_rng();

    let workspace_key = SigningKey::generate(&mut rng);
    let workspace_id: [u8; 32] = rand::random();
    let net = ParsedEvent::Workspace(WorkspaceEvent {
        created_at_ms: now_ms(),
        public_key: workspace_key.verifying_key().to_bytes(),
        workspace_id,
    });
    let net_blob = events::encode_event(&net).unwrap();
    let net_eid = insert_event_raw(conn, recorded_by, &net_blob);

    let ia = ParsedEvent::InviteAccepted(InviteAcceptedEvent {
        created_at_ms: now_ms(),
        invite_event_id: net_eid,
        workspace_id,
    });
    let ia_blob = events::encode_event(&ia).unwrap();
    let ia_eid = insert_event_raw(conn, recorded_by, &ia_blob);
    project_one(conn, recorded_by, &ia_eid).unwrap();
    project_one(conn, recorded_by, &net_eid).unwrap();

    let invite_key = SigningKey::generate(&mut rng);
    let uib = ParsedEvent::UserInviteBoot(UserInviteBootEvent {
        created_at_ms: now_ms(),
        public_key: invite_key.verifying_key().to_bytes(),
        workspace_id,
        signed_by: net_eid,
        signer_type: 1,
        signature: [0u8; 64],
    });
    let mut uib_blob = events::encode_event(&uib).unwrap();
    sign_blob(&workspace_key, &mut uib_blob);
    let uib_eid = insert_event_raw(conn, recorded_by, &uib_blob);
    project_one(conn, recorded_by, &uib_eid).unwrap();

    let user_key = SigningKey::generate(&mut rng);
    let ub = ParsedEvent::UserBoot(UserBootEvent {
        created_at_ms: now_ms(),
        public_key: user_key.verifying_key().to_bytes(),
        signed_by: uib_eid,
        signer_type: 2,
        signature: [0u8; 64],
    });
    let mut ub_blob = events::encode_event(&ub).unwrap();
    sign_blob(&invite_key, &mut ub_blob);
    let ub_eid = insert_event_raw(conn, recorded_by, &ub_blob);
    project_one(conn, recorded_by, &ub_eid).unwrap();

    let device_invite_key = SigningKey::generate(&mut rng);
    let dif = ParsedEvent::DeviceInviteFirst(DeviceInviteFirstEvent {
        created_at_ms: now_ms(),
        public_key: device_invite_key.verifying_key().to_bytes(),
        signed_by: ub_eid,
        signer_type: 4,
        signature: [0u8; 64],
    });
    let mut dif_blob = events::encode_event(&dif).unwrap();
    sign_blob(&user_key, &mut dif_blob);
    let dif_eid = insert_event_raw(conn, recorded_by, &dif_blob);
    project_one(conn, recorded_by, &dif_eid).unwrap();

    let peer_shared_key = SigningKey::generate(&mut rng);
    let psf = ParsedEvent::PeerSharedFirst(PeerSharedFirstEvent {
        created_at_ms: now_ms(),
        public_key: peer_shared_key.verifying_key().to_bytes(),
        signed_by: dif_eid,
        signer_type: 3,
        signature: [0u8; 64],
    });
    let mut psf_blob = events::encode_event(&psf).unwrap();
    sign_blob(&device_invite_key, &mut psf_blob);
    let psf_eid = insert_event_raw(conn, recorded_by, &psf_blob);
    project_one(conn, recorded_by, &psf_eid).unwrap();

    (psf_eid, peer_shared_key)
}

/// Create prerequisite events (identity chain, signed message, secret key) and return IDs + signing key.
fn create_prereqs(
    conn: &Connection,
    recorded_by: &str,
) -> (EventId, EventId, EventId, SigningKey) {
    let (signer_eid, signing_key) = make_identity_chain(conn, recorded_by);

    // Signed message
    let msg = ParsedEvent::Message(MessageEvent {
        created_at_ms: now_ms(),
        channel_id: [1u8; 32],
        author_id: [2u8; 32],
        content: "file parent".to_string(),
        signed_by: signer_eid,
        signer_type: 5,
        signature: [0u8; 64],
    });
    let mut msg_blob = events::encode_event(&msg).unwrap();
    sign_blob(&signing_key, &mut msg_blob);
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

    // Return signer_eid (PeerShared) instead of old peer_key eid
    (msg_eid, sk_eid, signer_eid, signing_key)
}

fn run_file_throughput(file_size_bytes: usize, slice_size: usize) {
    let (conn, _tmp) = setup();
    let recorded_by = "peer1";

    let (msg_eid, sk_eid, pk_eid, signing_key) = create_prereqs(&conn, recorded_by);

    let total_slices = (file_size_bytes + slice_size - 1) / slice_size;
    let file_id = [0xF0; 32];

    // Create and project signed message_attachment descriptor first (required for file_slice auth)
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
        signed_by: pk_eid,
        signer_type: 5,
        signature: [0u8; 64],
    });
    let mut att_blob = events::encode_event(&att).unwrap();
    sign_blob(&signing_key, &mut att_blob);
    let att_eid = insert_event_raw(&conn, recorded_by, &att_blob);
    project_one(&conn, recorded_by, &att_eid).unwrap();

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
            signer_type: 5,
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
