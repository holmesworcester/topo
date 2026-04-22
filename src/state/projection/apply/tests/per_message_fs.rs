//! Forward-secrecy proof tests for the Per-Message FS subsystem.
//!
//! These tests populate the state layer directly (events table,
//! key_secrets, message_keys, deleted_messages) and drive
//! `hard_purge_deleted_message_graph` to prove:
//!
//! 1. **FS on delete** — after MessageDeletion + hard_purge, the
//!    deleted message's K_m row, Encrypted blob, message_key row, and
//!    message_keys index row are all gone. The K_bundle row persists
//!    (other messages still need it). This is the cornerstone FS
//!    property: an adversary compromising honest-peer state post-
//!    purge has no K_m for the deleted message and no ciphertext.
//!
//! 2. **FS on expiry** — same end-state as (1): TTL-driven expiry
//!    flows through the same MessageDeletion tombstone path, so
//!    purge identically removes K_m + ciphertext. Under Per-Message
//!    FS every message has its own K_m, so expiry maps one-to-one
//!    to the cascade that (1) exercises.
//!
//! 3. **History preservation** — deleting one message does NOT
//!    affect other messages' K_m or blobs. Survivors remain fully
//!    decryptable. This is the "others aren't rekeyed" property:
//!    the per-message-K_m design inherently isolates messages from
//!    each other.

use crate::crypto::event_id_to_base64;
use crate::db::{open_in_memory, schema::create_tables};
use rusqlite::{params, Connection};

/// Helper: generate a real base64-encoded 32-byte event id from a
/// seed byte. Used for deterministic test-scope event ids.
fn test_event_id(seed: u8) -> String {
    event_id_to_base64(&[seed; 32])
}

/// Helper: set up a pristine in-memory DB with all tables.
fn setup_db() -> Connection {
    let conn = open_in_memory().expect("open in-memory");
    create_tables(&conn).expect("create tables");
    crate::event_modules::ensure_schema(&conn).expect("ensure_schema");
    conn
}

/// Helper: insert a minimal `events` row so purge verification
/// finds the blob-storage row to remove.
fn insert_event_row(conn: &Connection, event_id_b64: &str, type_name: &str, blob: &[u8]) {
    conn.execute(
        "INSERT OR IGNORE INTO events (event_id, event_type, blob, created_at, inserted_at, share_scope)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            event_id_b64,
            type_name,
            blob,
            0_i64,
            0_i64,
            "shared",
        ],
    )
    .expect("insert events");
    conn.execute(
        "INSERT OR IGNORE INTO recorded_events (peer_id, event_id, recorded_at, source)
         VALUES (?1, ?2, ?3, ?4)",
        params!["peer-test", event_id_b64, 0_i64, "test"],
    )
    .expect("insert recorded_events");
}

/// Helper: place a K_bundle row into `key_secrets` keyed by its
/// deterministic local event id.
fn insert_k_bundle(conn: &Connection, k_bundle: &[u8; 32]) -> String {
    let local_id = crate::event_modules::key_secret::deterministic_key_secret_event_id(k_bundle);
    let local_id_b64 = event_id_to_base64(&local_id);
    conn.execute(
        "INSERT OR IGNORE INTO key_secrets (event_id, key_bytes, created_at, recorded_by)
         VALUES (?1, ?2, ?3, ?4)",
        params![&local_id_b64, k_bundle.to_vec(), 0_i64, "peer-test"],
    )
    .expect("insert K_bundle");
    local_id_b64
}

/// Helper: place a per-message K_m row into `key_secrets` keyed by
/// `message_key_event_id` (how the Encrypted cascade finds it).
fn insert_k_m(conn: &Connection, message_key_event_id_b64: &str, k_m: &[u8; 32]) {
    conn.execute(
        "INSERT OR IGNORE INTO key_secrets (event_id, key_bytes, created_at, recorded_by)
         VALUES (?1, ?2, ?3, ?4)",
        params![message_key_event_id_b64, k_m.to_vec(), 0_i64, "peer-test"],
    )
    .expect("insert K_m");
}

/// Helper: place a `message_keys` index row + the `messages_to_
/// message_keys` reverse-index row so purge's enumeration finds the
/// message_key bound to a given owning message (Option C shape).
fn insert_message_key_index(
    conn: &Connection,
    message_key_event_id_b64: &str,
    bundle_id_b64: &str,
    owning_message_event_id_b64: &str,
) {
    conn.execute(
        "INSERT OR IGNORE INTO message_keys
             (event_id, bundle_id, k_bundle_local_event_id, created_at_ms, recorded_by)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            message_key_event_id_b64,
            bundle_id_b64,
            bundle_id_b64,
            0_i64,
            "peer-test",
        ],
    )
    .expect("insert message_keys row");
    conn.execute(
        "INSERT OR IGNORE INTO messages_to_message_keys
             (message_event_id, message_key_event_id, recorded_by)
         VALUES (?1, ?2, ?3)",
        params![
            owning_message_event_id_b64,
            message_key_event_id_b64,
            "peer-test",
        ],
    )
    .expect("insert messages_to_message_keys row");
}

/// Helper: insert a `deleted_messages` durable tombstone so
/// `hard_purge_deleted_message_graph` doesn't reject.
fn insert_tombstone(conn: &Connection, message_event_id_b64: &str) {
    conn.execute(
        "INSERT OR IGNORE INTO deleted_messages
             (recorded_by, message_id, deletion_event_id, author_id, deleted_at)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params!["peer-test", message_event_id_b64, "deletion-evt", "author-test", 0_i64],
    )
    .expect("insert deleted_messages");
}

/// Helper: check a key_secrets row exists.
fn key_secrets_row_exists(conn: &Connection, event_id_b64: &str) -> bool {
    conn.query_row(
        "SELECT COUNT(*) > 0 FROM key_secrets WHERE recorded_by = ?1 AND event_id = ?2",
        params!["peer-test", event_id_b64],
        |row| row.get::<_, bool>(0),
    )
    .unwrap_or(false)
}

fn events_row_exists(conn: &Connection, event_id_b64: &str) -> bool {
    conn.query_row(
        "SELECT COUNT(*) > 0 FROM events WHERE event_id = ?1",
        params![event_id_b64],
        |row| row.get::<_, bool>(0),
    )
    .unwrap_or(false)
}

fn message_keys_row_exists(conn: &Connection, event_id_b64: &str) -> bool {
    conn.query_row(
        "SELECT COUNT(*) > 0 FROM message_keys WHERE recorded_by = ?1 AND event_id = ?2",
        params!["peer-test", event_id_b64],
        |row| row.get::<_, bool>(0),
    )
    .unwrap_or(false)
}

fn deleted_messages_row_exists(conn: &Connection, message_id_b64: &str) -> bool {
    conn.query_row(
        "SELECT COUNT(*) > 0 FROM deleted_messages WHERE recorded_by = ?1 AND message_id = ?2",
        params!["peer-test", message_id_b64],
        |row| row.get::<_, bool>(0),
    )
    .unwrap_or(false)
}

// ────────────────────────────────────────────────────────────────
// Tests
// ────────────────────────────────────────────────────────────────

/// Cornerstone FS property: after delete + hard_purge, the deleted
/// message's K_m and blob are gone. An adversary snapshot at this
/// point has nothing to decrypt — no ciphertext for the message and
/// no K_m anywhere in local state.
#[test]
fn fs_preserved_for_deleted_message() {
    let conn = setup_db();

    // Setup: K_bundle distributed + m1 encrypted under its own K_m.
    let k_bundle = [0x11u8; 32];
    let k_bundle_id_b64 = insert_k_bundle(&conn, &k_bundle);

    let m1_event_id_b64 = test_event_id(0xA1);
    let m1_event_id_b64 = m1_event_id_b64.as_str();
    let m1_message_key_event_id_b64 = test_event_id(0xA2);
    let m1_message_key_event_id_b64 = m1_message_key_event_id_b64.as_str();
    let k_m1 = [0x21u8; 32];

    // Message (Encrypted blob) stored in events table.
    insert_event_row(&conn, m1_event_id_b64, "encrypted", b"ciphertext-of-m1");
    // message_key row + K_m row so the cascade sees them.
    insert_message_key_index(&conn, m1_message_key_event_id_b64, &k_bundle_id_b64, m1_event_id_b64);
    insert_k_m(&conn, m1_message_key_event_id_b64, &k_m1);
    insert_event_row(&conn, m1_message_key_event_id_b64, "message_key", b"mkey-blob");

    // Sanity: everything is present before deletion.
    assert!(key_secrets_row_exists(&conn, &k_bundle_id_b64));
    assert!(key_secrets_row_exists(&conn, m1_message_key_event_id_b64));
    assert!(events_row_exists(&conn, m1_event_id_b64));
    assert!(message_keys_row_exists(&conn, m1_message_key_event_id_b64));

    // Action: tombstone m1 + run hard purge.
    insert_tombstone(&conn, m1_event_id_b64);
    crate::projection::purge::hard_purge_deleted_message_graph(&conn, "peer-test", m1_event_id_b64)
        .expect("hard purge");

    // FS assertions:
    assert!(
        !key_secrets_row_exists(&conn, m1_message_key_event_id_b64),
        "K_m row must be purged — no decryption key for deleted message"
    );
    assert!(
        !events_row_exists(&conn, m1_event_id_b64),
        "message blob must be purged — no ciphertext for deleted message"
    );
    assert!(
        !message_keys_row_exists(&conn, m1_message_key_event_id_b64),
        "message_keys index row must be purged"
    );
    // K_bundle survives (other messages may use it).
    assert!(
        key_secrets_row_exists(&conn, &k_bundle_id_b64),
        "K_bundle row persists — other messages still need it"
    );
    // Durable tombstone persists (defends against late-replay re-
    // materialization of K_m when the message_key arrives again).
    assert!(
        deleted_messages_row_exists(&conn, m1_event_id_b64),
        "deleted_messages tombstone must persist after hard purge"
    );
}

/// TTL expiry flows through the same MessageDeletion path, so the
/// end state after expiry is identical to explicit delete. This test
/// simulates the TTL-driven tombstone (same table, same cascade) and
/// asserts the same FS property as `fs_preserved_for_deleted_message`.
#[test]
fn fs_preserved_for_ttl_expired_message() {
    let conn = setup_db();

    let k_bundle = [0x31u8; 32];
    let k_bundle_id_b64 = insert_k_bundle(&conn, &k_bundle);

    let m_event_id_b64 = test_event_id(0xB1);
    let m_event_id_b64 = m_event_id_b64.as_str();
    let m_message_key_event_id_b64 = test_event_id(0xB2);
    let m_message_key_event_id_b64 = m_message_key_event_id_b64.as_str();
    let k_m = [0x32u8; 32];

    insert_event_row(&conn, m_event_id_b64, "encrypted", b"ciphertext-ttl");
    insert_message_key_index(&conn, m_message_key_event_id_b64, &k_bundle_id_b64, m_event_id_b64);
    insert_k_m(&conn, m_message_key_event_id_b64, &k_m);
    insert_event_row(&conn, m_message_key_event_id_b64, "message_key", b"mkey-blob");

    // Simulate TTL expiry by emitting the same tombstone the runtime
    // TTL trigger would emit. Cascade is identical to explicit delete.
    insert_tombstone(&conn, m_event_id_b64);
    crate::projection::purge::hard_purge_deleted_message_graph(&conn, "peer-test", m_event_id_b64)
        .expect("hard purge");

    assert!(!key_secrets_row_exists(&conn, m_message_key_event_id_b64));
    assert!(!events_row_exists(&conn, m_event_id_b64));
    assert!(!message_keys_row_exists(&conn, m_message_key_event_id_b64));
    assert!(
        deleted_messages_row_exists(&conn, m_event_id_b64),
        "TTL-driven tombstone must persist (same as explicit delete)"
    );
}

/// History preservation: deleting one message does NOT affect any
/// other message. Per-Message FS isolates messages from each other
/// because each has its own K_m; no other message's K_m / blob /
/// message_key should be touched by the cascade.
#[test]
fn history_preserved_after_deletion() {
    let conn = setup_db();

    let k_bundle = [0x41u8; 32];
    let k_bundle_id_b64 = insert_k_bundle(&conn, &k_bundle);

    // Three messages, each with its own K_m, all using the same K_bundle.
    let m1_msg = test_event_id(0xC1);
    let m1_mkey = test_event_id(0xC2);
    let m2_msg = test_event_id(0xC3);
    let m2_mkey = test_event_id(0xC4);
    let m3_msg = test_event_id(0xC5);
    let m3_mkey = test_event_id(0xC6);
    let messages = [
        (m1_msg.as_str(), m1_mkey.as_str(), [0x51u8; 32]),
        (m2_msg.as_str(), m2_mkey.as_str(), [0x52u8; 32]),
        (m3_msg.as_str(), m3_mkey.as_str(), [0x53u8; 32]),
    ];
    for (msg_id, mkey_id, k_m) in &messages {
        insert_event_row(&conn, msg_id, "encrypted", format!("ct-{}", msg_id).as_bytes());
        insert_message_key_index(&conn, mkey_id, &k_bundle_id_b64, msg_id);
        insert_k_m(&conn, mkey_id, k_m);
        insert_event_row(&conn, mkey_id, "message_key", b"mkey-blob");
    }

    // Sanity.
    for (msg_id, mkey_id, _) in &messages {
        assert!(events_row_exists(&conn, msg_id));
        assert!(key_secrets_row_exists(&conn, mkey_id));
    }

    // Delete only m2.
    insert_tombstone(&conn, m2_msg.as_str());
    crate::projection::purge::hard_purge_deleted_message_graph(&conn, "peer-test", m2_msg.as_str())
        .expect("hard purge m2");

    // m2 is gone.
    assert!(!events_row_exists(&conn, m2_msg.as_str()));
    assert!(!key_secrets_row_exists(&conn, m2_mkey.as_str()));
    assert!(!message_keys_row_exists(&conn, m2_mkey.as_str()));

    // m1 and m3 are intact — history preserved.
    assert!(
        events_row_exists(&conn, m1_msg.as_str()),
        "m1 blob must be preserved after m2 delete"
    );
    assert!(
        key_secrets_row_exists(&conn, m1_mkey.as_str()),
        "m1 K_m must be preserved — still decryptable"
    );
    assert!(
        message_keys_row_exists(&conn, m1_mkey.as_str()),
        "m1 message_keys index must be preserved"
    );
    assert!(
        events_row_exists(&conn, m3_msg.as_str()),
        "m3 blob must be preserved after m2 delete"
    );
    assert!(
        key_secrets_row_exists(&conn, m3_mkey.as_str()),
        "m3 K_m must be preserved — still decryptable"
    );
    assert!(
        message_keys_row_exists(&conn, m3_mkey.as_str()),
        "m3 message_keys index must be preserved"
    );

    // K_bundle persists (m1, m3 still need it).
    assert!(key_secrets_row_exists(&conn, &k_bundle_id_b64));
}

/// Compound property: run multiple deletes sequentially. Each delete
/// purges only its target; survivors remain intact until they're
/// themselves deleted. Verifies the cascade is properly scoped per
/// message and doesn't leak effects across messages.
#[test]
fn sequential_deletes_preserve_non_target_history() {
    let conn = setup_db();

    let k_bundle = [0x61u8; 32];
    let k_bundle_id_b64 = insert_k_bundle(&conn, &k_bundle);

    let sm1_msg = test_event_id(0xD1);
    let sm1_mkey = test_event_id(0xD2);
    let sm2_msg = test_event_id(0xD3);
    let sm2_mkey = test_event_id(0xD4);
    let sm3_msg = test_event_id(0xD5);
    let sm3_mkey = test_event_id(0xD6);
    let sm4_msg = test_event_id(0xD7);
    let sm4_mkey = test_event_id(0xD8);
    let messages = [
        (sm1_msg.as_str(), sm1_mkey.as_str(), [0x71u8; 32]),
        (sm2_msg.as_str(), sm2_mkey.as_str(), [0x72u8; 32]),
        (sm3_msg.as_str(), sm3_mkey.as_str(), [0x73u8; 32]),
        (sm4_msg.as_str(), sm4_mkey.as_str(), [0x74u8; 32]),
    ];
    for (msg_id, mkey_id, k_m) in &messages {
        insert_event_row(&conn, msg_id, "encrypted", format!("ct-{}", msg_id).as_bytes());
        insert_message_key_index(&conn, mkey_id, &k_bundle_id_b64, msg_id);
        insert_k_m(&conn, mkey_id, k_m);
        insert_event_row(&conn, mkey_id, "message_key", b"mkey-blob");
    }

    // Delete m1, then m3 (skipping m2 and m4).
    for target in &[sm1_msg.as_str(), sm3_msg.as_str()] {
        insert_tombstone(&conn, target);
        crate::projection::purge::hard_purge_deleted_message_graph(&conn, "peer-test", target)
            .expect("purge");
    }

    // m1 and m3 are gone.
    assert!(!events_row_exists(&conn, sm1_msg.as_str()));
    assert!(!key_secrets_row_exists(&conn, sm1_mkey.as_str()));
    assert!(!events_row_exists(&conn, sm3_msg.as_str()));
    assert!(!key_secrets_row_exists(&conn, sm3_mkey.as_str()));

    // m2 and m4 are intact — selective deletion works.
    assert!(events_row_exists(&conn, sm2_msg.as_str()));
    assert!(key_secrets_row_exists(&conn, sm2_mkey.as_str()));
    assert!(events_row_exists(&conn, sm4_msg.as_str()));
    assert!(key_secrets_row_exists(&conn, sm4_mkey.as_str()));

    // K_bundle still persists — shared across m2 and m4.
    assert!(key_secrets_row_exists(&conn, &k_bundle_id_b64));
}
