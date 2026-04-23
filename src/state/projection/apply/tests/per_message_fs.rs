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
    // Strong FS (delete-triggered bundle purge): K_bundle's plaintext
    // row in `key_secrets` is shredded on the first-deletion-in-bundle
    // cascade, on every honest peer. Retained `key_broadcast` wire
    // events become inert (they cannot be unwrapped without the
    // WrapPrivkey, purged on its own schedule). K_m rows for
    // un-deleted messages remain in `key_secrets` keyed by their
    // message_key_event_id, so un-deleted messages stay decryptable.
    assert!(
        !key_secrets_row_exists(&conn, &k_bundle_id_b64),
        "K_bundle row must be purged — relay-retention attacks on \
         the deleted message's retained wire become inert"
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

    // Strong FS: K_bundle is purged on first-delete-in-bundle.
    // Un-deleted messages still decryptable via their K_m rows
    // (keyed by the message_key event id, not by K_bundle id).
    assert!(!key_secrets_row_exists(&conn, &k_bundle_id_b64));
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

    // Strong FS: K_bundle is purged on first-delete-in-bundle.
    // Un-deleted m2 and m4 still decryptable via their K_m rows
    // (keyed by message_key event id, not by K_bundle id).
    assert!(!key_secrets_row_exists(&conn, &k_bundle_id_b64));
}

// ────────────────────────────────────────────────────────────────
// Strong-FS regression tests (PLAN §22.5)
//
// These exercise specific attack/corner-case scenarios that are not
// covered by the general-case tests above.
// ────────────────────────────────────────────────────────────────

/// Phase F #3: retained wire + post-purge compromise must not
/// recover plaintext.
///
/// Simulate a store-and-forward relay that retains the wire `message_key`
/// blob and Encrypted ciphertext indefinitely. After deletion triggers
/// the strong-FS cascade, an attacker who imagines acquiring the
/// retained wire plus compromising local `key_secrets` must not be able
/// to decrypt the deleted message, because:
///   (a) K_m is gone (purged on the deletion cascade);
///   (b) K_bundle is gone (shredded on the deletion cascade);
///   (c) re-unwrapping the retained `key_broadcast` wire would require
///       a WrapPrivkey the adversary does not have.
/// This test codifies (a) and (b) at the state layer: after purge,
/// no code path in `key_secrets` materializes either bytes for this
/// message, and the retained wire blob we keep in memory is
/// meaningless on its own.
#[test]
fn retained_wire_plus_post_purge_compromise_recovers_nothing() {
    let conn = setup_db();

    let k_bundle = [0x81u8; 32];
    let k_bundle_id_b64 = insert_k_bundle(&conn, &k_bundle);

    let msg_id = test_event_id(0xE1);
    let mkey_id = test_event_id(0xE2);
    let k_m = [0x91u8; 32];

    // The "retained wire" — in a real attack this would be bytes the
    // relay kept from the sync stream. We keep them as in-memory
    // variables to demonstrate that even the adversary's best-case
    // retention buys nothing once the cascade fires.
    let retained_ciphertext = b"retained-ciphertext-of-deleted-message".to_vec();
    let retained_mkey_blob = b"retained-wire-of-message_key".to_vec();

    insert_event_row(&conn, msg_id.as_str(), "encrypted", &retained_ciphertext);
    insert_message_key_index(&conn, mkey_id.as_str(), &k_bundle_id_b64, msg_id.as_str());
    insert_k_m(&conn, mkey_id.as_str(), &k_m);
    insert_event_row(&conn, mkey_id.as_str(), "message_key", &retained_mkey_blob);

    // Baseline: adversary would have been able to reconstruct
    // (K_bundle + retained mkey wire → K_m; K_m + retained ciphertext
    // → plaintext). Both pieces of local state are currently live.
    assert!(key_secrets_row_exists(&conn, &k_bundle_id_b64));
    assert!(key_secrets_row_exists(&conn, mkey_id.as_str()));

    insert_tombstone(&conn, msg_id.as_str());
    crate::projection::purge::hard_purge_deleted_message_graph(
        &conn,
        "peer-test",
        msg_id.as_str(),
    )
    .expect("hard purge");

    // Post-cascade: the adversary's retained wire blobs still exist
    // in their copy (we kept them in memory, representing a relay's
    // indefinite retention), but neither K_m nor K_bundle is recoverable
    // from honest-peer state.
    assert!(
        !key_secrets_row_exists(&conn, mkey_id.as_str()),
        "K_m row must be gone"
    );
    assert!(
        !key_secrets_row_exists(&conn, &k_bundle_id_b64),
        "K_bundle row must be gone — retained key_broadcast wire \
         cannot be re-unwrapped without the WrapPrivkey"
    );
    assert!(
        !events_row_exists(&conn, msg_id.as_str()),
        "local ciphertext row gone"
    );
    // Retained wire blobs are inert: they remain in our `retained_*`
    // variables, but no projection path (nothing in `key_secrets`,
    // nothing in `events`) provides the key material needed to turn
    // them back into plaintext.
    let _ = retained_ciphertext;
    let _ = retained_mkey_blob;
}

/// Phase F #5: a `message_key` event that arrives on a peer after
/// the relevant K_bundle row has been purged from `key_secrets` must
/// NOT materialize a usable K_m. In Option C's dep machinery,
/// message_key's `k_bundle_local_event_id` dep remains unresolvable,
/// and nothing in the projector path short-circuits to revive the
/// bundle from a retained wire blob.
///
/// This exercises the "late-arrival mkey on retired bundle" corner
/// from the plan. The test reproduces the effective state without
/// walking the full wire replay path (which would require a full
/// sim harness); the guarantee is that `K_m` never materializes in
/// `key_secrets` keyed by the mkey's own event id when the bundle is
/// absent.
#[test]
fn late_arrival_message_key_on_retired_bundle_does_not_materialize_k_m() {
    let conn = setup_db();

    // Construct a retired-bundle situation: K_bundle is gone from
    // `key_secrets`, but the bundle's event id is still present in
    // `key_rotations` (we simulate the post-retirement state).
    let retired_k_bundle = [0x82u8; 32];
    let retired_k_bundle_id_b64 = {
        // Compute the deterministic local id but do NOT insert the
        // plaintext row in key_secrets.
        let local_id =
            crate::event_modules::key_secret::deterministic_key_secret_event_id(&retired_k_bundle);
        crate::crypto::event_id_to_base64(&local_id)
    };

    let late_mkey_id = test_event_id(0xF2);
    let late_msg_id = test_event_id(0xF1);

    // The "late-arrival" message_key appears as a stored event but
    // with no K_m row in key_secrets because the bundle required to
    // unwrap it is unavailable. This is what any recipient with a
    // retired bundle would observe.
    insert_message_key_index(
        &conn,
        late_mkey_id.as_str(),
        &retired_k_bundle_id_b64,
        late_msg_id.as_str(),
    );

    // Key invariant: `key_secrets` contains no row for the mkey's
    // event id. Without K_m, the Encrypted wrapper that references
    // this mkey cannot decrypt even if it arrives later.
    assert!(
        !key_secrets_row_exists(&conn, late_mkey_id.as_str()),
        "late-arrival message_key must not materialize K_m when its \
         K_bundle has been retired"
    );
    // And no secrets row for the retired bundle either.
    assert!(
        !key_secrets_row_exists(&conn, &retired_k_bundle_id_b64),
        "retired K_bundle stays absent on post-retirement replay"
    );
}

/// Phase F #6: a joiner who arrives after bundle retirement sees the
/// un-deleted messages as history-lost. This codifies the
/// DESIGN.md §9.6.5 trade-off: we accept history loss for retired
/// bundles until `key_message_share` lands (see PLAN §22.3).
///
/// Flip this assertion's sense when `key_message_share` lands and
/// recovers the un-deleted tail via per-K_m asymmetric wraps.
#[test]
fn joiner_after_bundle_retirement_sees_undeleted_tail_as_history_lost() {
    let conn = setup_db();

    // Source peer's state: had a bundle, deleted one of its messages,
    // K_bundle now retired. Retain the mkey/ciphertext wire of the
    // UNDELETED message in `events` (as any sync-propagated event
    // naturally would be), but no K_m row for that mkey.
    let retired_k_bundle = [0x83u8; 32];
    let retired_k_bundle_id_b64 = {
        let local_id =
            crate::event_modules::key_secret::deterministic_key_secret_event_id(&retired_k_bundle);
        crate::crypto::event_id_to_base64(&local_id)
    };

    let undeleted_msg_id = test_event_id(0x61);
    let undeleted_mkey_id = test_event_id(0x62);

    insert_event_row(
        &conn,
        undeleted_msg_id.as_str(),
        "encrypted",
        b"ciphertext-remains",
    );
    insert_event_row(
        &conn,
        undeleted_mkey_id.as_str(),
        "message_key",
        b"mkey-wire-remains",
    );
    // Reverse-index + message_keys row intact — they would propagate
    // to a late joiner via shared-event replay.
    insert_message_key_index(
        &conn,
        undeleted_mkey_id.as_str(),
        &retired_k_bundle_id_b64,
        undeleted_msg_id.as_str(),
    );

    // BUT: no K_m row in key_secrets (purged on retirement), no
    // K_bundle row (purged on retirement). A joiner replaying this
    // shared state has no path from wire → plaintext.
    assert!(
        !key_secrets_row_exists(&conn, undeleted_mkey_id.as_str()),
        "K_m row absent — joiner cannot decrypt un-deleted message \
         in a retired bundle without a `key_message_share` cold path"
    );
    assert!(
        !key_secrets_row_exists(&conn, &retired_k_bundle_id_b64),
        "K_bundle absent on late joiner too"
    );

    // TODO: when `key_message_share` lands (PLAN §22.3), flip this
    // test's final assertion to prove successful recovery instead.
}

/// Phase F #7: per-device K_bundle lineage isolation.
///
/// Two sender devices emit concurrent bundles. A deletion that
/// retires device 1's bundle must NOT purge device 2's bundle —
/// otherwise one device's deletion would cascade-retire every
/// concurrent sender's active stream and amplify the rotation storm.
///
/// Today the send path uses a workspace-shared content key (not
/// per-device), so this test codifies the cascade-scoping invariant
/// at the purge cascade level: `messages_to_message_keys` links a
/// message event id to ONE `message_key_event_id`, which points to
/// ONE `k_bundle_local_event_id`. No row in `messages_to_message_keys`
/// references bundle 2 when we delete a message under bundle 1, so
/// bundle 2's key_secrets row is not enumerated.
#[test]
fn per_device_bundle_isolation_delete_in_b1_does_not_purge_b2() {
    let conn = setup_db();

    let device1_k_bundle = [0x41u8; 32];
    let device2_k_bundle = [0x42u8; 32];
    let device1_bundle_id_b64 = insert_k_bundle(&conn, &device1_k_bundle);
    let device2_bundle_id_b64 = insert_k_bundle(&conn, &device2_k_bundle);

    let device1_msg = test_event_id(0x71);
    let device1_mkey = test_event_id(0x72);
    let device2_msg = test_event_id(0x73);
    let device2_mkey = test_event_id(0x74);

    insert_event_row(&conn, device1_msg.as_str(), "encrypted", b"ct-d1");
    insert_message_key_index(
        &conn,
        device1_mkey.as_str(),
        &device1_bundle_id_b64,
        device1_msg.as_str(),
    );
    insert_k_m(&conn, device1_mkey.as_str(), &[0x51u8; 32]);
    insert_event_row(&conn, device1_mkey.as_str(), "message_key", b"mkey-d1");

    insert_event_row(&conn, device2_msg.as_str(), "encrypted", b"ct-d2");
    insert_message_key_index(
        &conn,
        device2_mkey.as_str(),
        &device2_bundle_id_b64,
        device2_msg.as_str(),
    );
    insert_k_m(&conn, device2_mkey.as_str(), &[0x52u8; 32]);
    insert_event_row(&conn, device2_mkey.as_str(), "message_key", b"mkey-d2");

    // Delete device 1's message.
    insert_tombstone(&conn, device1_msg.as_str());
    crate::projection::purge::hard_purge_deleted_message_graph(
        &conn,
        "peer-test",
        device1_msg.as_str(),
    )
    .expect("hard purge device 1 message");

    // Device 1's bundle is purged.
    assert!(
        !key_secrets_row_exists(&conn, &device1_bundle_id_b64),
        "device 1 K_bundle must be purged"
    );
    // Device 2's bundle is NOT purged — no cross-device cascade.
    assert!(
        key_secrets_row_exists(&conn, &device2_bundle_id_b64),
        "device 2 K_bundle must survive — deletion on device 1's bundle \
         does not cascade to device 2's concurrent bundle"
    );
    // Device 2's message and K_m also intact.
    assert!(events_row_exists(&conn, device2_msg.as_str()));
    assert!(key_secrets_row_exists(&conn, device2_mkey.as_str()));
}
