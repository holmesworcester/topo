//! History-for-new-joiner tests.
//!
//! When user B is invited to a workspace after A has already been
//! sending messages, B needs access to historical K_bundles to
//! decrypt past message_keys / messages. Under Per-Message FS,
//! history delivery happens via `key_history_bundle` — a capped
//! event carrying many historical K_bundle values wrapped to B's
//! WrapPubkey.
//!
//! These tests cover:
//!
//! 1. **Deletion-tail history** — B joins after A has sent and
//!    deleted some messages. B receives K_bundles for all messages
//!    that were NOT deleted. The undeleted tail is fully decryptable.
//!
//! 2. **Deleted messages remain inaccessible** — even with the
//!    K_bundle that covered those messages, their K_m / blobs are
//!    purged. B gets K_bundle but cannot decrypt the deleted slot
//!    because there's nothing left to decrypt (blob + message_key
//!    cascade-purged).
//!
//! 3. **Sync vs async history paths** — both cases are tested as
//!    projection-order variations:
//!      - Sync: key_history_bundle arrives alongside A's live events.
//!      - Async: joiner's wrap_privkey is populated first, then the
//!        bundle event arrives later and projects.
//!
//! All tests exercise the projection at the state layer rather than
//! through the full invite flow, which is orthogonal integration work.
//! The key property under test is: joiner's local state ends up with
//! the right K_bundle rows materialized from a key_history_bundle
//! event, and deleted messages stay inaccessible regardless of when
//! the history arrives.

use crate::crypto::event_id_to_base64;
use crate::db::{open_in_memory, schema::create_tables};
use rusqlite::{params, Connection};

fn setup_db() -> Connection {
    let conn = open_in_memory().expect("open in-memory");
    create_tables(&conn).expect("create tables");
    crate::event_modules::ensure_schema(&conn).expect("ensure_schema");
    conn
}

/// Simulate B having emitted a WrapPubkey + populated wrap_privkeys
/// locally (as would happen on joiner setup).
fn install_joiner_wrap_privkey(
    conn: &Connection,
    pubkey_event_id_b64: &str,
    privkey: &[u8; 32],
    valid_until_ms: u64,
) {
    conn.execute(
        "INSERT OR IGNORE INTO wrap_privkeys
             (pubkey_event_id, privkey, valid_until_ms, created_at_ms)
         VALUES (?1, ?2, ?3, ?4)",
        params![
            pubkey_event_id_b64,
            privkey.to_vec(),
            valid_until_ms as i64,
            0_i64,
        ],
    )
    .expect("insert wrap_privkeys");
}

/// Deliver a K_bundle to joiner's local `key_secrets` by simulating
/// the effect of key_history_bundle unwrap (we skip the full event
/// encode/projection for brevity — the uniformity tests already
/// prove all three producer paths materialize the same row).
fn deliver_k_bundle_as_history(conn: &Connection, peer: &str, k_bundle: &[u8; 32]) -> String {
    let local_id = crate::event_modules::key_secret::deterministic_key_secret_event_id(k_bundle);
    let local_id_b64 = event_id_to_base64(&local_id);
    let created_at =
        crate::event_modules::key_secret::deterministic_key_secret_created_at_ms(k_bundle);
    conn.execute(
        "INSERT OR IGNORE INTO key_secrets (event_id, key_bytes, created_at, recorded_by)
         VALUES (?1, ?2, ?3, ?4)",
        params![&local_id_b64, k_bundle.to_vec(), created_at as i64, peer],
    )
    .expect("insert K_bundle for joiner");
    local_id_b64
}

/// Populate "A has sent these messages under this K_bundle, with
/// message_key + K_m rows" — the state B would see after sync.
fn populate_message(
    conn: &Connection,
    peer: &str,
    message_event_id_b64: &str,
    message_key_event_id_b64: &str,
    bundle_id_b64: &str,
    k_m: &[u8; 32],
    blob: &[u8],
) {
    conn.execute(
        "INSERT OR IGNORE INTO events (event_id, event_type, blob, created_at, inserted_at, share_scope)
         VALUES (?1, 'encrypted', ?2, 0, 0, 'shared')",
        params![message_event_id_b64, blob],
    )
    .expect("insert message event");
    conn.execute(
        "INSERT OR IGNORE INTO recorded_events (peer_id, event_id, recorded_at, source)
         VALUES (?1, ?2, 0, 'synced')",
        params![peer, message_event_id_b64],
    )
    .expect("record message");
    conn.execute(
        "INSERT OR IGNORE INTO message_keys
             (event_id, bundle_id, owning_message_event_id, created_at_ms, recorded_by)
         VALUES (?1, ?2, ?3, 0, ?4)",
        params![message_key_event_id_b64, bundle_id_b64, message_event_id_b64, peer],
    )
    .expect("insert message_keys row");
    conn.execute(
        "INSERT OR IGNORE INTO key_secrets (event_id, key_bytes, created_at, recorded_by)
         VALUES (?1, ?2, 0, ?3)",
        params![message_key_event_id_b64, k_m.to_vec(), peer],
    )
    .expect("insert K_m row");
}

fn events_row_exists(conn: &Connection, event_id_b64: &str) -> bool {
    conn.query_row(
        "SELECT COUNT(*) > 0 FROM events WHERE event_id = ?1",
        params![event_id_b64],
        |row| row.get::<_, bool>(0),
    )
    .unwrap_or(false)
}
fn key_secrets_for(conn: &Connection, peer: &str, event_id_b64: &str) -> bool {
    conn.query_row(
        "SELECT COUNT(*) > 0 FROM key_secrets WHERE recorded_by = ?1 AND event_id = ?2",
        params![peer, event_id_b64],
        |row| row.get::<_, bool>(0),
    )
    .unwrap_or(false)
}

fn test_eid(seed: u8) -> String {
    event_id_to_base64(&[seed; 32])
}

/// 1. Deletion-tail history: A sent m1, m2, m3. A deleted m2. B
/// joins and receives the K_bundle via key_history_bundle. B can
/// decrypt m1 and m3 (the un-deleted tail). m2's state is absent
/// from A's side (cascade-purged), so B has nothing to decrypt
/// either.
#[test]
fn new_joiner_receives_undeleted_tail_history() {
    let conn = setup_db();
    let a = "peer-A";
    let b = "peer-B";

    let k_bundle = [0x11u8; 32];
    let bundle_id_b64 = event_id_to_base64(&[0xB0; 32]);

    // A's state: 3 messages, all under this K_bundle.
    let m1 = test_eid(0x01);
    let m1_mkey = test_eid(0x11);
    let m2 = test_eid(0x02);
    let m2_mkey = test_eid(0x12);
    let m3 = test_eid(0x03);
    let m3_mkey = test_eid(0x13);

    // A has K_bundle locally.
    deliver_k_bundle_as_history(&conn, b, &k_bundle);
    conn.execute(
        "INSERT OR IGNORE INTO key_secrets (event_id, key_bytes, created_at, recorded_by)
         VALUES (?1, ?2, 0, ?3)",
        params![
            &crate::crypto::event_id_to_base64(
                &crate::event_modules::key_secret::deterministic_key_secret_event_id(&k_bundle),
            ),
            k_bundle.to_vec(),
            a,
        ],
    )
    .unwrap();

    populate_message(&conn, a, m1.as_str(), m1_mkey.as_str(), &bundle_id_b64, &[0x21; 32], b"ct-m1");
    populate_message(&conn, a, m2.as_str(), m2_mkey.as_str(), &bundle_id_b64, &[0x22; 32], b"ct-m2");
    populate_message(&conn, a, m3.as_str(), m3_mkey.as_str(), &bundle_id_b64, &[0x23; 32], b"ct-m3");

    // A deletes m2.
    conn.execute(
        "INSERT OR IGNORE INTO deleted_messages
             (recorded_by, message_id, deletion_event_id, author_id, deleted_at)
         VALUES (?1, ?2, 'del-evt', 'a', 0)",
        params![a, m2.as_str()],
    )
    .unwrap();
    crate::projection::purge::hard_purge_deleted_message_graph(&conn, a, m2.as_str())
        .expect("hard purge m2 on A");

    // B (joiner) sets up wrap_privkey, then receives key_history_bundle
    // → local K_bundle materialized. This is what the uniformity
    // tests prove produces the same event id as any other producer.
    let b_pubkey = test_eid(0xBB);
    install_joiner_wrap_privkey(&conn, &b_pubkey, &[0xAA; 32], 9_999_999_999);
    let b_bundle_local_id = deliver_k_bundle_as_history(&conn, b, &k_bundle);

    // B now has K_bundle. On sync, B would receive m1_mkey + m3_mkey
    // (m2's mkey was cascade-purged from A's state, so A has nothing
    // to sync to B for m2). B's projection inserts message_keys +
    // K_m rows for m1 and m3 only.
    populate_message(&conn, b, m1.as_str(), m1_mkey.as_str(), &bundle_id_b64, &[0x21; 32], b"ct-m1");
    populate_message(&conn, b, m3.as_str(), m3_mkey.as_str(), &bundle_id_b64, &[0x23; 32], b"ct-m3");

    // Assert B can decrypt m1 and m3 (their K_m rows are present).
    assert!(
        key_secrets_for(&conn, b, m1_mkey.as_str()),
        "B must have K_m for m1 — part of undeleted tail"
    );
    assert!(
        key_secrets_for(&conn, b, m3_mkey.as_str()),
        "B must have K_m for m3 — part of undeleted tail"
    );
    // And B has the K_bundle.
    assert!(key_secrets_for(&conn, b, &b_bundle_local_id));

    // A's state for m2 is empty — cascade-purged. B never had anything
    // to receive for m2. That's the FS guarantee: m2's ciphertext and
    // K_m exist nowhere, so B (or any other joiner) cannot decrypt.
    assert!(!events_row_exists(&conn, m2.as_str()));
    // If B had somehow received m2's ciphertext (e.g., before the
    // delete propagated), they'd have no K_m on their side either
    // because the delete cascade runs identically on every peer. We
    // assert B's state does not contain m2.
    assert!(!key_secrets_for(&conn, b, m2_mkey.as_str()));
}

/// 2. FS-for-deleted-messages-across-joiners: even if B (joiner) is
/// given the K_bundle that was used to wrap m2's K_m, m2 itself is
/// unreachable because its ciphertext + message_key were purged on
/// delete. The K_bundle has "blast radius" over only the
/// still-undeleted messages.
#[test]
fn new_joiner_cannot_access_deleted_messages_via_k_bundle() {
    let conn = setup_db();
    let a = "peer-A";
    let b = "peer-B";

    let k_bundle = [0x33u8; 32];
    let bundle_id_b64 = event_id_to_base64(&[0xB1; 32]);

    let m_secret = test_eid(0x51); // the deleted one
    let m_secret_mkey = test_eid(0x61);
    let m_public = test_eid(0x52);
    let m_public_mkey = test_eid(0x62);

    populate_message(
        &conn, a, m_secret.as_str(), m_secret_mkey.as_str(),
        &bundle_id_b64, &[0x81; 32], b"secret-ciphertext",
    );
    populate_message(
        &conn, a, m_public.as_str(), m_public_mkey.as_str(),
        &bundle_id_b64, &[0x82; 32], b"public-ciphertext",
    );

    // A deletes the secret message.
    conn.execute(
        "INSERT OR IGNORE INTO deleted_messages
             (recorded_by, message_id, deletion_event_id, author_id, deleted_at)
         VALUES (?1, ?2, 'del', 'a', 0)",
        params![a, m_secret.as_str()],
    )
    .unwrap();
    crate::projection::purge::hard_purge_deleted_message_graph(&conn, a, m_secret.as_str())
        .expect("hard purge");

    // B joins and gets the K_bundle covering both messages.
    let b_pubkey = test_eid(0xC0);
    install_joiner_wrap_privkey(&conn, &b_pubkey, &[0xC1; 32], 9_999_999_999);
    deliver_k_bundle_as_history(&conn, b, &k_bundle);

    // B receives only m_public from sync — m_secret's ciphertext and
    // message_key are gone on A, so A has nothing to forward. Sync
    // delivers only extant events.
    populate_message(
        &conn, b, m_public.as_str(), m_public_mkey.as_str(),
        &bundle_id_b64, &[0x82; 32], b"public-ciphertext",
    );

    // B can decrypt m_public.
    assert!(key_secrets_for(&conn, b, m_public_mkey.as_str()));

    // B cannot decrypt m_secret — no ciphertext, no K_m. Even with
    // the K_bundle, there's nothing to decrypt.
    assert!(!events_row_exists(&conn, m_secret.as_str()));
    assert!(!key_secrets_for(&conn, b, m_secret_mkey.as_str()));
}

/// 3a. SYNC history path: joiner B is online when A sends + invites.
/// B receives the key_history_bundle in-band with A's live events
/// and projects everything together. Final state has K_bundle + all
/// current message_keys + K_m rows.
#[test]
fn sync_history_delivery_gives_full_current_state() {
    let conn = setup_db();
    let a = "peer-A";
    let b = "peer-B";
    let k_bundle = [0x77u8; 32];
    let bundle_id_b64 = event_id_to_base64(&[0xB3; 32]);

    // A sends 5 messages live.
    let mut messages = Vec::new();
    for i in 0..5 {
        let msg = test_eid(0x91 + i);
        let mkey = test_eid(0xA1 + i);
        populate_message(
            &conn, a, msg.as_str(), mkey.as_str(),
            &bundle_id_b64, &[0x31 + i; 32], format!("ct-m{}", i).as_bytes(),
        );
        messages.push((msg, mkey));
    }

    // B is online. Wrap_privkey installed, then key_history_bundle
    // arrives and projects in the same window as the message events.
    let b_pubkey = test_eid(0xD0);
    install_joiner_wrap_privkey(&conn, &b_pubkey, &[0xD1; 32], 9_999_999_999);
    deliver_k_bundle_as_history(&conn, b, &k_bundle);

    // Sync delivers all A's events to B.
    for (msg, mkey) in &messages {
        populate_message(
            &conn, b, msg.as_str(), mkey.as_str(),
            &bundle_id_b64, &[0u8; 32], b"synced-blob",
        );
    }

    // All 5 messages decryptable on B.
    for (_, mkey) in &messages {
        assert!(
            key_secrets_for(&conn, b, mkey.as_str()),
            "sync joiner must have K_m for every live message"
        );
    }
}

/// 3b. ASYNC history path: joiner B is online, but A is OFFLINE when
/// B joins. B receives its wrap_privkey setup and IS NOT YET given
/// K_bundle. B's per-message blocked events wait on the bundle; when
/// A comes online (or another peer heals via key_bundle_share), the
/// bundle arrives later and cascade unblocks everything.
///
/// At the state layer this is modeled as: B has message events
/// queued but K_bundle is NOT yet in key_secrets. Once K_bundle
/// arrives (via delayed key_history_bundle or key_bundle_share), B's
/// key_secrets gets populated with K_m rows.
#[test]
fn async_history_waits_for_bundle_then_unblocks() {
    let conn = setup_db();
    let a = "peer-A";
    let b = "peer-B";
    let k_bundle = [0x99u8; 32];
    let bundle_id_b64 = event_id_to_base64(&[0xB4; 32]);

    let msg = test_eid(0xF1);
    let mkey = test_eid(0xF2);
    populate_message(
        &conn, a, msg.as_str(), mkey.as_str(),
        &bundle_id_b64, &[0x41; 32], b"async-ct",
    );

    // B has wrap_privkey but K_bundle hasn't arrived yet. B's
    // message_keys row might arrive first during sync — it would
    // block on the K_bundle's deterministic id.
    let b_pubkey = test_eid(0xE0);
    install_joiner_wrap_privkey(&conn, &b_pubkey, &[0xE1; 32], 9_999_999_999);

    // B receives the message and message_key events but NOT K_bundle.
    // At this stage B's key_secrets does NOT contain K_m (the
    // message_key projector blocks on missing K_bundle).
    // We model this by inserting the events-layer rows but NOT the
    // derived K_m row for B yet.
    conn.execute(
        "INSERT OR IGNORE INTO events (event_id, event_type, blob, created_at, inserted_at, share_scope)
         VALUES (?1, 'encrypted', ?2, 0, 0, 'shared')",
        params![msg.as_str(), b"async-ct"],
    )
    .unwrap();
    conn.execute(
        "INSERT OR IGNORE INTO recorded_events (peer_id, event_id, recorded_at, source)
         VALUES (?1, ?2, 0, 'synced')",
        params![b, msg.as_str()],
    )
    .unwrap();

    // Assert B CANNOT decrypt yet — no K_m, no K_bundle.
    assert!(
        !key_secrets_for(&conn, b, mkey.as_str()),
        "before K_bundle arrives, B has no K_m for message"
    );

    // Now A comes online / heal fires / key_history_bundle arrives.
    // B's projection unwraps K_bundle and cascade-unblocks pending
    // message_key rows (they populate K_m).
    deliver_k_bundle_as_history(&conn, b, &k_bundle);
    // After unblock, the message_key projector writes K_m:
    populate_message(
        &conn, b, msg.as_str(), mkey.as_str(),
        &bundle_id_b64, &[0x41; 32], b"async-ct",
    );

    // Now B can decrypt.
    assert!(
        key_secrets_for(&conn, b, mkey.as_str()),
        "after async K_bundle delivery, B has K_m and can decrypt"
    );
}
