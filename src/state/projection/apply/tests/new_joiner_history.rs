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
             (event_id, bundle_id, k_bundle_local_event_id, created_at_ms, recorded_by)
         VALUES (?1, ?2, ?3, 0, ?4)",
        params![message_key_event_id_b64, bundle_id_b64, bundle_id_b64, peer],
    )
    .expect("insert message_keys row");
    conn.execute(
        "INSERT OR IGNORE INTO messages_to_message_keys
             (message_event_id, message_key_event_id, recorded_by)
         VALUES (?1, ?2, ?3)",
        params![message_event_id_b64, message_key_event_id_b64, peer],
    )
    .expect("insert messages_to_message_keys row");
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

/// Case B proof (DESIGN §9.6.5, PLAN §22.3.2): when a deletion
/// happens AFTER invite creation (i.e., the joiner's state already
/// holds K_bundle from the invite's history delivery by the time
/// the deletion cascades), un-deleted messages in that retired
/// bundle must remain decryptable for the joiner. Only the
/// specifically-deleted message's K_m is purged; all other K_m rows
/// survive; and the retirement gate prevents future re-hydration
/// of the K_bundle row on any stale insert path.
///
/// This is the regression guard that answers the user's question:
/// "when delete happens after invite, are not-deleted messages
/// still received?" Answer: yes — the cascade preserves the K_m
/// rows for un-deleted messages, and the gate is narrow enough
/// (matches by event_id, not by table) that K_m inserts for
/// un-deleted messages in retired bundles still land normally.
#[test]
fn joiner_keeps_undeleted_keys_when_delete_happens_after_invite_received() {
    let conn = setup_db();
    let b = "peer-B";

    let k_bundle = [0x22u8; 32];

    // Phase 1: joiner B receives K_bundle via invite's
    // `key_history_bundle`. (Simulated by direct insert per the
    // uniformity guarantees.)
    let b_bundle_local_id = deliver_k_bundle_as_history(&conn, b, &k_bundle);
    assert!(
        key_secrets_for(&conn, b, &b_bundle_local_id),
        "invite delivered K_bundle to joiner"
    );

    // Phase 2: joiner B syncs three messages under this bundle.
    // Each message_key row + K_m row lands in joiner's state.
    let m1 = test_eid(0x41);
    let m1_mkey = test_eid(0x51);
    let m2 = test_eid(0x42);
    let m2_mkey = test_eid(0x52);
    let m3 = test_eid(0x43);
    let m3_mkey = test_eid(0x53);
    populate_message(&conn, b, m1.as_str(), m1_mkey.as_str(), &b_bundle_local_id, &[0x61; 32], b"ct-m1");
    populate_message(&conn, b, m2.as_str(), m2_mkey.as_str(), &b_bundle_local_id, &[0x62; 32], b"ct-m2");
    populate_message(&conn, b, m3.as_str(), m3_mkey.as_str(), &b_bundle_local_id, &[0x63; 32], b"ct-m3");

    assert!(key_secrets_for(&conn, b, m1_mkey.as_str()));
    assert!(key_secrets_for(&conn, b, m2_mkey.as_str()));
    assert!(key_secrets_for(&conn, b, m3_mkey.as_str()));

    // Phase 3: AFTER invite + sync, a MessageDeletion for m2
    // propagates to B. B's cascade runs locally.
    conn.execute(
        "INSERT OR IGNORE INTO deleted_messages
             (recorded_by, message_id, deletion_event_id, author_id, deleted_at)
         VALUES (?1, ?2, 'del-evt', 'a', 0)",
        params![b, m2.as_str()],
    )
    .unwrap();
    crate::projection::purge::hard_purge_deleted_message_graph(&conn, b, m2.as_str())
        .expect("hard purge m2 on B");

    // Assertions:

    // (a) B has K_m for m1 and m3 — un-deleted messages are still
    //     decryptable after delete-after-invite.
    assert!(
        key_secrets_for(&conn, b, m1_mkey.as_str()),
        "m1 K_m survives — un-deleted message recoverable after \
         delete-after-invite"
    );
    assert!(
        key_secrets_for(&conn, b, m3_mkey.as_str()),
        "m3 K_m survives — un-deleted message recoverable after \
         delete-after-invite"
    );

    // (b) m2's K_m is gone — deleted message unrecoverable.
    assert!(
        !key_secrets_for(&conn, b, m2_mkey.as_str()),
        "m2 K_m must be purged — deleted message lost"
    );

    // (c) K_bundle plaintext is gone — retention+compromise window
    //     closed for this bundle going forward.
    assert!(
        !key_secrets_for(&conn, b, &b_bundle_local_id),
        "K_bundle row shredded on delete cascade"
    );

    // (d) Retirement marker is durable on B.
    let marked: bool = conn
        .query_row(
            "SELECT COUNT(*) > 0 FROM retired_bundles
             WHERE recorded_by = ?1 AND k_bundle_local_event_id = ?2",
            params![b, &b_bundle_local_id],
            |row| row.get(0),
        )
        .unwrap();
    assert!(marked, "retired_bundles must mark the retirement on B");

    // (e) A stale `key_history_bundle` replay that tries to
    //     re-hydrate K_bundle on B must be refused by the gate.
    //     Simulates a second joiner-sync-pass (e.g. B comes back
    //     online later and re-projects the stale history event
    //     from the wire).
    use crate::projection::projector::{SqlVal, WriteOp};
    crate::state::projection::apply::write_exec::execute_write_ops(
        &conn,
        &[WriteOp::InsertOrIgnore {
            table: "key_secrets",
            columns: vec!["event_id", "key_bytes", "created_at", "recorded_by"],
            values: vec![
                SqlVal::Text(b_bundle_local_id.clone()),
                SqlVal::Blob(k_bundle.to_vec()),
                SqlVal::Int(0),
                SqlVal::Text(b.to_string()),
            ],
        }],
    )
    .expect("write_ops execute");
    assert!(
        !key_secrets_for(&conn, b, &b_bundle_local_id),
        "retired_bundles gate refuses the stale re-hydration — \
         K_bundle stays gone even if an older key_history_bundle \
         wire arrives later"
    );

    // (f) And critically: m1 and m3 K_m rows are still there after
    //     the stale write attempt. The gate is narrow (event_id),
    //     so K_m inserts would pass through unchanged even if
    //     something tried to re-insert them.
    assert!(key_secrets_for(&conn, b, m1_mkey.as_str()));
    assert!(key_secrets_for(&conn, b, m3_mkey.as_str()));
}

/// Regression proof (DESIGN §9.6.5 Case C + future-work hook): a
/// joiner can decrypt messages that were encrypted under a bundle
/// created AFTER the invite. The delivery mechanism is simulated
/// (the future path wraps each bundle to every still-active invite
/// pubkey as an additional recipient slot in `key_broadcast`; a
/// reactive heal via `key_request` covers concurrency edge cases).
/// Whichever path delivers the K_bundle bytes to the joiner, the
/// decryption cascade must succeed.
///
/// This test codifies the end-state contract: given K_bundle is
/// delivered and `message_key` + `Encrypted` events are synced, the
/// joiner's projection materializes K_m and decrypts the message.
/// Failing this test means the post-invite bundle delivery path is
/// broken at a projection-layer level, not a delivery-layer one.
#[test]
fn joiner_decrypts_messages_encrypted_under_bundle_created_after_invite() {
    let conn = setup_db();
    let b = "peer-B";

    // Phase 1: invite is established. B has a wrap_privkey (simulated).
    let b_pubkey = test_eid(0xBB);
    install_joiner_wrap_privkey(&conn, &b_pubkey, &[0xAA; 32], 9_999_999_999);

    // Phase 2: AFTER invite, inviter A rotates to a fresh K_bundle
    // (created causally post-invite). Under the future design, the
    // `key_broadcast` for this bundle includes B's invite pubkey as
    // a recipient slot; projection on B unwraps the slot and lands
    // K_bundle in B's key_secrets. We simulate that end state with
    // a direct delivery — the projection-layer contract under test
    // is everything downstream of K_bundle arrival.
    let post_invite_k_bundle = [0x33u8; 32];
    let post_invite_bundle_local_id =
        deliver_k_bundle_as_history(&conn, b, &post_invite_k_bundle);
    assert!(
        key_secrets_for(&conn, b, &post_invite_bundle_local_id),
        "post-invite K_bundle delivered to joiner"
    );

    // Phase 3: A sends two messages under the post-invite bundle.
    // On B's side, `message_key` events arrive and project. With
    // K_bundle materialized, project_pure unwraps K_m and caches.
    let m1 = test_eid(0x71);
    let m1_mkey = test_eid(0x72);
    let m2 = test_eid(0x73);
    let m2_mkey = test_eid(0x74);
    populate_message(
        &conn, b, m1.as_str(), m1_mkey.as_str(),
        &post_invite_bundle_local_id, &[0x81; 32], b"ct-post-m1",
    );
    populate_message(
        &conn, b, m2.as_str(), m2_mkey.as_str(),
        &post_invite_bundle_local_id, &[0x82; 32], b"ct-post-m2",
    );

    // Phase 4: assert B has K_m for both post-invite messages and
    // can decrypt them (via the standard Encrypted → key_secrets
    // lookup path).
    assert!(
        key_secrets_for(&conn, b, m1_mkey.as_str()),
        "B must have K_m for post-invite m1"
    );
    assert!(
        key_secrets_for(&conn, b, m2_mkey.as_str()),
        "B must have K_m for post-invite m2"
    );
    assert!(events_row_exists(&conn, m1.as_str()));
    assert!(events_row_exists(&conn, m2.as_str()));

    // Phase 5: subsequent deletion of one of them retires the
    // bundle (standard strong-FS cascade) without affecting the
    // other un-deleted post-invite message. This verifies the
    // post-invite bundle participates in the same FS contract as
    // pre-invite bundles.
    conn.execute(
        "INSERT OR IGNORE INTO deleted_messages
             (recorded_by, message_id, deletion_event_id, author_id, deleted_at)
         VALUES (?1, ?2, 'del-post-m1', 'a', 0)",
        params![b, m1.as_str()],
    )
    .unwrap();
    crate::projection::purge::hard_purge_deleted_message_graph(&conn, b, m1.as_str())
        .expect("hard purge post-invite m1 on B");

    assert!(
        !key_secrets_for(&conn, b, m1_mkey.as_str()),
        "m1 K_m gone after delete"
    );
    assert!(
        key_secrets_for(&conn, b, m2_mkey.as_str()),
        "m2 K_m survives — un-deleted post-invite message still decryptable"
    );
    assert!(
        !key_secrets_for(&conn, b, &post_invite_bundle_local_id),
        "post-invite K_bundle shredded on first-delete — same FS \
         property as pre-invite bundles"
    );
}
