use super::*;
use crate::db::{open_in_memory, schema::create_tables};

#[test]
fn test_binding_alone_not_in_allowlist() {
    let conn = open_in_memory().unwrap();
    create_tables(&conn).unwrap();

    let recorded_by = "aaaa";
    let peer_id = "bbbb";
    let spki: [u8; 32] = [42u8; 32];

    // Record a transport binding (observation telemetry)
    record_transport_binding(&conn, recorded_by, peer_id, &spki).unwrap();

    // Binding alone must NOT appear in allowed peers
    let allowed = authorized_fingerprints_from_db(&conn, recorded_by).unwrap();
    assert!(!allowed.contains(&spki));

    // Idempotent insert still works
    record_transport_binding(&conn, recorded_by, peer_id, &spki).unwrap();
}

/// Helper: insert a PeerShared row and return its SPKI fingerprint.
fn insert_peer_shared(
    conn: &Connection,
    recorded_by: &str,
    event_id: &str,
    pubkey: &[u8; 32],
) -> [u8; 32] {
    let transport_fingerprint = spki_fingerprint_from_ed25519_pubkey(pubkey);
    conn.execute(
        "INSERT INTO peers_shared
             (recorded_by, event_id, public_key, transport_fingerprint)
             VALUES (?1, ?2, ?3, ?4)",
        rusqlite::params![
            recorded_by,
            event_id,
            pubkey.as_slice(),
            transport_fingerprint.as_slice(),
        ],
    )
    .unwrap();
    transport_fingerprint
}

#[test]
fn test_peer_shared_derived_in_allowlist() {
    let conn = open_in_memory().unwrap();
    create_tables(&conn).unwrap();

    let recorded_by = "aaaa";
    let pubkey: [u8; 32] = [42u8; 32];
    let spki = insert_peer_shared(&conn, recorded_by, "ps1", &pubkey);

    let allowed = authorized_fingerprints_from_db(&conn, recorded_by).unwrap();
    assert!(allowed.contains(&spki));
}

#[test]
fn test_invite_bootstrap_trust_in_allowlist() {
    let conn = open_in_memory().unwrap();
    create_tables(&conn).unwrap();

    let recorded_by = "aaaa";
    let spki: [u8; 32] = [11u8; 32];
    record_invite_bootstrap_trust(
        &conn,
        recorded_by,
        "ia1",
        "invite1",
        "workspace1",
        "127.0.0.1:4433",
        &spki,
    )
    .unwrap();

    let allowed = authorized_fingerprints_from_db(&conn, recorded_by).unwrap();
    assert!(allowed.contains(&spki));
}

#[test]
fn test_invite_bootstrap_superseded_when_peer_shared_exists() {
    let conn = open_in_memory().unwrap();
    create_tables(&conn).unwrap();

    let recorded_by = "aaaa";
    let pubkey: [u8; 32] = [14u8; 32];
    let spki = spki_fingerprint_from_ed25519_pubkey(&pubkey);
    record_invite_bootstrap_trust(
        &conn,
        recorded_by,
        "ia-supersede",
        "invite-supersede",
        "workspace-supersede",
        "127.0.0.1:4433",
        &spki,
    )
    .unwrap();

    // Add PeerShared entry whose derived SPKI matches the bootstrap SPKI
    insert_peer_shared(&conn, recorded_by, "ps-supersede", &pubkey);

    // Supersession now happens at projection time, not on read
    consume_bootstrap_for_peer_shared(&conn, recorded_by, &pubkey).unwrap();

    let allowed = authorized_fingerprints_from_db(&conn, recorded_by).unwrap();
    assert!(allowed.contains(&spki));

    let remaining_rows: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM invite_bootstrap_trust
                  WHERE recorded_by = ?1 AND invite_accepted_event_id = ?2",
            rusqlite::params![recorded_by, "ia-supersede"],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(remaining_rows, 0);
}

#[test]
fn test_expired_invite_bootstrap_not_in_allowlist() {
    let conn = open_in_memory().unwrap();
    create_tables(&conn).unwrap();

    let recorded_by = "aaaa";
    let spki: [u8; 32] = [15u8; 32];
    let now = now_ms_i64();
    conn.execute(
            "INSERT INTO invite_bootstrap_trust
             (recorded_by, invite_accepted_event_id, invite_event_id, workspace_id, bootstrap_addr, bootstrap_spki_fingerprint, accepted_at, expires_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            rusqlite::params![
                recorded_by,
                "ia-expired",
                "invite-expired",
                "workspace-expired",
                "127.0.0.1:4433",
                spki.as_slice(),
                now - 1000,
                now - 1,
            ],
        )
        .unwrap();

    let allowed = authorized_fingerprints_from_db(&conn, recorded_by).unwrap();
    assert!(!allowed.contains(&spki));
}

#[test]
fn test_pending_invite_bootstrap_trust_in_allowlist() {
    let conn = open_in_memory().unwrap();
    create_tables(&conn).unwrap();

    let recorded_by = "aaaa";
    let invite_eid = "invite-bootstrap";
    let workspace_id = "workspace-bootstrap";
    let spki: [u8; 32] = [55u8; 32];
    record_pending_invite_bootstrap_trust(&conn, recorded_by, invite_eid, workspace_id, &spki)
        .unwrap();

    let allowed = authorized_fingerprints_from_db(&conn, recorded_by).unwrap();
    assert!(allowed.contains(&spki));
}

#[test]
fn test_pending_invite_bootstrap_superseded_when_peer_shared_exists() {
    let conn = open_in_memory().unwrap();
    create_tables(&conn).unwrap();

    let recorded_by = "aaaa";
    let pubkey: [u8; 32] = [12u8; 32];
    let spki = spki_fingerprint_from_ed25519_pubkey(&pubkey);
    record_pending_invite_bootstrap_trust(&conn, recorded_by, "invite1", "workspace1", &spki)
        .unwrap();

    // Add PeerShared entry whose derived SPKI matches the pending SPKI
    insert_peer_shared(&conn, recorded_by, "ps1", &pubkey);

    // Supersession now happens at projection time, not on read
    consume_bootstrap_for_peer_shared(&conn, recorded_by, &pubkey).unwrap();

    let allowed = authorized_fingerprints_from_db(&conn, recorded_by).unwrap();
    assert!(allowed.contains(&spki));

    let remaining_rows: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM pending_invite_bootstrap_trust
                  WHERE recorded_by = ?1 AND invite_event_id = ?2",
            rusqlite::params![recorded_by, "invite1"],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(remaining_rows, 0);
}

#[test]
fn test_expired_pending_invite_bootstrap_not_in_allowlist() {
    let conn = open_in_memory().unwrap();
    create_tables(&conn).unwrap();

    let recorded_by = "aaaa";
    let spki: [u8; 32] = [13u8; 32];
    let now = now_ms_i64();
    conn.execute(
            "INSERT INTO pending_invite_bootstrap_trust
             (recorded_by, invite_event_id, workspace_id, expected_bootstrap_spki_fingerprint, created_at, expires_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params![
                recorded_by,
                "invite-expired",
                "workspace-expired",
                spki.as_slice(),
                now - 1000,
                now - 1,
            ],
        )
        .unwrap();

    let allowed = authorized_fingerprints_from_db(&conn, recorded_by).unwrap();
    assert!(!allowed.contains(&spki));
}

#[test]
fn test_is_peer_allowed_checks_all_sources() {
    let conn = open_in_memory().unwrap();
    create_tables(&conn).unwrap();

    let recorded_by = "aaaa";
    let pubkey: [u8; 32] = [2u8; 32];
    let peer_shared_spki = insert_peer_shared(&conn, recorded_by, "ps_db", &pubkey);
    let pending_only: [u8; 32] = [3u8; 32];
    let denied: [u8; 32] = [4u8; 32];

    record_pending_invite_bootstrap_trust(
        &conn,
        recorded_by,
        "invite-pending",
        "workspace",
        &pending_only,
    )
    .unwrap();

    assert!(is_authorized_for_tenant(&conn, recorded_by, &peer_shared_spki).unwrap());
    assert!(is_authorized_for_tenant(&conn, recorded_by, &pending_only).unwrap());
    assert!(!is_authorized_for_tenant(&conn, recorded_by, &denied).unwrap());

    // Compatibility wrapper stays aligned with the canonical auth query.
    assert_eq!(
        is_peer_allowed(&conn, recorded_by, &peer_shared_spki).unwrap(),
        is_authorized_for_tenant(&conn, recorded_by, &peer_shared_spki).unwrap()
    );
}

#[test]
fn test_node_auth_and_tenant_resolution_use_projected_trust_union() {
    let conn = open_in_memory().unwrap();
    create_tables(&conn).unwrap();

    let peer_shared_tenant = "tenant-peershared";
    let bootstrap_tenant = "tenant-bootstrap";
    let pending_tenant = "tenant-pending";
    let denied: [u8; 32] = [0xDD; 32];
    let binding_only: [u8; 32] = [0xEE; 32];

    let peer_shared_pubkey: [u8; 32] = [0xA1; 32];
    let peer_shared_spki =
        insert_peer_shared(&conn, peer_shared_tenant, "ps-node", &peer_shared_pubkey);
    let bootstrap_spki: [u8; 32] = [0xB2; 32];
    let pending_spki: [u8; 32] = [0xC3; 32];

    record_invite_bootstrap_trust(
        &conn,
        bootstrap_tenant,
        "ia-node",
        "invite-node",
        "ws-node",
        "127.0.0.1:4433",
        &bootstrap_spki,
    )
    .unwrap();
    record_pending_invite_bootstrap_trust(
        &conn,
        pending_tenant,
        "invite-node-pending",
        "ws-node-pending",
        &pending_spki,
    )
    .unwrap();
    record_transport_binding(&conn, "binding-only-tenant", "peer-observed", &binding_only).unwrap();

    assert!(is_authorized_for_node(&conn, &peer_shared_spki).unwrap());
    assert_eq!(
        resolve_authorizing_tenant(&conn, &peer_shared_spki).unwrap(),
        Some(peer_shared_tenant.to_string())
    );

    assert!(is_authorized_for_node(&conn, &bootstrap_spki).unwrap());
    assert_eq!(
        resolve_authorizing_tenant(&conn, &bootstrap_spki).unwrap(),
        Some(bootstrap_tenant.to_string())
    );

    assert!(is_authorized_for_node(&conn, &pending_spki).unwrap());
    assert_eq!(
        resolve_authorizing_tenant(&conn, &pending_spki).unwrap(),
        Some(pending_tenant.to_string())
    );

    assert!(!is_authorized_for_node(&conn, &binding_only).unwrap());
    assert_eq!(
        resolve_authorizing_tenant(&conn, &binding_only).unwrap(),
        None
    );

    assert!(!is_authorized_for_node(&conn, &denied).unwrap());
    assert_eq!(resolve_authorizing_tenant(&conn, &denied).unwrap(), None);
}

#[test]
fn test_mutual_trust_requires_both_sides() {
    let conn = open_in_memory().unwrap();
    create_tables(&conn).unwrap();

    let alice = "alice";
    let bob = "bob";
    let alice_spki: [u8; 32] = [0xA1; 32];
    let bob_spki: [u8; 32] = [0xB2; 32];

    record_pending_invite_bootstrap_trust(&conn, alice, "invite-a", "ws", &bob_spki).unwrap();
    record_pending_invite_bootstrap_trust(&conn, bob, "invite-b", "ws", &alice_spki).unwrap();

    assert!(
        is_peer_allowed(&conn, alice, &bob_spki).unwrap(),
        "alice should trust bob once bob is in alice's trust rows"
    );
    assert!(
        is_peer_allowed(&conn, bob, &alice_spki).unwrap(),
        "bob should trust alice once alice is in bob's trust rows"
    );

    // One-sided trust is not mutual auth.
    let carol = "carol";
    assert!(
        !is_peer_allowed(&conn, carol, &alice_spki).unwrap(),
        "carol has no trust rows and must not trust alice"
    );
}

#[test]
fn test_pending_invite_bootstrap_trust_authorizes() {
    let conn = open_in_memory().unwrap();
    create_tables(&conn).unwrap();

    let recorded_by = "aaaa";
    let pending_1: [u8; 32] = [0xAA; 32];
    let pending_2: [u8; 32] = [0xBB; 32];
    let not_pending: [u8; 32] = [0xCC; 32];

    record_pending_invite_bootstrap_trust(&conn, recorded_by, "invite-1", "ws", &pending_1)
        .unwrap();
    record_pending_invite_bootstrap_trust(&conn, recorded_by, "invite-2", "ws", &pending_2)
        .unwrap();

    let allowed = authorized_fingerprints_from_db(&conn, recorded_by).unwrap();
    assert!(allowed.contains(&pending_1));
    assert!(allowed.contains(&pending_2));
    assert!(!allowed.contains(&not_pending));
    assert!(is_peer_allowed(&conn, recorded_by, &pending_1).unwrap());
    assert!(is_peer_allowed(&conn, recorded_by, &pending_2).unwrap());
    assert!(!is_peer_allowed(&conn, recorded_by, &not_pending).unwrap());
}

#[test]
fn test_pending_bootstrap_superseded_by_peer_shared() {
    let conn = open_in_memory().unwrap();
    create_tables(&conn).unwrap();

    let recorded_by = "aaaa";
    let pubkey: [u8; 32] = [0xDD; 32];
    let pending_fp = spki_fingerprint_from_ed25519_pubkey(&pubkey);

    record_pending_invite_bootstrap_trust(&conn, recorded_by, "invite-1", "ws", &pending_fp)
        .unwrap();
    assert!(is_peer_allowed(&conn, recorded_by, &pending_fp).unwrap());

    insert_peer_shared(&conn, recorded_by, "ps-steady", &pubkey);
    consume_bootstrap_for_peer_shared(&conn, recorded_by, &pubkey).unwrap();
    assert!(is_peer_allowed(&conn, recorded_by, &pending_fp).unwrap());
    let allowed = authorized_fingerprints_from_db(&conn, recorded_by).unwrap();
    assert!(allowed.contains(&pending_fp));
    let remaining_rows: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM pending_invite_bootstrap_trust
                  WHERE recorded_by = ?1 AND invite_event_id = ?2",
            rusqlite::params![recorded_by, "invite-1"],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        remaining_rows, 0,
        "pending bootstrap row should be consumed after steady-state trust arrives"
    );
}

#[test]
fn test_unlisted_fingerprint_not_silently_trusted() {
    let conn = open_in_memory().unwrap();
    create_tables(&conn).unwrap();

    let recorded_by = "aaaa";
    let raw_fp: [u8; 32] = [0xEE; 32];

    assert!(!is_peer_allowed(&conn, recorded_by, &raw_fp).unwrap());
    let allowed = authorized_fingerprints_from_db(&conn, recorded_by).unwrap();
    assert!(!allowed.contains(&raw_fp));
}

#[test]
fn test_pending_bootstrap_invites_do_not_collide_on_shared_prefix() {
    let conn = open_in_memory().unwrap();
    create_tables(&conn).unwrap();

    let recorded_by = "aaaa";
    let mut fp_a: [u8; 32] = [0xAB; 32];
    let mut fp_b: [u8; 32] = [0xAB; 32];
    fp_a[8] = 0x01;
    fp_b[8] = 0x02;

    record_pending_invite_bootstrap_trust(&conn, recorded_by, "invite-a", "ws", &fp_a).unwrap();
    record_pending_invite_bootstrap_trust(&conn, recorded_by, "invite-b", "ws", &fp_b).unwrap();

    assert!(
        is_peer_allowed(&conn, recorded_by, &fp_a).unwrap(),
        "fp_a should be trusted after recording distinct pending bootstrap rows"
    );
    assert!(
        is_peer_allowed(&conn, recorded_by, &fp_b).unwrap(),
        "fp_b should be trusted after recording distinct pending bootstrap rows"
    );

    let allowed = authorized_fingerprints_from_db(&conn, recorded_by).unwrap();
    assert!(allowed.contains(&fp_a), "fp_a should be in allowed set");
    assert!(allowed.contains(&fp_b), "fp_b should be in allowed set");
}

#[test]
fn test_invite_bootstrap_trust_insert_idempotent() {
    let conn = open_in_memory().unwrap();
    create_tables(&conn).unwrap();

    let recorded_by = "aaaa";
    let spki: [u8; 32] = [20u8; 32];

    // First insert
    record_invite_bootstrap_trust(
        &conn,
        recorded_by,
        "ia1",
        "invite1",
        "workspace1",
        "127.0.0.1:4433",
        &spki,
    )
    .unwrap();

    // Second insert with same (recorded_by, invite_accepted_event_id, bootstrap_addr) —
    // should be ignored (true idempotency).
    let spki2: [u8; 32] = [21u8; 32];
    record_invite_bootstrap_trust(
        &conn,
        recorded_by,
        "ia1",
        "invite2",
        "workspace2",
        "127.0.0.1:4433",
        &spki2,
    )
    .unwrap();

    // Should be exactly 1 row — same PK means INSERT OR IGNORE
    let count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM invite_bootstrap_trust
             WHERE recorded_by = ?1 AND invite_accepted_event_id = ?2",
            rusqlite::params![recorded_by, "ia1"],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(count, 1, "INSERT OR IGNORE should not create duplicate");

    // Original values preserved (second insert ignored)
    let (addr, ws): (String, String) = conn
        .query_row(
            "SELECT bootstrap_addr, workspace_id FROM invite_bootstrap_trust
             WHERE recorded_by = ?1 AND invite_accepted_event_id = ?2",
            rusqlite::params![recorded_by, "ia1"],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(addr, "127.0.0.1:4433", "original value preserved");
    assert_eq!(ws, "workspace1", "original value preserved");

    // Third insert with different bootstrap_addr — creates a second row (multi-addr support)
    record_invite_bootstrap_trust(
        &conn,
        recorded_by,
        "ia1",
        "invite1",
        "workspace1",
        "10.0.0.1:4434",
        &spki,
    )
    .unwrap();

    let count2: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM invite_bootstrap_trust
             WHERE recorded_by = ?1 AND invite_accepted_event_id = ?2",
            rusqlite::params![recorded_by, "ia1"],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        count2, 2,
        "different bootstrap_addr should create a second row"
    );
}

#[test]
fn test_pending_invite_bootstrap_trust_insert_idempotent() {
    let conn = open_in_memory().unwrap();
    create_tables(&conn).unwrap();

    let recorded_by = "aaaa";
    let spki: [u8; 32] = [30u8; 32];

    // First insert
    record_pending_invite_bootstrap_trust(&conn, recorded_by, "invite1", "workspace1", &spki)
        .unwrap();

    // Second insert with same PK but different values — should be ignored
    let spki2: [u8; 32] = [31u8; 32];
    record_pending_invite_bootstrap_trust(&conn, recorded_by, "invite1", "workspace2", &spki2)
        .unwrap();

    // Should be exactly 1 row
    let count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM pending_invite_bootstrap_trust
             WHERE recorded_by = ?1 AND invite_event_id = ?2",
            rusqlite::params![recorded_by, "invite1"],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(count, 1, "INSERT OR IGNORE should not create duplicate");

    // Original values preserved (second insert ignored)
    let ws: String = conn
        .query_row(
            "SELECT workspace_id FROM pending_invite_bootstrap_trust
             WHERE recorded_by = ?1 AND invite_event_id = ?2",
            rusqlite::params![recorded_by, "invite1"],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(ws, "workspace1", "original value preserved");

    // Original SPKI preserved
    let fp_blob: Vec<u8> = conn
        .query_row(
            "SELECT expected_bootstrap_spki_fingerprint FROM pending_invite_bootstrap_trust
             WHERE recorded_by = ?1 AND invite_event_id = ?2",
            rusqlite::params![recorded_by, "invite1"],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(fp_blob, spki.to_vec(), "original SPKI preserved");
}

#[test]
fn test_different_recorded_by_isolation() {
    let conn = open_in_memory().unwrap();
    create_tables(&conn).unwrap();

    let pubkey: [u8; 32] = [42u8; 32];
    let spki = insert_peer_shared(&conn, "peer_a", "ps1", &pubkey);

    let allowed_a = authorized_fingerprints_from_db(&conn, "peer_a").unwrap();
    assert!(allowed_a.contains(&spki));

    let allowed_b = authorized_fingerprints_from_db(&conn, "peer_b").unwrap();
    assert!(!allowed_b.contains(&spki));
}

#[test]
fn test_malformed_peer_shared_pubkey_skipped() {
    let conn = open_in_memory().unwrap();
    create_tables(&conn).unwrap();

    let recorded_by = "aaaa";
    let good_pubkey: [u8; 32] = [42u8; 32];
    let good_spki = insert_peer_shared(&conn, recorded_by, "ps1", &good_pubkey);

    // Insert a malformed peers_shared row (wrong length public_key)
    conn.execute(
        "INSERT INTO peers_shared (recorded_by, event_id, public_key) VALUES (?1, ?2, ?3)",
        rusqlite::params![recorded_by, "ps_bad", &[0u8; 16][..]],
    )
    .unwrap();

    let allowed = authorized_fingerprints_from_db(&conn, recorded_by).unwrap();
    assert!(allowed.contains(&good_spki));
    // Malformed entry should be skipped — only 1 valid entry
    let zero_fp: [u8; 32] = [0u8; 32];
    assert!(!allowed.contains(&zero_fp));
}

#[test]
fn test_allowed_peers_count() {
    let conn = open_in_memory().unwrap();
    create_tables(&conn).unwrap();

    let recorded_by = "aaaa";
    let pubkey_ps: [u8; 32] = [1u8; 32];
    let spki_bootstrap: [u8; 32] = [2u8; 32];
    let spki_pending: [u8; 32] = [3u8; 32];

    // Empty → count should be 0
    assert_eq!(
        authorized_fingerprints_from_db(&conn, recorded_by)
            .unwrap()
            .len(),
        0
    );

    // Add PeerShared row
    insert_peer_shared(&conn, recorded_by, "ps1", &pubkey_ps);
    assert_eq!(
        authorized_fingerprints_from_db(&conn, recorded_by)
            .unwrap()
            .len(),
        1
    );

    // Add accepted invite bootstrap trust
    record_invite_bootstrap_trust(
        &conn,
        recorded_by,
        "ia1",
        "invite1",
        "ws1",
        "127.0.0.1:4433",
        &spki_bootstrap,
    )
    .unwrap();
    assert_eq!(
        authorized_fingerprints_from_db(&conn, recorded_by)
            .unwrap()
            .len(),
        2
    );

    // Add pending invite bootstrap trust
    record_pending_invite_bootstrap_trust(&conn, recorded_by, "invite2", "ws2", &spki_pending)
        .unwrap();
    assert_eq!(
        authorized_fingerprints_from_db(&conn, recorded_by)
            .unwrap()
            .len(),
        3
    );

    // Cross-tenant isolation: different recorded_by sees 0
    assert_eq!(
        authorized_fingerprints_from_db(&conn, "other_peer")
            .unwrap()
            .len(),
        0
    );
}

#[test]
fn test_allowed_peers_count_dedupes_overlap_across_sources() {
    let conn = open_in_memory().unwrap();
    create_tables(&conn).unwrap();

    let recorded_by = "count_dedupe";
    let pubkey: [u8; 32] = [0x42; 32];
    let spki = insert_peer_shared(&conn, recorded_by, "ps-overlap", &pubkey);

    record_invite_bootstrap_trust(
        &conn,
        recorded_by,
        "ia-overlap",
        "invite-overlap",
        "ws-overlap",
        "127.0.0.1:4433",
        &spki,
    )
    .unwrap();
    record_pending_invite_bootstrap_trust(
        &conn,
        recorded_by,
        "invite-overlap-pending",
        "ws-overlap",
        &spki,
    )
    .unwrap();

    assert_eq!(
        authorized_fingerprints_from_db(&conn, recorded_by)
            .unwrap()
            .len(),
        1,
        "same fingerprint in peers_shared + bootstrap rows should count once"
    );
}

#[test]
fn test_has_any_trusted_peer() {
    let conn = open_in_memory().unwrap();
    create_tables(&conn).unwrap();

    let recorded_by = "aaaa";

    // Empty → false
    assert!(!has_any_trusted_peer(&conn, recorded_by).unwrap());

    // PeerShared only → true
    let pubkey_ps: [u8; 32] = [10u8; 32];
    insert_peer_shared(&conn, recorded_by, "ps_only", &pubkey_ps);
    assert!(has_any_trusted_peer(&conn, recorded_by).unwrap());

    // Start fresh for bootstrap-only test
    let rb_boot = "boot_only";
    assert!(!has_any_trusted_peer(&conn, rb_boot).unwrap());
    let spki_boot: [u8; 32] = [20u8; 32];
    record_invite_bootstrap_trust(
        &conn,
        rb_boot,
        "ia_boot",
        "inv_boot",
        "ws_boot",
        "127.0.0.1:4433",
        &spki_boot,
    )
    .unwrap();
    assert!(has_any_trusted_peer(&conn, rb_boot).unwrap());

    // Pending-only test
    let rb_pend = "pending_only";
    assert!(!has_any_trusted_peer(&conn, rb_pend).unwrap());
    let spki_pend: [u8; 32] = [30u8; 32];
    record_pending_invite_bootstrap_trust(&conn, rb_pend, "inv_pend", "ws_pend", &spki_pend)
        .unwrap();
    assert!(has_any_trusted_peer(&conn, rb_pend).unwrap());
}

#[test]
fn test_allowed_peers_count_ignores_malformed_rows() {
    let conn = open_in_memory().unwrap();
    create_tables(&conn).unwrap();

    let recorded_by = "malformed_count";

    // Malformed PeerShared public key (wrong length)
    conn.execute(
        "INSERT INTO peers_shared (recorded_by, event_id, public_key) VALUES (?1, ?2, ?3)",
        rusqlite::params![recorded_by, "ps_short", &[9u8; 16][..]],
    )
    .unwrap();
    conn.execute(
            "INSERT INTO invite_bootstrap_trust
             (recorded_by, invite_accepted_event_id, invite_event_id, workspace_id, bootstrap_addr, bootstrap_spki_fingerprint, accepted_at, expires_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            rusqlite::params![
                recorded_by,
                "ia_short",
                "invite_short",
                "ws",
                "127.0.0.1:4433",
                &[7u8; 31][..],
                now_ms_i64(),
                now_ms_i64() + 60_000,
            ],
        ).unwrap();
    conn.execute(
            "INSERT INTO pending_invite_bootstrap_trust
             (recorded_by, invite_event_id, workspace_id, expected_bootstrap_spki_fingerprint, created_at, expires_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params![
                recorded_by,
                "invite_short_pending",
                "ws",
                &[8u8; 8][..],
                now_ms_i64(),
                now_ms_i64() + 60_000,
            ],
        ).unwrap();

    assert_eq!(
        authorized_fingerprints_from_db(&conn, recorded_by)
            .unwrap()
            .len(),
        0
    );
    assert!(!has_any_trusted_peer(&conn, recorded_by).unwrap());
}

// ---------------------------------------------------------------
// Characterization tests: behavioral contracts that must survive
// the trust-projection-eventization refactor (phases 1–5).
// ---------------------------------------------------------------

/// Characterization: inviter pre-accept pending trust allows first dial.
///
/// When an inviter creates an invite, it records pending bootstrap trust
/// with the expected SPKI derived from the invite key. This MUST allow
/// the invitee's first TLS connection (using an invite-key-derived cert)
/// to pass strict mTLS, even though no InviteAccepted or PeerShared
/// events exist yet.
///
/// After eventization: this row must still be produced (by projection
/// from the locally-created invite event + bootstrap context), and
/// is_peer_allowed must still return true for the expected SPKI.
#[test]
fn characterization_inviter_pending_trust_allows_first_dial() {
    let conn = open_in_memory().unwrap();
    create_tables(&conn).unwrap();

    let inviter_id = "inviter_peer_aaaa";
    let invite_event_id = "invite_evt_1";
    let workspace_id = "workspace_1";
    // This SPKI would be derived from the invite key in production
    let expected_invitee_spki: [u8; 32] = [0x77; 32];

    // --- Inviter creates invite: pending trust recorded ---
    record_pending_invite_bootstrap_trust(
        &conn,
        inviter_id,
        invite_event_id,
        workspace_id,
        &expected_invitee_spki,
    )
    .unwrap();

    // Invitee's first dial: transport layer checks is_peer_allowed
    assert!(
        is_peer_allowed(&conn, inviter_id, &expected_invitee_spki).unwrap(),
        "INVARIANT: inviter must allow invitee's invite-derived SPKI before accept"
    );

    // Unknown SPKI must still be denied
    let unknown: [u8; 32] = [0x99; 32];
    assert!(
        !is_peer_allowed(&conn, inviter_id, &unknown).unwrap(),
        "INVARIANT: unknown SPKI must be denied even when pending trust exists"
    );
}

/// Characterization: joiner accepted trust allows bootstrap sync.
///
/// After the invitee accepts an invite, accepted bootstrap trust is
/// recorded with the inviter's bootstrap SPKI. This MUST allow the
/// joiner to continue syncing with the inviter's bootstrap address
/// until PeerShared-derived trust supersedes it.
///
/// After eventization: this row must be produced by the InviteAccepted
/// projector (using bootstrap_context), not by the service layer.
#[test]
fn characterization_joiner_accepted_trust_allows_bootstrap_sync() {
    let conn = open_in_memory().unwrap();
    create_tables(&conn).unwrap();

    let joiner_id = "joiner_peer_bbbb";
    let invite_accepted_eid = "ia_evt_1";
    let invite_event_id = "invite_evt_1";
    let workspace_id = "workspace_1";
    let bootstrap_addr = "192.168.1.10:4433";
    let inviter_spki: [u8; 32] = [0x88; 32];

    // --- Joiner accepts invite: accepted trust recorded ---
    record_invite_bootstrap_trust(
        &conn,
        joiner_id,
        invite_accepted_eid,
        invite_event_id,
        workspace_id,
        bootstrap_addr,
        &inviter_spki,
    )
    .unwrap();

    // Joiner's transport layer checks the inviter's SPKI
    assert!(
        is_peer_allowed(&conn, joiner_id, &inviter_spki).unwrap(),
        "INVARIANT: joiner must allow inviter's bootstrap SPKI after accept"
    );

    // Bootstrap address should be listed for autodial
    let addrs = list_active_invite_bootstrap_addrs(&conn, joiner_id).unwrap();
    assert!(
        addrs.contains(&bootstrap_addr.to_string()),
        "INVARIANT: accepted bootstrap addr must be available for autodial"
    );
}

#[test]
fn test_list_active_invite_bootstrap_targets_keeps_distinct_invites_same_addr() {
    let conn = open_in_memory().unwrap();
    create_tables(&conn).unwrap();

    let recorded_by = "joiner_targets_1";
    let addr = "10.0.0.1:4433";
    let spki_a: [u8; 32] = [0x31; 32];
    let spki_b: [u8; 32] = [0x32; 32];

    record_invite_bootstrap_trust(
        &conn,
        recorded_by,
        "ia-1",
        "invite-1",
        "ws-1",
        addr,
        &spki_a,
    )
    .unwrap();
    record_invite_bootstrap_trust(
        &conn,
        recorded_by,
        "ia-2",
        "invite-2",
        "ws-1",
        addr,
        &spki_b,
    )
    .unwrap();

    let targets = list_active_invite_bootstrap_targets(&conn, recorded_by).unwrap();
    assert_eq!(targets.len(), 2, "two invite ids must produce two targets");
    let ids: std::collections::HashSet<String> =
        targets.iter().map(|t| t.invite_event_id.clone()).collect();
    assert!(ids.contains("invite-1"));
    assert!(ids.contains("invite-2"));
    let fps: std::collections::HashSet<String> = targets
        .iter()
        .map(|t| t.bootstrap_transport_peer_id.clone())
        .collect();
    assert!(fps.contains(&hex::encode(spki_a)));
    assert!(fps.contains(&hex::encode(spki_b)));
}

#[test]
fn test_list_active_invite_bootstrap_targets_latest_row_wins_per_invite() {
    let conn = open_in_memory().unwrap();
    create_tables(&conn).unwrap();

    let recorded_by = "joiner_targets_2";
    let spki: [u8; 32] = [0x41; 32];

    record_invite_bootstrap_trust(
        &conn,
        recorded_by,
        "ia-1",
        "invite-1",
        "ws-1",
        "10.0.0.1:4433",
        &spki,
    )
    .unwrap();
    record_invite_bootstrap_trust(
        &conn,
        recorded_by,
        "ia-2",
        "invite-1",
        "ws-1",
        "10.0.0.2:4433",
        &spki,
    )
    .unwrap();

    let targets = list_active_invite_bootstrap_targets(&conn, recorded_by).unwrap();
    assert_eq!(targets.len(), 1, "one deterministic winner per invite id");
    assert_eq!(targets[0].invite_event_id, "invite-1");
    assert_eq!(targets[0].bootstrap_addr, "10.0.0.2:4433");
    assert_eq!(targets[0].bootstrap_transport_peer_id, hex::encode(spki));
}

/// Characterization: full trust lifecycle — pending → accepted → superseded.
///
/// Covers the complete lifecycle:
/// 1. Inviter records pending trust (allows invitee first dial)
/// 2. Joiner records accepted trust (allows bootstrap sync)
/// 3. PeerShared event arrives → both types of bootstrap trust are superseded
/// 4. Steady-state PeerShared-derived SPKI is the sole trust source
///
/// After eventization: the lifecycle must produce identical trust decisions
/// at each stage, even though the writes come from projections.
#[test]
fn characterization_full_trust_lifecycle() {
    let conn = open_in_memory().unwrap();
    create_tables(&conn).unwrap();

    let inviter = "inviter_cccc";
    let joiner = "joiner_dddd";
    let invite_eid = "invite_lifecycle_1";
    let workspace_id = "ws_lifecycle_1";
    let invitee_spki: [u8; 32] = [0xAA; 32];
    let inviter_spki: [u8; 32] = [0xBB; 32];

    // --- Stage 1: Inviter creates invite, records pending trust ---
    record_pending_invite_bootstrap_trust(&conn, inviter, invite_eid, workspace_id, &invitee_spki)
        .unwrap();
    assert!(
        is_peer_allowed(&conn, inviter, &invitee_spki).unwrap(),
        "Stage 1: inviter allows invitee SPKI via pending trust"
    );

    // --- Stage 2: Joiner accepts, records accepted trust ---
    record_invite_bootstrap_trust(
        &conn,
        joiner,
        "ia_lifecycle_1",
        invite_eid,
        workspace_id,
        "10.0.0.1:4433",
        &inviter_spki,
    )
    .unwrap();
    assert!(
        is_peer_allowed(&conn, joiner, &inviter_spki).unwrap(),
        "Stage 2: joiner allows inviter SPKI via accepted trust"
    );

    // --- Stage 3: PeerShared arrives for the invitee SPKI on inviter side ---
    // The invitee's PeerShared public key must derive to the same SPKI
    // as the pending trust. For this test we use a known pubkey→SPKI mapping.
    let invitee_pubkey: [u8; 32] = [0xCC; 32];
    let invitee_derived_spki = insert_peer_shared(&conn, inviter, "ps_invitee", &invitee_pubkey);

    // After PeerShared, the derived SPKI is trusted via steady state
    assert!(
        is_peer_allowed(&conn, inviter, &invitee_derived_spki).unwrap(),
        "Stage 3: inviter allows invitee via PeerShared-derived SPKI"
    );

    // If the PeerShared SPKI matches the pending trust SPKI, pending is superseded.
    // (In this test they differ, so pending trust is NOT superseded — both paths remain.)
    // When they match, only one trust source remains:
    let matching_pubkey: [u8; 32] = {
        // We need a pubkey whose SPKI matches invitee_spki — but that's hard to
        // reverse. Instead, test supersession explicitly with matching values.
        let test_pubkey: [u8; 32] = [0xDD; 32];
        test_pubkey
    };
    let matching_spki = spki_fingerprint_from_ed25519_pubkey(&matching_pubkey);
    // Set up: pending trust with matching_spki, then PeerShared whose derived SPKI matches
    record_pending_invite_bootstrap_trust(
        &conn,
        inviter,
        "invite_match",
        workspace_id,
        &matching_spki,
    )
    .unwrap();
    assert!(
        is_peer_allowed(&conn, inviter, &matching_spki).unwrap(),
        "Stage 3b: pending trust allows matching SPKI before PeerShared"
    );

    insert_peer_shared(&conn, inviter, "ps_match", &matching_pubkey);
    // Supersession now happens at projection time via PeerShared writes
    consume_bootstrap_for_peer_shared(&conn, inviter, &matching_pubkey).unwrap();
    assert!(
        is_peer_allowed(&conn, inviter, &matching_spki).unwrap(),
        "Stage 3b: SPKI still allowed after PeerShared (via PeerShared path)"
    );
    // Pending trust should now be consumed (PeerShared SPKI matches).
    let remaining_rows: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM pending_invite_bootstrap_trust
             WHERE recorded_by = ?1 AND invite_event_id = ?2",
            rusqlite::params![inviter, "invite_match"],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(remaining_rows, 0);
    // But the SPKI is still allowed (via PeerShared path)
    assert!(
        is_peer_allowed(&conn, inviter, &matching_spki).unwrap(),
        "Stage 3b: SPKI still allowed via PeerShared after supersession"
    );
}

/// Characterization: trust check reads are pure (no side effects).
///
/// After eventization (Phase 5), the tenant- and node-scoped auth queries are
/// pure read-only queries. Supersession is handled at projection time by
/// PeerShared projection writes.
/// This test verifies that reads do NOT mutate the database.
#[test]
fn characterization_trust_check_reads_are_pure() {
    let conn = open_in_memory().unwrap();
    create_tables(&conn).unwrap();

    let recorded_by = "pure_read_test";
    let pubkey: [u8; 32] = [0x44; 32];
    let spki = spki_fingerprint_from_ed25519_pubkey(&pubkey);

    // Record pending trust, then add matching PeerShared
    record_pending_invite_bootstrap_trust(&conn, recorded_by, "invite_se", "ws_se", &spki).unwrap();
    insert_peer_shared(&conn, recorded_by, "ps_se", &pubkey);

    // Trust checks should NOT trigger supersession as a side effect
    let _ = is_authorized_for_tenant(&conn, recorded_by, &spki).unwrap();
    let _ = is_authorized_for_node(&conn, &spki).unwrap();
    let _ = resolve_authorizing_tenant(&conn, &spki).unwrap();
    let _ = authorized_fingerprints_from_db(&conn, recorded_by).unwrap();

    let before_consume_rows: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM pending_invite_bootstrap_trust
             WHERE recorded_by = ?1 AND invite_event_id = ?2",
            rusqlite::params![recorded_by, "invite_se"],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(before_consume_rows, 1);

    // Explicit projection-time consumption works.
    consume_bootstrap_for_peer_shared(&conn, recorded_by, &pubkey).unwrap();
    let after_consume_rows: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM pending_invite_bootstrap_trust
             WHERE recorded_by = ?1 AND invite_event_id = ?2",
            rusqlite::params![recorded_by, "invite_se"],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(after_consume_rows, 0);
}

// ---------------------------------------------------------------
// bootstrap_context tests
// ---------------------------------------------------------------

#[test]
fn test_bootstrap_context_append_and_read() {
    let conn = open_in_memory().unwrap();
    create_tables(&conn).unwrap();

    let recorded_by = "ctx_peer_1";
    let invite_eid = "invite_ctx_1";
    let workspace_id = "ws_ctx_1";
    let addr = "192.168.1.10:4433";
    let spki: [u8; 32] = [0xAA; 32];

    // No context yet
    let ctx = read_bootstrap_context(&conn, recorded_by, invite_eid).unwrap();
    assert!(ctx.is_none());

    // Append
    append_bootstrap_context(&conn, recorded_by, invite_eid, workspace_id, addr, &spki).unwrap();

    let ctx = read_bootstrap_context(&conn, recorded_by, invite_eid)
        .unwrap()
        .unwrap();
    assert_eq!(ctx.bootstrap_addrs, vec![addr.to_string()]);
    assert_eq!(ctx.bootstrap_spki_fingerprint, spki);
    assert_eq!(ctx.workspace_id, workspace_id);
}

#[test]
fn test_bootstrap_context_latest_wins() {
    let conn = open_in_memory().unwrap();
    create_tables(&conn).unwrap();

    let recorded_by = "ctx_peer_2";
    let invite_eid = "invite_ctx_2";
    let spki: [u8; 32] = [0xBB; 32];

    // Insert two rows — manual observed_at to control ordering
    conn.execute(
            "INSERT INTO bootstrap_context
             (recorded_by, invite_event_id, workspace_id, bootstrap_addr, bootstrap_spki_fingerprint, observed_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params![recorded_by, invite_eid, "ws1", "10.0.0.1:4433", spki.as_slice(), 1000],
        ).unwrap();
    conn.execute(
            "INSERT INTO bootstrap_context
             (recorded_by, invite_event_id, workspace_id, bootstrap_addr, bootstrap_spki_fingerprint, observed_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params![recorded_by, invite_eid, "ws1", "10.0.0.2:4433", spki.as_slice(), 2000],
        ).unwrap();

    let ctx = read_bootstrap_context(&conn, recorded_by, invite_eid)
        .unwrap()
        .unwrap();
    // Both addresses returned, ordered by observed_at DESC
    assert_eq!(
        ctx.bootstrap_addrs,
        vec!["10.0.0.2:4433".to_string(), "10.0.0.1:4433".to_string()],
        "all addresses should be returned, newest first"
    );
}

#[test]
fn test_bootstrap_context_tenant_isolation() {
    let conn = open_in_memory().unwrap();
    create_tables(&conn).unwrap();

    let spki: [u8; 32] = [0xCC; 32];
    append_bootstrap_context(&conn, "peer_a", "invite_1", "ws_1", "1.1.1.1:4433", &spki).unwrap();

    assert!(read_bootstrap_context(&conn, "peer_a", "invite_1")
        .unwrap()
        .is_some());
    assert!(read_bootstrap_context(&conn, "peer_b", "invite_1")
        .unwrap()
        .is_none());
}

#[test]
fn test_bootstrap_context_multiple_addrs_same_invite() {
    let conn = open_in_memory().unwrap();
    create_tables(&conn).unwrap();

    let recorded_by = "ctx_multi_1";
    let invite_eid = "invite_multi_1";
    let workspace_id = "ws_multi_1";
    let spki: [u8; 32] = [0xDD; 32];

    // Append multiple addresses for the same invite
    append_bootstrap_context(
        &conn,
        recorded_by,
        invite_eid,
        workspace_id,
        "192.168.1.50:4433",
        &spki,
    )
    .unwrap();
    append_bootstrap_context(
        &conn,
        recorded_by,
        invite_eid,
        workspace_id,
        "100.64.1.20:4433",
        &spki,
    )
    .unwrap();
    append_bootstrap_context(
        &conn,
        recorded_by,
        invite_eid,
        workspace_id,
        "myhost.ts.net:4433",
        &spki,
    )
    .unwrap();

    let ctx = read_bootstrap_context(&conn, recorded_by, invite_eid)
        .unwrap()
        .unwrap();
    assert_eq!(
        ctx.bootstrap_addrs.len(),
        3,
        "should return all 3 addresses"
    );
    assert!(ctx
        .bootstrap_addrs
        .contains(&"192.168.1.50:4433".to_string()));
    assert!(ctx
        .bootstrap_addrs
        .contains(&"100.64.1.20:4433".to_string()));
    assert!(ctx
        .bootstrap_addrs
        .contains(&"myhost.ts.net:4433".to_string()));
    assert_eq!(ctx.bootstrap_spki_fingerprint, spki);
    assert_eq!(ctx.workspace_id, workspace_id);
}

#[test]
fn test_bootstrap_context_deduplicates_addrs() {
    let conn = open_in_memory().unwrap();
    create_tables(&conn).unwrap();

    let recorded_by = "ctx_dedup_1";
    let invite_eid = "invite_dedup_1";
    let spki: [u8; 32] = [0xEE; 32];

    // Append same address twice
    append_bootstrap_context(
        &conn,
        recorded_by,
        invite_eid,
        "ws1",
        "10.0.0.1:4433",
        &spki,
    )
    .unwrap();
    append_bootstrap_context(
        &conn,
        recorded_by,
        invite_eid,
        "ws1",
        "10.0.0.1:4433",
        &spki,
    )
    .unwrap();

    let ctx = read_bootstrap_context(&conn, recorded_by, invite_eid)
        .unwrap()
        .unwrap();
    assert_eq!(
        ctx.bootstrap_addrs.len(),
        1,
        "duplicate addresses should be deduplicated"
    );
    assert_eq!(ctx.bootstrap_addrs[0], "10.0.0.1:4433");
}
