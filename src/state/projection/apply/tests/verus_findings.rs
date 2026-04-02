//! Regression tests for bugs discovered by Verus formal verification.
//!
//! Each test targets a specific finding from verus-proofs/src/bug_hunt.rs.

use super::*;

// ═══════════════════════════════════════════════════════════════════
// FINDING 2: Empty-Missing Block Creates Unresolvable State
// ═══════════════════════════════════════════════════════════════════

#[test]
fn finding_2_empty_missing_block_records_no_dep_edges_and_cascade_cannot_resolve() {
    let conn = setup();
    let recorded_by = "peer1";

    // Create a workspace event. Without an accepted invite binding,
    // the context loader returns Block{missing: []}.
    let ws = ParsedEvent::Workspace(WorkspaceEvent {
        created_at_ms: now_ms(),
        public_key: [0xAA; 32],
        name: "test-workspace".to_string(),
    });
    let ws_blob = events::encode_event(&ws).unwrap();
    let ws_eid = insert_event_raw(&conn, recorded_by, &ws_blob);
    let ws_b64 = event_id_to_base64(&ws_eid);

    // Project the workspace event — should block (no invite binding)
    let result = project_one(&conn, recorded_by, &ws_eid).unwrap();
    assert!(
        matches!(result, ProjectionDecision::Block { .. }),
        "workspace event should block without invite binding, got {:?}",
        result
    );

    // Verify: no blocked_event_deps edges were written (this is the bug)
    let dep_edge_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM blocked_event_deps WHERE peer_id = ?1 AND event_id = ?2",
            rusqlite::params![recorded_by, &ws_b64],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        dep_edge_count, 0,
        "empty-missing block writes zero dep edges — cascade can never resolve"
    );

    // Simulate the invite_accepted binding that RetryWorkspaceEvent provides.
    let fake_tenant_eid = event_id_to_base64(&[0xF1u8; 32]);
    let fake_invite_eid = event_id_to_base64(&[0xF2u8; 32]);
    conn.execute(
        "INSERT OR IGNORE INTO invites_accepted
         (recorded_by, event_id, tenant_event_id, invite_event_id, workspace_id, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        rusqlite::params![
            recorded_by,
            &ws_b64,
            &fake_tenant_eid,
            &fake_invite_eid,
            &ws_b64,
            now_ms() as i64
        ],
    )
    .unwrap();

    // Direct retry — the workspace should now project valid.
    let retry_result = project_one(&conn, recorded_by, &ws_eid).unwrap();
    assert_eq!(
        retry_result,
        ProjectionDecision::Valid,
        "workspace should project after invite binding is set and retry fires"
    );
}

// ═══════════════════════════════════════════════════════════════════
// FINDING 3: deps_remaining Counter Desync on Re-Block
// ═══════════════════════════════════════════════════════════════════

#[test]
fn finding_3_reblock_via_project_one_retry_preserves_stale_deps_remaining() {
    let conn = setup();
    let recorded_by = "peer1";

    // Create dep A (KeySecret, no deps of its own)
    let sk_a = ParsedEvent::KeySecret(KeySecretEvent {
        created_at_ms: now_ms(),
        key_bytes: [0xAA; 32],
    });
    let sk_a_blob = events::encode_event(&sk_a).unwrap();
    let sk_a_eid = insert_event_raw(&conn, recorded_by, &sk_a_blob);

    // Create dep B
    let sk_b = ParsedEvent::KeySecret(KeySecretEvent {
        created_at_ms: now_ms(),
        key_bytes: [0xBB; 32],
    });
    let sk_b_blob = events::encode_event(&sk_b).unwrap();
    let sk_b_eid = insert_event_raw(&conn, recorded_by, &sk_b_blob);

    // Create event E depending on A and B
    let bench = ParsedEvent::BenchDep(BenchDepEvent {
        created_at_ms: now_ms(),
        dep_ids: vec![sk_a_eid, sk_b_eid],
        payload: [0x42; 16],
    });
    let bench_blob = events::encode_event(&bench).unwrap();
    let bench_eid = insert_event_raw(&conn, recorded_by, &bench_blob);
    let bench_b64 = event_id_to_base64(&bench_eid);

    // First projection: blocks on both A and B
    let result = project_one(&conn, recorded_by, &bench_eid).unwrap();
    assert!(matches!(result, ProjectionDecision::Block { .. }));

    let deps_remaining: i64 = conn
        .query_row(
            "SELECT deps_remaining FROM blocked_events WHERE peer_id = ?1 AND event_id = ?2",
            rusqlite::params![recorded_by, &bench_b64],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(deps_remaining, 2, "initial deps_remaining should be 2");

    // Resolve dep A via proper project_one (triggers cascade)
    project_one(&conn, recorded_by, &sk_a_eid).unwrap();

    // After cascade from A: E's deps_remaining should be 1
    let deps_remaining_after_a: i64 = conn
        .query_row(
            "SELECT deps_remaining FROM blocked_events WHERE peer_id = ?1 AND event_id = ?2",
            rusqlite::params![recorded_by, &bench_b64],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(deps_remaining_after_a, 1);

    // Call project_one directly for E (simulating a retry command).
    // B is still missing. record_block_rows will INSERT OR IGNORE.
    let retry_result = project_one(&conn, recorded_by, &bench_eid).unwrap();
    assert!(matches!(retry_result, ProjectionDecision::Block { .. }));

    // Check: deps_remaining should match actual unique missing dep edge count.
    // Before fix: deps_remaining=1 but edge_count=2 (stale A edge + B edge).
    // After fix: record_block_rows cleans stale edges and uses REPLACE.
    let deps_remaining_after_retry: i64 = conn
        .query_row(
            "SELECT deps_remaining FROM blocked_events WHERE peer_id = ?1 AND event_id = ?2",
            rusqlite::params![recorded_by, &bench_b64],
            |row| row.get(0),
        )
        .unwrap();
    let edge_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM blocked_event_deps WHERE peer_id = ?1 AND event_id = ?2",
            rusqlite::params![recorded_by, &bench_b64],
            |row| row.get(0),
        )
        .unwrap();

    assert_eq!(
        deps_remaining_after_retry, edge_count,
        "deps_remaining ({}) must match actual dep edge count ({})",
        deps_remaining_after_retry, edge_count
    );
}

// ═══════════════════════════════════════════════════════════════════
// FINDING 4: Removal Revokes Transport Authorization
// ═══════════════════════════════════════════════════════════════════

#[test]
fn finding_4_removal_revokes_transport_authorization() {
    use crate::db::transport_trust::is_authorized_for_tenant;

    let conn = setup();
    let recorded_by = "peer1";

    let transport_fp = [0x42u8; 32];
    let peer_shared_eid = [0x01u8; 32];
    let peer_shared_b64 = event_id_to_base64(&peer_shared_eid);

    // Insert a peers_shared row with the correct schema
    conn.execute(
        "INSERT INTO peers_shared (recorded_by, event_id, public_key, transport_fingerprint)
         VALUES (?1, ?2, ?3, ?4)",
        rusqlite::params![
            recorded_by,
            &peer_shared_b64,
            [0xCCu8; 32].as_slice(),
            transport_fp.as_slice()
        ],
    )
    .unwrap();

    // Authorized before removal
    let authorized_before = is_authorized_for_tenant(&conn, recorded_by, &transport_fp).unwrap();
    assert!(
        authorized_before,
        "peer should be authorized before removal"
    );

    // Remove the peer
    let removal_eid = [0x99u8; 32];
    let removal_b64 = event_id_to_base64(&removal_eid);
    conn.execute(
        "INSERT INTO removed_entities (recorded_by, event_id, target_event_id, removal_type)
         VALUES (?1, ?2, ?3, 'peer')",
        rusqlite::params![recorded_by, &removal_b64, &peer_shared_b64],
    )
    .unwrap();

    // NOT authorized after removal
    let authorized_after = is_authorized_for_tenant(&conn, recorded_by, &transport_fp).unwrap();
    assert!(
        !authorized_after,
        "peer should NOT be authorized after removal (TOCTOU: \
         sessions opened before removal continue until next re-auth check)"
    );
}

// ═══════════════════════════════════════════════════════════════════
// FINDING 7: Bootstrap Trust Expiry Works in DB
// ═══════════════════════════════════════════════════════════════════

#[test]
fn finding_7_bootstrap_trust_expires_in_db_but_cache_has_no_ttl() {
    use crate::db::transport_trust::is_authorized_for_tenant;

    let conn = setup();
    let recorded_by = "peer1";

    let bootstrap_fp = [0x55u8; 32];
    let invite_eid = [0x10u8; 32];
    let invite_b64 = event_id_to_base64(&invite_eid);
    let ia_eid = [0x11u8; 32];
    let ia_b64 = event_id_to_base64(&ia_eid);
    let ws_eid = [0x12u8; 32];
    let ws_b64 = event_id_to_base64(&ws_eid);
    let now = now_ms() as i64;

    // Create bootstrap trust that has ALREADY expired
    let expired_at = now - 1000;
    conn.execute(
        "INSERT INTO invite_bootstrap_trust
         (recorded_by, invite_accepted_event_id, invite_event_id, workspace_id,
          bootstrap_addr, bootstrap_spki_fingerprint, accepted_at, expires_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        rusqlite::params![
            recorded_by,
            &ia_b64,
            &invite_b64,
            &ws_b64,
            "127.0.0.1:4433",
            bootstrap_fp.as_slice(),
            now,
            expired_at
        ],
    )
    .unwrap();

    // DB correctly says this is expired
    let authorized = is_authorized_for_tenant(&conn, recorded_by, &bootstrap_fp).unwrap();
    assert!(
        !authorized,
        "expired bootstrap trust should NOT authorize in DB"
    );

    // Verify unexpired bootstrap trust DOES authorize
    let active_fp = [0x77u8; 32];
    let active_ia_b64 = event_id_to_base64(&[0x13u8; 32]);
    let future_expiry = now + 86_400_000; // 24 hours from now
    conn.execute(
        "INSERT INTO invite_bootstrap_trust
         (recorded_by, invite_accepted_event_id, invite_event_id, workspace_id,
          bootstrap_addr, bootstrap_spki_fingerprint, accepted_at, expires_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        rusqlite::params![
            recorded_by,
            &active_ia_b64,
            &invite_b64,
            &ws_b64,
            "127.0.0.1:4433",
            active_fp.as_slice(),
            now,
            future_expiry
        ],
    )
    .unwrap();

    let active_authorized = is_authorized_for_tenant(&conn, recorded_by, &active_fp).unwrap();
    assert!(
        active_authorized,
        "unexpired bootstrap trust should authorize"
    );

    // The bug: DaemonConnection's AcceptedBootstrapAuthCache has no TTL.
    // Once cached on the connection object, it stays forever — even after
    // the DB row expires. The fix: add created_at to cached entries and
    // check TTL on lookup.
}
