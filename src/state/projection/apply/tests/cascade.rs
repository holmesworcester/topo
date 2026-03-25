use super::*;

// ========================================================================
// New tests for single-entrypoint cascade refactor (Issue 1)
// ========================================================================

#[test]
fn test_multi_dep_event_projects_only_when_all_resolve() {
    // BenchDepEvent with 2 deps: verify it only projects when both deps are valid.
    let conn = setup();
    let recorded_by = "peer1";

    // Create two KeySecret events as deps (no deps of their own)
    let sk_a = ParsedEvent::KeySecret(KeySecretEvent {
        created_at_ms: now_ms(),
        key_bytes: [0xAA; 32],
    });
    let sk_a_blob = events::encode_event(&sk_a).unwrap();
    let sk_a_eid = insert_event_raw(&conn, recorded_by, &sk_a_blob);

    let sk_b = ParsedEvent::KeySecret(KeySecretEvent {
        created_at_ms: now_ms(),
        key_bytes: [0xBB; 32],
    });
    let sk_b_blob = events::encode_event(&sk_b).unwrap();
    let sk_b_eid = insert_event_raw(&conn, recorded_by, &sk_b_blob);

    // Create BenchDepEvent depending on both
    let bench = ParsedEvent::BenchDep(BenchDepEvent {
        created_at_ms: now_ms(),
        dep_ids: vec![sk_a_eid, sk_b_eid],
        payload: [0x42; 16],
    });
    let bench_blob = events::encode_event(&bench).unwrap();
    let bench_eid = insert_event_raw(&conn, recorded_by, &bench_blob);

    // Project bench first — should block on both deps
    let result = project_one(&conn, recorded_by, &bench_eid).unwrap();
    assert!(
        matches!(result, ProjectionDecision::Block { ref missing } if missing.len() == 2),
        "should block on 2 missing deps, got {:?}",
        result
    );

    // Project dep A only — bench should still be blocked
    project_one(&conn, recorded_by, &sk_a_eid).unwrap();
    let bench_b64 = event_id_to_base64(&bench_eid);
    let still_blocked: bool = conn
        .query_row(
            "SELECT COUNT(*) > 0 FROM blocked_events WHERE peer_id = ?1 AND event_id = ?2",
            rusqlite::params![recorded_by, &bench_b64],
            |row| row.get(0),
        )
        .unwrap();
    assert!(
        still_blocked,
        "bench should still be blocked after only one dep resolves"
    );

    // Project dep B — now bench should cascade to valid
    project_one(&conn, recorded_by, &sk_b_eid).unwrap();
    let bench_valid: bool = conn
        .query_row(
            "SELECT COUNT(*) > 0 FROM valid_events WHERE peer_id = ?1 AND event_id = ?2",
            rusqlite::params![recorded_by, &bench_b64],
            |row| row.get(0),
        )
        .unwrap();
    assert!(
        bench_valid,
        "bench should be valid after both deps resolve via cascade"
    );
}

#[test]
fn test_cascade_and_direct_produce_same_state() {
    // Compare direct (in-order) projection vs out-of-order cascade.
    // Both should produce identical valid_events sets.
    let recorded_by = "peer1";

    // --- Direct path (in dependency order) ---
    let conn_direct = setup();
    let (signer_eid, signing_key) = make_identity_chain(&conn_direct, recorded_by);
    let (_msg, msg_blob) = make_message_signed(&signing_key, &signer_eid, "hello");
    let msg_eid = insert_event_raw(&conn_direct, recorded_by, &msg_blob);
    project_one(&conn_direct, recorded_by, &msg_eid).unwrap();

    let (_rxn, rxn_blob) = make_reaction_signed(&signing_key, &signer_eid, &msg_eid, "thumbs_up");
    let rxn_eid = insert_event_raw(&conn_direct, recorded_by, &rxn_blob);
    project_one(&conn_direct, recorded_by, &rxn_eid).unwrap();

    // --- Cascade path (reaction before message) ---
    let conn_cascade = setup();
    // Same identity chain
    let (signer_eid_c, signing_key_c) = make_identity_chain(&conn_cascade, recorded_by);
    let (_msg_c, msg_blob_c) = make_message_signed(&signing_key_c, &signer_eid_c, "hello");
    let msg_eid_c = insert_event_raw(&conn_cascade, recorded_by, &msg_blob_c);
    // DON'T project message yet

    let (_rxn_c, rxn_blob_c) =
        make_reaction_signed(&signing_key_c, &signer_eid_c, &msg_eid_c, "thumbs_up");
    let rxn_eid_c = insert_event_raw(&conn_cascade, recorded_by, &rxn_blob_c);
    // Reaction should block (message not valid yet)
    let r = project_one(&conn_cascade, recorded_by, &rxn_eid_c).unwrap();
    assert!(matches!(r, ProjectionDecision::Block { .. }));

    // Now project message — should cascade and unblock reaction
    project_one(&conn_cascade, recorded_by, &msg_eid_c).unwrap();

    // Both should have the reaction as valid
    let rxn_b64 = event_id_to_base64(&rxn_eid);
    let rxn_valid_direct: bool = conn_direct
        .query_row(
            "SELECT COUNT(*) > 0 FROM valid_events WHERE peer_id = ?1 AND event_id = ?2",
            rusqlite::params![recorded_by, &rxn_b64],
            |row| row.get(0),
        )
        .unwrap();

    let rxn_b64_c = event_id_to_base64(&rxn_eid_c);
    let rxn_valid_cascade: bool = conn_cascade
        .query_row(
            "SELECT COUNT(*) > 0 FROM valid_events WHERE peer_id = ?1 AND event_id = ?2",
            rusqlite::params![recorded_by, &rxn_b64_c],
            |row| row.get(0),
        )
        .unwrap();

    assert!(rxn_valid_direct, "reaction should be valid via direct path");
    assert!(
        rxn_valid_cascade,
        "reaction should be valid via cascade path"
    );
}

#[test]
fn test_encrypted_inner_dep_cascade_unblock() {
    // Encrypted event whose inner event (a Reaction) depends on a message.
    // Insert encrypted event first (blocks on key), then provide key (cascades
    // to decrypt, but inner reaction blocks on message), then provide message
    // (cascades to unblock inner reaction -> encrypted becomes valid).
    let conn = setup();
    let recorded_by = "peer1";
    let (signer_eid, signing_key) = make_identity_chain(&conn, recorded_by);

    // Create the message that the inner reaction will target
    let (_msg, msg_blob) = make_message_signed(&signing_key, &signer_eid, "target msg");
    let msg_eid = insert_event_raw(&conn, recorded_by, &msg_blob);
    // DON'T project message yet

    // Create the secret key for encryption
    let key_bytes: [u8; 32] = rand::random();
    let (_sk, sk_blob) = make_key_secret(key_bytes);
    let sk_eid = insert_event_raw(&conn, recorded_by, &sk_blob);
    // DON'T project key yet

    // Create inner event: a Reaction targeting the message
    let rxn = ReactionEvent {
        created_at_ms: now_ms(),
        target_event_id: msg_eid,
        author_id: user_for_signer(&signer_eid),
        emoji: "heart".to_string(),
        signed_by: signer_eid,
        signer_type: 5,
        signature: [0u8; 64],
    };
    let rxn_event = ParsedEvent::Reaction(rxn);
    let mut inner_blob = events::encode_event(&rxn_event).unwrap();
    sign_blob(&signing_key, &mut inner_blob);

    // Wrap in encrypted envelope
    let (_enc, enc_blob) =
        make_encrypted_event(&key_bytes, &inner_blob, EVENT_TYPE_REACTION, &sk_eid);
    let enc_eid = insert_event_raw(&conn, recorded_by, &enc_blob);

    // Project encrypted event — should block on missing key_event_id dep
    let r1 = project_one(&conn, recorded_by, &enc_eid).unwrap();
    assert!(
        matches!(r1, ProjectionDecision::Block { .. }),
        "encrypted should block on missing key, got {:?}",
        r1
    );

    // Project key — encrypted event cascades, decrypts, but inner reaction
    // blocks on missing message. Encrypted event should NOT be valid yet.
    project_one(&conn, recorded_by, &sk_eid).unwrap();
    let enc_b64 = event_id_to_base64(&enc_eid);
    let enc_valid_after_key: bool = conn
        .query_row(
            "SELECT COUNT(*) > 0 FROM valid_events WHERE peer_id = ?1 AND event_id = ?2",
            rusqlite::params![recorded_by, &enc_b64],
            |row| row.get(0),
        )
        .unwrap();
    assert!(
        !enc_valid_after_key,
        "encrypted event should NOT be valid yet (inner dep missing)"
    );

    // Project message — inner reaction unblocks, encrypted event should cascade to valid
    project_one(&conn, recorded_by, &msg_eid).unwrap();
    let enc_valid_final: bool = conn
        .query_row(
            "SELECT COUNT(*) > 0 FROM valid_events WHERE peer_id = ?1 AND event_id = ?2",
            rusqlite::params![recorded_by, &enc_b64],
            |row| row.get(0),
        )
        .unwrap();
    assert!(
        enc_valid_final,
        "encrypted event should be valid after all inner deps resolve"
    );
}

#[test]
fn test_invite_accepted_guard_retry_on_workspace() {
    // Workspace events are guard-blocked (not dep-blocked) until InviteAccepted
    // sets the trust anchor. Verify that projecting InviteAccepted triggers
    // guard retry and unblocks the Workspace event.
    let conn = setup();
    let recorded_by = "peer1";
    let mut rng = rand::thread_rng();

    // Create workspace event
    let workspace_key = SigningKey::generate(&mut rng);
    let workspace_pub = workspace_key.verifying_key().to_bytes();
    let ws_event = ParsedEvent::Workspace(WorkspaceEvent {
        created_at_ms: now_ms(),
        public_key: workspace_pub,
        name: "workspace".to_string(),
    });
    let ws_blob = events::encode_event(&ws_event).unwrap();
    let ws_eid = insert_event_raw(&conn, recorded_by, &ws_blob);

    // Project workspace first — should be guard-blocked (no trust anchor yet)
    let r1 = project_one(&conn, recorded_by, &ws_eid).unwrap();
    assert!(
        matches!(r1, ProjectionDecision::Block { ref missing } if missing.is_empty()),
        "workspace should be guard-blocked with empty missing, got {:?}",
        r1
    );

    // Create and project InviteAccepted — should set trust anchor and trigger guard retry
    let ia_event = ParsedEvent::InviteAccepted(InviteAcceptedEvent {
        created_at_ms: now_ms(),
        tenant_event_id: setup_tenant_event(&conn, recorded_by),
        invite_event_id: ws_eid,
        workspace_id: ws_eid,
    });
    let ia_blob = events::encode_event(&ia_event).unwrap();
    let ia_eid = insert_event_raw(&conn, recorded_by, &ia_blob);
    let r2 = project_one(&conn, recorded_by, &ia_eid).unwrap();
    assert_eq!(
        r2,
        ProjectionDecision::Valid,
        "invite_accepted should project Valid"
    );

    // Workspace should now be valid via guard retry cascade
    let ws_b64 = event_id_to_base64(&ws_eid);
    let ws_valid: bool = conn
        .query_row(
            "SELECT COUNT(*) > 0 FROM valid_events WHERE peer_id = ?1 AND event_id = ?2",
            rusqlite::params![recorded_by, &ws_b64],
            |row| row.get(0),
        )
        .unwrap();
    assert!(
        ws_valid,
        "workspace should be valid after invite_accepted guard retry"
    );
}

#[test]
fn test_file_slice_guard_retry_after_cascaded_attachment() {
    // FileSlice is guard-blocked waiting for descriptor (File).
    // File is dep-blocked on a message. When the message projects,
    // it cascades the attachment, which triggers guard retry on the file_slice.
    let conn = setup();
    let recorded_by = "peer1";
    let (signer_eid, signing_key) = make_identity_chain(&conn, recorded_by);
    let file_key_event_id = ensure_test_content_key(&conn, recorded_by);

    let file_id = [77u8; 32];

    // Create message (dep for attachment) but DON'T project yet
    let (_msg, msg_blob) = make_message_signed(&signing_key, &signer_eid, "parent msg");
    let msg_eid = insert_event_raw(&conn, recorded_by, &msg_blob);

    // Create attachment (descriptor) — dep-blocked on message
    let att = FileEvent {
        created_at_ms: now_ms(),
        message_id: msg_eid,
        file_id,
        blob_bytes: 204800,
        total_slices: 4,
        slice_bytes: 65536,
        root_hash: [12u8; 32],
        key_event_id: file_key_event_id,
        filename: "test.bin".to_string(),
        mime_type: "application/octet-stream".to_string(),
        signed_by: signer_eid,
        signer_type: 5,
        signature: [0u8; 64],
    };
    let att_event = ParsedEvent::File(att);
    let mut att_blob = events::encode_event(&att_event).unwrap();
    sign_blob(&signing_key, &mut att_blob);
    let att_eid = insert_event_raw(&conn, recorded_by, &att_blob);
    let r1 = project_one(&conn, recorded_by, &att_eid).unwrap();
    assert!(
        matches!(r1, ProjectionDecision::Block { .. }),
        "attachment should block on missing message dep, got {:?}",
        r1
    );

    // Create file_slice — guard-blocked (no descriptor yet)
    let (_fs, fs_blob) = make_file_slice(&signing_key, &signer_eid, file_id, 0, b"slice data");
    let fs_eid = insert_event_raw(&conn, recorded_by, &fs_blob);
    let r2 = project_one(&conn, recorded_by, &fs_eid).unwrap();
    // file_slice returns Block with empty missing (guard block) because no descriptor exists
    assert!(
        matches!(r2, ProjectionDecision::Block { ref missing } if missing.is_empty()),
        "file_slice should be guard-blocked, got {:?}",
        r2
    );

    // Verify file_slice is in guard block table
    let fs_b64 = event_id_to_base64(&fs_eid);
    let guard_blocked: bool = conn
        .query_row(
            "SELECT COUNT(*) > 0 FROM file_slice_guard_blocks WHERE peer_id = ?1 AND event_id = ?2",
            rusqlite::params![recorded_by, &fs_b64],
            |row| row.get(0),
        )
        .unwrap();
    assert!(guard_blocked, "file_slice should be in guard_blocks table");

    // Now project message — should cascade: attachment unblocks, then guard retry unblocks file_slice
    project_one(&conn, recorded_by, &msg_eid).unwrap();

    // Attachment should be valid
    let att_b64 = event_id_to_base64(&att_eid);
    let att_valid: bool = conn
        .query_row(
            "SELECT COUNT(*) > 0 FROM valid_events WHERE peer_id = ?1 AND event_id = ?2",
            rusqlite::params![recorded_by, &att_b64],
            |row| row.get(0),
        )
        .unwrap();
    assert!(
        att_valid,
        "attachment should be valid after message cascade"
    );

    // File slice should be valid (guard retry triggered by attachment cascade)
    let fs_valid: bool = conn
        .query_row(
            "SELECT COUNT(*) > 0 FROM valid_events WHERE peer_id = ?1 AND event_id = ?2",
            rusqlite::params![recorded_by, &fs_b64],
            |row| row.get(0),
        )
        .unwrap();
    assert!(
        fs_valid,
        "file_slice should be valid after cascaded guard retry"
    );
}

// =========================================================================
// Source-isomorphism invariance tests
//
// These tests prove that all ingest orderings — direct (in-order),
// cascade (out-of-order), and reverse replay — converge to the same
// terminal projected state.  This validates the two-layer model:
//   project_one (public entrypoint + cascade) and
//   project_one_step (internal non-cascading step)
// produce equivalent results regardless of event arrival order.
// =========================================================================

/// Count valid events for a tenant.
fn count_valid(conn: &Connection, recorded_by: &str) -> i64 {
    conn.query_row(
        "SELECT COUNT(*) FROM valid_events WHERE peer_id = ?1",
        rusqlite::params![recorded_by],
        |row| row.get(0),
    )
    .unwrap()
}

/// Count blocked events for a tenant.
fn count_blocked(conn: &Connection, recorded_by: &str) -> i64 {
    conn.query_row(
        "SELECT COUNT(*) FROM blocked_events WHERE peer_id = ?1",
        rusqlite::params![recorded_by],
        |row| row.get(0),
    )
    .unwrap()
}

/// Count message rows for a tenant.
fn count_messages(conn: &Connection, recorded_by: &str) -> i64 {
    conn.query_row(
        "SELECT COUNT(*) FROM messages WHERE recorded_by = ?1",
        rusqlite::params![recorded_by],
        |row| row.get(0),
    )
    .unwrap()
}

/// Count reaction rows for a tenant.
fn count_reactions(conn: &Connection, recorded_by: &str) -> i64 {
    conn.query_row(
        "SELECT COUNT(*) FROM reactions WHERE recorded_by = ?1",
        rusqlite::params![recorded_by],
        |row| row.get(0),
    )
    .unwrap()
}

/// Count deleted messages for a tenant.
fn count_deleted_messages(conn: &Connection, recorded_by: &str) -> i64 {
    conn.query_row(
        "SELECT COUNT(*) FROM deleted_messages WHERE recorded_by = ?1",
        rusqlite::params![recorded_by],
        |row| row.get(0),
    )
    .unwrap()
}

#[test]
fn test_source_isomorphism_message_reaction_chain() {
    // Prove that direct (in-order) and cascade (out-of-order) projection
    // produce identical projected state for a message → reaction chain.
    let recorded_by = "iso_peer";

    // --- Path A: Direct (in dependency order) ---
    let conn_a = setup();
    let (signer_a, key_a) = make_identity_chain(&conn_a, recorded_by);
    let (_msg_a, msg_blob_a) = make_message_signed(&key_a, &signer_a, "iso msg");
    let msg_eid_a = insert_event_raw(&conn_a, recorded_by, &msg_blob_a);
    project_one(&conn_a, recorded_by, &msg_eid_a).unwrap();

    let (_rxn_a, rxn_blob_a) = make_reaction_signed(&key_a, &signer_a, &msg_eid_a, "thumbs_up");
    let rxn_eid_a = insert_event_raw(&conn_a, recorded_by, &rxn_blob_a);
    project_one(&conn_a, recorded_by, &rxn_eid_a).unwrap();

    // --- Path B: Cascade (reaction first, then message unblocks it) ---
    let conn_b = setup();
    let (signer_b, key_b) = make_identity_chain(&conn_b, recorded_by);
    let (_msg_b, msg_blob_b) = make_message_signed(&key_b, &signer_b, "iso msg");
    let msg_eid_b = insert_event_raw(&conn_b, recorded_by, &msg_blob_b);

    let (_rxn_b, rxn_blob_b) = make_reaction_signed(&key_b, &signer_b, &msg_eid_b, "thumbs_up");
    let _rxn_eid_b = insert_event_raw(&conn_b, recorded_by, &rxn_blob_b);
    let r = project_one(&conn_b, recorded_by, &_rxn_eid_b).unwrap();
    assert!(matches!(r, ProjectionDecision::Block { .. }));

    // Now project message — reaction should cascade to valid
    project_one(&conn_b, recorded_by, &msg_eid_b).unwrap();

    // --- Compare projected state ---
    // Both should have same count of valid events (identity chain + msg + rxn)
    assert_eq!(
        count_valid(&conn_a, recorded_by),
        count_valid(&conn_b, recorded_by),
        "valid event counts must match"
    );
    assert_eq!(
        count_blocked(&conn_a, recorded_by),
        count_blocked(&conn_b, recorded_by),
        "blocked event counts must match (should be 0)"
    );
    assert_eq!(0, count_blocked(&conn_a, recorded_by));

    // Messages table must have same rows
    assert_eq!(
        count_messages(&conn_a, recorded_by),
        count_messages(&conn_b, recorded_by),
        "messages table must match"
    );

    // Reactions table must have same rows
    assert_eq!(
        count_reactions(&conn_a, recorded_by),
        count_reactions(&conn_b, recorded_by),
        "reactions table must match"
    );
}

#[test]
fn test_source_isomorphism_encrypted_message() {
    // Prove that direct and cascade paths produce the same state for
    // encrypted events: key → encrypted(message) in-order vs
    // encrypted first (blocks on key), then key cascades.
    let recorded_by = "iso_enc";

    let key_bytes: [u8; 32] = rand::random();

    // --- Path A: Direct (key first, then encrypted) ---
    let conn_a = setup();
    let (signer_a, signing_key_a) = make_identity_chain(&conn_a, recorded_by);
    let (_sk_a, sk_blob_a) = make_key_secret(key_bytes);
    let sk_eid_a = insert_event_raw(&conn_a, recorded_by, &sk_blob_a);
    project_one(&conn_a, recorded_by, &sk_eid_a).unwrap();

    let (_msg_a, msg_blob_a) = make_message_signed(&signing_key_a, &signer_a, "enc msg");
    let (_enc_a, enc_blob_a) =
        make_encrypted_event(&key_bytes, &msg_blob_a, EVENT_TYPE_MESSAGE, &sk_eid_a);
    let enc_eid_a = insert_event_raw(&conn_a, recorded_by, &enc_blob_a);
    let r_a = project_one(&conn_a, recorded_by, &enc_eid_a).unwrap();
    assert_eq!(r_a, ProjectionDecision::Valid);

    // --- Path B: Cascade (encrypted first, blocks; then key unblocks) ---
    let conn_b = setup();
    let (signer_b, signing_key_b) = make_identity_chain(&conn_b, recorded_by);
    let (_sk_b, sk_blob_b) = make_key_secret(key_bytes);
    let sk_eid_b = insert_event_raw(&conn_b, recorded_by, &sk_blob_b);

    let (_msg_b, msg_blob_b) = make_message_signed(&signing_key_b, &signer_b, "enc msg");
    let (_enc_b, enc_blob_b) =
        make_encrypted_event(&key_bytes, &msg_blob_b, EVENT_TYPE_MESSAGE, &sk_eid_b);
    let enc_eid_b = insert_event_raw(&conn_b, recorded_by, &enc_blob_b);
    let r_b = project_one(&conn_b, recorded_by, &enc_eid_b).unwrap();
    assert!(matches!(r_b, ProjectionDecision::Block { .. }));

    // Now project key — encrypted should cascade to valid
    project_one(&conn_b, recorded_by, &sk_eid_b).unwrap();

    // --- Compare ---
    assert_eq!(
        count_valid(&conn_a, recorded_by),
        count_valid(&conn_b, recorded_by),
        "valid event counts must match"
    );
    assert_eq!(0, count_blocked(&conn_a, recorded_by));
    assert_eq!(0, count_blocked(&conn_b, recorded_by));
    assert_eq!(
        count_messages(&conn_a, recorded_by),
        count_messages(&conn_b, recorded_by),
        "messages table must match"
    );
}

#[test]
fn test_source_isomorphism_deletion_cascade() {
    // Prove direct vs intent-then-create produce same state for message → deletion.
    // Path A: message first, then deletion (standard order).
    // Path B: deletion first (intent-only), then message (tombstoned via intent).
    let recorded_by = "iso_del";

    // --- Path A: Direct (message first, then deletion) ---
    let conn_a = setup();
    let (signer_a, key_a) = make_identity_chain(&conn_a, recorded_by);
    let (_msg_a, msg_blob_a) = make_message_signed(&key_a, &signer_a, "to delete");
    let msg_eid_a = insert_event_raw(&conn_a, recorded_by, &msg_blob_a);
    project_one(&conn_a, recorded_by, &msg_eid_a).unwrap();

    let (_del_a, del_blob_a) = make_deletion_signed(&key_a, &signer_a, &msg_eid_a, [2u8; 32]);
    let del_eid_a = insert_event_raw(&conn_a, recorded_by, &del_blob_a);
    project_one(&conn_a, recorded_by, &del_eid_a).unwrap();

    // --- Path B: Deletion first (intent-only), then message (tombstoned) ---
    let conn_b = setup();
    let (signer_b, key_b) = make_identity_chain(&conn_b, recorded_by);
    let (_msg_b, msg_blob_b) = make_message_signed(&key_b, &signer_b, "to delete");
    let msg_eid_b = insert_event_raw(&conn_b, recorded_by, &msg_blob_b);

    let (_del_b, del_blob_b) = make_deletion_signed(&key_b, &signer_b, &msg_eid_b, [2u8; 32]);
    let del_eid_b = insert_event_raw(&conn_b, recorded_by, &del_blob_b);
    let r = project_one(&conn_b, recorded_by, &del_eid_b).unwrap();
    assert_eq!(
        r,
        ProjectionDecision::Valid,
        "deletion writes intent, not blocked"
    );

    project_one(&conn_b, recorded_by, &msg_eid_b).unwrap();

    // --- Compare ---
    assert_eq!(
        count_valid(&conn_a, recorded_by),
        count_valid(&conn_b, recorded_by),
        "valid event counts must match"
    );
    assert_eq!(0, count_blocked(&conn_a, recorded_by));
    assert_eq!(0, count_blocked(&conn_b, recorded_by));

    // Both should have the message marked as deleted
    let del_count_a = count_deleted_messages(&conn_a, recorded_by);
    let del_count_b = count_deleted_messages(&conn_b, recorded_by);
    assert_eq!(del_count_a, del_count_b, "deletion counts must match");
    assert!(del_count_a > 0, "deletion should have been projected");
}

#[test]
fn test_source_isomorphism_reverse_order_replay() {
    // Build a chain: identity → message → reaction → deletion.
    // Insert all events, then project in reverse order.
    // Cascade should unblock everything and converge to the same state
    // as projecting in dependency order.
    let recorded_by = "iso_rev";

    // --- Path A: Forward order (in-order projection) ---
    let conn_a = setup();
    let (signer_a, key_a, chain_a) = build_identity_chain_deferred(recorded_by);
    for (_eid, blob) in &chain_a {
        insert_event_raw(&conn_a, recorded_by, blob);
    }
    for (eid, _blob) in &chain_a {
        project_one(&conn_a, recorded_by, eid).unwrap();
    }

    let (_msg_a, msg_blob_a) = make_message_signed(&key_a, &signer_a, "rev msg");
    let msg_eid_a = insert_event_raw(&conn_a, recorded_by, &msg_blob_a);
    project_one(&conn_a, recorded_by, &msg_eid_a).unwrap();

    let (_rxn_a, rxn_blob_a) = make_reaction_signed(&key_a, &signer_a, &msg_eid_a, "star");
    let rxn_eid_a = insert_event_raw(&conn_a, recorded_by, &rxn_blob_a);
    project_one(&conn_a, recorded_by, &rxn_eid_a).unwrap();

    let (_del_a, del_blob_a) = make_deletion_signed(&key_a, &signer_a, &msg_eid_a, [2u8; 32]);
    let del_eid_a = insert_event_raw(&conn_a, recorded_by, &del_blob_a);
    project_one(&conn_a, recorded_by, &del_eid_a).unwrap();

    // --- Path B: Reverse order ---
    let conn_b = setup();
    let (signer_b, key_b, chain_b) = build_identity_chain_deferred(recorded_by);

    // Insert all identity chain events
    for (_eid, blob) in &chain_b {
        insert_event_raw(&conn_b, recorded_by, blob);
    }

    // Create content events using the same chain
    let (_msg_b, msg_blob_b) = make_message_signed(&key_b, &signer_b, "rev msg");
    let msg_eid_b = insert_event_raw(&conn_b, recorded_by, &msg_blob_b);

    let (_rxn_b, rxn_blob_b) = make_reaction_signed(&key_b, &signer_b, &msg_eid_b, "star");
    let rxn_eid_b = insert_event_raw(&conn_b, recorded_by, &rxn_blob_b);

    let (_del_b, del_blob_b) = make_deletion_signed(&key_b, &signer_b, &msg_eid_b, [2u8; 32]);
    let del_eid_b = insert_event_raw(&conn_b, recorded_by, &del_blob_b);

    // Project in reverse: deletion, reaction, message, then identity chain in reverse
    project_one(&conn_b, recorded_by, &del_eid_b).unwrap();
    project_one(&conn_b, recorded_by, &rxn_eid_b).unwrap();
    project_one(&conn_b, recorded_by, &msg_eid_b).unwrap();
    for (eid, _blob) in chain_b.iter().rev() {
        project_one(&conn_b, recorded_by, eid).unwrap();
    }

    // --- Compare ---
    assert_eq!(
        count_valid(&conn_a, recorded_by),
        count_valid(&conn_b, recorded_by),
        "valid event counts must match between forward and reverse"
    );
    assert_eq!(0, count_blocked(&conn_a, recorded_by));
    assert_eq!(0, count_blocked(&conn_b, recorded_by));
    assert_eq!(
        count_messages(&conn_a, recorded_by),
        count_messages(&conn_b, recorded_by),
        "messages table must match"
    );
    assert_eq!(
        count_reactions(&conn_a, recorded_by),
        count_reactions(&conn_b, recorded_by),
        "reactions table must match"
    );
}

#[test]
fn test_source_isomorphism_multi_event_deep_cascade() {
    // Deeper chain: message → reaction₁ → reaction₂ (reaction to a reaction's event).
    // Actually, reactions depend on target_event_id which is the message.
    // So instead test: message → reaction, message → deletion, all via cascade.
    // Insert all three content events before projecting message.
    // Cascade should unblock both reaction and deletion.
    let recorded_by = "iso_deep";

    // --- Path A: In-order ---
    let conn_a = setup();
    let (signer_a, key_a) = make_identity_chain(&conn_a, recorded_by);

    let (_msg_a, msg_blob_a) = make_message_signed(&key_a, &signer_a, "deep msg");
    let msg_eid_a = insert_event_raw(&conn_a, recorded_by, &msg_blob_a);
    project_one(&conn_a, recorded_by, &msg_eid_a).unwrap();

    let (_rxn_a, rxn_blob_a) = make_reaction_signed(&key_a, &signer_a, &msg_eid_a, "fire");
    let rxn_eid_a = insert_event_raw(&conn_a, recorded_by, &rxn_blob_a);
    project_one(&conn_a, recorded_by, &rxn_eid_a).unwrap();

    let (_del_a, del_blob_a) = make_deletion_signed(&key_a, &signer_a, &msg_eid_a, [2u8; 32]);
    let del_eid_a = insert_event_raw(&conn_a, recorded_by, &del_blob_a);
    project_one(&conn_a, recorded_by, &del_eid_a).unwrap();

    // --- Path B: All content blocked, then single cascade ---
    let conn_b = setup();
    let (signer_b, key_b) = make_identity_chain(&conn_b, recorded_by);

    let (_msg_b, msg_blob_b) = make_message_signed(&key_b, &signer_b, "deep msg");
    let msg_eid_b = insert_event_raw(&conn_b, recorded_by, &msg_blob_b);

    let (_rxn_b, rxn_blob_b) = make_reaction_signed(&key_b, &signer_b, &msg_eid_b, "fire");
    let _rxn_eid_b = insert_event_raw(&conn_b, recorded_by, &rxn_blob_b);

    let (_del_b, del_blob_b) = make_deletion_signed(&key_b, &signer_b, &msg_eid_b, [2u8; 32]);
    let _del_eid_b = insert_event_raw(&conn_b, recorded_by, &del_blob_b);

    // Project reaction and deletion first (both block on message)
    project_one(&conn_b, recorded_by, &_rxn_eid_b).unwrap();
    project_one(&conn_b, recorded_by, &_del_eid_b).unwrap();

    // Project message — should cascade both
    project_one(&conn_b, recorded_by, &msg_eid_b).unwrap();

    // --- Compare ---
    assert_eq!(
        count_valid(&conn_a, recorded_by),
        count_valid(&conn_b, recorded_by),
        "valid event counts must match"
    );
    assert_eq!(0, count_blocked(&conn_a, recorded_by));
    assert_eq!(0, count_blocked(&conn_b, recorded_by));
    assert_eq!(
        count_messages(&conn_a, recorded_by),
        count_messages(&conn_b, recorded_by),
    );
    assert_eq!(
        count_reactions(&conn_a, recorded_by),
        count_reactions(&conn_b, recorded_by),
    );
}

#[test]
fn test_source_isomorphism_encrypted_reaction_three_phase_cascade() {
    // Three-phase cascade: encrypted(reaction) depends on both a secret key
    // and the inner reaction depends on a message. Test all orderings converge.
    //
    // Phase 1: Insert encrypted(reaction), message, key — project encrypted first (blocks on key)
    // Phase 2: Project key (cascades decrypt, but inner blocks on message)
    // Phase 3: Project message (cascades inner reaction → encrypted valid)
    //
    // Compare with direct: key, message, encrypted(reaction) in-order.
    let recorded_by = "iso_enc_rxn";

    let key_bytes: [u8; 32] = rand::random();

    // --- Path A: Direct ---
    let conn_a = setup();
    let (signer_a, signing_key_a) = make_identity_chain(&conn_a, recorded_by);

    // Key
    let (_sk_a, sk_blob_a) = make_key_secret(key_bytes);
    let sk_eid_a = insert_event_raw(&conn_a, recorded_by, &sk_blob_a);
    project_one(&conn_a, recorded_by, &sk_eid_a).unwrap();

    // Message (target for inner reaction)
    let (_msg_a, msg_blob_a) = make_message_signed(&signing_key_a, &signer_a, "enc rxn target");
    let msg_eid_a = insert_event_raw(&conn_a, recorded_by, &msg_blob_a);
    project_one(&conn_a, recorded_by, &msg_eid_a).unwrap();

    // Inner reaction blob
    let (_rxn_a, rxn_blob_a) = make_reaction_signed(&signing_key_a, &signer_a, &msg_eid_a, "heart");
    let (_enc_a, enc_blob_a) =
        make_encrypted_event(&key_bytes, &rxn_blob_a, EVENT_TYPE_REACTION, &sk_eid_a);
    let enc_eid_a = insert_event_raw(&conn_a, recorded_by, &enc_blob_a);
    let r_a = project_one(&conn_a, recorded_by, &enc_eid_a).unwrap();
    assert_eq!(r_a, ProjectionDecision::Valid);

    // --- Path B: Three-phase cascade ---
    let conn_b = setup();
    let (signer_b, signing_key_b) = make_identity_chain(&conn_b, recorded_by);

    // Insert all but don't project content events yet
    let (_sk_b, sk_blob_b) = make_key_secret(key_bytes);
    let sk_eid_b = insert_event_raw(&conn_b, recorded_by, &sk_blob_b);

    let (_msg_b, msg_blob_b) = make_message_signed(&signing_key_b, &signer_b, "enc rxn target");
    let msg_eid_b = insert_event_raw(&conn_b, recorded_by, &msg_blob_b);

    let (_rxn_b, rxn_blob_b) = make_reaction_signed(&signing_key_b, &signer_b, &msg_eid_b, "heart");
    let (_enc_b, enc_blob_b) =
        make_encrypted_event(&key_bytes, &rxn_blob_b, EVENT_TYPE_REACTION, &sk_eid_b);
    let enc_eid_b = insert_event_raw(&conn_b, recorded_by, &enc_blob_b);

    // Phase 1: Project encrypted — blocks on key
    let r1 = project_one(&conn_b, recorded_by, &enc_eid_b).unwrap();
    assert!(matches!(r1, ProjectionDecision::Block { .. }));

    // Phase 2: Project key — encrypted cascades decrypt, but inner blocks on message
    project_one(&conn_b, recorded_by, &sk_eid_b).unwrap();
    let enc_b64 = event_id_to_base64(&enc_eid_b);
    let enc_valid_mid: bool = conn_b
        .query_row(
            "SELECT COUNT(*) > 0 FROM valid_events WHERE peer_id = ?1 AND event_id = ?2",
            rusqlite::params![recorded_by, &enc_b64],
            |row| row.get(0),
        )
        .unwrap();
    assert!(
        !enc_valid_mid,
        "encrypted should NOT be valid mid-cascade (inner dep still missing)"
    );

    // Phase 3: Project message — inner reaction unblocks, encrypted cascades to valid
    project_one(&conn_b, recorded_by, &msg_eid_b).unwrap();

    // --- Compare ---
    assert_eq!(
        count_valid(&conn_a, recorded_by),
        count_valid(&conn_b, recorded_by),
        "valid event counts must match"
    );
    assert_eq!(0, count_blocked(&conn_a, recorded_by));
    assert_eq!(0, count_blocked(&conn_b, recorded_by));
    assert_eq!(
        count_messages(&conn_a, recorded_by),
        count_messages(&conn_b, recorded_by),
    );
    assert_eq!(
        count_reactions(&conn_a, recorded_by),
        count_reactions(&conn_b, recorded_by),
    );
}

#[test]
fn test_source_isomorphism_idempotent_double_projection() {
    // Projecting the same events twice must produce exactly the same state
    // as projecting once. This validates AlreadyProcessed idempotency.
    let recorded_by = "iso_idem";
    let conn = setup();
    let (signer, key) = make_identity_chain(&conn, recorded_by);

    let (_msg, msg_blob) = make_message_signed(&key, &signer, "idempotent");
    let msg_eid = insert_event_raw(&conn, recorded_by, &msg_blob);
    let r1 = project_one(&conn, recorded_by, &msg_eid).unwrap();
    assert_eq!(r1, ProjectionDecision::Valid);

    let valid_after_first = count_valid(&conn, recorded_by);
    let msgs_after_first = count_messages(&conn, recorded_by);

    // Second projection — must return AlreadyProcessed and not change state
    let r2 = project_one(&conn, recorded_by, &msg_eid).unwrap();
    assert_eq!(r2, ProjectionDecision::AlreadyProcessed);

    assert_eq!(
        count_valid(&conn, recorded_by),
        valid_after_first,
        "valid count must not change on re-projection"
    );
    assert_eq!(
        count_messages(&conn, recorded_by),
        msgs_after_first,
        "messages must not change on re-projection"
    );
}
