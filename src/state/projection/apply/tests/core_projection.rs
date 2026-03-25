use super::*;

#[test]
fn key_shared_does_not_block_non_recipient_observers_on_local_invite_secret() {
    let conn = open_in_memory().unwrap();
    create_tables(&conn).unwrap();
    let recorded_by = "observer-tenant";
    let (signer_eid, signer_key, chain_blobs) = build_identity_chain_deferred(recorded_by);
    insert_and_project_identity_chain(&conn, recorded_by, &chain_blobs);

    let recipient_event_id: EventId = conn
        .query_row(
            "SELECT event_id FROM user_invites WHERE recorded_by = ?1 LIMIT 1",
            rusqlite::params![recorded_by],
            |row| row.get(0),
        )
        .map(|eid_b64: String| event_id_from_base64(&eid_b64).expect("valid user_invite event id"))
        .unwrap();
    let key_shared = ParsedEvent::KeyShared(KeySharedEvent {
        created_at_ms: now_ms(),
        key_event_id: [0x44; 32],
        recipient_event_id,
        // This is recipient-local invite_secret material; the observer tenant
        // does not have it and should still be able to validate/project the
        // shared key wrapper row without blocking.
        unwrap_key_event_id: [0x55; 32],
        wrapped_key: [0x66; 32],
        signed_by: signer_eid,
        signer_type: 5,
        signature: [0u8; 64],
    });
    let mut blob = events::encode_event(&key_shared).unwrap();
    sign_blob(&signer_key, &mut blob);
    let key_shared_eid = insert_event_raw(&conn, recorded_by, &blob);

    let decision = project_one(&conn, recorded_by, &key_shared_eid).unwrap();
    assert_eq!(decision, ProjectionDecision::Valid);

    let key_shared_b64 = event_id_to_base64(&key_shared_eid);
    let blocked: bool = conn
        .query_row(
            "SELECT COUNT(*) > 0 FROM blocked_events WHERE peer_id = ?1 AND event_id = ?2",
            rusqlite::params![recorded_by, &key_shared_b64],
            |row| row.get(0),
        )
        .unwrap();
    assert!(
        !blocked,
        "non-recipient observers must not block on recipient-local invite_secret"
    );

    let projected: bool = conn
        .query_row(
            "SELECT COUNT(*) > 0 FROM key_shared WHERE recorded_by = ?1 AND event_id = ?2",
            rusqlite::params![recorded_by, &key_shared_b64],
            |row| row.get(0),
        )
        .unwrap();
    assert!(
        projected,
        "key_shared row should still project for observers"
    );

    let emitted_key_secret: bool = conn
        .query_row(
            "SELECT COUNT(*) > 0 FROM key_secrets WHERE recorded_by = ?1",
            rusqlite::params![recorded_by],
            |row| row.get(0),
        )
        .unwrap();
    assert!(
        !emitted_key_secret,
        "observer without local invite_secret must not derive key material"
    );
}

#[test]
fn test_project_message_valid() {
    let conn = setup();
    let recorded_by = "peer1";
    let (_msg, blob) = make_message(&conn, recorded_by, "hello");
    let eid = insert_event_raw(&conn, recorded_by, &blob);

    let result = project_one(&conn, recorded_by, &eid).unwrap();
    assert_eq!(result, ProjectionDecision::Valid);

    // Verify in messages table
    let eid_b64 = event_id_to_base64(&eid);
    let count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM messages WHERE message_id = ?1 AND recorded_by = ?2",
            rusqlite::params![&eid_b64, recorded_by],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(count, 1);

    // Verify in valid_events
    let valid: bool = conn
        .query_row(
            "SELECT COUNT(*) > 0 FROM valid_events WHERE peer_id = ?1 AND event_id = ?2",
            rusqlite::params![recorded_by, &eid_b64],
            |row| row.get(0),
        )
        .unwrap();
    assert!(valid);
}

#[test]
fn test_project_reaction_valid() {
    let conn = setup();
    let recorded_by = "peer1";
    let _net_eid = setup_workspace_event(&conn, recorded_by);

    // Create identity chain once for this tenant
    let (signer_eid, signing_key) = make_identity_chain(&conn, recorded_by);

    // Create target message first
    let (_msg, msg_blob) = make_message_signed(&signing_key, &signer_eid, "target");
    let msg_eid = insert_event_raw(&conn, recorded_by, &msg_blob);
    project_one(&conn, recorded_by, &msg_eid).unwrap();

    // Create reaction targeting it
    let (_rxn, rxn_blob) = make_reaction_signed(&signing_key, &signer_eid, &msg_eid, "\u{1f44d}");
    let rxn_eid = insert_event_raw(&conn, recorded_by, &rxn_blob);

    let result = project_one(&conn, recorded_by, &rxn_eid).unwrap();
    assert_eq!(result, ProjectionDecision::Valid);

    let rxn_b64 = event_id_to_base64(&rxn_eid);
    let count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM reactions WHERE event_id = ?1 AND recorded_by = ?2",
            rusqlite::params![&rxn_b64, recorded_by],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(count, 1);
}

#[test]
fn test_project_reaction_blocked() {
    let conn = setup();
    let recorded_by = "peer1";

    // Create reaction with a target that doesn't exist
    let fake_target = [99u8; 32];
    let (_rxn, rxn_blob) = make_reaction(&conn, recorded_by, &fake_target, "\u{1f44d}");
    let rxn_eid = insert_event_raw(&conn, recorded_by, &rxn_blob);

    let result = project_one(&conn, recorded_by, &rxn_eid).unwrap();
    match result {
        ProjectionDecision::Block { missing } => {
            // May block on fake_target (and possibly signed_by dep)
            assert!(missing.contains(&fake_target));
        }
        other => panic!("expected Block, got {:?}", other),
    }

    // Verify in blocked_event_deps
    let count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM blocked_event_deps WHERE peer_id = ?1",
            rusqlite::params![recorded_by],
            |row| row.get(0),
        )
        .unwrap();
    assert!(count >= 1);

    // Verify NOT in valid_events
    let rxn_b64 = event_id_to_base64(&rxn_eid);
    let valid: bool = conn
        .query_row(
            "SELECT COUNT(*) > 0 FROM valid_events WHERE peer_id = ?1 AND event_id = ?2",
            rusqlite::params![recorded_by, &rxn_b64],
            |row| row.get(0),
        )
        .unwrap();
    assert!(!valid);
}

#[test]
fn test_project_unblock_cascade() {
    let conn = setup();
    let recorded_by = "peer1";
    let _net_eid = setup_workspace_event(&conn, recorded_by);

    // Create identity chain for signing
    let (signer_eid, signing_key) = make_identity_chain(&conn, recorded_by);

    // Create message blob but don't insert yet
    let (_msg, msg_blob) = make_message_signed(&signing_key, &signer_eid, "target");
    let msg_eid = canonical_test_event_id(&conn, recorded_by, &msg_blob);

    // Create reaction targeting it — insert reaction first (out of order)
    let (_rxn, rxn_blob) =
        make_reaction_signed(&signing_key, &signer_eid, &msg_eid, "\u{2764}\u{fe0f}");
    let rxn_eid = insert_event_raw(&conn, recorded_by, &rxn_blob);

    // Project reaction — should block
    let result = project_one(&conn, recorded_by, &rxn_eid).unwrap();
    assert!(matches!(result, ProjectionDecision::Block { .. }));

    // Now insert and project the message
    let msg_eid2 = insert_event_raw(&conn, recorded_by, &msg_blob);
    assert_eq!(msg_eid, msg_eid2);
    let result = project_one(&conn, recorded_by, &msg_eid).unwrap();
    assert_eq!(result, ProjectionDecision::Valid);

    // Reaction should have been auto-unblocked
    let rxn_b64 = event_id_to_base64(&rxn_eid);
    let valid: bool = conn
        .query_row(
            "SELECT COUNT(*) > 0 FROM valid_events WHERE peer_id = ?1 AND event_id = ?2",
            rusqlite::params![recorded_by, &rxn_b64],
            |row| row.get(0),
        )
        .unwrap();
    assert!(
        valid,
        "reaction should be auto-projected after target arrives"
    );

    // No remaining blocked deps
    let blocked: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM blocked_event_deps WHERE peer_id = ?1",
            rusqlite::params![recorded_by],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(blocked, 0);

    let timeline = EventTimeline::new(&conn);
    let row = timeline.load(&rxn_b64).unwrap().unwrap();
    let msg_b64 = event_id_to_base64(&msg_eid);
    assert!(
        row.blocked_at.is_some(),
        "reaction should record blocked_at"
    );
    assert!(
        row.unblocked_at.is_some(),
        "reaction should record unblocked_at"
    );
    assert_eq!(
        row.unblocked_by_event_id.as_deref(),
        Some(msg_b64.as_str()),
        "reaction should record the final unblocking dependency",
    );
}

#[test]
fn test_duplicate_dep_ids_unblock_correctly() {
    // Regression: if an event has the same dep_id in multiple dep fields,
    // deps_remaining must reflect the unique blocker count, not the raw
    // vec length, or the event gets permanently stuck.
    let conn = setup();
    let recorded_by = "peer1";

    // E_root: no deps
    let root = ParsedEvent::BenchDep(BenchDepEvent {
        created_at_ms: now_ms(),
        dep_ids: vec![],
        payload: [0xAA; 16],
    });
    let root_blob = events::encode_event(&root).unwrap();
    let root_eid = hash_event(&root_blob);

    // E_dup: depends on E_root TWICE (duplicate dep IDs)
    let dup = ParsedEvent::BenchDep(BenchDepEvent {
        created_at_ms: now_ms(),
        dep_ids: vec![root_eid, root_eid],
        payload: [0xBB; 16],
    });
    let dup_blob = events::encode_event(&dup).unwrap();
    let dup_eid = hash_event(&dup_blob);

    // Insert both, project E_dup first (out of order) — should block
    insert_event_raw(&conn, recorded_by, &root_blob);
    insert_event_raw(&conn, recorded_by, &dup_blob);
    let result = project_one(&conn, recorded_by, &dup_eid).unwrap();
    assert!(matches!(result, ProjectionDecision::Block { .. }));

    // deps_remaining must be 1 (unique), not 2 (raw)
    let dup_b64 = event_id_to_base64(&dup_eid);
    let deps_remaining: i64 = conn
        .query_row(
            "SELECT deps_remaining FROM blocked_events WHERE peer_id = ?1 AND event_id = ?2",
            rusqlite::params![recorded_by, &dup_b64],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        deps_remaining, 1,
        "deps_remaining should be unique blocker count"
    );

    // Now project E_root — cascade should unblock E_dup
    let result = project_one(&conn, recorded_by, &root_eid).unwrap();
    assert_eq!(result, ProjectionDecision::Valid);

    let valid: bool = conn
        .query_row(
            "SELECT COUNT(*) > 0 FROM valid_events WHERE peer_id = ?1 AND event_id = ?2",
            rusqlite::params![recorded_by, &dup_b64],
            |row| row.get(0),
        )
        .unwrap();
    assert!(
        valid,
        "event with duplicate deps should be unblocked after blocker resolves"
    );

    // No stuck blocked_events rows
    let stuck: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM blocked_events WHERE peer_id = ?1",
            rusqlite::params![recorded_by],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(stuck, 0);
}

#[test]
fn test_already_processed() {
    let conn = setup();
    let recorded_by = "peer1";
    let (_msg, blob) = make_message(&conn, recorded_by, "hello");
    let eid = insert_event_raw(&conn, recorded_by, &blob);

    let r1 = project_one(&conn, recorded_by, &eid).unwrap();
    assert_eq!(r1, ProjectionDecision::Valid);

    let r2 = project_one(&conn, recorded_by, &eid).unwrap();
    assert_eq!(r2, ProjectionDecision::AlreadyProcessed);
}

#[test]
fn test_multi_blocker() {
    let conn = setup();
    let recorded_by = "peer1";
    let _net_eid = setup_workspace_event(&conn, recorded_by);

    // Create identity chain for signing
    let (signer_eid, signing_key) = make_identity_chain(&conn, recorded_by);

    // Create two messages (targets) — pre-compute hashes
    let (_msg1, msg1_blob) = make_message_signed(&signing_key, &signer_eid, "target1");
    let msg1_eid = canonical_test_event_id(&conn, recorded_by, &msg1_blob);
    let (_msg2, msg2_blob) = make_message_signed(&signing_key, &signer_eid, "target2");
    let msg2_eid = canonical_test_event_id(&conn, recorded_by, &msg2_blob);

    // Create reaction targeting msg1 — insert without msg1 in events
    let (_rxn1, rxn1_blob) =
        make_reaction_signed(&signing_key, &signer_eid, &msg1_eid, "\u{1f44d}");
    let rxn1_eid = insert_event_raw(&conn, recorded_by, &rxn1_blob);

    // Create reaction targeting msg2 — insert without msg2 in events
    let (_rxn2, rxn2_blob) =
        make_reaction_signed(&signing_key, &signer_eid, &msg2_eid, "\u{2764}\u{fe0f}");
    let rxn2_eid = insert_event_raw(&conn, recorded_by, &rxn2_blob);

    // Both should block
    assert!(matches!(
        project_one(&conn, recorded_by, &rxn1_eid).unwrap(),
        ProjectionDecision::Block { .. }
    ));
    assert!(matches!(
        project_one(&conn, recorded_by, &rxn2_eid).unwrap(),
        ProjectionDecision::Block { .. }
    ));

    // Insert msg1 — rxn1 unblocks, rxn2 stays blocked
    let msg1_inserted = insert_event_raw(&conn, recorded_by, &msg1_blob);
    assert_eq!(msg1_inserted, msg1_eid);
    project_one(&conn, recorded_by, &msg1_eid).unwrap();

    let rxn1_b64 = event_id_to_base64(&rxn1_eid);
    let rxn2_b64 = event_id_to_base64(&rxn2_eid);
    let r1_valid: bool = conn
        .query_row(
            "SELECT COUNT(*) > 0 FROM valid_events WHERE peer_id = ?1 AND event_id = ?2",
            rusqlite::params![recorded_by, &rxn1_b64],
            |row| row.get(0),
        )
        .unwrap();
    assert!(r1_valid);

    let r2_valid: bool = conn
        .query_row(
            "SELECT COUNT(*) > 0 FROM valid_events WHERE peer_id = ?1 AND event_id = ?2",
            rusqlite::params![recorded_by, &rxn2_b64],
            |row| row.get(0),
        )
        .unwrap();
    assert!(!r2_valid);

    // Insert msg2 — rxn2 unblocks
    let msg2_inserted = insert_event_raw(&conn, recorded_by, &msg2_blob);
    assert_eq!(msg2_inserted, msg2_eid);
    project_one(&conn, recorded_by, &msg2_eid).unwrap();

    let r2_valid2: bool = conn
        .query_row(
            "SELECT COUNT(*) > 0 FROM valid_events WHERE peer_id = ?1 AND event_id = ?2",
            rusqlite::params![recorded_by, &rxn2_b64],
            |row| row.get(0),
        )
        .unwrap();
    assert!(r2_valid2);
}

#[test]
fn test_retired_type3_peer_key_blob_rejected() {
    let conn = setup();
    let recorded_by = "peer1";
    // Retired type-3 peer_key wire format: [type=3][created_at][public_key]
    let mut blob = Vec::with_capacity(41);
    blob.push(3);
    blob.extend_from_slice(&now_ms().to_le_bytes());
    blob.extend_from_slice(&[42u8; 32]);
    let eid = insert_event_raw(&conn, recorded_by, &blob);

    let result = project_one(&conn, recorded_by, &eid).unwrap();
    match result {
        ProjectionDecision::Reject { reason } => {
            assert!(
                reason.contains("unknown event type: 3"),
                "reason: {}",
                reason
            );
        }
        other => panic!("expected Reject, got {:?}", other),
    }
}
