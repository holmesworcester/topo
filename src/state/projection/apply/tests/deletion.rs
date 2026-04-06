use super::*;

// ===== Message deletion helpers =====

/// Convenience: create identity chain + signed deletion.
fn make_deletion(
    conn: &Connection,
    recorded_by: &str,
    target: &EventId,
    author_id: [u8; 32],
) -> (ParsedEvent, Vec<u8>) {
    let (signer_eid, signing_key) = make_identity_chain(conn, recorded_by);
    make_deletion_signed(&signing_key, &signer_eid, target, author_id)
}

#[test]
fn test_project_message_deletion_valid() {
    let conn = setup();
    let recorded_by = "peer1";
    let _net_eid = setup_workspace_event(&conn, recorded_by);

    // Create identity chain once for this tenant
    let (signer_eid, signing_key) = make_identity_chain(&conn, recorded_by);

    // Create and project a message
    let (_msg, msg_blob) = make_message_signed(&signing_key, &signer_eid, "to be deleted");
    let msg_eid = insert_event_raw(&conn, recorded_by, &msg_blob);
    let r = project_one(&conn, recorded_by, &msg_eid).unwrap();
    assert_eq!(r, ProjectionDecision::Valid);

    // Create and project the deletion
    let (_del, del_blob) = make_deletion_signed(&signing_key, &signer_eid, &msg_eid, [2u8; 32]); // author_id matches message
    let del_eid = insert_event_raw(&conn, recorded_by, &del_blob);
    let result = project_one(&conn, recorded_by, &del_eid).unwrap();
    assert_eq!(result, ProjectionDecision::Valid);

    // Message should be removed
    let msg_b64 = event_id_to_base64(&msg_eid);
    let msg_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM messages WHERE recorded_by = ?1 AND message_id = ?2",
            rusqlite::params![recorded_by, &msg_b64],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(msg_count, 0);

    // Tombstone should exist
    let del_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM deleted_messages WHERE recorded_by = ?1 AND message_id = ?2",
            rusqlite::params![recorded_by, &msg_b64],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(del_count, 1);

    // Deletion event should be in valid_events
    let del_b64 = event_id_to_base64(&del_eid);
    let valid: bool = conn
        .query_row(
            "SELECT COUNT(*) > 0 FROM valid_events WHERE peer_id = ?1 AND event_id = ?2",
            rusqlite::params![recorded_by, &del_b64],
            |row| row.get(0),
        )
        .unwrap();
    assert!(valid);
}

#[test]
fn test_deletion_cascades_reactions() {
    let conn = setup();
    let recorded_by = "peer1";
    let _net_eid = setup_workspace_event(&conn, recorded_by);

    // Create identity chain once for this tenant
    let (signer_eid, signing_key) = make_identity_chain(&conn, recorded_by);

    // Create message + 2 reactions
    let (_msg, msg_blob) = make_message_signed(&signing_key, &signer_eid, "with reactions");
    let msg_eid = insert_event_raw(&conn, recorded_by, &msg_blob);
    project_one(&conn, recorded_by, &msg_eid).unwrap();

    let (_rxn1, rxn1_blob) = make_reaction_signed(&signing_key, &signer_eid, &msg_eid, "\u{1f44d}");
    let rxn1_eid = insert_event_raw(&conn, recorded_by, &rxn1_blob);
    project_one(&conn, recorded_by, &rxn1_eid).unwrap();

    let (_rxn2, rxn2_blob) =
        make_reaction_signed(&signing_key, &signer_eid, &msg_eid, "\u{2764}\u{fe0f}");
    let rxn2_eid = insert_event_raw(&conn, recorded_by, &rxn2_blob);
    project_one(&conn, recorded_by, &rxn2_eid).unwrap();

    // Verify 2 reactions exist
    let rxn_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM reactions WHERE recorded_by = ?1",
            rusqlite::params![recorded_by],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(rxn_count, 2);

    // Delete the message
    let (_del, del_blob) = make_deletion_signed(&signing_key, &signer_eid, &msg_eid, [2u8; 32]);
    let del_eid = insert_event_raw(&conn, recorded_by, &del_blob);
    let result = project_one(&conn, recorded_by, &del_eid).unwrap();
    assert_eq!(result, ProjectionDecision::Valid);

    // Reactions should be cascaded away
    let rxn_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM reactions WHERE recorded_by = ?1",
            rusqlite::params![recorded_by],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(rxn_count, 0);

    // Tombstone exists
    let del_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM deleted_messages WHERE recorded_by = ?1",
            rusqlite::params![recorded_by],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(del_count, 1);
}

#[test]
fn test_deletion_intent_only_on_missing_target() {
    let conn = setup();
    let recorded_by = "peer1";

    let fake_target = [77u8; 32];
    let (_del, del_blob) = make_deletion(&conn, recorded_by, &fake_target, [2u8; 32]);
    let del_eid = insert_event_raw(&conn, recorded_by, &del_blob);

    // Deletion no longer dep-blocks on target — writes intent and returns Valid
    let result = project_one(&conn, recorded_by, &del_eid).unwrap();
    assert_eq!(result, ProjectionDecision::Valid);

    // Verify deletion_intent was written
    let target_b64 = event_id_to_base64(&fake_target);
    let intent_count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM deletion_intents WHERE recorded_by = ?1 AND target_kind = 'message' AND target_id = ?2",
        rusqlite::params![recorded_by, &target_b64],
        |row| row.get(0),
    ).unwrap();
    assert_eq!(
        intent_count, 1,
        "deletion_intent must be written for missing target"
    );

    // No tombstone yet (target doesn't exist)
    let tombstone: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM deleted_messages WHERE recorded_by = ?1",
            rusqlite::params![recorded_by],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(tombstone, 0, "no tombstone until target message arrives");
}

#[test]
fn test_deletion_intent_then_target_arrives() {
    let conn = setup();
    let recorded_by = "peer1";
    let _net_eid = setup_workspace_event(&conn, recorded_by);

    // Create identity chain for signing
    let (signer_eid, signing_key) = make_identity_chain(&conn, recorded_by);

    // Pre-compute message blob and eid
    let (_msg, msg_blob) = make_message_signed(&signing_key, &signer_eid, "will arrive later");
    let msg_eid = canonical_test_event_id(&conn, recorded_by, &msg_blob);

    // Create deletion first (before message exists) — writes intent, returns Valid
    let (_del, del_blob) = make_deletion_signed(&signing_key, &signer_eid, &msg_eid, [2u8; 32]);
    let del_eid = insert_event_raw(&conn, recorded_by, &del_blob);
    let result = project_one(&conn, recorded_by, &del_eid).unwrap();
    assert_eq!(
        result,
        ProjectionDecision::Valid,
        "deletion writes intent, not blocked"
    );

    // Deletion is already valid (intent-only)
    let del_b64 = event_id_to_base64(&del_eid);
    let valid: bool = conn
        .query_row(
            "SELECT COUNT(*) > 0 FROM valid_events WHERE peer_id = ?1 AND event_id = ?2",
            rusqlite::params![recorded_by, &del_b64],
            |row| row.get(0),
        )
        .unwrap();
    assert!(valid, "deletion should be valid after intent write");

    // Now insert and project the message — should be tombstoned immediately
    let inserted_msg_eid = insert_event_raw(&conn, recorded_by, &msg_blob);
    assert_eq!(inserted_msg_eid, msg_eid);
    let r = project_one(&conn, recorded_by, &msg_eid).unwrap();
    assert_eq!(r, ProjectionDecision::Valid);

    // Message should be tombstoned (not in messages table)
    let msg_b64 = event_id_to_base64(&msg_eid);
    let msg_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM messages WHERE recorded_by = ?1 AND message_id = ?2",
            rusqlite::params![recorded_by, &msg_b64],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(msg_count, 0);

    let tombstone: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM deleted_messages WHERE recorded_by = ?1 AND message_id = ?2",
            rusqlite::params![recorded_by, &msg_b64],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(tombstone, 1);
}

#[test]
fn test_deletion_wrong_author_rejects() {
    let conn = setup();
    let recorded_by = "peer1";
    let _net_eid = setup_workspace_event(&conn, recorded_by);

    // Create identity chain once for this tenant
    let (signer_eid, signing_key) = make_identity_chain(&conn, recorded_by);

    // Create message with author_id = [2u8; 32]
    let (_msg, msg_blob) = make_message_signed(&signing_key, &signer_eid, "wrong author test");
    let msg_eid = insert_event_raw(&conn, recorded_by, &msg_blob);
    project_one(&conn, recorded_by, &msg_eid).unwrap();

    // Create deletion with different author_id
    let (_del, del_blob) = make_deletion_signed(&signing_key, &signer_eid, &msg_eid, [99u8; 32]); // wrong author
    let del_eid = insert_event_raw(&conn, recorded_by, &del_blob);

    let result = project_one(&conn, recorded_by, &del_eid).unwrap();
    match result {
        ProjectionDecision::Reject { reason } => {
            assert!(
                reason.contains("author") || reason.contains("signer"),
                "reason: {}",
                reason
            );
        }
        other => panic!("expected Reject, got {:?}", other),
    }
}

#[test]
fn test_deletion_idempotent() {
    let conn = setup();
    let recorded_by = "peer1";
    let _net_eid = setup_workspace_event(&conn, recorded_by);

    // Create identity chain for signing
    let (signer_eid, signing_key) = make_identity_chain(&conn, recorded_by);

    // Create and project message
    let (_msg, msg_blob) = make_message_signed(&signing_key, &signer_eid, "delete me twice");
    let msg_eid = insert_event_raw(&conn, recorded_by, &msg_blob);
    project_one(&conn, recorded_by, &msg_eid).unwrap();

    // First deletion
    let (_del1, del1_blob) = make_deletion_signed(&signing_key, &signer_eid, &msg_eid, [2u8; 32]);
    let del1_eid = insert_event_raw(&conn, recorded_by, &del1_blob);
    let r1 = project_one(&conn, recorded_by, &del1_eid).unwrap();
    assert_eq!(r1, ProjectionDecision::Valid);

    // Second deletion (same target, different event) — also signed
    let (_del2, del2_blob) = make_deletion_signed(&signing_key, &signer_eid, &msg_eid, [2u8; 32]);
    let del2_eid = insert_event_raw(&conn, recorded_by, &del2_blob);
    let r2 = project_one(&conn, recorded_by, &del2_eid).unwrap();
    // Second deletion finds tombstone already exists → AlreadyProcessed from projector,
    // which means apply_projection returns AlreadyProcessed, pipeline treats it as Valid
    assert!(
        matches!(
            r2,
            ProjectionDecision::Valid | ProjectionDecision::AlreadyProcessed
        ),
        "expected Valid or AlreadyProcessed, got {:?}",
        r2
    );

    // Only one tombstone
    let del_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM deleted_messages WHERE recorded_by = ?1",
            rusqlite::params![recorded_by],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(del_count, 1);
}

#[test]
fn test_reaction_after_deletion_skipped() {
    let conn = setup();
    let recorded_by = "peer1";
    let _net_eid = setup_workspace_event(&conn, recorded_by);

    // Create identity chain once for this tenant
    let (signer_eid, signing_key) = make_identity_chain(&conn, recorded_by);

    // Create and project message
    let (_msg, msg_blob) = make_message_signed(&signing_key, &signer_eid, "will be deleted");
    let msg_eid = insert_event_raw(&conn, recorded_by, &msg_blob);
    project_one(&conn, recorded_by, &msg_eid).unwrap();

    // Delete message
    let (_del, del_blob) = make_deletion_signed(&signing_key, &signer_eid, &msg_eid, [2u8; 32]);
    let del_eid = insert_event_raw(&conn, recorded_by, &del_blob);
    project_one(&conn, recorded_by, &del_eid).unwrap();

    // Now create a reaction targeting the deleted message
    let (_rxn, rxn_blob) = make_reaction_signed(&signing_key, &signer_eid, &msg_eid, "\u{1f44d}");
    let rxn_eid = insert_event_raw(&conn, recorded_by, &rxn_blob);
    let result = project_one(&conn, recorded_by, &rxn_eid).unwrap();

    // The reaction is structurally valid (target dep exists in valid_events),
    // but project_reaction skips it because the message is deleted
    assert_eq!(result, ProjectionDecision::Valid);

    // No reactions in the table
    let rxn_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM reactions WHERE recorded_by = ?1",
            rusqlite::params![recorded_by],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(rxn_count, 0);
}

#[test]
fn test_deletion_convergence() {
    let conn = setup();
    let recorded_by = "peer1";
    let net_eid = setup_workspace_event(&conn, recorded_by);

    // Create identity chain for signing (used across both orderings)
    let (signer_eid, signing_key) = make_identity_chain(&conn, recorded_by);

    // === Forward order: msg → rxn → del ===
    let (_msg, msg_blob) = make_message_signed(&signing_key, &signer_eid, "convergence test");
    let msg_eid = insert_event_raw(&conn, recorded_by, &msg_blob);
    project_one(&conn, recorded_by, &msg_eid).unwrap();

    let (_rxn, rxn_blob) = make_reaction_signed(&signing_key, &signer_eid, &msg_eid, "\u{1f44d}");
    let rxn_eid = insert_event_raw(&conn, recorded_by, &rxn_blob);
    project_one(&conn, recorded_by, &rxn_eid).unwrap();

    let (_del, del_blob) = make_deletion_signed(&signing_key, &signer_eid, &msg_eid, [2u8; 32]);
    let del_eid = insert_event_raw(&conn, recorded_by, &del_blob);
    project_one(&conn, recorded_by, &del_eid).unwrap();

    // Capture forward state
    let fwd_msg: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM messages WHERE recorded_by = ?1",
            rusqlite::params![recorded_by],
            |row| row.get(0),
        )
        .unwrap();
    let fwd_rxn: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM reactions WHERE recorded_by = ?1",
            rusqlite::params![recorded_by],
            |row| row.get(0),
        )
        .unwrap();
    let fwd_del: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM deleted_messages WHERE recorded_by = ?1",
            rusqlite::params![recorded_by],
            |row| row.get(0),
        )
        .unwrap();

    assert_eq!(fwd_msg, 0, "message should be deleted");
    assert_eq!(fwd_rxn, 0, "reactions should be cascaded");
    assert_eq!(fwd_del, 1, "tombstone should exist");

    // === Reverse order: clear content tables and replay del → rxn → msg ===
    // Only clear the 3 content events from valid_events, keeping identity chain intact
    let msg_b64 = event_id_to_base64(&msg_eid);
    let rxn_b64 = event_id_to_base64(&rxn_eid);
    let del_b64 = event_id_to_base64(&del_eid);
    conn.execute(
        "DELETE FROM messages WHERE recorded_by = ?1",
        rusqlite::params![recorded_by],
    )
    .unwrap();
    conn.execute(
        "DELETE FROM reactions WHERE recorded_by = ?1",
        rusqlite::params![recorded_by],
    )
    .unwrap();
    conn.execute(
        "DELETE FROM deleted_messages WHERE recorded_by = ?1",
        rusqlite::params![recorded_by],
    )
    .unwrap();
    for eid_b64 in [&msg_b64, &rxn_b64, &del_b64] {
        conn.execute(
            "DELETE FROM valid_events WHERE peer_id = ?1 AND event_id = ?2",
            rusqlite::params![recorded_by, eid_b64],
        )
        .unwrap();
    }
    conn.execute(
        "DELETE FROM blocked_event_deps WHERE peer_id = ?1",
        rusqlite::params![recorded_by],
    )
    .unwrap();
    conn.execute(
        "DELETE FROM rejected_events WHERE peer_id = ?1",
        rusqlite::params![recorded_by],
    )
    .unwrap();
    conn.execute(
        "DELETE FROM deletion_intents WHERE recorded_by = ?1",
        rusqlite::params![recorded_by],
    )
    .unwrap();

    // Re-insert workspace event as valid (it was cleared above)
    mark_valid_for_test(&conn, recorded_by, &net_eid, events::EVENT_TYPE_WORKSPACE);

    // Project in reverse order: del first (intent-only), then rxn (dep-blocks on msg), then msg (tombstones + unblocks rxn)
    insert_event_raw(&conn, recorded_by, &msg_blob);
    insert_event_raw(&conn, recorded_by, &rxn_blob);
    insert_event_raw(&conn, recorded_by, &del_blob);
    project_one(&conn, recorded_by, &del_eid).unwrap();
    project_one(&conn, recorded_by, &rxn_eid).unwrap();
    project_one(&conn, recorded_by, &msg_eid).unwrap();

    // Capture reverse state
    let rev_msg: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM messages WHERE recorded_by = ?1",
            rusqlite::params![recorded_by],
            |row| row.get(0),
        )
        .unwrap();
    let rev_rxn: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM reactions WHERE recorded_by = ?1",
            rusqlite::params![recorded_by],
            |row| row.get(0),
        )
        .unwrap();
    let rev_del: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM deleted_messages WHERE recorded_by = ?1",
            rusqlite::params![recorded_by],
            |row| row.get(0),
        )
        .unwrap();

    // Both orders produce the same result
    assert_eq!(
        rev_msg, fwd_msg,
        "message count mismatch: fwd={}, rev={}",
        fwd_msg, rev_msg
    );
    assert_eq!(
        rev_rxn, fwd_rxn,
        "reaction count mismatch: fwd={}, rev={}",
        fwd_rxn, rev_rxn
    );
    assert_eq!(
        rev_del, fwd_del,
        "tombstone count mismatch: fwd={}, rev={}",
        fwd_del, rev_del
    );
}

// ========================================================================
// Deletion invariant tests (per OPTION3 instructions §Deletion invariants)
// ========================================================================

/// Invariant 1: Duplicate delete event replay leaves state unchanged after first application.
#[test]
fn test_deletion_invariant_duplicate_replay_unchanged() {
    let conn = setup();
    let recorded_by = "peer1";
    let _net_eid = setup_workspace_event(&conn, recorded_by);
    let (signer_eid, signing_key) = make_identity_chain(&conn, recorded_by);

    // Create and project message
    let (_msg, msg_blob) = make_message_signed(&signing_key, &signer_eid, "dup delete test");
    let msg_eid = insert_event_raw(&conn, recorded_by, &msg_blob);
    project_one(&conn, recorded_by, &msg_eid).unwrap();

    // Delete once
    let (_del, del_blob) = make_deletion_signed(&signing_key, &signer_eid, &msg_eid, [2u8; 32]);
    let del_eid = insert_event_raw(&conn, recorded_by, &del_blob);
    project_one(&conn, recorded_by, &del_eid).unwrap();

    // Capture state after first deletion
    let tombstone_count_1: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM deleted_messages WHERE recorded_by = ?1",
            rusqlite::params![recorded_by],
            |row| row.get(0),
        )
        .unwrap();
    let intent_count_1: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM deletion_intents WHERE recorded_by = ?1",
            rusqlite::params![recorded_by],
            |row| row.get(0),
        )
        .unwrap();
    let msg_count_1: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM messages WHERE recorded_by = ?1",
            rusqlite::params![recorded_by],
            |row| row.get(0),
        )
        .unwrap();

    // Replay the deletion event (clear its valid status, re-project)
    let del_b64 = event_id_to_base64(&del_eid);
    conn.execute(
        "DELETE FROM valid_events WHERE peer_id = ?1 AND event_id = ?2",
        rusqlite::params![recorded_by, &del_b64],
    )
    .unwrap();
    project_one(&conn, recorded_by, &del_eid).unwrap();

    // State must be identical
    let tombstone_count_2: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM deleted_messages WHERE recorded_by = ?1",
            rusqlite::params![recorded_by],
            |row| row.get(0),
        )
        .unwrap();
    let intent_count_2: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM deletion_intents WHERE recorded_by = ?1",
            rusqlite::params![recorded_by],
            |row| row.get(0),
        )
        .unwrap();
    let msg_count_2: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM messages WHERE recorded_by = ?1",
            rusqlite::params![recorded_by],
            |row| row.get(0),
        )
        .unwrap();

    assert_eq!(
        tombstone_count_1, tombstone_count_2,
        "tombstone count must not change on replay"
    );
    assert_eq!(
        intent_count_1, intent_count_2,
        "intent count must not change on replay"
    );
    assert_eq!(
        msg_count_1, msg_count_2,
        "message count must not change on replay"
    );
}

/// Invariant 2: Delete-before-create converges to same final state as create-before-delete.
/// Validates identical tombstone rows, not just counts.
#[test]
fn test_deletion_invariant_order_convergence_identical_state() {
    let conn = setup();
    let recorded_by = "peer1";
    let _net_eid = setup_workspace_event(&conn, recorded_by);
    let (signer_eid, signing_key) = make_identity_chain(&conn, recorded_by);

    // Pre-compute message and deletion blobs
    let (_msg, msg_blob) = make_message_signed(&signing_key, &signer_eid, "order convergence");
    let msg_eid = canonical_test_event_id(&conn, recorded_by, &msg_blob);
    let (_del, del_blob) = make_deletion_signed(&signing_key, &signer_eid, &msg_eid, [2u8; 32]);
    let del_eid = canonical_test_event_id(&conn, recorded_by, &del_blob);

    // === Order A: create → delete ===
    let inserted_msg_eid = insert_event_raw(&conn, recorded_by, &msg_blob);
    assert_eq!(inserted_msg_eid, msg_eid);
    project_one(&conn, recorded_by, &msg_eid).unwrap();
    let inserted_del_eid = insert_event_raw(&conn, recorded_by, &del_blob);
    assert_eq!(inserted_del_eid, del_eid);
    project_one(&conn, recorded_by, &del_eid).unwrap();

    // Capture state A
    let msg_b64 = event_id_to_base64(&msg_eid);
    let tombstone_a: Option<(String, String)> = conn.query_row(
        "SELECT deletion_event_id, author_id FROM deleted_messages WHERE recorded_by = ?1 AND message_id = ?2",
        rusqlite::params![recorded_by, &msg_b64],
        |row| Ok((row.get(0)?, row.get(1)?)),
    ).ok();
    let msg_count_a: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM messages WHERE recorded_by = ?1 AND message_id = ?2",
            rusqlite::params![recorded_by, &msg_b64],
            |row| row.get(0),
        )
        .unwrap();
    let rxn_count_a: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM reactions WHERE recorded_by = ?1 AND target_event_id = ?2",
            rusqlite::params![recorded_by, &msg_b64],
            |row| row.get(0),
        )
        .unwrap();

    // === Order B: clear and replay delete → create ===
    let del_b64 = event_id_to_base64(&del_eid);
    for eid_b64 in [&msg_b64, &del_b64] {
        conn.execute(
            "DELETE FROM valid_events WHERE peer_id = ?1 AND event_id = ?2",
            rusqlite::params![recorded_by, eid_b64],
        )
        .unwrap();
    }
    conn.execute(
        "DELETE FROM messages WHERE recorded_by = ?1",
        rusqlite::params![recorded_by],
    )
    .unwrap();
    conn.execute(
        "DELETE FROM reactions WHERE recorded_by = ?1",
        rusqlite::params![recorded_by],
    )
    .unwrap();
    conn.execute(
        "DELETE FROM deleted_messages WHERE recorded_by = ?1",
        rusqlite::params![recorded_by],
    )
    .unwrap();
    conn.execute(
        "DELETE FROM deletion_intents WHERE recorded_by = ?1",
        rusqlite::params![recorded_by],
    )
    .unwrap();
    conn.execute(
        "DELETE FROM blocked_event_deps WHERE peer_id = ?1",
        rusqlite::params![recorded_by],
    )
    .unwrap();
    conn.execute(
        "DELETE FROM blocked_events WHERE peer_id = ?1",
        rusqlite::params![recorded_by],
    )
    .unwrap();
    conn.execute(
        "DELETE FROM rejected_events WHERE peer_id = ?1",
        rusqlite::params![recorded_by],
    )
    .unwrap();

    insert_event_raw(&conn, recorded_by, &msg_blob);
    insert_event_raw(&conn, recorded_by, &del_blob);

    // Project in reverse: delete first, then message
    project_one(&conn, recorded_by, &del_eid).unwrap();
    project_one(&conn, recorded_by, &msg_eid).unwrap();

    // Capture state B
    let tombstone_b: Option<(String, String)> = conn.query_row(
        "SELECT deletion_event_id, author_id FROM deleted_messages WHERE recorded_by = ?1 AND message_id = ?2",
        rusqlite::params![recorded_by, &msg_b64],
        |row| Ok((row.get(0)?, row.get(1)?)),
    ).ok();
    let msg_count_b: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM messages WHERE recorded_by = ?1 AND message_id = ?2",
            rusqlite::params![recorded_by, &msg_b64],
            |row| row.get(0),
        )
        .unwrap();
    let rxn_count_b: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM reactions WHERE recorded_by = ?1 AND target_event_id = ?2",
            rusqlite::params![recorded_by, &msg_b64],
            |row| row.get(0),
        )
        .unwrap();

    // Both orders must produce identical final state
    assert_eq!(tombstone_a, tombstone_b, "tombstone rows must be identical");
    assert_eq!(msg_count_a, msg_count_b, "message count must converge");
    assert_eq!(rxn_count_a, rxn_count_b, "reaction count must converge");
    assert_eq!(msg_count_a, 0, "no live messages");
    assert!(tombstone_a.is_some(), "tombstone must exist");
}

/// Invariant 3: Authorization failure paths are deterministic from projected context.
#[test]
fn test_deletion_invariant_auth_deterministic() {
    let conn = setup();
    let recorded_by = "peer1";
    let _net_eid = setup_workspace_event(&conn, recorded_by);
    let (signer_eid, signing_key) = make_identity_chain(&conn, recorded_by);

    // Create message with author_id from signer chain
    let (_msg, msg_blob) = make_message_signed(&signing_key, &signer_eid, "auth test");
    let msg_eid = insert_event_raw(&conn, recorded_by, &msg_blob);
    project_one(&conn, recorded_by, &msg_eid).unwrap();

    // Create deletion with wrong author
    let (_del, del_blob) = make_deletion_signed(&signing_key, &signer_eid, &msg_eid, [99u8; 32]);
    let del_eid = insert_event_raw(&conn, recorded_by, &del_blob);

    // First attempt
    let r1 = project_one(&conn, recorded_by, &del_eid).unwrap();

    // Re-attempt (clear rejection status)
    let del_b64 = event_id_to_base64(&del_eid);
    conn.execute(
        "DELETE FROM rejected_events WHERE peer_id = ?1 AND event_id = ?2",
        rusqlite::params![recorded_by, &del_b64],
    )
    .unwrap();
    let r2 = project_one(&conn, recorded_by, &del_eid).unwrap();

    // Both must produce the same Reject with the same reason
    match (&r1, &r2) {
        (
            ProjectionDecision::Reject { reason: r1_reason },
            ProjectionDecision::Reject { reason: r2_reason },
        ) => {
            assert_eq!(
                r1_reason, r2_reason,
                "rejection reasons must be deterministic"
            );
        }
        _ => panic!("both attempts must reject: r1={:?}, r2={:?}", r1, r2),
    }
}

/// Invariant 5: Cleanup fanout is complete — no live reactions remain for tombstoned message.
#[test]
fn test_deletion_invariant_cleanup_complete() {
    let conn = setup();
    let recorded_by = "peer1";
    let _net_eid = setup_workspace_event(&conn, recorded_by);
    let (signer_eid, signing_key) = make_identity_chain(&conn, recorded_by);

    // Create message with multiple reactions
    let (_msg, msg_blob) = make_message_signed(&signing_key, &signer_eid, "fanout test");
    let msg_eid = insert_event_raw(&conn, recorded_by, &msg_blob);
    project_one(&conn, recorded_by, &msg_eid).unwrap();

    for emoji in ["\u{1f44d}", "\u{2764}\u{fe0f}", "\u{1f525}"] {
        let (_rxn, rxn_blob) = make_reaction_signed(&signing_key, &signer_eid, &msg_eid, emoji);
        let rxn_eid = insert_event_raw(&conn, recorded_by, &rxn_blob);
        project_one(&conn, recorded_by, &rxn_eid).unwrap();
    }

    // Verify 3 reactions exist
    let rxn_pre: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM reactions WHERE recorded_by = ?1",
            rusqlite::params![recorded_by],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(rxn_pre, 3);

    // Delete the message
    let (_del, del_blob) = make_deletion_signed(&signing_key, &signer_eid, &msg_eid, [2u8; 32]);
    let del_eid = insert_event_raw(&conn, recorded_by, &del_blob);
    project_one(&conn, recorded_by, &del_eid).unwrap();

    // No live reactions must remain
    let rxn_post: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM reactions WHERE recorded_by = ?1",
            rusqlite::params![recorded_by],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(rxn_post, 0, "all reactions must be cascaded on delete");

    // No live message must remain
    let msg_b64 = event_id_to_base64(&msg_eid);
    let msg_live: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM messages WHERE recorded_by = ?1 AND message_id = ?2",
            rusqlite::params![recorded_by, &msg_b64],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(msg_live, 0, "no query can surface deleted entity");

    // Tombstone must exist
    let tombstone: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM deleted_messages WHERE recorded_by = ?1",
            rusqlite::params![recorded_by],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(tombstone, 1);
}

/// Invariant 6: Command execution idempotence — deletion_intent identities are stable.
/// Re-running the deletion projector does not mutate final state.
#[test]
fn test_deletion_invariant_command_idempotence() {
    let conn = setup();
    let recorded_by = "peer1";
    let _net_eid = setup_workspace_event(&conn, recorded_by);
    let (signer_eid, signing_key) = make_identity_chain(&conn, recorded_by);

    // Create and project message
    let (_msg, msg_blob) = make_message_signed(&signing_key, &signer_eid, "idempotent cmds");
    let msg_eid = insert_event_raw(&conn, recorded_by, &msg_blob);
    project_one(&conn, recorded_by, &msg_eid).unwrap();

    // Delete
    let (_del, del_blob) = make_deletion_signed(&signing_key, &signer_eid, &msg_eid, [2u8; 32]);
    let del_eid = insert_event_raw(&conn, recorded_by, &del_blob);
    project_one(&conn, recorded_by, &del_eid).unwrap();

    // Capture deletion_intent identity
    let intent_1: (String, String) = conn.query_row(
        "SELECT deletion_event_id, author_id FROM deletion_intents WHERE recorded_by = ?1 AND target_kind = 'message'",
        rusqlite::params![recorded_by],
        |row| Ok((row.get(0)?, row.get(1)?)),
    ).unwrap();

    // Re-run by clearing valid status and re-projecting
    let del_b64 = event_id_to_base64(&del_eid);
    conn.execute(
        "DELETE FROM valid_events WHERE peer_id = ?1 AND event_id = ?2",
        rusqlite::params![recorded_by, &del_b64],
    )
    .unwrap();
    project_one(&conn, recorded_by, &del_eid).unwrap();

    // Intent identity must be stable (same event_id, same author)
    let intent_2: (String, String) = conn.query_row(
        "SELECT deletion_event_id, author_id FROM deletion_intents WHERE recorded_by = ?1 AND target_kind = 'message'",
        rusqlite::params![recorded_by],
        |row| Ok((row.get(0)?, row.get(1)?)),
    ).unwrap();

    assert_eq!(
        intent_1, intent_2,
        "deletion_intent identity must be stable across re-execution"
    );

    // Only one intent row
    let intent_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM deletion_intents WHERE recorded_by = ?1",
            rusqlite::params![recorded_by],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(intent_count, 1, "no duplicate intents from re-execution");
}

/// Invariant: Deletion state is monotonic — tombstoned → active is forbidden.
/// Once a message has a deletion_intent, it cannot be "un-deleted" even if
/// the message event arrives after the deletion.
#[test]
fn test_deletion_invariant_monotonic() {
    let conn = setup();
    let recorded_by = "peer1";
    let _net_eid = setup_workspace_event(&conn, recorded_by);
    let (signer_eid, signing_key) = make_identity_chain(&conn, recorded_by);

    // Pre-compute message
    let (_msg, msg_blob) = make_message_signed(&signing_key, &signer_eid, "monotonic test");
    let msg_eid = canonical_test_event_id(&conn, recorded_by, &msg_blob);

    // Delete first (intent-only)
    let (_del, del_blob) = make_deletion_signed(&signing_key, &signer_eid, &msg_eid, [2u8; 32]);
    let del_eid = insert_event_raw(&conn, recorded_by, &del_blob);
    project_one(&conn, recorded_by, &del_eid).unwrap();

    // Insert message — should be tombstoned immediately
    let inserted_msg_eid = insert_event_raw(&conn, recorded_by, &msg_blob);
    assert_eq!(inserted_msg_eid, msg_eid);
    project_one(&conn, recorded_by, &msg_eid).unwrap();

    // Message must NOT be in messages table (active state)
    let msg_b64 = event_id_to_base64(&msg_eid);
    let msg_active: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM messages WHERE recorded_by = ?1 AND message_id = ?2",
            rusqlite::params![recorded_by, &msg_b64],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        msg_active, 0,
        "tombstoned message must not appear in active state"
    );

    // Tombstone must exist
    let tombstone: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM deleted_messages WHERE recorded_by = ?1 AND message_id = ?2",
            rusqlite::params![recorded_by, &msg_b64],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        tombstone, 1,
        "tombstone must exist for delete-before-create"
    );
}

#[test]
fn test_hard_purge_removes_message_graph_and_auxiliary_rows() {
    let conn = setup();
    let recorded_by = "peer-hard-purge";
    let _workspace_eid = setup_workspace_event(&conn, recorded_by);
    let (signer_eid, signing_key) = make_identity_chain(&conn, recorded_by);
    let key_event_id = ensure_test_content_key(&conn, recorded_by);

    let (_msg, msg_blob) = make_message_signed(&signing_key, &signer_eid, "purge graph");
    let msg_eid = insert_event_raw(&conn, recorded_by, &msg_blob);
    project_one(&conn, recorded_by, &msg_eid).unwrap();

    let (_rxn, rxn_blob) = make_reaction_signed(&signing_key, &signer_eid, &msg_eid, "🔥");
    let rxn_eid = insert_event_raw(&conn, recorded_by, &rxn_blob);
    project_one(&conn, recorded_by, &rxn_eid).unwrap();

    let (file_event, file_blob) =
        make_attachment_signed(&signing_key, &signer_eid, &msg_eid, &key_event_id);
    let file_id = match &file_event {
        ParsedEvent::File(file) => file.file_id,
        other => panic!("expected file event, got {:?}", other),
    };
    let file_eid = insert_event_raw(&conn, recorded_by, &file_blob);
    project_one(&conn, recorded_by, &file_eid).unwrap();

    let (_slice, slice_blob) = make_file_slice(&signing_key, &signer_eid, file_id, 0, b"slice-0");
    let slice_eid = insert_event_raw(&conn, recorded_by, &slice_blob);
    project_one(&conn, recorded_by, &slice_eid).unwrap();

    let msg_b64 = event_id_to_base64(&msg_eid);
    let rxn_b64 = event_id_to_base64(&rxn_eid);
    let file_b64 = event_id_to_base64(&file_eid);
    let slice_b64 = event_id_to_base64(&slice_eid);
    let file_id_b64 = event_id_to_base64(&file_id);

    crate::db::local_client_ops::insert(&conn, recorded_by, "op-msg", &msg_eid, "send", 10)
        .unwrap();
    crate::db::local_client_ops::insert(&conn, recorded_by, "op-rxn", &rxn_eid, "react", 11)
        .unwrap();
    crate::db::local_client_ops::insert(&conn, recorded_by, "op-file", &file_eid, "send-file", 12)
        .unwrap();
    crate::db::local_client_ops::insert(
        &conn,
        recorded_by,
        "op-slice",
        &slice_eid,
        "file-slice",
        13,
    )
    .unwrap();

    conn.execute(
        "INSERT INTO local_subscription_state
         (recorded_by, subscription_id, next_seq, pending_count, dirty, latest_event_id, latest_created_at_ms, updated_at_ms)
         VALUES (?1, 'purge-sub', 5, 4, 1, ?2, 99, 99)",
        rusqlite::params![recorded_by, &slice_b64],
    )
    .unwrap();
    for (seq, event_type, event_id) in [
        (1_i64, "message", msg_b64.clone()),
        (2_i64, "reaction", rxn_b64.clone()),
        (3_i64, "file", file_b64.clone()),
        (4_i64, "file_slice", slice_b64.clone()),
    ] {
        conn.execute(
            "INSERT INTO local_subscription_feed
             (recorded_by, subscription_id, seq, event_type, event_id, created_at_ms, payload_json, emitted_at_ms)
             VALUES (?1, 'purge-sub', ?2, ?3, ?4, 1, '{}', 1)",
            rusqlite::params![recorded_by, seq, event_type, event_id],
        )
        .unwrap();
    }

    for event_id in [&msg_eid, &rxn_eid, &file_eid, &slice_eid] {
        conn.execute(
            "INSERT INTO pending_shared_fanouts (origin_peer_id, workspace_id, event_id)
             VALUES (?1, '', ?2)",
            rusqlite::params![recorded_by, &event_id[..]],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO deferred_need_events (peer_id, id, first_seen_at)
             VALUES (?1, ?2, 1)",
            rusqlite::params![recorded_by, &event_id[..]],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO sync_run_rx_events (run_id, event_id) VALUES (1, ?1)",
            rusqlite::params![event_id_to_base64(event_id)],
        )
        .unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO event_timeline
             (event_id, first_received_at, first_stored_at, blocked_at, unblocked_at, unblocked_by_event_id, projected_at)
             VALUES (?1, 1, 1, NULL, NULL, NULL, 1)",
            rusqlite::params![event_id_to_base64(event_id)],
        )
        .unwrap();
    }
    conn.execute(
        "INSERT INTO event_timeline
         (event_id, first_received_at, first_stored_at, blocked_at, unblocked_at, unblocked_by_event_id, projected_at)
         VALUES ('other-event', 1, 1, NULL, NULL, ?1, NULL)",
        rusqlite::params![&msg_b64],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO blocked_event_deps (peer_id, event_id, blocker_event_id)
         VALUES (?1, ?2, ?3)",
        rusqlite::params![recorded_by, &rxn_b64, &msg_b64],
    )
    .unwrap();

    let (_del, del_blob) = make_deletion_signed(&signing_key, &signer_eid, &msg_eid, [2u8; 32]);
    let del_eid = insert_event_raw(&conn, recorded_by, &del_blob);
    let del_b64 = event_id_to_base64(&del_eid);
    assert_eq!(
        project_one(&conn, recorded_by, &del_eid).unwrap(),
        ProjectionDecision::Valid
    );

    let deleted_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM deleted_messages WHERE recorded_by = ?1 AND message_id = ?2",
            rusqlite::params![recorded_by, &msg_b64],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(deleted_count, 1, "tombstone must remain after purge");

    let intent_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM deletion_intents
             WHERE recorded_by = ?1 AND target_kind = 'message' AND target_id = ?2",
            rusqlite::params![recorded_by, &msg_b64],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(intent_count, 1, "deletion intent must remain after purge");

    let deletion_valid: bool = conn
        .query_row(
            "SELECT COUNT(*) > 0 FROM valid_events WHERE peer_id = ?1 AND event_id = ?2",
            rusqlite::params![recorded_by, &del_b64],
            |row| row.get(0),
        )
        .unwrap();
    assert!(deletion_valid, "deletion event itself must remain valid");

    for event_id in [&msg_b64, &rxn_b64, &file_b64, &slice_b64] {
        let still_recorded: bool = conn
            .query_row(
                "SELECT COUNT(*) > 0 FROM recorded_events WHERE peer_id = ?1 AND event_id = ?2",
                rusqlite::params![recorded_by, event_id],
                |row| row.get(0),
            )
            .unwrap();
        assert!(
            !still_recorded,
            "hard purge must remove recorded event {}",
            event_id
        );

        let still_valid: bool = conn
            .query_row(
                "SELECT COUNT(*) > 0 FROM valid_events WHERE peer_id = ?1 AND event_id = ?2",
                rusqlite::params![recorded_by, event_id],
                |row| row.get(0),
            )
            .unwrap();
        assert!(
            !still_valid,
            "hard purge must remove valid row {}",
            event_id
        );

        let still_global: bool = conn
            .query_row(
                "SELECT COUNT(*) > 0 FROM events WHERE event_id = ?1",
                rusqlite::params![event_id],
                |row| row.get(0),
            )
            .unwrap();
        assert!(
            !still_global,
            "hard purge must remove event blob {}",
            event_id
        );

        let still_timeline: bool = conn
            .query_row(
                "SELECT COUNT(*) > 0 FROM event_timeline WHERE event_id = ?1",
                rusqlite::params![event_id],
                |row| row.get(0),
            )
            .unwrap();
        assert!(
            !still_timeline,
            "hard purge must remove event_timeline row {}",
            event_id
        );
    }

    let message_rows: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM messages WHERE recorded_by = ?1 AND message_id = ?2",
            rusqlite::params![recorded_by, &msg_b64],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(message_rows, 0);

    let reaction_rows: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM reactions WHERE recorded_by = ?1 AND target_event_id = ?2",
            rusqlite::params![recorded_by, &msg_b64],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(reaction_rows, 0);

    let file_rows: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM files WHERE recorded_by = ?1 AND message_id = ?2",
            rusqlite::params![recorded_by, &msg_b64],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(file_rows, 0);

    let slice_rows: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM file_slices WHERE recorded_by = ?1 AND file_id = ?2",
            rusqlite::params![recorded_by, &file_id_b64],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(slice_rows, 0);

    let client_ops_left: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM local_client_ops WHERE recorded_by = ?1",
            rusqlite::params![recorded_by],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(client_ops_left, 0, "purge must remove client-op mappings");

    let feed_rows_left: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM local_subscription_feed WHERE recorded_by = ?1",
            rusqlite::params![recorded_by],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        feed_rows_left, 0,
        "purge must remove subscription feed rows"
    );

    let sub_state: (i64, i64, i64, String) = conn
        .query_row(
            "SELECT next_seq, pending_count, dirty, latest_event_id
             FROM local_subscription_state
             WHERE recorded_by = ?1 AND subscription_id = 'purge-sub'",
            rusqlite::params![recorded_by],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .unwrap();
    assert_eq!(sub_state.0, 5, "purge must not rewind next_seq");
    assert_eq!(sub_state.1, 0, "purge must clear pending_count");
    assert_eq!(sub_state.2, 0, "purge must clear dirty when feed empties");
    assert_eq!(sub_state.3, "", "purge must clear latest_event_id");

    let shared_fanouts_left: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM pending_shared_fanouts WHERE origin_peer_id = ?1",
            rusqlite::params![recorded_by],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(shared_fanouts_left, 0);

    let deferred_need_left: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM deferred_need_events WHERE peer_id = ?1",
            rusqlite::params![recorded_by],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(deferred_need_left, 0);

    let sync_rx_left: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM sync_run_rx_events WHERE event_id IN (?1, ?2, ?3, ?4)",
            rusqlite::params![&msg_b64, &rxn_b64, &file_b64, &slice_b64],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(sync_rx_left, 0);

    let other_unblocked_by: Option<String> = conn
        .query_row(
            "SELECT unblocked_by_event_id FROM event_timeline WHERE event_id = 'other-event'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        other_unblocked_by, None,
        "purge must clear dangling unblocked_by_event_id references"
    );
}

#[test]
fn test_delete_before_create_hard_purges_arriving_message_event() {
    let conn = setup();
    let recorded_by = "peer-delete-before-create";
    let _workspace_eid = setup_workspace_event(&conn, recorded_by);
    let (signer_eid, signing_key) = make_identity_chain(&conn, recorded_by);

    let (_msg, msg_blob) = make_message_signed(&signing_key, &signer_eid, "arrives after delete");
    let msg_eid = canonical_test_event_id(&conn, recorded_by, &msg_blob);
    let msg_b64 = event_id_to_base64(&msg_eid);

    let (_del, del_blob) = make_deletion_signed(&signing_key, &signer_eid, &msg_eid, [2u8; 32]);
    let del_eid = insert_event_raw(&conn, recorded_by, &del_blob);
    project_one(&conn, recorded_by, &del_eid).unwrap();

    let inserted_msg_eid = insert_event_raw(&conn, recorded_by, &msg_blob);
    assert_eq!(inserted_msg_eid, msg_eid);
    assert_eq!(
        project_one(&conn, recorded_by, &msg_eid).unwrap(),
        ProjectionDecision::Valid
    );

    let message_still_recorded: bool = conn
        .query_row(
            "SELECT COUNT(*) > 0 FROM recorded_events WHERE peer_id = ?1 AND event_id = ?2",
            rusqlite::params![recorded_by, &msg_b64],
            |row| row.get(0),
        )
        .unwrap();
    assert!(
        !message_still_recorded,
        "message arriving after tombstone must be purged from recorded_events"
    );

    let message_valid: bool = conn
        .query_row(
            "SELECT COUNT(*) > 0 FROM valid_events WHERE peer_id = ?1 AND event_id = ?2",
            rusqlite::params![recorded_by, &msg_b64],
            |row| row.get(0),
        )
        .unwrap();
    assert!(
        !message_valid,
        "hard-purged message must not be left in valid_events"
    );

    let message_global: bool = conn
        .query_row(
            "SELECT COUNT(*) > 0 FROM events WHERE event_id = ?1",
            rusqlite::params![&msg_b64],
            |row| row.get(0),
        )
        .unwrap();
    assert!(!message_global, "hard-purged message blob must be removed");

    let tombstone_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM deleted_messages WHERE recorded_by = ?1 AND message_id = ?2",
            rusqlite::params![recorded_by, &msg_b64],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        tombstone_count, 1,
        "tombstone must remain for purged message"
    );
}

#[test]
fn test_replaying_deletion_on_existing_tombstone_repurges_legacy_material() {
    let conn = setup();
    let recorded_by = "peer-legacy-cleanup";
    let _workspace_eid = setup_workspace_event(&conn, recorded_by);
    let (signer_eid, signing_key) = make_identity_chain(&conn, recorded_by);

    let (_msg, msg_blob) = make_message_signed(&signing_key, &signer_eid, "legacy leftovers");
    let msg_eid = insert_event_raw(&conn, recorded_by, &msg_blob);
    project_one(&conn, recorded_by, &msg_eid).unwrap();

    let (_rxn, rxn_blob) = make_reaction_signed(&signing_key, &signer_eid, &msg_eid, "🧹");
    let rxn_eid = insert_event_raw(&conn, recorded_by, &rxn_blob);
    project_one(&conn, recorded_by, &rxn_eid).unwrap();

    let msg_b64 = event_id_to_base64(&msg_eid);
    let rxn_b64 = event_id_to_base64(&rxn_eid);
    let legacy_del_b64 = event_id_to_base64(&[0xD1; 32]);
    let author_b64 = event_id_to_base64(&user_for_signer(&signer_eid));

    conn.execute(
        "INSERT INTO deleted_messages
         (recorded_by, message_id, deletion_event_id, author_id, deleted_at)
         VALUES (?1, ?2, ?3, ?4, 1)",
        rusqlite::params![recorded_by, &msg_b64, &legacy_del_b64, &author_b64],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO deletion_intents
         (recorded_by, target_kind, target_id, deletion_event_id, author_id, created_at)
         VALUES (?1, 'message', ?2, ?3, ?4, 1)",
        rusqlite::params![recorded_by, &msg_b64, &legacy_del_b64, &author_b64],
    )
    .unwrap();

    let (_del, del_blob) = make_deletion_signed(&signing_key, &signer_eid, &msg_eid, [2u8; 32]);
    let del_eid = insert_event_raw(&conn, recorded_by, &del_blob);
    project_one(&conn, recorded_by, &del_eid).unwrap();

    let msg_left: bool = conn
        .query_row(
            "SELECT COUNT(*) > 0 FROM recorded_events WHERE peer_id = ?1 AND event_id = ?2",
            rusqlite::params![recorded_by, &msg_b64],
            |row| row.get(0),
        )
        .unwrap();
    assert!(
        !msg_left,
        "replayed deletion must purge legacy message event"
    );

    let rxn_left: bool = conn
        .query_row(
            "SELECT COUNT(*) > 0 FROM recorded_events WHERE peer_id = ?1 AND event_id = ?2",
            rusqlite::params![recorded_by, &rxn_b64],
            |row| row.get(0),
        )
        .unwrap();
    assert!(
        !rxn_left,
        "replayed deletion must purge legacy dependent event"
    );

    let tombstone_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM deleted_messages WHERE recorded_by = ?1 AND message_id = ?2",
            rusqlite::params![recorded_by, &msg_b64],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(tombstone_count, 1, "legacy tombstone must remain stable");
}

#[test]
fn test_reaction_arriving_after_tombstone_is_hard_purged() {
    let conn = setup();
    let recorded_by = "peer-late-reaction";
    let _workspace_eid = setup_workspace_event(&conn, recorded_by);
    let (signer_eid, signing_key) = make_identity_chain(&conn, recorded_by);

    let (_msg, msg_blob) = make_message_signed(&signing_key, &signer_eid, "target");
    let msg_eid = insert_event_raw(&conn, recorded_by, &msg_blob);
    project_one(&conn, recorded_by, &msg_eid).unwrap();

    let (_del, del_blob) = make_deletion_signed(&signing_key, &signer_eid, &msg_eid, [2u8; 32]);
    let del_eid = insert_event_raw(&conn, recorded_by, &del_blob);
    project_one(&conn, recorded_by, &del_eid).unwrap();

    let (_rxn, rxn_blob) = make_reaction_signed(&signing_key, &signer_eid, &msg_eid, "❌");
    let rxn_eid = insert_event_raw(&conn, recorded_by, &rxn_blob);
    let rxn_b64 = event_id_to_base64(&rxn_eid);
    assert_eq!(
        project_one(&conn, recorded_by, &rxn_eid).unwrap(),
        ProjectionDecision::Valid
    );

    let rxn_recorded: bool = conn
        .query_row(
            "SELECT COUNT(*) > 0 FROM recorded_events WHERE peer_id = ?1 AND event_id = ?2",
            rusqlite::params![recorded_by, &rxn_b64],
            |row| row.get(0),
        )
        .unwrap();
    assert!(!rxn_recorded, "late reaction must be hard-purged");

    let rxn_valid: bool = conn
        .query_row(
            "SELECT COUNT(*) > 0 FROM valid_events WHERE peer_id = ?1 AND event_id = ?2",
            rusqlite::params![recorded_by, &rxn_b64],
            |row| row.get(0),
        )
        .unwrap();
    assert!(!rxn_valid, "late reaction must not survive in valid_events");

    let rxn_global: bool = conn
        .query_row(
            "SELECT COUNT(*) > 0 FROM events WHERE event_id = ?1",
            rusqlite::params![&rxn_b64],
            |row| row.get(0),
        )
        .unwrap();
    assert!(!rxn_global, "late reaction blob must be purged");
}

#[test]
fn test_file_arriving_after_tombstone_is_hard_purged() {
    let conn = setup();
    let recorded_by = "peer-late-file";
    let _workspace_eid = setup_workspace_event(&conn, recorded_by);
    let (signer_eid, signing_key) = make_identity_chain(&conn, recorded_by);
    let key_event_id = ensure_test_content_key(&conn, recorded_by);

    let (_msg, msg_blob) = make_message_signed(&signing_key, &signer_eid, "target");
    let msg_eid = insert_event_raw(&conn, recorded_by, &msg_blob);
    project_one(&conn, recorded_by, &msg_eid).unwrap();

    let (_del, del_blob) = make_deletion_signed(&signing_key, &signer_eid, &msg_eid, [2u8; 32]);
    let del_eid = insert_event_raw(&conn, recorded_by, &del_blob);
    project_one(&conn, recorded_by, &del_eid).unwrap();

    let (_file_event, file_blob) =
        make_attachment_signed(&signing_key, &signer_eid, &msg_eid, &key_event_id);
    let file_eid = insert_event_raw(&conn, recorded_by, &file_blob);
    let file_b64 = event_id_to_base64(&file_eid);
    assert_eq!(
        project_one(&conn, recorded_by, &file_eid).unwrap(),
        ProjectionDecision::Valid
    );

    let file_recorded: bool = conn
        .query_row(
            "SELECT COUNT(*) > 0 FROM recorded_events WHERE peer_id = ?1 AND event_id = ?2",
            rusqlite::params![recorded_by, &file_b64],
            |row| row.get(0),
        )
        .unwrap();
    assert!(!file_recorded, "late file must be hard-purged");

    let file_valid: bool = conn
        .query_row(
            "SELECT COUNT(*) > 0 FROM valid_events WHERE peer_id = ?1 AND event_id = ?2",
            rusqlite::params![recorded_by, &file_b64],
            |row| row.get(0),
        )
        .unwrap();
    assert!(!file_valid, "late file must not survive in valid_events");

    let file_global: bool = conn
        .query_row(
            "SELECT COUNT(*) > 0 FROM events WHERE event_id = ?1",
            rusqlite::params![&file_b64],
            |row| row.get(0),
        )
        .unwrap();
    assert!(!file_global, "late file blob must be purged");
}

#[test]
fn test_file_slice_dependents_of_deleted_message_are_hard_purged_by_owner() {
    let conn = setup();
    let recorded_by = "peer-late-file-slice";
    let _workspace_eid = setup_workspace_event(&conn, recorded_by);
    let (signer_eid, signing_key) = make_identity_chain(&conn, recorded_by);
    let key_event_id = ensure_test_content_key(&conn, recorded_by);

    let (_msg, msg_blob) = make_message_signed(&signing_key, &signer_eid, "target");
    let msg_eid = insert_event_raw(&conn, recorded_by, &msg_blob);
    project_one(&conn, recorded_by, &msg_eid).unwrap();

    let (_del, del_blob) = make_deletion_signed(&signing_key, &signer_eid, &msg_eid, [2u8; 32]);
    let del_eid = insert_event_raw(&conn, recorded_by, &del_blob);
    project_one(&conn, recorded_by, &del_eid).unwrap();

    let (file_event, file_blob) =
        make_attachment_signed(&signing_key, &signer_eid, &msg_eid, &key_event_id);
    let file_id = match &file_event {
        ParsedEvent::File(file) => file.file_id,
        other => panic!("expected file event, got {:?}", other),
    };
    let file_id_b64 = event_id_to_base64(&file_id);

    let (_early_slice, early_slice_blob) = make_file_slice_with_owner(
        &signing_key,
        &signer_eid,
        &msg_eid,
        file_id,
        0,
        b"slice-before-file",
    );
    let early_slice_eid = insert_event_raw(&conn, recorded_by, &early_slice_blob);
    assert_eq!(
        project_one(&conn, recorded_by, &early_slice_eid).unwrap(),
        ProjectionDecision::Valid
    );
    let early_slice_b64 = event_id_to_base64(&early_slice_eid);

    let dep_blocked_before: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM blocked_event_deps WHERE peer_id = ?1 AND blocker_event_id = ?2",
            rusqlite::params![recorded_by, &file_id_b64],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        dep_blocked_before, 0,
        "owner-tombstoned slice should purge immediately instead of blocking on file_id"
    );

    let file_eid = insert_event_raw(&conn, recorded_by, &file_blob);
    let file_b64 = event_id_to_base64(&file_eid);
    assert_eq!(
        project_one(&conn, recorded_by, &file_eid).unwrap(),
        ProjectionDecision::Valid
    );

    for event_id in [&file_b64, &early_slice_b64] {
        let still_recorded: bool = conn
            .query_row(
                "SELECT COUNT(*) > 0 FROM recorded_events WHERE peer_id = ?1 AND event_id = ?2",
                rusqlite::params![recorded_by, event_id],
                |row| row.get(0),
            )
            .unwrap();
        assert!(
            !still_recorded,
            "deleted-message dependent {} must be purged from recorded_events",
            event_id
        );

        let still_valid: bool = conn
            .query_row(
                "SELECT COUNT(*) > 0 FROM valid_events WHERE peer_id = ?1 AND event_id = ?2",
                rusqlite::params![recorded_by, event_id],
                |row| row.get(0),
            )
            .unwrap();
        assert!(
            !still_valid,
            "deleted-message dependent {} must not survive in valid_events",
            event_id
        );

        let still_global: bool = conn
            .query_row(
                "SELECT COUNT(*) > 0 FROM events WHERE event_id = ?1",
                rusqlite::params![event_id],
                |row| row.get(0),
            )
            .unwrap();
        assert!(
            !still_global,
            "deleted-message dependent {} must be purged from events",
            event_id
        );
    }

    let (_late_slice, late_slice_blob) = make_file_slice_with_owner(
        &signing_key,
        &signer_eid,
        &msg_eid,
        file_id,
        1,
        b"slice-after-file",
    );
    let late_slice_eid = insert_event_raw(&conn, recorded_by, &late_slice_blob);
    let late_slice_b64 = event_id_to_base64(&late_slice_eid);
    assert_eq!(
        project_one(&conn, recorded_by, &late_slice_eid).unwrap(),
        ProjectionDecision::Valid
    );

    let late_slice_recorded: bool = conn
        .query_row(
            "SELECT COUNT(*) > 0 FROM recorded_events WHERE peer_id = ?1 AND event_id = ?2",
            rusqlite::params![recorded_by, &late_slice_b64],
            |row| row.get(0),
        )
        .unwrap();
    assert!(
        !late_slice_recorded,
        "late file_slice owned by a deleted message must be hard-purged"
    );

    let late_slice_valid: bool = conn
        .query_row(
            "SELECT COUNT(*) > 0 FROM valid_events WHERE peer_id = ?1 AND event_id = ?2",
            rusqlite::params![recorded_by, &late_slice_b64],
            |row| row.get(0),
        )
        .unwrap();
    assert!(
        !late_slice_valid,
        "late file_slice owned by a deleted message must not survive in valid_events"
    );

    let late_slice_global: bool = conn
        .query_row(
            "SELECT COUNT(*) > 0 FROM events WHERE event_id = ?1",
            rusqlite::params![&late_slice_b64],
            |row| row.get(0),
        )
        .unwrap();
    assert!(
        !late_slice_global,
        "late file_slice owned by a deleted message must be purged from events"
    );
}

#[test]
fn test_hard_purge_failure_rolls_back_and_retries_from_project_queue() {
    let conn = setup();
    let recorded_by = "peer-purge-retry";
    let _workspace_eid = setup_workspace_event(&conn, recorded_by);
    let (signer_eid, signing_key) = make_identity_chain(&conn, recorded_by);

    let (_msg, msg_blob) = make_message_signed(&signing_key, &signer_eid, "retry purge");
    let msg_eid = insert_event_raw(&conn, recorded_by, &msg_blob);
    project_one(&conn, recorded_by, &msg_eid).unwrap();

    let (_rxn, rxn_blob) = make_reaction_signed(&signing_key, &signer_eid, &msg_eid, "↩");
    let rxn_eid = insert_event_raw(&conn, recorded_by, &rxn_blob);
    project_one(&conn, recorded_by, &rxn_eid).unwrap();

    let (_del, del_blob) = make_deletion_signed(&signing_key, &signer_eid, &msg_eid, [2u8; 32]);
    let del_eid = insert_event_raw(&conn, recorded_by, &del_blob);
    let del_b64 = event_id_to_base64(&del_eid);
    let msg_b64 = event_id_to_base64(&msg_eid);
    let rxn_b64 = event_id_to_base64(&rxn_eid);

    let pq = crate::state::db::project_queue::ProjectQueue::new(&conn);
    pq.enqueue(recorded_by, &del_b64).unwrap();

    crate::state::projection::purge::set_test_fail_after_steps(Some(2));
    let drained = pq
        .drain_with_limit(recorded_by, 1, |db, event_id_b64| {
            let event_id =
                crate::crypto::event_id_from_base64(event_id_b64).expect("decode queued event id");
            project_one(db, recorded_by, &event_id).map(|_| ())
        })
        .unwrap();
    crate::state::projection::purge::set_test_fail_after_steps(None);
    assert_eq!(drained, 0, "failed purge must not count as a success");

    let message_still_present: bool = conn
        .query_row(
            "SELECT COUNT(*) > 0 FROM recorded_events WHERE peer_id = ?1 AND event_id = ?2",
            rusqlite::params![recorded_by, &msg_b64],
            |row| row.get(0),
        )
        .unwrap();
    assert!(
        message_still_present,
        "failed purge must roll back message removal"
    );

    let reaction_still_present: bool = conn
        .query_row(
            "SELECT COUNT(*) > 0 FROM recorded_events WHERE peer_id = ?1 AND event_id = ?2",
            rusqlite::params![recorded_by, &rxn_b64],
            |row| row.get(0),
        )
        .unwrap();
    assert!(
        reaction_still_present,
        "failed purge must roll back dependent removal"
    );

    let tombstone_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM deleted_messages WHERE recorded_by = ?1 AND message_id = ?2",
            rusqlite::params![recorded_by, &msg_b64],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        tombstone_count, 0,
        "failed purge must roll back tombstone write"
    );

    let deletion_valid: bool = conn
        .query_row(
            "SELECT COUNT(*) > 0 FROM valid_events WHERE peer_id = ?1 AND event_id = ?2",
            rusqlite::params![recorded_by, &del_b64],
            |row| row.get(0),
        )
        .unwrap();
    assert!(
        !deletion_valid,
        "failed purge must roll back deletion event terminal state"
    );

    let attempts: i64 = conn
        .query_row(
            "SELECT attempts FROM project_queue WHERE peer_id = ?1 AND event_id = ?2",
            rusqlite::params![recorded_by, &del_b64],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(attempts, 1, "failed purge must schedule a retry");

    conn.execute(
        "UPDATE project_queue SET available_at = 0, lease_until = NULL WHERE peer_id = ?1 AND event_id = ?2",
        rusqlite::params![recorded_by, &del_b64],
    )
    .unwrap();

    let drained = pq
        .drain_with_limit(recorded_by, 1, |db, event_id_b64| {
            let event_id =
                crate::crypto::event_id_from_base64(event_id_b64).expect("decode queued event id");
            project_one(db, recorded_by, &event_id).map(|_| ())
        })
        .unwrap();
    assert_eq!(
        drained, 1,
        "retry should succeed once purge no longer fails"
    );

    let message_left: bool = conn
        .query_row(
            "SELECT COUNT(*) > 0 FROM recorded_events WHERE peer_id = ?1 AND event_id = ?2",
            rusqlite::params![recorded_by, &msg_b64],
            |row| row.get(0),
        )
        .unwrap();
    assert!(!message_left, "successful retry must purge message");

    let reaction_left: bool = conn
        .query_row(
            "SELECT COUNT(*) > 0 FROM recorded_events WHERE peer_id = ?1 AND event_id = ?2",
            rusqlite::params![recorded_by, &rxn_b64],
            |row| row.get(0),
        )
        .unwrap();
    assert!(!reaction_left, "successful retry must purge dependent");

    let queue_left: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM project_queue WHERE peer_id = ?1 AND event_id = ?2",
            rusqlite::params![recorded_by, &del_b64],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(queue_left, 0, "successful retry must dequeue the deletion");
}
