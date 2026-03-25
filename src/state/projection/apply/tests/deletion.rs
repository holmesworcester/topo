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
