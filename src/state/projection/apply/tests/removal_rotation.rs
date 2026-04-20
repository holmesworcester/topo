use super::*;
use crate::crypto::{event_id_from_base64, hash_event};
use crate::event_modules::key_rotation::{KeyRotationEvent, KEY_ROTATION_CAP};
use crate::event_modules::removal::{frontier_hash_from_refs, RemovalEvent};

fn make_signed_removal(
    signing_key: &SigningKey,
    signer_eid: &EventId,
    removed_member_ref: [u8; 32],
    parents: &[[u8; 32]],
    frontier_hash_override: Option<[u8; 32]>,
) -> (ParsedEvent, Vec<u8>) {
    assert!(
        parents.len() <= 4,
        "test helper supports up to 4 frontier refs"
    );
    let mut slots = [[0u8; 32]; 4];
    for (slot, parent) in slots.iter_mut().zip(parents.iter()) {
        *slot = *parent;
    }
    let event = ParsedEvent::Removal(RemovalEvent {
        created_at_ms: now_ms(),
        removed_member_ref,
        parent_count: parents.len() as u8,
        parent_1: slots[0],
        parent_2: slots[1],
        parent_3: slots[2],
        parent_4: slots[3],
        frontier_hash: frontier_hash_override.unwrap_or_else(|| frontier_hash_from_refs(parents)),
        removed_by: *signer_eid,
    });
    let blob = sign_blob(signing_key, signer_eid, &event);
    let parsed = events::parse_event(&blob).unwrap();
    (parsed, blob)
}

fn make_signed_key_rotation(
    signing_key: &SigningKey,
    signer_eid: &EventId,
    frontier: &[[u8; 32]],
    frontier_hash_override: Option<[u8; 32]>,
) -> (ParsedEvent, Vec<u8>) {
    assert!(
        frontier.len() <= 4,
        "test helper supports up to 4 frontier refs"
    );
    let mut slots = [[0u8; 32]; 4];
    for (slot, parent) in slots.iter_mut().zip(frontier.iter()) {
        *slot = *parent;
    }
    let event = ParsedEvent::KeyRotation(KeyRotationEvent {
        created_at_ms: now_ms(),
        frontier_count: frontier.len() as u8,
        frontier_ref_1: slots[0],
        frontier_ref_2: slots[1],
        frontier_ref_3: slots[2],
        frontier_ref_4: slots[3],
        frontier_hash: frontier_hash_override.unwrap_or_else(|| frontier_hash_from_refs(frontier)),
        rotated_by: *signer_eid,
        recipient_slots: vec![[0u8; 32]; KEY_ROTATION_CAP],
        wrapped_keys: vec![[0u8; 32]; KEY_ROTATION_CAP],
    });
    let blob = sign_blob(signing_key, signer_eid, &event);
    let parsed = events::parse_event(&blob).unwrap();
    (parsed, blob)
}

fn seed_admin_for_signer(conn: &Connection, recorded_by: &str, signer_eid: &EventId) {
    let signer_b64 = event_id_to_base64(signer_eid);
    let public_key: Vec<u8> = conn
        .query_row(
            "SELECT u.public_key
             FROM peers_shared ps
             JOIN users u
               ON u.recorded_by = ps.recorded_by
              AND u.event_id = ps.user_event_id
             WHERE ps.recorded_by = ?1
               AND ps.event_id = ?2",
            rusqlite::params![recorded_by, &signer_b64],
            |row| crate::db::sql_types::get_blob(row, 0),
        )
        .unwrap();
    let admin_eid = event_id_to_base64(&hash_event(signer_b64.as_bytes()));
    conn.execute(
        "INSERT OR IGNORE INTO admins (recorded_by, event_id, public_key)
         VALUES (?1, ?2, ?3)",
        rusqlite::params![recorded_by, &admin_eid, &public_key],
    )
    .unwrap();
}

fn local_user_for_signer(conn: &Connection, recorded_by: &str, signer_eid: &EventId) -> EventId {
    let signer_b64 = event_id_to_base64(signer_eid);
    let user_b64: String = conn
        .query_row(
            "SELECT user_event_id
             FROM peers_shared
             WHERE recorded_by = ?1
               AND event_id = ?2",
            rusqlite::params![recorded_by, &signer_b64],
            |row| crate::db::sql_types::get_text(row, 0),
        )
        .unwrap();
    event_id_from_base64(&user_b64).expect("peer_shared.user_event_id")
}

#[test]
fn test_removal_projects_and_rejects_bad_frontier_hash() {
    let conn = setup();
    let recorded_by = "peer1";
    let (signer_eid, signing_key, chain_blobs) = build_identity_chain_deferred(recorded_by);
    insert_and_project_identity_chain(&conn, recorded_by, &chain_blobs);
    seed_admin_for_signer(&conn, recorded_by, &signer_eid);

    let (_valid_removal, valid_blob) =
        make_signed_removal(&signing_key, &signer_eid, signer_eid, &[], None);
    let valid_eid = insert_event_raw(&conn, recorded_by, &valid_blob);
    let result = project_one(&conn, recorded_by, &valid_eid).unwrap();
    assert_eq!(result, ProjectionDecision::Valid);

    let valid_b64 = event_id_to_base64(&valid_eid);
    let projected: bool = conn
        .query_row(
            "SELECT COUNT(*) > 0 FROM removals WHERE recorded_by = ?1 AND event_id = ?2",
            rusqlite::params![recorded_by, &valid_b64],
            |row| row.get(0),
        )
        .unwrap();
    assert!(projected, "valid removal should project");

    let (_bad_removal, bad_blob) =
        make_signed_removal(&signing_key, &signer_eid, signer_eid, &[], Some([0x99; 32]));
    let bad_eid = insert_event_raw(&conn, recorded_by, &bad_blob);
    let result = project_one(&conn, recorded_by, &bad_eid).unwrap();
    match result {
        ProjectionDecision::Reject { reason } => {
            assert!(
                reason.contains("frontier_hash does not match parent frontier"),
                "unexpected reject reason: {reason}"
            );
        }
        other => panic!("expected Reject, got {other:?}"),
    }
}

#[test]
fn test_removal_blocks_on_missing_removed_member_ref() {
    let conn = setup();
    let recorded_by = "peer1";
    let (signer_eid, signing_key, chain_blobs) = build_identity_chain_deferred(recorded_by);
    insert_and_project_identity_chain(&conn, recorded_by, &chain_blobs);
    seed_admin_for_signer(&conn, recorded_by, &signer_eid);

    let (_removal, blob) = make_signed_removal(&signing_key, &signer_eid, [0x44; 32], &[], None);
    let event_id = insert_event_raw(&conn, recorded_by, &blob);
    let result = project_one(&conn, recorded_by, &event_id).unwrap();
    match result {
        ProjectionDecision::BlockOnMissingDeps { missing } => {
            assert!(
                missing.contains(&[0x44; 32]),
                "expected missing removed_member_ref dep, got {missing:?}"
            );
        }
        other => panic!("expected BlockOnMissingDeps, got {other:?}"),
    }
}

#[test]
fn test_removal_projects_removed_entities_for_user_target() {
    let conn = setup();
    let recorded_by = "peer1";
    let (signer_eid, signing_key, chain_blobs) = build_identity_chain_deferred(recorded_by);
    insert_and_project_identity_chain(&conn, recorded_by, &chain_blobs);
    seed_admin_for_signer(&conn, recorded_by, &signer_eid);

    let removed_user_b64: String = conn
        .query_row(
            "SELECT event_id FROM users WHERE recorded_by = ?1 ORDER BY event_id ASC LIMIT 1",
            rusqlite::params![recorded_by],
            |row| crate::db::sql_types::get_text(row, 0),
        )
        .unwrap();
    let removed_user_eid = event_id_from_base64(&removed_user_b64).expect("user event id");

    let (_removal, blob) =
        make_signed_removal(&signing_key, &signer_eid, removed_user_eid, &[], None);
    let event_id = insert_event_raw(&conn, recorded_by, &blob);
    assert_eq!(
        project_one(&conn, recorded_by, &event_id).unwrap(),
        ProjectionDecision::Valid
    );

    let event_id_b64 = event_id_to_base64(&event_id);
    let wrote_removed_entity: bool = conn
        .query_row(
            "SELECT COUNT(*) > 0
             FROM removed_entities
             WHERE recorded_by = ?1
               AND event_id = ?2
               AND target_event_id = ?3
               AND removal_type = 'user'",
            rusqlite::params![recorded_by, &event_id_b64, &removed_user_b64],
            |row| row.get(0),
        )
        .unwrap();
    assert!(
        wrote_removed_entity,
        "valid removal should materialize removed_entities for transport/runtime enforcement"
    );
}

#[test]
fn test_key_rotation_projects_root_frontier_and_rejects_bad_hash() {
    let conn = setup();
    let recorded_by = "peer1";
    let (signer_eid, signing_key, chain_blobs) = build_identity_chain_deferred(recorded_by);
    insert_and_project_identity_chain(&conn, recorded_by, &chain_blobs);
    seed_admin_for_signer(&conn, recorded_by, &signer_eid);

    let (_valid_rotation, valid_blob) =
        make_signed_key_rotation(&signing_key, &signer_eid, &[], None);
    let valid_eid = insert_event_raw(&conn, recorded_by, &valid_blob);
    let result = project_one(&conn, recorded_by, &valid_eid).unwrap();
    assert_eq!(result, ProjectionDecision::Valid);

    let valid_b64 = event_id_to_base64(&valid_eid);
    let projected: bool = conn
        .query_row(
            "SELECT COUNT(*) > 0 FROM key_rotations WHERE recorded_by = ?1 AND event_id = ?2",
            rusqlite::params![recorded_by, &valid_b64],
            |row| row.get(0),
        )
        .unwrap();
    assert!(projected, "root-frontier rotation should project");

    let (_bad_rotation, bad_blob) =
        make_signed_key_rotation(&signing_key, &signer_eid, &[], Some([0xAB; 32]));
    let bad_eid = insert_event_raw(&conn, recorded_by, &bad_blob);
    let result = project_one(&conn, recorded_by, &bad_eid).unwrap();
    match result {
        ProjectionDecision::Reject { reason } => {
            assert!(
                reason.contains("frontier_hash does not match frontier refs"),
                "unexpected reject reason: {reason}"
            );
        }
        other => panic!("expected Reject, got {other:?}"),
    }
}

#[test]
fn test_key_rotation_blocks_on_missing_frontier_then_projects_and_rejects_bad_hash() {
    let conn = setup();
    let recorded_by = "peer1";
    let (signer_eid, signing_key, chain_blobs) = build_identity_chain_deferred(recorded_by);
    insert_and_project_identity_chain(&conn, recorded_by, &chain_blobs);
    seed_admin_for_signer(&conn, recorded_by, &signer_eid);

    let (_frontier_removal, frontier_blob) =
        make_signed_removal(&signing_key, &signer_eid, signer_eid, &[], None);
    let frontier_eid = canonical_test_event_id(&conn, recorded_by, &frontier_blob);
    let (_blocked_rotation, blocked_blob) =
        make_signed_key_rotation(&signing_key, &signer_eid, &[frontier_eid], None);
    let blocked_eid = insert_event_raw(&conn, recorded_by, &blocked_blob);
    let result = project_one(&conn, recorded_by, &blocked_eid).unwrap();
    match result {
        ProjectionDecision::BlockOnMissingDeps { missing } => {
            assert!(
                missing.contains(&frontier_eid),
                "expected missing frontier dep, got {missing:?}"
            );
        }
        other => panic!("expected Block, got {other:?}"),
    }

    let inserted_frontier_eid = insert_event_raw(&conn, recorded_by, &frontier_blob);
    assert_eq!(inserted_frontier_eid, frontier_eid);
    let result = project_one(&conn, recorded_by, &frontier_eid).unwrap();
    assert_eq!(result, ProjectionDecision::Valid);

    let blocked_b64 = event_id_to_base64(&blocked_eid);
    let projected: bool = conn
        .query_row(
            "SELECT COUNT(*) > 0 FROM key_rotations WHERE recorded_by = ?1 AND event_id = ?2",
            rusqlite::params![recorded_by, &blocked_b64],
            |row| row.get(0),
        )
        .unwrap();
    assert!(
        projected,
        "rotation should auto-project once frontier arrives"
    );

    let (_bad_rotation, bad_blob) = make_signed_key_rotation(
        &signing_key,
        &signer_eid,
        &[frontier_eid],
        Some([0xAB; 32]),
    );
    let bad_eid = insert_event_raw(&conn, recorded_by, &bad_blob);
    let result = project_one(&conn, recorded_by, &bad_eid).unwrap();
    match result {
        ProjectionDecision::Reject { reason } => {
            assert!(
                reason.contains("frontier_hash does not match frontier refs"),
                "unexpected reject reason: {reason}"
            );
        }
        other => panic!("expected Reject, got {other:?}"),
    }
}

#[test]
fn test_concurrent_multi_parent_frontier_hash_converges_despite_parent_order() {
    let conn = setup();
    let recorded_by = "peer1";
    let (signer_eid, signing_key, chain_blobs) = build_identity_chain_deferred(recorded_by);
    insert_and_project_identity_chain(&conn, recorded_by, &chain_blobs);
    seed_admin_for_signer(&conn, recorded_by, &signer_eid);
    let signer_user_eid = local_user_for_signer(&conn, recorded_by, &signer_eid);

    let (_left_parent, left_blob) =
        make_signed_removal(&signing_key, &signer_eid, signer_eid, &[], None);
    let left_eid = insert_event_raw(&conn, recorded_by, &left_blob);
    assert_eq!(
        project_one(&conn, recorded_by, &left_eid).unwrap(),
        ProjectionDecision::Valid
    );

    let (_right_parent, right_blob) =
        make_signed_removal(&signing_key, &signer_eid, signer_user_eid, &[], None);
    let right_eid = insert_event_raw(&conn, recorded_by, &right_blob);
    assert_eq!(
        project_one(&conn, recorded_by, &right_eid).unwrap(),
        ProjectionDecision::Valid
    );

    let canonical_frontier = if left_eid <= right_eid {
        vec![left_eid, right_eid]
    } else {
        vec![right_eid, left_eid]
    };
    let frontier_hash = frontier_hash_from_refs(&canonical_frontier);

    let (_merge_left_right, merge_left_right_blob) = make_signed_removal(
        &signing_key,
        &signer_eid,
        signer_eid,
        &canonical_frontier,
        Some(frontier_hash),
    );
    let merge_left_right_eid = insert_event_raw(&conn, recorded_by, &merge_left_right_blob);
    assert_eq!(
        project_one(&conn, recorded_by, &merge_left_right_eid).unwrap(),
        ProjectionDecision::Valid
    );

    let (_merge_right_left, merge_right_left_blob) = make_signed_removal(
        &signing_key,
        &signer_eid,
        signer_user_eid,
        &canonical_frontier,
        Some(frontier_hash),
    );
    let merge_right_left_eid = insert_event_raw(&conn, recorded_by, &merge_right_left_blob);
    assert_eq!(
        project_one(&conn, recorded_by, &merge_right_left_eid).unwrap(),
        ProjectionDecision::Valid
    );

    let merge_left_right_b64 = event_id_to_base64(&merge_left_right_eid);
    let merge_right_left_b64 = event_id_to_base64(&merge_right_left_eid);

    let stored_left_right: String = conn
        .query_row(
            "SELECT frontier_hash FROM removals WHERE recorded_by = ?1 AND event_id = ?2",
            rusqlite::params![recorded_by, &merge_left_right_b64],
            |row| crate::db::sql_types::get_text(row, 0),
        )
        .unwrap();
    let stored_right_left: String = conn
        .query_row(
            "SELECT frontier_hash FROM removals WHERE recorded_by = ?1 AND event_id = ?2",
            rusqlite::params![recorded_by, &merge_right_left_b64],
            |row| crate::db::sql_types::get_text(row, 0),
        )
        .unwrap();

    let expected_b64 = event_id_to_base64(&frontier_hash);
    assert_eq!(stored_left_right, expected_b64);
    assert_eq!(stored_right_left, expected_b64);
}

#[test]
fn test_key_rotation_multi_parent_frontier_blocks_until_all_frontier_deps_arrive() {
    let conn = setup();
    let recorded_by = "peer1";
    let (signer_eid, signing_key, chain_blobs) = build_identity_chain_deferred(recorded_by);
    insert_and_project_identity_chain(&conn, recorded_by, &chain_blobs);
    seed_admin_for_signer(&conn, recorded_by, &signer_eid);
    let signer_user_eid = local_user_for_signer(&conn, recorded_by, &signer_eid);

    let (_left_parent, left_blob) =
        make_signed_removal(&signing_key, &signer_eid, signer_eid, &[], None);
    let left_eid = canonical_test_event_id(&conn, recorded_by, &left_blob);

    let (_right_parent, right_blob) =
        make_signed_removal(&signing_key, &signer_eid, signer_user_eid, &[], None);
    let right_eid = canonical_test_event_id(&conn, recorded_by, &right_blob);

    let canonical_frontier = if left_eid <= right_eid {
        vec![left_eid, right_eid]
    } else {
        vec![right_eid, left_eid]
    };

    let (_rotation, rotation_blob) = make_signed_key_rotation(
        &signing_key,
        &signer_eid,
        &canonical_frontier,
        None,
    );
    let rotation_eid = insert_event_raw(&conn, recorded_by, &rotation_blob);

    match project_one(&conn, recorded_by, &rotation_eid).unwrap() {
        ProjectionDecision::BlockOnMissingDeps { missing } => {
            assert!(
                missing.contains(&left_eid),
                "missing frontier should include left parent"
            );
            assert!(
                missing.contains(&right_eid),
                "missing frontier should include right parent"
            );
        }
        other => panic!("expected Block on both frontier parents, got {other:?}"),
    }

    let inserted_left_eid = insert_event_raw(&conn, recorded_by, &left_blob);
    assert_eq!(inserted_left_eid, left_eid);
    assert_eq!(
        project_one(&conn, recorded_by, &left_eid).unwrap(),
        ProjectionDecision::Valid
    );

    match project_one(&conn, recorded_by, &rotation_eid).unwrap() {
        ProjectionDecision::BlockOnMissingDeps { missing } => {
            assert!(
                !missing.contains(&left_eid),
                "projected frontier dep should no longer be missing"
            );
            assert!(
                missing.contains(&right_eid),
                "unseen frontier dep should still block the rotation"
            );
        }
        other => panic!("expected Block on remaining frontier parent, got {other:?}"),
    }

    let inserted_right_eid = insert_event_raw(&conn, recorded_by, &right_blob);
    assert_eq!(inserted_right_eid, right_eid);
    assert_eq!(
        project_one(&conn, recorded_by, &right_eid).unwrap(),
        ProjectionDecision::Valid
    );

    let rotation_b64 = event_id_to_base64(&rotation_eid);
    let projected: bool = conn
        .query_row(
            "SELECT COUNT(*) > 0 FROM key_rotations WHERE recorded_by = ?1 AND event_id = ?2",
            rusqlite::params![recorded_by, &rotation_b64],
            |row| row.get(0),
        )
        .unwrap();
    assert!(
        projected,
        "multi-parent frontier rotation should auto-project once all frontier deps arrive"
    );

    let stored_frontier_hash: String = conn
        .query_row(
            "SELECT frontier_hash FROM key_rotations WHERE recorded_by = ?1 AND event_id = ?2",
            rusqlite::params![recorded_by, &rotation_b64],
            |row| crate::db::sql_types::get_text(row, 0),
        )
        .unwrap();
    assert_eq!(
        stored_frontier_hash,
        event_id_to_base64(&frontier_hash_from_refs(&canonical_frontier)),
        "rotation frontier should converge to the same hash regardless of carried parent order"
    );
}

#[test]
fn test_key_rotation_rejects_unsorted_multi_parent_frontier_even_when_hash_matches() {
    let conn = setup();
    let recorded_by = "peer1";
    let (signer_eid, signing_key, chain_blobs) = build_identity_chain_deferred(recorded_by);
    insert_and_project_identity_chain(&conn, recorded_by, &chain_blobs);
    seed_admin_for_signer(&conn, recorded_by, &signer_eid);
    let signer_user_eid = local_user_for_signer(&conn, recorded_by, &signer_eid);

    let (_left_parent, left_blob) =
        make_signed_removal(&signing_key, &signer_eid, signer_eid, &[], None);
    let left_eid = insert_event_raw(&conn, recorded_by, &left_blob);
    assert_eq!(
        project_one(&conn, recorded_by, &left_eid).unwrap(),
        ProjectionDecision::Valid
    );

    let (_right_parent, right_blob) =
        make_signed_removal(&signing_key, &signer_eid, signer_user_eid, &[], None);
    let right_eid = insert_event_raw(&conn, recorded_by, &right_blob);
    assert_eq!(
        project_one(&conn, recorded_by, &right_eid).unwrap(),
        ProjectionDecision::Valid
    );

    let sorted_frontier = if left_eid <= right_eid {
        vec![left_eid, right_eid]
    } else {
        vec![right_eid, left_eid]
    };
    let unsorted_frontier = if left_eid <= right_eid {
        vec![right_eid, left_eid]
    } else {
        vec![left_eid, right_eid]
    };

    let (_rotation, unsorted_rotation_blob) = make_signed_key_rotation(
        &signing_key,
        &signer_eid,
        &unsorted_frontier,
        Some(frontier_hash_from_refs(&sorted_frontier)),
    );
    let unsorted_rotation_eid = insert_event_raw(&conn, recorded_by, &unsorted_rotation_blob);

    match project_one(&conn, recorded_by, &unsorted_rotation_eid).unwrap() {
        ProjectionDecision::Reject { reason } => {
            assert!(
                reason.contains("frontier refs must be sorted in canonical order"),
                "unexpected reject reason: {reason}"
            );
        }
        other => panic!("expected Reject, got {other:?}"),
    }
}
