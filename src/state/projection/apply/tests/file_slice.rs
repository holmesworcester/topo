use super::*;

#[test]
fn test_file_slice_valid() {
    let conn = setup();
    let recorded_by = "peer1";
    let file_key_event_id = ensure_test_content_key(&conn, recorded_by);

    // Create identity chain as signer
    let (signer_eid, signing_key) = make_identity_chain(&conn, recorded_by);

    // Create descriptor (File) for this file_id
    let file_id = [99u8; 32];
    setup_descriptor_for_file(
        &conn,
        recorded_by,
        &signing_key,
        &signer_eid,
        file_id,
        &file_key_event_id,
    );

    // Create FileSlice
    let (_fs, fs_blob) = make_file_slice(&signing_key, &signer_eid, file_id, 0, b"encrypted data");
    let fs_eid = insert_event_raw(&conn, recorded_by, &fs_blob);
    let result = project_one(&conn, recorded_by, &fs_eid).unwrap();
    assert_eq!(result, ProjectionDecision::Valid);

    // Verify in file_slices table
    let fs_b64 = event_id_to_base64(&fs_eid);
    let count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM file_slices WHERE recorded_by = ?1 AND event_id = ?2",
            rusqlite::params![recorded_by, &fs_b64],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(count, 1);
}

#[test]
fn test_file_slice_blocks_on_missing_signer() {
    let conn = setup();
    let recorded_by = "peer1";
    let mut rng = rand::thread_rng();
    let signing_key = SigningKey::generate(&mut rng);

    // Use a fake signer event_id that doesn't exist
    let fake_signer = [77u8; 32];
    let file_id = [99u8; 32];
    let (_fs, fs_blob) = make_file_slice(&signing_key, &fake_signer, file_id, 0, b"data");
    let fs_eid = insert_event_raw(&conn, recorded_by, &fs_blob);
    let result = project_one(&conn, recorded_by, &fs_eid).unwrap();
    assert!(matches!(result, ProjectionDecision::Block { .. }));
}

#[test]
fn test_file_slice_unblocks_when_signer_arrives() {
    let conn = setup();
    let recorded_by = "peer1";
    let file_key_event_id = ensure_test_content_key(&conn, recorded_by);

    // Build identity chain without inserting (deferred)
    let (signer_eid, signing_key, chain_blobs) = build_identity_chain_deferred(recorded_by);

    // Create FileSlice referencing the not-yet-existing signer
    let file_id = [99u8; 32];
    let (_fs, fs_blob) = make_file_slice(&signing_key, &signer_eid, file_id, 0, b"data");
    let fs_eid = insert_event_raw(&conn, recorded_by, &fs_blob);

    // Should block on missing signer dep
    let result = project_one(&conn, recorded_by, &fs_eid).unwrap();
    assert!(matches!(result, ProjectionDecision::Block { .. }));

    // Insert and project the full identity chain — signer dep resolves,
    // but file_slice will now guard-block on missing descriptor
    insert_and_project_identity_chain(&conn, recorded_by, &chain_blobs);

    // File slice should NOT yet be valid (guard-blocked on missing descriptor)
    let fs_b64 = event_id_to_base64(&fs_eid);
    let valid_before_descriptor: bool = conn
        .query_row(
            "SELECT COUNT(*) > 0 FROM valid_events WHERE peer_id = ?1 AND event_id = ?2",
            rusqlite::params![recorded_by, &fs_b64],
            |row| row.get(0),
        )
        .unwrap();
    assert!(
        !valid_before_descriptor,
        "file_slice should still be guard-blocked before descriptor"
    );

    // Now create the descriptor — this should cascade-unblock the file_slice
    setup_descriptor_for_file(
        &conn,
        recorded_by,
        &signing_key,
        &signer_eid,
        file_id,
        &file_key_event_id,
    );

    // FileSlice should now be cascade-unblocked
    let valid: bool = conn
        .query_row(
            "SELECT COUNT(*) > 0 FROM valid_events WHERE peer_id = ?1 AND event_id = ?2",
            rusqlite::params![recorded_by, &fs_b64],
            |row| row.get(0),
        )
        .unwrap();
    assert!(
        valid,
        "file_slice should have been cascade-unblocked after descriptor"
    );
}

#[test]
fn test_file_slice_invalid_signature_rejects() {
    let conn = setup();
    let recorded_by = "peer1";
    let file_key_event_id = ensure_test_content_key(&conn, recorded_by);
    let mut rng = rand::thread_rng();
    let wrong_key = SigningKey::generate(&mut rng);
    let (signer_eid, signer_key) = make_identity_chain(&conn, recorded_by);

    // Sign file_slice with the WRONG key
    let file_id = [99u8; 32];
    let (_fs, fs_blob) = make_file_slice(&wrong_key, &signer_eid, file_id, 0, b"data");
    setup_descriptor_for_file(
        &conn,
        recorded_by,
        &signer_key,
        &signer_eid,
        file_id,
        &file_key_event_id,
    );
    let fs_eid = insert_event_raw(&conn, recorded_by, &fs_blob);
    let result = project_one(&conn, recorded_by, &fs_eid).unwrap();
    assert!(matches!(result, ProjectionDecision::Reject { .. }));
}

#[test]
fn test_multiple_slices_same_file() {
    let conn = setup();
    let recorded_by = "peer1";
    let file_key_event_id = ensure_test_content_key(&conn, recorded_by);

    // Create identity chain as signer
    let (signer_eid, signing_key) = make_identity_chain(&conn, recorded_by);

    // Create descriptor for this file_id
    let file_id = [99u8; 32];
    setup_descriptor_for_file(
        &conn,
        recorded_by,
        &signing_key,
        &signer_eid,
        file_id,
        &file_key_event_id,
    );

    for i in 0..5u32 {
        let (_fs, fs_blob) = make_file_slice(
            &signing_key,
            &signer_eid,
            file_id,
            i,
            format!("slice {}", i).as_bytes(),
        );
        let fs_eid = insert_event_raw(&conn, recorded_by, &fs_blob);
        let result = project_one(&conn, recorded_by, &fs_eid).unwrap();
        assert_eq!(
            result,
            ProjectionDecision::Valid,
            "slice {} should be valid",
            i
        );
    }

    // Verify all 5 slices in table
    let file_id_b64 = crate::crypto::event_id_to_base64(&file_id);
    let count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM file_slices WHERE recorded_by = ?1 AND file_id = ?2",
            rusqlite::params![recorded_by, &file_id_b64],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(count, 5);
}

#[test]
fn test_file_slice_tenant_isolation() {
    let conn = setup();
    let file_key_event_id = ensure_test_content_key(&conn, "tenant_a");
    let (signer_eid_a, signing_key_a) = make_identity_chain(&conn, "tenant_a");
    let (_signer_eid_b, _signing_key_b) = make_identity_chain(&conn, "tenant_b");

    let file_id = [99u8; 32];
    setup_descriptor_for_file(
        &conn,
        "tenant_a",
        &signing_key_a,
        &signer_eid_a,
        file_id,
        &file_key_event_id,
    );
    let (_fs, fs_blob) = make_file_slice(&signing_key_a, &signer_eid_a, file_id, 0, b"data");
    let fs_eid = insert_event_raw(&conn, "tenant_a", &fs_blob);
    project_one(&conn, "tenant_a", &fs_eid).unwrap();

    // Tenant B should not see tenant A's slice
    let file_id_b64 = crate::crypto::event_id_to_base64(&file_id);
    let count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM file_slices WHERE recorded_by = 'tenant_b' AND file_id = ?1",
            rusqlite::params![&file_id_b64],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(count, 0);
}

#[test]
fn test_project_attachment_valid() {
    let conn = setup();
    let recorded_by = "peer1";
    let _net_eid = setup_workspace_event(&conn, recorded_by);

    // Create identity chain once for this tenant
    let (signer_eid, signing_key) = make_identity_chain(&conn, recorded_by);

    // Create message (dep)
    let (_msg, msg_blob) = make_message_signed(&signing_key, &signer_eid, "hello attachment");
    let msg_eid = insert_event_raw(&conn, recorded_by, &msg_blob);
    project_one(&conn, recorded_by, &msg_eid).unwrap();

    // Create KeySecret (dep)
    let sk = ParsedEvent::KeySecret(KeySecretEvent {
        created_at_ms: now_ms(),
        key_bytes: [0xAA; 32],
    });
    let sk_blob = events::encode_event(&sk).unwrap();
    let sk_eid = insert_event_raw(&conn, recorded_by, &sk_blob);
    project_one(&conn, recorded_by, &sk_eid).unwrap();

    // Create attachment referencing both deps
    let (_att, att_blob) = make_attachment_signed(&signing_key, &signer_eid, &msg_eid, &sk_eid);
    let att_eid = insert_event_raw(&conn, recorded_by, &att_blob);
    let result = project_one(&conn, recorded_by, &att_eid).unwrap();
    assert_eq!(result, ProjectionDecision::Valid);

    // Verify in table
    let att_b64 = event_id_to_base64(&att_eid);
    let count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM files WHERE recorded_by = ?1 AND event_id = ?2",
            rusqlite::params![recorded_by, &att_b64],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(count, 1);
}

#[test]
fn test_attachment_blocks_on_missing_message() {
    let conn = setup();
    let recorded_by = "peer1";

    // Create KeySecret but NOT message
    let sk = ParsedEvent::KeySecret(KeySecretEvent {
        created_at_ms: now_ms(),
        key_bytes: [0xAA; 32],
    });
    let sk_blob = events::encode_event(&sk).unwrap();
    let sk_eid = insert_event_raw(&conn, recorded_by, &sk_blob);
    project_one(&conn, recorded_by, &sk_eid).unwrap();

    let fake_msg_id = [88u8; 32];
    let (_att, att_blob) = make_file(&conn, recorded_by, &fake_msg_id, &sk_eid);
    let att_eid = insert_event_raw(&conn, recorded_by, &att_blob);
    let result = project_one(&conn, recorded_by, &att_eid).unwrap();
    assert!(matches!(result, ProjectionDecision::Block { .. }));
}

#[test]
fn test_attachment_blocks_on_missing_key() {
    let conn = setup();
    let recorded_by = "peer1";

    // Create identity chain once for this tenant
    let (signer_eid, signing_key) = make_identity_chain(&conn, recorded_by);

    // Create message but NOT secret key
    let (_msg, msg_blob) = make_message_signed(&signing_key, &signer_eid, "hello");
    let msg_eid = insert_event_raw(&conn, recorded_by, &msg_blob);
    project_one(&conn, recorded_by, &msg_eid).unwrap();

    let fake_key_id = [77u8; 32];
    let (_att, att_blob) =
        make_attachment_signed(&signing_key, &signer_eid, &msg_eid, &fake_key_id);
    let att_eid = insert_event_raw(&conn, recorded_by, &att_blob);
    let result = project_one(&conn, recorded_by, &att_eid).unwrap();
    assert!(matches!(result, ProjectionDecision::Block { .. }));
}

#[test]
fn test_attachment_blocks_on_both_missing() {
    let conn = setup();
    let recorded_by = "peer1";

    let fake_msg_id = [88u8; 32];
    let fake_key_id = [77u8; 32];
    let (_att, att_blob) = make_file(&conn, recorded_by, &fake_msg_id, &fake_key_id);
    let att_eid = insert_event_raw(&conn, recorded_by, &att_blob);
    let result = project_one(&conn, recorded_by, &att_eid).unwrap();
    match result {
        ProjectionDecision::Block { ref missing } => {
            // Should block on at least the 2 fake deps (message_id + key_event_id)
            assert!(
                missing.contains(&fake_msg_id),
                "should block on missing message_id"
            );
            assert!(
                missing.contains(&fake_key_id),
                "should block on missing key_event_id"
            );
        }
        _ => panic!("expected Block, got {:?}", result),
    }
}

#[test]
fn test_attachment_cascade_unblock() {
    let conn = setup();
    let recorded_by = "peer1";
    let _net_eid = setup_workspace_event(&conn, recorded_by);

    // Create identity chain for signing
    let (signer_eid, signing_key) = make_identity_chain(&conn, recorded_by);

    // Pre-compute the message and key event IDs
    let (_msg, msg_blob) = make_message_signed(&signing_key, &signer_eid, "hello cascade");
    let msg_eid = canonical_test_event_id(&conn, recorded_by, &msg_blob);

    let sk = ParsedEvent::KeySecret(KeySecretEvent {
        created_at_ms: now_ms(),
        key_bytes: [0xBB; 32],
    });
    let sk_blob = events::encode_event(&sk).unwrap();
    let sk_eid = crate::crypto::hash_event(&sk_blob);

    // Insert attachment first (both deps missing → blocks)
    let (_att, att_blob) = make_attachment_signed(&signing_key, &signer_eid, &msg_eid, &sk_eid);
    let att_eid = insert_event_raw(&conn, recorded_by, &att_blob);
    let result = project_one(&conn, recorded_by, &att_eid).unwrap();
    assert!(matches!(result, ProjectionDecision::Block { .. }));

    // Insert message dep — still blocked (key missing)
    let msg_eid2 = insert_event_raw(&conn, recorded_by, &msg_blob);
    assert_eq!(msg_eid, msg_eid2);
    project_one(&conn, recorded_by, &msg_eid).unwrap();

    // Attachment still not valid
    let att_b64 = event_id_to_base64(&att_eid);
    let valid: bool = conn
        .query_row(
            "SELECT COUNT(*) > 0 FROM valid_events WHERE peer_id = ?1 AND event_id = ?2",
            rusqlite::params![recorded_by, &att_b64],
            |row| row.get(0),
        )
        .unwrap();
    assert!(!valid, "attachment should still be blocked");

    // Insert key dep — should cascade-unblock attachment
    let sk_eid2 = insert_event_raw(&conn, recorded_by, &sk_blob);
    assert_eq!(sk_eid, sk_eid2);
    project_one(&conn, recorded_by, &sk_eid).unwrap();

    // Attachment should now be valid
    let valid2: bool = conn
        .query_row(
            "SELECT COUNT(*) > 0 FROM valid_events WHERE peer_id = ?1 AND event_id = ?2",
            rusqlite::params![recorded_by, &att_b64],
            |row| row.get(0),
        )
        .unwrap();
    assert!(valid2, "attachment should have been cascade-unblocked");
}

#[test]
fn test_file_slice_idempotent_replay() {
    let conn = setup();
    let recorded_by = "peer1";
    let file_key_event_id = ensure_test_content_key(&conn, recorded_by);

    // Create identity chain as signer
    let (signer_eid, signing_key) = make_identity_chain(&conn, recorded_by);

    // Create descriptor for this file_id
    let file_id = [99u8; 32];
    setup_descriptor_for_file(
        &conn,
        recorded_by,
        &signing_key,
        &signer_eid,
        file_id,
        &file_key_event_id,
    );

    let (_fs, fs_blob) = make_file_slice(&signing_key, &signer_eid, file_id, 0, b"data");
    let fs_eid = insert_event_raw(&conn, recorded_by, &fs_blob);

    // First projection
    let result = project_one(&conn, recorded_by, &fs_eid).unwrap();
    assert_eq!(result, ProjectionDecision::Valid);

    // Replay — should return AlreadyProcessed (already in valid_events)
    let result2 = project_one(&conn, recorded_by, &fs_eid).unwrap();
    assert_eq!(result2, ProjectionDecision::AlreadyProcessed);
}

#[test]
fn test_file_slice_duplicate_slot_conflict_rejects() {
    let conn = setup();
    let recorded_by = "peer1";
    let file_key_event_id = ensure_test_content_key(&conn, recorded_by);

    // Create identity chain as signer
    let (signer_eid, signing_key) = make_identity_chain(&conn, recorded_by);

    // Create descriptor for this file_id
    let file_id = [99u8; 32];
    setup_descriptor_for_file(
        &conn,
        recorded_by,
        &signing_key,
        &signer_eid,
        file_id,
        &file_key_event_id,
    );

    // First slice at slot 0
    let (_fs1, fs1_blob) = make_file_slice(&signing_key, &signer_eid, file_id, 0, b"first");
    let fs1_eid = insert_event_raw(&conn, recorded_by, &fs1_blob);
    let result = project_one(&conn, recorded_by, &fs1_eid).unwrap();
    assert_eq!(result, ProjectionDecision::Valid);

    // Second, DIFFERENT slice at same slot 0 — should reject
    let (_fs2, fs2_blob) = make_file_slice(&signing_key, &signer_eid, file_id, 0, b"second");
    let fs2_eid = insert_event_raw(&conn, recorded_by, &fs2_blob);
    let result2 = project_one(&conn, recorded_by, &fs2_eid).unwrap();
    assert!(
        matches!(result2, ProjectionDecision::Reject { .. }),
        "duplicate slot with different event_id should reject, got {:?}",
        result2
    );
}

#[test]
fn test_file_slice_wrong_signer_rejected() {
    let conn = setup();
    let recorded_by = "peer1";
    let mut rng = rand::thread_rng();

    // Build a shared identity chain up through User, then branch
    // into two separate PeerShared signers (A and B).

    // 1. Workspace
    let workspace_key = SigningKey::generate(&mut rng);
    let workspace_pub = workspace_key.verifying_key().to_bytes();
    let net_event = ParsedEvent::Workspace(WorkspaceEvent {
        created_at_ms: now_ms(),
        public_key: workspace_pub,
        name: "workspace".to_string(),
    });
    let net_blob = events::encode_event(&net_event).unwrap();
    let net_eid = insert_event_raw(&conn, recorded_by, &net_blob);

    // 2. InviteAccepted
    let ia_event = ParsedEvent::InviteAccepted(InviteAcceptedEvent {
        created_at_ms: now_ms(),
        tenant_event_id: setup_tenant_event(&conn, recorded_by),
        invite_event_id: net_eid,
        workspace_id: net_eid,
    });
    let ia_blob = events::encode_event(&ia_event).unwrap();
    let ia_eid = insert_event_raw(&conn, recorded_by, &ia_blob);
    project_one(&conn, recorded_by, &ia_eid).unwrap();
    project_one(&conn, recorded_by, &net_eid).unwrap();

    // 3. UserInvite (signed by workspace key)
    let invite_key = SigningKey::generate(&mut rng);
    let invite_pub = invite_key.verifying_key().to_bytes();
    let uib = UserInviteEvent {
        created_at_ms: now_ms(),
        public_key: invite_pub,
        workspace_id: net_eid,
        authority_event_id: net_eid,
        signed_by: net_eid,
        signer_type: 1,
        signature: [0u8; 64],
    };
    let uib_event = ParsedEvent::UserInvite(uib);
    let mut uib_blob = events::encode_event(&uib_event).unwrap();
    sign_blob(&workspace_key, &mut uib_blob);
    let uib_eid = insert_event_raw(&conn, recorded_by, &uib_blob);
    project_one(&conn, recorded_by, &uib_eid).unwrap();

    // 4. User (signed by invite key)
    let user_key = SigningKey::generate(&mut rng);
    let user_pub = user_key.verifying_key().to_bytes();
    let ub = UserEvent {
        created_at_ms: now_ms(),
        public_key: user_pub,
        username: "user".to_string(),
        signed_by: uib_eid,
        signer_type: 2,
        signature: [0u8; 64],
    };
    let ub_event = ParsedEvent::User(ub);
    let mut ub_blob = events::encode_event(&ub_event).unwrap();
    sign_blob(&invite_key, &mut ub_blob);
    let ub_eid = insert_event_raw(&conn, recorded_by, &ub_blob);
    project_one(&conn, recorded_by, &ub_eid).unwrap();

    // 5a. DeviceInvite A (signed by user key)
    let device_invite_key_a = SigningKey::generate(&mut rng);
    let device_invite_pub_a = device_invite_key_a.verifying_key().to_bytes();
    let dif_a = DeviceInviteEvent {
        created_at_ms: now_ms(),
        public_key: device_invite_pub_a,
        authority_event_id: ub_eid,
        signed_by: ub_eid,
        signer_type: 4,
        signature: [0u8; 64],
    };
    let dif_a_event = ParsedEvent::DeviceInvite(dif_a);
    let mut dif_a_blob = events::encode_event(&dif_a_event).unwrap();
    sign_blob(&user_key, &mut dif_a_blob);
    let dif_a_eid = insert_event_raw(&conn, recorded_by, &dif_a_blob);
    project_one(&conn, recorded_by, &dif_a_eid).unwrap();

    // 6a. PeerShared A (signed by device_invite_a)
    let signer_key_a = SigningKey::generate(&mut rng);
    let peer_pub_a = signer_key_a.verifying_key().to_bytes();
    let psf_a = PeerSharedEvent {
        created_at_ms: now_ms(),
        public_key: peer_pub_a,
        user_event_id: ub_eid,
        device_name: "device-a".to_string(),
        signed_by: dif_a_eid,
        signer_type: 3,
        signature: [0u8; 64],
    };
    let psf_a_event = ParsedEvent::PeerShared(psf_a);
    let mut psf_a_blob = events::encode_event(&psf_a_event).unwrap();
    sign_blob(&device_invite_key_a, &mut psf_a_blob);
    let signer_a_eid = insert_event_raw(&conn, recorded_by, &psf_a_blob);
    project_one(&conn, recorded_by, &signer_a_eid).unwrap();
    register_signer_user(signer_a_eid, ub_eid);

    // 5b. DeviceInvite B (signed by user key — branching from same User)
    let device_invite_key_b = SigningKey::generate(&mut rng);
    let device_invite_pub_b = device_invite_key_b.verifying_key().to_bytes();
    let dif_b = DeviceInviteEvent {
        created_at_ms: now_ms(),
        public_key: device_invite_pub_b,
        authority_event_id: ub_eid,
        signed_by: ub_eid,
        signer_type: 4,
        signature: [0u8; 64],
    };
    let dif_b_event = ParsedEvent::DeviceInvite(dif_b);
    let mut dif_b_blob = events::encode_event(&dif_b_event).unwrap();
    sign_blob(&user_key, &mut dif_b_blob);
    let dif_b_eid = insert_event_raw(&conn, recorded_by, &dif_b_blob);
    project_one(&conn, recorded_by, &dif_b_eid).unwrap();

    // 6b. PeerShared B (signed by device_invite_b)
    let signer_key_b = SigningKey::generate(&mut rng);
    let peer_pub_b = signer_key_b.verifying_key().to_bytes();
    let psf_b = PeerSharedEvent {
        created_at_ms: now_ms(),
        public_key: peer_pub_b,
        user_event_id: ub_eid,
        device_name: "device-b".to_string(),
        signed_by: dif_b_eid,
        signer_type: 3,
        signature: [0u8; 64],
    };
    let psf_b_event = ParsedEvent::PeerShared(psf_b);
    let mut psf_b_blob = events::encode_event(&psf_b_event).unwrap();
    sign_blob(&device_invite_key_b, &mut psf_b_blob);
    let signer_b_eid = insert_event_raw(&conn, recorded_by, &psf_b_blob);
    project_one(&conn, recorded_by, &signer_b_eid).unwrap();
    register_signer_user(signer_b_eid, ub_eid);

    // Create descriptor with signer A
    let file_id = [99u8; 32];
    let file_key_event_id = ensure_test_content_key(&conn, recorded_by);
    setup_descriptor_for_file(
        &conn,
        recorded_by,
        &signer_key_a,
        &signer_a_eid,
        file_id,
        &file_key_event_id,
    );

    // Create file_slice signed by signer B (different from descriptor's signer A)
    let (_fs, fs_blob) = make_file_slice(
        &signer_key_b,
        &signer_b_eid,
        file_id,
        0,
        b"unauthorized data",
    );
    let fs_eid = insert_event_raw(&conn, recorded_by, &fs_blob);
    let result = project_one(&conn, recorded_by, &fs_eid).unwrap();
    assert!(
        matches!(result, ProjectionDecision::Reject { .. }),
        "file_slice with wrong signer should be rejected, got {:?}",
        result
    );
}
