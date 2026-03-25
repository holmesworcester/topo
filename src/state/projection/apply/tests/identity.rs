use super::*;

#[test]
fn test_unsupported_signer_type_rejects() {
    let conn = setup();
    let recorded_by = "peer1";
    let mut rng = rand::thread_rng();
    let signing_key = SigningKey::generate(&mut rng);
    let (signer_eid, _signing_key) = make_identity_chain(&conn, recorded_by);

    // Create a message but mutate signer_type byte to 255
    let (_msg, mut msg_blob) = make_message_signed(&signing_key, &signer_eid, "bad signer type");
    // signer_type is at the signer_type offset in message wire format
    // message layout: type(1) + created_at(8) + workspace_id(32) + author_id(32) + content(1024) + signed_by(32) + signer_type(1) + signature(64)
    // signer_type offset = 1 + 8 + 32 + 32 + 1024 + 32 = 1129
    msg_blob[1129] = 255;
    // Re-hash since blob changed
    let msg_eid = insert_event_raw(&conn, recorded_by, &msg_blob);

    let result = project_one(&conn, recorded_by, &msg_eid).unwrap();
    match result {
        ProjectionDecision::Reject { reason } => {
            assert!(
                reason.contains("unsupported signer_type"),
                "reason: {}",
                reason
            );
        }
        other => panic!("expected Reject, got {:?}", other),
    }

    // Verify rejected_events row exists
    let msg_b64 = event_id_to_base64(&msg_eid);
    let rej_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM rejected_events WHERE peer_id = ?1 AND event_id = ?2",
            rusqlite::params![recorded_by, &msg_b64],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(rej_count, 1);
}

fn assert_parse_error_rejection(
    conn: &Connection,
    recorded_by: &str,
    blob: &[u8],
    expected_substring: &str,
) {
    let event_id = insert_event_raw(conn, recorded_by, blob);
    let result = project_one(conn, recorded_by, &event_id).unwrap();
    match result {
        ProjectionDecision::Reject { reason } => {
            assert!(
                reason.contains("parse error: invalid metadata")
                    && reason.contains(expected_substring),
                "unexpected parse rejection reason: {}",
                reason
            );
        }
        other => panic!("expected Reject, got {:?}", other),
    }

    let event_id_b64 = event_id_to_base64(&event_id);
    let rej_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM rejected_events WHERE peer_id = ?1 AND event_id = ?2",
            rusqlite::params![recorded_by, &event_id_b64],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(rej_count, 1, "rejected_events row must be recorded");
}

fn setup_workspace_anchor(conn: &Connection, recorded_by: &str) -> (EventId, SigningKey) {
    let mut rng = rand::thread_rng();

    let tenant_eid = setup_tenant_event(conn, recorded_by);

    let workspace_key = SigningKey::generate(&mut rng);
    let workspace_event = ParsedEvent::Workspace(WorkspaceEvent {
        created_at_ms: now_ms(),
        public_key: workspace_key.verifying_key().to_bytes(),
        name: "workspace".to_string(),
    });
    let workspace_eid = create_event_staged(conn, recorded_by, &workspace_event).unwrap();

    let invite_accepted = ParsedEvent::InviteAccepted(crate::event_modules::InviteAcceptedEvent {
        created_at_ms: now_ms(),
        tenant_event_id: tenant_eid,
        invite_event_id: workspace_eid,
        workspace_id: workspace_eid,
    });
    create_event_synchronous(conn, recorded_by, &invite_accepted).unwrap();
    assert!(
        matches!(
            project_one(conn, recorded_by, &workspace_eid).unwrap(),
            ProjectionDecision::Valid | ProjectionDecision::AlreadyProcessed
        ),
        "workspace should be projected by the invite_accepted retry path"
    );

    (workspace_eid, workspace_key)
}

fn create_bootstrap_user_invite(
    conn: &Connection,
    recorded_by: &str,
    workspace_eid: EventId,
    workspace_key: &SigningKey,
) -> (EventId, SigningKey) {
    let mut rng = rand::thread_rng();
    let invite_key = SigningKey::generate(&mut rng);
    let invite_event = ParsedEvent::UserInvite(crate::event_modules::UserInviteEvent {
        created_at_ms: now_ms(),
        public_key: invite_key.verifying_key().to_bytes(),
        workspace_id: workspace_eid,
        authority_event_id: workspace_eid,
        signed_by: workspace_eid,
        signer_type: 1,
        signature: [0u8; 64],
    });
    let invite_eid =
        create_signed_event_synchronous(conn, recorded_by, &invite_event, workspace_key).unwrap();
    (invite_eid, invite_key)
}

fn project_valid_user_from_invite(
    conn: &Connection,
    recorded_by: &str,
    invite_event_id: EventId,
    invite_key: &SigningKey,
    username: &str,
) -> (EventId, SigningKey) {
    let user_key = SigningKey::generate(&mut rand::thread_rng());
    let user_event = ParsedEvent::User(crate::event_modules::UserEvent {
        created_at_ms: now_ms(),
        public_key: user_key.verifying_key().to_bytes(),
        username: username.to_string(),
        signed_by: invite_event_id,
        signer_type: 2,
        signature: [0u8; 64],
    });
    let user_eid =
        create_signed_event_synchronous(conn, recorded_by, &user_event, invite_key).unwrap();
    (user_eid, user_key)
}

fn project_valid_bootstrap_device_invite(
    conn: &Connection,
    recorded_by: &str,
    user_event_id: EventId,
    user_key: &SigningKey,
) -> (EventId, SigningKey) {
    let mut rng = rand::thread_rng();
    let device_invite_key = SigningKey::generate(&mut rng);
    let device_invite_event = ParsedEvent::DeviceInvite(crate::event_modules::DeviceInviteEvent {
        created_at_ms: now_ms(),
        public_key: device_invite_key.verifying_key().to_bytes(),
        authority_event_id: user_event_id,
        signed_by: user_event_id,
        signer_type: 4,
        signature: [0u8; 64],
    });
    let device_invite_eid =
        create_signed_event_synchronous(conn, recorded_by, &device_invite_event, user_key).unwrap();
    (device_invite_eid, device_invite_key)
}

fn project_valid_admin_for_user(
    conn: &Connection,
    recorded_by: &str,
    workspace_eid: EventId,
    workspace_key: &SigningKey,
    user_event_id: EventId,
    user_public_key: [u8; 32],
) -> EventId {
    let admin_event = ParsedEvent::Admin(crate::event_modules::AdminEvent {
        created_at_ms: now_ms(),
        public_key: user_public_key,
        user_event_id,
        signed_by: workspace_eid,
        signer_type: 1,
        signature: [0u8; 64],
    });
    create_signed_event_synchronous(conn, recorded_by, &admin_event, workspace_key).unwrap()
}

fn project_valid_peer_shared_for_user(
    conn: &Connection,
    recorded_by: &str,
    user_event_id: EventId,
    device_invite_eid: EventId,
    device_invite_key: &SigningKey,
    device_name: &str,
) -> (EventId, SigningKey) {
    let mut rng = rand::thread_rng();
    let peer_shared_key = SigningKey::generate(&mut rng);
    let peer_shared = ParsedEvent::PeerShared(crate::event_modules::PeerSharedEvent {
        created_at_ms: now_ms(),
        public_key: peer_shared_key.verifying_key().to_bytes(),
        user_event_id,
        device_name: device_name.to_string(),
        signed_by: device_invite_eid,
        signer_type: 3,
        signature: [0u8; 64],
    });
    let peer_shared_eid =
        create_signed_event_synchronous(conn, recorded_by, &peer_shared, device_invite_key)
            .unwrap();
    (peer_shared_eid, peer_shared_key)
}

fn setup_admin_signer_peer(
    conn: &Connection,
    recorded_by: &str,
    workspace_eid: EventId,
    workspace_key: &SigningKey,
    user_event_id: EventId,
    user_key: &SigningKey,
    device_name: &str,
) -> (EventId, EventId, SigningKey) {
    let (device_invite_eid, device_invite_key) =
        project_valid_bootstrap_device_invite(conn, recorded_by, user_event_id, user_key);
    let admin_eid = project_valid_admin_for_user(
        conn,
        recorded_by,
        workspace_eid,
        workspace_key,
        user_event_id,
        user_key.verifying_key().to_bytes(),
    );
    let (peer_shared_eid, peer_shared_key) = project_valid_peer_shared_for_user(
        conn,
        recorded_by,
        user_event_id,
        device_invite_eid,
        &device_invite_key,
        device_name,
    );
    (admin_eid, peer_shared_eid, peer_shared_key)
}

#[test]
fn test_user_rejects_wrong_signer_family_at_projection() {
    let conn = setup();
    let recorded_by = "peer1";

    let event = ParsedEvent::User(crate::event_modules::UserEvent {
        created_at_ms: now_ms(),
        public_key: [1u8; 32],
        username: "alice".to_string(),
        signed_by: [2u8; 32],
        signer_type: 1,
        signature: [0u8; 64],
    });
    let blob = events::encode_event(&event).unwrap();

    assert_parse_error_rejection(&conn, recorded_by, &blob, "user signer_type must be 2");
}

#[test]
fn test_peer_shared_rejects_wrong_signer_family_at_projection() {
    let conn = setup();
    let recorded_by = "peer1";

    let event = ParsedEvent::PeerShared(crate::event_modules::PeerSharedEvent {
        created_at_ms: now_ms(),
        public_key: [1u8; 32],
        user_event_id: [2u8; 32],
        device_name: "device".to_string(),
        signed_by: [3u8; 32],
        signer_type: 5,
        signature: [0u8; 64],
    });
    let blob = events::encode_event(&event).unwrap();

    assert_parse_error_rejection(
        &conn,
        recorded_by,
        &blob,
        "peer_shared signer_type must be 3",
    );
}

#[test]
fn test_admin_rejects_wrong_signer_family_at_projection() {
    let conn = setup();
    let recorded_by = "peer1";

    let event = ParsedEvent::Admin(crate::event_modules::AdminEvent {
        created_at_ms: now_ms(),
        public_key: [1u8; 32],
        user_event_id: [2u8; 32],
        signed_by: [3u8; 32],
        signer_type: 4,
        signature: [0u8; 64],
    });
    let blob = events::encode_event(&event).unwrap();

    assert_parse_error_rejection(&conn, recorded_by, &blob, "admin signer_type must be 1");
}

#[test]
fn test_admin_projects_with_workspace_signer_family() {
    let conn = setup();
    let recorded_by = "peer1";
    let mut rng = rand::thread_rng();

    let tenant_event = ParsedEvent::Tenant(TenantEvent {
        created_at_ms: now_ms(),
        public_key: SigningKey::generate(&mut rng).verifying_key().to_bytes(),
    });
    let tenant_blob = events::encode_event(&tenant_event).unwrap();
    let tenant_eid = insert_event_raw(&conn, recorded_by, &tenant_blob);
    assert_eq!(
        project_one(&conn, recorded_by, &tenant_eid).unwrap(),
        ProjectionDecision::Valid
    );

    let workspace_key = SigningKey::generate(&mut rng);
    let workspace_event = ParsedEvent::Workspace(WorkspaceEvent {
        created_at_ms: now_ms(),
        public_key: workspace_key.verifying_key().to_bytes(),
        name: "workspace".to_string(),
    });
    let workspace_blob = events::encode_event(&workspace_event).unwrap();
    let workspace_eid = insert_event_raw(&conn, recorded_by, &workspace_blob);

    let invite_accepted = ParsedEvent::InviteAccepted(InviteAcceptedEvent {
        created_at_ms: now_ms(),
        tenant_event_id: tenant_eid,
        invite_event_id: workspace_eid,
        workspace_id: workspace_eid,
    });
    let invite_accepted_blob = events::encode_event(&invite_accepted).unwrap();
    let invite_accepted_eid = insert_event_raw(&conn, recorded_by, &invite_accepted_blob);
    assert_eq!(
        project_one(&conn, recorded_by, &invite_accepted_eid).unwrap(),
        ProjectionDecision::Valid
    );
    assert!(
        matches!(
            project_one(&conn, recorded_by, &workspace_eid).unwrap(),
            ProjectionDecision::Valid | ProjectionDecision::AlreadyProcessed
        ),
        "workspace should be projected by the invite_accepted retry path"
    );

    let invite_key = SigningKey::generate(&mut rng);
    let user_invite = UserInviteEvent {
        created_at_ms: now_ms(),
        public_key: invite_key.verifying_key().to_bytes(),
        workspace_id: workspace_eid,
        authority_event_id: workspace_eid,
        signed_by: workspace_eid,
        signer_type: 1,
        signature: [0u8; 64],
    };
    let user_invite_event = ParsedEvent::UserInvite(user_invite);
    let mut user_invite_blob = events::encode_event(&user_invite_event).unwrap();
    sign_blob(&workspace_key, &mut user_invite_blob);
    let user_invite_eid = insert_event_raw(&conn, recorded_by, &user_invite_blob);
    assert_eq!(
        project_one(&conn, recorded_by, &user_invite_eid).unwrap(),
        ProjectionDecision::Valid
    );

    let user_key = SigningKey::generate(&mut rng);
    let user_event = UserEvent {
        created_at_ms: now_ms(),
        public_key: user_key.verifying_key().to_bytes(),
        username: "alice".to_string(),
        signed_by: user_invite_eid,
        signer_type: 2,
        signature: [0u8; 64],
    };
    let user_parsed = ParsedEvent::User(user_event);
    let mut user_blob = events::encode_event(&user_parsed).unwrap();
    sign_blob(&invite_key, &mut user_blob);
    let user_eid = insert_event_raw(&conn, recorded_by, &user_blob);
    assert_eq!(
        project_one(&conn, recorded_by, &user_eid).unwrap(),
        ProjectionDecision::Valid
    );

    let admin_event = ParsedEvent::Admin(crate::event_modules::AdminEvent {
        created_at_ms: now_ms(),
        public_key: user_key.verifying_key().to_bytes(),
        user_event_id: user_eid,
        signed_by: workspace_eid,
        signer_type: 1,
        signature: [0u8; 64],
    });
    let mut admin_blob = events::encode_event(&admin_event).unwrap();
    sign_blob(&workspace_key, &mut admin_blob);
    let admin_eid = insert_event_raw(&conn, recorded_by, &admin_blob);

    assert_eq!(
        project_one(&conn, recorded_by, &admin_eid).unwrap(),
        ProjectionDecision::Valid
    );
}

#[test]
fn test_admin_rejects_public_key_that_does_not_match_user() {
    let conn = setup();
    let recorded_by = "peer1";

    let (workspace_eid, workspace_key) = setup_workspace_anchor(&conn, recorded_by);
    let (invite_eid, invite_key) =
        create_bootstrap_user_invite(&conn, recorded_by, workspace_eid, &workspace_key);
    let (user_eid, _user_key) =
        project_valid_user_from_invite(&conn, recorded_by, invite_eid, &invite_key, "alice");

    let bad_admin = ParsedEvent::Admin(crate::event_modules::AdminEvent {
        created_at_ms: now_ms(),
        public_key: [0xAA; 32],
        user_event_id: user_eid,
        signed_by: workspace_eid,
        signer_type: 1,
        signature: [0u8; 64],
    });
    let mut bad_admin_blob = events::encode_event(&bad_admin).unwrap();
    sign_blob(&workspace_key, &mut bad_admin_blob);

    assert_projection_rejection_contains(
        &conn,
        recorded_by,
        &bad_admin_blob,
        "admin public_key does not match user public_key",
    );
}

#[test]
fn test_peer_shared_rejects_bootstrap_user_mismatch() {
    let conn = setup();
    let recorded_by = "peer1";
    let mut rng = rand::thread_rng();

    let (workspace_eid, workspace_key) = setup_workspace_anchor(&conn, recorded_by);
    let (invite_a_eid, invite_a_key) =
        create_bootstrap_user_invite(&conn, recorded_by, workspace_eid, &workspace_key);
    let (user_a_eid, user_a_key) =
        project_valid_user_from_invite(&conn, recorded_by, invite_a_eid, &invite_a_key, "alice");
    let (device_invite_eid, device_invite_key) =
        project_valid_bootstrap_device_invite(&conn, recorded_by, user_a_eid, &user_a_key);

    let (invite_b_eid, invite_b_key) =
        create_bootstrap_user_invite(&conn, recorded_by, workspace_eid, &workspace_key);
    let (user_b_eid, _user_b_key) =
        project_valid_user_from_invite(&conn, recorded_by, invite_b_eid, &invite_b_key, "bob");

    let bad_peer_shared = ParsedEvent::PeerShared(crate::event_modules::PeerSharedEvent {
        created_at_ms: now_ms(),
        public_key: SigningKey::generate(&mut rng).verifying_key().to_bytes(),
        user_event_id: user_b_eid,
        device_name: "device".to_string(),
        signed_by: device_invite_eid,
        signer_type: 3,
        signature: [0u8; 64],
    });
    let mut bad_peer_shared_blob = events::encode_event(&bad_peer_shared).unwrap();
    sign_blob(&device_invite_key, &mut bad_peer_shared_blob);

    assert_projection_rejection_contains(
        &conn,
        recorded_by,
        &bad_peer_shared_blob,
        "peer_shared signer authorizes user",
    );
}

#[test]
fn test_peer_shared_rejects_peer_signed_device_link_user_mismatch() {
    let conn = setup();
    let recorded_by = "peer1";
    let mut rng = rand::thread_rng();

    let (workspace_eid, workspace_key) = setup_workspace_anchor(&conn, recorded_by);
    let (invite_a_eid, invite_a_key) =
        create_bootstrap_user_invite(&conn, recorded_by, workspace_eid, &workspace_key);
    let (user_a_eid, user_a_key) =
        project_valid_user_from_invite(&conn, recorded_by, invite_a_eid, &invite_a_key, "alice");
    let (bootstrap_device_invite_eid, bootstrap_device_invite_key) =
        project_valid_bootstrap_device_invite(&conn, recorded_by, user_a_eid, &user_a_key);
    let user_a_public_key = user_a_key.verifying_key().to_bytes();
    let _admin_eid = project_valid_admin_for_user(
        &conn,
        recorded_by,
        workspace_eid,
        &workspace_key,
        user_a_eid,
        user_a_public_key,
    );

    let admin_peer_shared_key = SigningKey::generate(&mut rng);
    let admin_peer_shared = ParsedEvent::PeerShared(crate::event_modules::PeerSharedEvent {
        created_at_ms: now_ms(),
        public_key: admin_peer_shared_key.verifying_key().to_bytes(),
        user_event_id: user_a_eid,
        device_name: "laptop".to_string(),
        signed_by: bootstrap_device_invite_eid,
        signer_type: 3,
        signature: [0u8; 64],
    });
    let mut admin_peer_shared_blob = events::encode_event(&admin_peer_shared).unwrap();
    sign_blob(&bootstrap_device_invite_key, &mut admin_peer_shared_blob);
    let admin_peer_shared_eid = insert_event_raw(&conn, recorded_by, &admin_peer_shared_blob);
    assert_eq!(
        project_one(&conn, recorded_by, &admin_peer_shared_eid).unwrap(),
        ProjectionDecision::Valid
    );

    let (invite_b_eid, invite_b_key) =
        create_bootstrap_user_invite(&conn, recorded_by, workspace_eid, &workspace_key);
    let (user_b_eid, _user_b_key) =
        project_valid_user_from_invite(&conn, recorded_by, invite_b_eid, &invite_b_key, "bob");

    let link_device_invite_key = SigningKey::generate(&mut rng);
    let link_device_invite = ParsedEvent::DeviceInvite(crate::event_modules::DeviceInviteEvent {
        created_at_ms: now_ms(),
        public_key: link_device_invite_key.verifying_key().to_bytes(),
        authority_event_id: user_a_eid,
        signed_by: admin_peer_shared_eid,
        signer_type: 5,
        signature: [0u8; 64],
    });
    let mut link_device_invite_blob = events::encode_event(&link_device_invite).unwrap();
    sign_blob(&admin_peer_shared_key, &mut link_device_invite_blob);
    let link_device_invite_eid = insert_event_raw(&conn, recorded_by, &link_device_invite_blob);
    assert_eq!(
        project_one(&conn, recorded_by, &link_device_invite_eid).unwrap(),
        ProjectionDecision::Valid
    );

    let bad_peer_shared = ParsedEvent::PeerShared(crate::event_modules::PeerSharedEvent {
        created_at_ms: now_ms(),
        public_key: SigningKey::generate(&mut rng).verifying_key().to_bytes(),
        user_event_id: user_b_eid,
        device_name: "phone".to_string(),
        signed_by: link_device_invite_eid,
        signer_type: 3,
        signature: [0u8; 64],
    });
    let mut bad_peer_shared_blob = events::encode_event(&bad_peer_shared).unwrap();
    sign_blob(&link_device_invite_key, &mut bad_peer_shared_blob);

    assert_projection_rejection_contains(
        &conn,
        recorded_by,
        &bad_peer_shared_blob,
        "peer_shared signer authorizes user",
    );
}

#[test]
fn test_user_invite_rejects_bootstrap_authority_mismatch_at_projection() {
    let conn = setup();
    let recorded_by = "peer1";
    let mut rng = rand::thread_rng();

    let (workspace_eid, workspace_key) = setup_workspace_anchor(&conn, recorded_by);
    let (invite_eid, invite_key) =
        create_bootstrap_user_invite(&conn, recorded_by, workspace_eid, &workspace_key);
    let (user_eid, user_key) =
        project_valid_user_from_invite(&conn, recorded_by, invite_eid, &invite_key, "alice");
    let admin_eid = project_valid_admin_for_user(
        &conn,
        recorded_by,
        workspace_eid,
        &workspace_key,
        user_eid,
        user_key.verifying_key().to_bytes(),
    );

    let bad_invite = ParsedEvent::UserInvite(crate::event_modules::UserInviteEvent {
        created_at_ms: now_ms(),
        public_key: SigningKey::generate(&mut rng).verifying_key().to_bytes(),
        workspace_id: workspace_eid,
        authority_event_id: admin_eid,
        signed_by: workspace_eid,
        signer_type: 1,
        signature: [0u8; 64],
    });
    let mut bad_invite_blob = events::encode_event(&bad_invite).unwrap();
    sign_blob(&workspace_key, &mut bad_invite_blob);

    assert_projection_rejection_contains(
        &conn,
        recorded_by,
        &bad_invite_blob,
        "bootstrap user_invite must use workspace as signer and authority",
    );
}

#[test]
fn test_user_invite_projects_with_peer_signed_admin_authority() {
    let conn = setup();
    let recorded_by = "peer1";
    let mut rng = rand::thread_rng();

    let (workspace_eid, workspace_key) = setup_workspace_anchor(&conn, recorded_by);
    let (invite_eid, invite_key) =
        create_bootstrap_user_invite(&conn, recorded_by, workspace_eid, &workspace_key);
    let (user_eid, user_key) =
        project_valid_user_from_invite(&conn, recorded_by, invite_eid, &invite_key, "alice");
    let (admin_eid, admin_peer_shared_eid, admin_peer_shared_key) = setup_admin_signer_peer(
        &conn,
        recorded_by,
        workspace_eid,
        &workspace_key,
        user_eid,
        &user_key,
        "laptop",
    );

    let user_invite = ParsedEvent::UserInvite(crate::event_modules::UserInviteEvent {
        created_at_ms: now_ms(),
        public_key: SigningKey::generate(&mut rng).verifying_key().to_bytes(),
        workspace_id: workspace_eid,
        authority_event_id: admin_eid,
        signed_by: admin_peer_shared_eid,
        signer_type: 5,
        signature: [0u8; 64],
    });
    let mut user_invite_blob = events::encode_event(&user_invite).unwrap();
    sign_blob(&admin_peer_shared_key, &mut user_invite_blob);
    let user_invite_eid = insert_event_raw(&conn, recorded_by, &user_invite_blob);

    assert_eq!(
        project_one(&conn, recorded_by, &user_invite_eid).unwrap(),
        ProjectionDecision::Valid
    );
}

#[test]
fn test_user_invite_rejects_peer_signed_authority_mismatch_at_projection() {
    let conn = setup();
    let recorded_by = "peer1";
    let mut rng = rand::thread_rng();

    let (workspace_eid, workspace_key) = setup_workspace_anchor(&conn, recorded_by);
    let (invite_a_eid, invite_a_key) =
        create_bootstrap_user_invite(&conn, recorded_by, workspace_eid, &workspace_key);
    let (user_a_eid, user_a_key) =
        project_valid_user_from_invite(&conn, recorded_by, invite_a_eid, &invite_a_key, "alice");
    let (_admin_a_eid, admin_peer_shared_eid, admin_peer_shared_key) = setup_admin_signer_peer(
        &conn,
        recorded_by,
        workspace_eid,
        &workspace_key,
        user_a_eid,
        &user_a_key,
        "laptop",
    );

    let (invite_b_eid, invite_b_key) =
        create_bootstrap_user_invite(&conn, recorded_by, workspace_eid, &workspace_key);
    let (user_b_eid, user_b_key) =
        project_valid_user_from_invite(&conn, recorded_by, invite_b_eid, &invite_b_key, "bob");
    let admin_b_eid = project_valid_admin_for_user(
        &conn,
        recorded_by,
        workspace_eid,
        &workspace_key,
        user_b_eid,
        user_b_key.verifying_key().to_bytes(),
    );

    let bad_invite = ParsedEvent::UserInvite(crate::event_modules::UserInviteEvent {
        created_at_ms: now_ms(),
        public_key: SigningKey::generate(&mut rng).verifying_key().to_bytes(),
        workspace_id: workspace_eid,
        authority_event_id: admin_b_eid,
        signed_by: admin_peer_shared_eid,
        signer_type: 5,
        signature: [0u8; 64],
    });
    let mut bad_invite_blob = events::encode_event(&bad_invite).unwrap();
    sign_blob(&admin_peer_shared_key, &mut bad_invite_blob);

    assert_projection_rejection_contains(
        &conn,
        recorded_by,
        &bad_invite_blob,
        "peer-signed user_invite authority does not match signer admin identity",
    );
}

#[test]
fn test_device_invite_rejects_bootstrap_authority_mismatch_at_projection() {
    let conn = setup();
    let recorded_by = "peer1";
    let mut rng = rand::thread_rng();

    let (workspace_eid, workspace_key) = setup_workspace_anchor(&conn, recorded_by);
    let (invite_eid, invite_key) =
        create_bootstrap_user_invite(&conn, recorded_by, workspace_eid, &workspace_key);
    let (user_eid, user_key) =
        project_valid_user_from_invite(&conn, recorded_by, invite_eid, &invite_key, "alice");
    let (invite_b_eid, invite_b_key) =
        create_bootstrap_user_invite(&conn, recorded_by, workspace_eid, &workspace_key);
    let (user_b_eid, _user_b_key) =
        project_valid_user_from_invite(&conn, recorded_by, invite_b_eid, &invite_b_key, "bob");

    let bad_invite = ParsedEvent::DeviceInvite(crate::event_modules::DeviceInviteEvent {
        created_at_ms: now_ms(),
        public_key: SigningKey::generate(&mut rng).verifying_key().to_bytes(),
        authority_event_id: user_b_eid,
        signed_by: user_eid,
        signer_type: 4,
        signature: [0u8; 64],
    });
    let mut bad_invite_blob = events::encode_event(&bad_invite).unwrap();
    sign_blob(&user_key, &mut bad_invite_blob);

    assert_projection_rejection_contains(
        &conn,
        recorded_by,
        &bad_invite_blob,
        "bootstrap device_invite authority must match signer user event",
    );
}

#[test]
fn test_device_invite_projects_with_peer_signed_admin_authority() {
    let conn = setup();
    let recorded_by = "peer1";
    let mut rng = rand::thread_rng();

    let (workspace_eid, workspace_key) = setup_workspace_anchor(&conn, recorded_by);
    let (invite_eid, invite_key) =
        create_bootstrap_user_invite(&conn, recorded_by, workspace_eid, &workspace_key);
    let (user_eid, user_key) =
        project_valid_user_from_invite(&conn, recorded_by, invite_eid, &invite_key, "alice");
    let (_admin_eid, admin_peer_shared_eid, admin_peer_shared_key) = setup_admin_signer_peer(
        &conn,
        recorded_by,
        workspace_eid,
        &workspace_key,
        user_eid,
        &user_key,
        "laptop",
    );

    let device_invite = ParsedEvent::DeviceInvite(crate::event_modules::DeviceInviteEvent {
        created_at_ms: now_ms(),
        public_key: SigningKey::generate(&mut rng).verifying_key().to_bytes(),
        authority_event_id: user_eid,
        signed_by: admin_peer_shared_eid,
        signer_type: 5,
        signature: [0u8; 64],
    });
    let mut device_invite_blob = events::encode_event(&device_invite).unwrap();
    sign_blob(&admin_peer_shared_key, &mut device_invite_blob);
    let device_invite_eid = insert_event_raw(&conn, recorded_by, &device_invite_blob);

    assert_eq!(
        project_one(&conn, recorded_by, &device_invite_eid).unwrap(),
        ProjectionDecision::Valid
    );
}

#[test]
fn test_device_invite_rejects_peer_signed_authority_mismatch_at_projection() {
    let conn = setup();
    let recorded_by = "peer1";
    let mut rng = rand::thread_rng();

    let (workspace_eid, workspace_key) = setup_workspace_anchor(&conn, recorded_by);
    let (invite_a_eid, invite_a_key) =
        create_bootstrap_user_invite(&conn, recorded_by, workspace_eid, &workspace_key);
    let (user_a_eid, user_a_key) =
        project_valid_user_from_invite(&conn, recorded_by, invite_a_eid, &invite_a_key, "alice");
    let (_admin_a_eid, admin_peer_shared_eid, admin_peer_shared_key) = setup_admin_signer_peer(
        &conn,
        recorded_by,
        workspace_eid,
        &workspace_key,
        user_a_eid,
        &user_a_key,
        "laptop",
    );

    let (invite_b_eid, invite_b_key) =
        create_bootstrap_user_invite(&conn, recorded_by, workspace_eid, &workspace_key);
    let (user_b_eid, user_b_key) =
        project_valid_user_from_invite(&conn, recorded_by, invite_b_eid, &invite_b_key, "bob");
    let _admin_b_eid = project_valid_admin_for_user(
        &conn,
        recorded_by,
        workspace_eid,
        &workspace_key,
        user_b_eid,
        user_b_key.verifying_key().to_bytes(),
    );

    let bad_invite = ParsedEvent::DeviceInvite(crate::event_modules::DeviceInviteEvent {
        created_at_ms: now_ms(),
        public_key: SigningKey::generate(&mut rng).verifying_key().to_bytes(),
        authority_event_id: user_b_eid,
        signed_by: admin_peer_shared_eid,
        signer_type: 5,
        signature: [0u8; 64],
    });
    let mut bad_invite_blob = events::encode_event(&bad_invite).unwrap();
    sign_blob(&admin_peer_shared_key, &mut bad_invite_blob);

    assert_projection_rejection_contains(
        &conn,
        recorded_by,
        &bad_invite_blob,
        "peer-signed device_invite authority does not match signer user identity",
    );
}

#[test]
fn test_emit_cross_tenant_records_and_projects() {
    use crate::projection::emit::emit_deterministic_event;

    let conn = setup();
    let tenant_a = "tenant_a";
    let tenant_b = "tenant_b";
    let net_eid = setup_workspace_event(&conn, tenant_a);
    // Also mark valid for tenant_b
    insert_recorded_event(&conn, tenant_b, &net_eid, now_ms() as i64, "test").unwrap();
    mark_valid_for_test(&conn, tenant_b, &net_eid, events::EVENT_TYPE_WORKSPACE);

    // Use a KeySecret event (unsigned, no signer_required) for the cross-tenant
    // emit test. This avoids needing to set up identity chains for emit_deterministic_event.
    let sk = ParsedEvent::KeySecret(KeySecretEvent {
        created_at_ms: 1000,
        key_bytes: [42u8; 32],
    });

    // Tenant A emits it
    let eid_a = emit_deterministic_event(&conn, tenant_a, &sk).unwrap();
    let eid_b64 = event_id_to_base64(&eid_a);

    // Tenant B emits the same deterministic event
    let eid_b = emit_deterministic_event(&conn, tenant_b, &sk).unwrap();
    assert_eq!(
        eid_a, eid_b,
        "same deterministic event should produce same event_id"
    );

    // Global events table: 1 row
    let event_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM events WHERE event_id = ?1",
            rusqlite::params![&eid_b64],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(event_count, 1);

    // recorded_events: 2 rows (one per tenant)
    let rec_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM recorded_events WHERE event_id = ?1",
            rusqlite::params![&eid_b64],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(rec_count, 2);

    // valid_events: 2 rows (one per tenant)
    for tenant in [tenant_a, tenant_b] {
        let valid: bool = conn
            .query_row(
                "SELECT COUNT(*) > 0 FROM valid_events WHERE peer_id = ?1 AND event_id = ?2",
                rusqlite::params![tenant, &eid_b64],
                |row| row.get(0),
            )
            .unwrap();
        assert!(valid, "tenant {} should have valid_events entry", tenant);
    }

    // key_secrets: 2 rows (one per tenant)
    let sk_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM key_secrets WHERE event_id = ?1",
            rusqlite::params![&eid_b64],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(sk_count, 2, "both tenants should have projected key_secret");
}

#[test]
fn test_emit_local_share_scope_no_shared_event_index() {
    use crate::projection::emit::emit_deterministic_event;

    let conn = setup();
    let recorded_by = "peer1";

    // KeySecretEvent has ShareScope::Local
    let sk = ParsedEvent::KeySecret(KeySecretEvent {
        created_at_ms: 2000,
        key_bytes: [42u8; 32],
    });

    let eid = emit_deterministic_event(&conn, recorded_by, &sk).unwrap();
    let eid_b64 = event_id_to_base64(&eid);

    // events table should have the event
    let event_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM events WHERE event_id = ?1",
            rusqlite::params![&eid_b64],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(event_count, 1);

    // recorded_events should have the entry
    let rec_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM recorded_events WHERE event_id = ?1 AND peer_id = ?2",
            rusqlite::params![&eid_b64, recorded_by],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(rec_count, 1);

    // shared_event_index should have 0 rows (ShareScope::Local)
    let shared_event_index_count: i64 = conn
        .query_row("SELECT COUNT(*) FROM shared_event_index", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(
        shared_event_index_count, 0,
        "local-scope events must not be inserted into shared_event_index"
    );
}

#[test]
fn test_post_tombstone_wrong_author_deletion_rejects() {
    let conn = setup();
    let recorded_by = "peer1";
    let _net_eid = setup_workspace_event(&conn, recorded_by);

    // Create identity chain for signing
    let (signer_eid, signing_key) = make_identity_chain(&conn, recorded_by);

    // Create and project a message (author_id = [2u8; 32])
    let (_msg, msg_blob) =
        make_message_signed(&signing_key, &signer_eid, "post-tombstone auth test");
    let msg_eid = insert_event_raw(&conn, recorded_by, &msg_blob);
    project_one(&conn, recorded_by, &msg_eid).unwrap();

    // Delete with correct author → Valid
    let (_del1, del1_blob) = make_deletion_signed(&signing_key, &signer_eid, &msg_eid, [2u8; 32]);
    let del1_eid = insert_event_raw(&conn, recorded_by, &del1_blob);
    let r1 = project_one(&conn, recorded_by, &del1_eid).unwrap();
    assert_eq!(r1, ProjectionDecision::Valid);

    // Second deletion with wrong author_id = [99u8; 32] — also signed
    let (_del2, del2_blob) = make_deletion_signed(&signing_key, &signer_eid, &msg_eid, [99u8; 32]);
    let del2_eid = insert_event_raw(&conn, recorded_by, &del2_blob);
    let r2 = project_one(&conn, recorded_by, &del2_eid).unwrap();

    // Should be Reject, NOT AlreadyProcessed or Valid
    match r2 {
        ProjectionDecision::Reject { reason } => {
            assert!(
                reason.contains("author") || reason.contains("signer"),
                "reason: {}",
                reason
            );
        }
        other => panic!(
            "expected Reject for wrong-author post-tombstone deletion, got {:?}",
            other
        ),
    }

    // rejected_events should have an entry for the wrong-author deletion
    let del2_b64 = event_id_to_base64(&del2_eid);
    let rej_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM rejected_events WHERE peer_id = ?1 AND event_id = ?2",
            rusqlite::params![recorded_by, &del2_b64],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(rej_count, 1);
}

#[test]
fn test_rejected_events_recorded_for_invalid_sig() {
    let conn = setup();
    let recorded_by = "peer1";
    let mut rng = rand::thread_rng();
    let wrong_key = SigningKey::generate(&mut rng);

    // Create identity chain as signer
    let (signer_eid, _signing_key) = make_identity_chain(&conn, recorded_by);

    // Sign the message with the WRONG key
    let (_msg, msg_blob) = make_message_signed(&wrong_key, &signer_eid, "bad sig msg");
    let msg_eid = insert_event_raw(&conn, recorded_by, &msg_blob);

    let result = project_one(&conn, recorded_by, &msg_eid).unwrap();
    assert!(matches!(result, ProjectionDecision::Reject { .. }));

    // Verify rejected_events row exists with correct reason
    let msg_b64 = event_id_to_base64(&msg_eid);
    let rej_reason: String = conn
        .query_row(
            "SELECT reason FROM rejected_events WHERE peer_id = ?1 AND event_id = ?2",
            rusqlite::params![recorded_by, &msg_b64],
            |row| row.get(0),
        )
        .unwrap();
    assert!(
        rej_reason.contains("invalid signature"),
        "reason: {}",
        rej_reason
    );
}
