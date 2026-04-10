use super::*;
use rusqlite::OptionalExtension;

#[test]
fn test_endpoint_secret_projects_under_endpoint_scope() {
    let conn = setup();
    let private_key_bytes = [0x11u8; 32];
    let endpoint_id = crate::event_modules::endpoint_secret::endpoint_id_from_private_key_bytes(
        &private_key_bytes,
    );
    let event = crate::event_modules::endpoint_secret::deterministic_endpoint_secret_event(
        private_key_bytes,
    );
    let event_id = create_event_synchronous(&conn, &endpoint_id, &event).unwrap();

    let stored: (String, String) = conn
        .query_row(
            "SELECT endpoint_id, event_id FROM endpoint_secrets LIMIT 1",
            [],
            |row| {
                Ok((
                    crate::db::sql_types::get_text(row, 0)?,
                    crate::db::sql_types::get_text(row, 1)?,
                ))
            },
        )
        .unwrap();
    assert_eq!(stored.0, endpoint_id);
    assert_eq!(stored.1, event_id_to_base64(&event_id));
}

#[test]
fn test_endpoint_secret_rejects_mismatched_scope() {
    let conn = setup();
    let private_key_bytes = [0x22u8; 32];
    let event = crate::event_modules::endpoint_secret::deterministic_endpoint_secret_event(
        private_key_bytes,
    );
    let blob = events::encode_event(&event).unwrap();
    let event_id = insert_event_raw(&conn, "wrong-endpoint-scope", &blob);

    let result = project_one(&conn, "wrong-endpoint-scope", &event_id).unwrap();
    match result {
        ProjectionDecision::Reject { reason } => {
            assert!(
                reason.contains("endpoint_secret recorded_by must equal endpoint_id"),
                "reason: {}",
                reason
            );
        }
        other => panic!("expected Reject, got {:?}", other),
    }

    let event_id_b64 = event_id_to_base64(&event_id);
    let rej_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM rejected_events WHERE peer_id = ?1 AND event_id = ?2",
            rusqlite::params!["wrong-endpoint-scope", &event_id_b64],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(rej_count, 1, "rejected_events row must be recorded");
}

#[test]
fn test_endpoint_shared_projects_under_endpoint_scope() {
    let conn = setup();
    let private_key_bytes = [0x33u8; 32];
    let endpoint_id = crate::event_modules::endpoint_secret::endpoint_id_from_private_key_bytes(
        &private_key_bytes,
    );
    let event = crate::event_modules::endpoint_shared::deterministic_endpoint_shared_event(
        private_key_bytes,
    );
    let event_id = create_event_synchronous(&conn, &endpoint_id, &event).unwrap();

    let stored: (String, String) = conn
        .query_row(
            "SELECT endpoint_id, event_id FROM endpoints_shared LIMIT 1",
            [],
            |row| {
                Ok((
                    crate::db::sql_types::get_text(row, 0)?,
                    crate::db::sql_types::get_text(row, 1)?,
                ))
            },
        )
        .unwrap();
    assert_eq!(stored.0, endpoint_id);
    assert_eq!(stored.1, event_id_to_base64(&event_id));
}

#[test]
fn test_endpoint_shared_rejects_mismatched_scope() {
    let conn = setup();
    let event =
        crate::event_modules::endpoint_shared::deterministic_endpoint_shared_event([0x44u8; 32]);
    let blob = events::encode_event(&event).unwrap();
    let event_id = insert_event_raw(&conn, "wrong-endpoint-scope", &blob);

    let result = project_one(&conn, "wrong-endpoint-scope", &event_id).unwrap();
    match result {
        ProjectionDecision::Reject { reason } => {
            assert!(
                reason.contains("endpoint_shared recorded_by must equal endpoint_id"),
                "reason: {}",
                reason
            );
        }
        other => panic!("expected Reject, got {:?}", other),
    }

    let event_id_b64 = event_id_to_base64(&event_id);
    let rej_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM rejected_events WHERE peer_id = ?1 AND event_id = ?2",
            rusqlite::params!["wrong-endpoint-scope", &event_id_b64],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(rej_count, 1, "rejected_events row must be recorded");
}

#[test]
fn test_endpoint_shared_rejects_invalid_signature() {
    let conn = setup();
    let private_key_bytes = [0x55u8; 32];
    let endpoint_id = crate::event_modules::endpoint_secret::endpoint_id_from_private_key_bytes(
        &private_key_bytes,
    );
    let mut blob = events::encode_event(
        &crate::event_modules::endpoint_shared::deterministic_endpoint_shared_event(
            private_key_bytes,
        ),
    )
    .unwrap();
    let last = blob.len() - 1;
    blob[last] ^= 0x01;
    let event_id = insert_event_raw(&conn, &endpoint_id, &blob);

    let result = project_one(&conn, &endpoint_id, &event_id).unwrap();
    match result {
        ProjectionDecision::Reject { reason } => {
            assert!(
                reason.contains("endpoint_shared self-signature verification failed"),
                "reason: {}",
                reason
            );
        }
        other => panic!("expected Reject, got {:?}", other),
    }

    let event_id_b64 = event_id_to_base64(&event_id);
    let rej_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM rejected_events WHERE peer_id = ?1 AND event_id = ?2",
            rusqlite::params![&endpoint_id, &event_id_b64],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(rej_count, 1, "rejected_events row must be recorded");
}

#[test]
fn test_peer_shared_blocks_when_endpoint_shared_missing() {
    let conn = setup();
    let recorded_by = "peer1";
    let mut rng = rand::thread_rng();

    let (workspace_eid, workspace_key) = setup_workspace_anchor(&conn, recorded_by);
    let (invite_eid, invite_key) =
        create_bootstrap_user_invite(&conn, recorded_by, workspace_eid, &workspace_key);
    let (user_eid, user_key) =
        project_valid_user_from_invite(&conn, recorded_by, invite_eid, &invite_key, "alice");
    let (device_invite_eid, device_invite_key) =
        project_valid_bootstrap_device_invite(&conn, recorded_by, user_eid, &user_key);

    let endpoint_key = SigningKey::generate(&mut rng);
    let endpoint_event = crate::event_modules::endpoint_shared::deterministic_endpoint_shared_event(
        endpoint_key.to_bytes(),
    );
    let endpoint_eid = crate::crypto::hash_event(&events::encode_event(&endpoint_event).unwrap());

    let peer_shared = ParsedEvent::PeerShared(crate::event_modules::PeerSharedEvent {
        created_at_ms: now_ms(),
        public_key: SigningKey::generate(&mut rng).verifying_key().to_bytes(),
        user_event_id: user_eid,
        endpoint_shared_event_id: endpoint_eid,
        device_name: "device".to_string(),
    });
    let peer_shared_blob = sign_blob(&device_invite_key, &device_invite_eid, &peer_shared);
    let peer_shared_eid = insert_event_raw(&conn, recorded_by, &peer_shared_blob);

    match project_one(&conn, recorded_by, &peer_shared_eid).unwrap() {
        ProjectionDecision::Block { missing } => {
            assert!(
                missing.contains(&endpoint_eid),
                "missing deps should include endpoint_shared"
            );
        }
        other => panic!("expected Block, got {:?}", other),
    }
}

#[test]
fn test_peer_shared_unblocks_after_endpoint_shared_projects() {
    let conn = setup();
    let recorded_by = "peer1";
    let mut rng = rand::thread_rng();

    let (workspace_eid, workspace_key) = setup_workspace_anchor(&conn, recorded_by);
    let (invite_eid, invite_key) =
        create_bootstrap_user_invite(&conn, recorded_by, workspace_eid, &workspace_key);
    let (user_eid, user_key) =
        project_valid_user_from_invite(&conn, recorded_by, invite_eid, &invite_key, "alice");
    let (device_invite_eid, device_invite_key) =
        project_valid_bootstrap_device_invite(&conn, recorded_by, user_eid, &user_key);

    let endpoint_key = SigningKey::generate(&mut rng);
    let endpoint_event = crate::event_modules::endpoint_shared::deterministic_endpoint_shared_event(
        endpoint_key.to_bytes(),
    );
    let endpoint_blob = events::encode_event(&endpoint_event).unwrap();
    let endpoint_eid = crate::crypto::hash_event(&endpoint_blob);
    let endpoint_id = hex::encode(endpoint_key.verifying_key().to_bytes());

    let peer_shared = ParsedEvent::PeerShared(crate::event_modules::PeerSharedEvent {
        created_at_ms: now_ms(),
        public_key: SigningKey::generate(&mut rng).verifying_key().to_bytes(),
        user_event_id: user_eid,
        endpoint_shared_event_id: endpoint_eid,
        device_name: "device".to_string(),
    });
    let peer_shared_blob = sign_blob(&device_invite_key, &device_invite_eid, &peer_shared);
    let peer_shared_eid = insert_event_raw(&conn, recorded_by, &peer_shared_blob);

    assert!(matches!(
        project_one(&conn, recorded_by, &peer_shared_eid).unwrap(),
        ProjectionDecision::Block { .. }
    ));

    insert_event_raw(&conn, &endpoint_id, &endpoint_blob);
    assert_eq!(
        project_one(&conn, &endpoint_id, &endpoint_eid).unwrap(),
        ProjectionDecision::Valid
    );

    let peer_shared_eid_b64 = event_id_to_base64(&peer_shared_eid);
    let projected: (String, String) = conn
        .query_row(
            "SELECT endpoint_id, endpoint_shared_event_id
             FROM peers_shared
             WHERE recorded_by = ?1
               AND event_id = ?2",
            rusqlite::params![recorded_by, &peer_shared_eid_b64],
            |row| {
                Ok((
                    crate::db::sql_types::get_text(row, 0)?,
                    crate::db::sql_types::get_text(row, 1)?,
                ))
            },
        )
        .unwrap();
    assert_eq!(projected.0, endpoint_id);
    assert_eq!(projected.1, event_id_to_base64(&endpoint_eid));
}

#[test]
fn test_ingest_endpoint_shared_normalizes_to_endpoint_scope() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("endpoint-ingest.db");
    let conn = crate::db::open_connection(db_path.to_str().unwrap()).unwrap();
    crate::db::schema::create_tables(&conn).unwrap();
    drop(conn);

    let endpoint_key = SigningKey::generate(&mut rand::thread_rng());
    let endpoint_event = crate::event_modules::endpoint_shared::deterministic_endpoint_shared_event(
        endpoint_key.to_bytes(),
    );
    let endpoint_blob = events::encode_event(&endpoint_event).unwrap();
    let endpoint_eid = crate::crypto::hash_event(&endpoint_blob);
    let endpoint_id = hex::encode(endpoint_key.verifying_key().to_bytes());

    crate::state::pipeline::ingest_now(
        db_path.to_str().unwrap(),
        vec![(
            endpoint_eid,
            endpoint_blob,
            "tenant-a".to_string(),
            "sync".to_string(),
            0,
            0,
        )],
    )
    .unwrap();

    let conn = crate::db::open_connection(db_path.to_str().unwrap()).unwrap();
    let endpoint_eid_b64 = event_id_to_base64(&endpoint_eid);
    let normalized_recorded: bool = conn
        .query_row(
            "SELECT COUNT(*) > 0
             FROM recorded_events
             WHERE peer_id = ?1 AND event_id = ?2",
            rusqlite::params![&endpoint_id, &endpoint_eid_b64],
            |row| row.get(0),
        )
        .unwrap();
    assert!(
        normalized_recorded,
        "endpoint_shared should record under endpoint scope"
    );

    let tenant_recorded: bool = conn
        .query_row(
            "SELECT COUNT(*) > 0
             FROM recorded_events
             WHERE peer_id = ?1 AND event_id = ?2",
            rusqlite::params!["tenant-a", &endpoint_eid_b64],
            |row| row.get(0),
        )
        .unwrap();
    assert!(
        !tenant_recorded,
        "endpoint_shared should not remain recorded under tenant scope"
    );

    let projected: Option<String> = conn
        .query_row(
            "SELECT endpoint_id
             FROM endpoints_shared
             WHERE event_id = ?1",
            rusqlite::params![&endpoint_eid_b64],
            |row| crate::db::sql_types::get_text(row, 0),
        )
        .optional()
        .unwrap();
    assert_eq!(projected.as_deref(), Some(endpoint_id.as_str()));
}

#[test]
fn test_unsupported_signer_type_rejects() {
    let conn = setup();
    let recorded_by = "peer1";

    let unsupported_signer = ParsedEvent::BenchDep(BenchDepEvent {
        created_at_ms: now_ms(),
        dep_ids: Vec::new(),
        payload: [0xAB; 16],
    });
    let unsupported_signer_blob = events::encode_event(&unsupported_signer).unwrap();
    let unsupported_signer_eid = insert_event_raw(&conn, recorded_by, &unsupported_signer_blob);
    assert_eq!(
        project_one(&conn, recorded_by, &unsupported_signer_eid).unwrap(),
        ProjectionDecision::Valid
    );

    let (_workspace_eid, workspace_key) = setup_workspace_anchor(&conn, recorded_by);
    let msg = ParsedEvent::Message(MessageEvent {
        created_at_ms: now_ms(),
        workspace_id: [1u8; 32],
        author_id: [2u8; 32],
        content: "bad signer type".to_string(),
    });
    let msg_blob = sign_blob(&workspace_key, &unsupported_signer_eid, &msg);
    let msg_eid = insert_event_raw(&conn, recorded_by, &msg_blob);

    let result = project_one(&conn, recorded_by, &msg_eid).unwrap();
    match result {
        ProjectionDecision::Reject { reason } => {
            assert!(
                reason.contains("semantic type code 26")
                    || reason.contains("expected one of [8, 10, 12, 14, 16]"),
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

fn assert_projection_rejection_with_reason(
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
                reason.contains(expected_substring),
                "unexpected rejection reason: {}",
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
    });
    let invite_eid = create_signed_event_synchronous(
        conn,
        recorded_by,
        &workspace_eid,
        &invite_event,
        workspace_key,
    )
    .unwrap();
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
    });
    let user_eid = create_signed_event_synchronous(
        conn,
        recorded_by,
        &invite_event_id,
        &user_event,
        invite_key,
    )
    .unwrap();
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
    });
    let device_invite_eid = create_signed_event_synchronous(
        conn,
        recorded_by,
        &user_event_id,
        &device_invite_event,
        user_key,
    )
    .unwrap();
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
    });
    create_signed_event_synchronous(
        conn,
        recorded_by,
        &workspace_eid,
        &admin_event,
        workspace_key,
    )
    .unwrap()
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
    let endpoint_shared_event_id = ensure_test_endpoint_shared(conn);
    let peer_shared_key = SigningKey::generate(&mut rng);
    let peer_shared = ParsedEvent::PeerShared(crate::event_modules::PeerSharedEvent {
        created_at_ms: now_ms(),
        public_key: peer_shared_key.verifying_key().to_bytes(),
        user_event_id,
        endpoint_shared_event_id,
        device_name: device_name.to_string(),
    });
    let peer_shared_eid = create_signed_event_synchronous(
        conn,
        recorded_by,
        &device_invite_eid,
        &peer_shared,
        device_invite_key,
    )
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
fn test_user_projects_with_workspace_signer_at_projection() {
    let conn = setup();
    let recorded_by = "peer1";

    let (workspace_eid, workspace_key) = setup_workspace_anchor(&conn, recorded_by);
    let event = ParsedEvent::User(crate::event_modules::UserEvent {
        created_at_ms: now_ms(),
        public_key: [1u8; 32],
        username: "alice".to_string(),
    });
    let blob = sign_blob(&workspace_key, &workspace_eid, &event);
    let event_id = insert_event_raw(&conn, recorded_by, &blob);
    assert_eq!(
        project_one(&conn, recorded_by, &event_id).unwrap(),
        ProjectionDecision::Valid
    );

    let users_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM users WHERE recorded_by = ?1 AND event_id = ?2",
            rusqlite::params![recorded_by, event_id_to_base64(&event_id)],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(users_count, 1);
}

#[test]
fn test_peer_shared_rejects_wrong_signer_family_at_projection() {
    let conn = setup();
    let recorded_by = "peer1";

    let (workspace_eid, workspace_key) = setup_workspace_anchor(&conn, recorded_by);
    let (invite_eid, invite_key) =
        create_bootstrap_user_invite(&conn, recorded_by, workspace_eid, &workspace_key);
    let (user_eid, user_key) =
        project_valid_user_from_invite(&conn, recorded_by, invite_eid, &invite_key, "alice");
    let admin_event = ParsedEvent::Admin(crate::event_modules::AdminEvent {
        created_at_ms: now_ms(),
        public_key: user_key.verifying_key().to_bytes(),
        user_event_id: user_eid,
    });
    let admin_eid = create_signed_event_synchronous(
        &conn,
        recorded_by,
        &workspace_eid,
        &admin_event,
        &workspace_key,
    )
    .unwrap();
    let endpoint_shared_eid = ensure_test_endpoint_shared(&conn);
    let event = ParsedEvent::PeerShared(crate::event_modules::PeerSharedEvent {
        created_at_ms: now_ms(),
        public_key: [1u8; 32],
        user_event_id: user_eid,
        endpoint_shared_event_id: endpoint_shared_eid,
        device_name: "device".to_string(),
    });
    let blob = sign_blob(&user_key, &admin_eid, &event);
    assert_projection_rejection_with_reason(
        &conn,
        recorded_by,
        &blob,
        "peer_shared signer must be device_invite, got semantic type 18",
    );
}

#[test]
fn test_admin_rejects_wrong_signer_family_at_projection() {
    let conn = setup();
    let recorded_by = "peer1";

    let (workspace_eid, workspace_key) = setup_workspace_anchor(&conn, recorded_by);
    let (invite_eid, invite_key) =
        create_bootstrap_user_invite(&conn, recorded_by, workspace_eid, &workspace_key);
    let (user_eid, _user_key) =
        project_valid_user_from_invite(&conn, recorded_by, invite_eid, &invite_key, "alice");
    let event = ParsedEvent::Admin(crate::event_modules::AdminEvent {
        created_at_ms: now_ms(),
        public_key: [1u8; 32],
        user_event_id: user_eid,
    });
    let blob = sign_blob(&invite_key, &invite_eid, &event);
    assert_projection_rejection_with_reason(
        &conn,
        recorded_by,
        &blob,
        "admin signer must be workspace, got semantic type 10",
    );
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
    };
    let user_invite_event = ParsedEvent::UserInvite(user_invite);
    let user_invite_blob = sign_blob(&workspace_key, &workspace_eid, &user_invite_event);
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
    };
    let user_parsed = ParsedEvent::User(user_event);
    let user_blob = sign_blob(&invite_key, &user_invite_eid, &user_parsed);
    let user_eid = insert_event_raw(&conn, recorded_by, &user_blob);
    assert_eq!(
        project_one(&conn, recorded_by, &user_eid).unwrap(),
        ProjectionDecision::Valid
    );

    let admin_event = ParsedEvent::Admin(crate::event_modules::AdminEvent {
        created_at_ms: now_ms(),
        public_key: user_key.verifying_key().to_bytes(),
        user_event_id: user_eid,
    });
    let admin_blob = sign_blob(&workspace_key, &workspace_eid, &admin_event);
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
    });
    let bad_admin_blob = sign_blob(&workspace_key, &workspace_eid, &bad_admin);

    assert_projection_rejection_contains(
        &conn,
        recorded_by,
        &bad_admin_blob,
        "admin public_key does not match user public_key",
    );
}

#[test]
fn test_admin_rejects_malformed_user_public_key_at_projection() {
    let conn = setup();
    let recorded_by = "peer1";

    let (workspace_eid, workspace_key) = setup_workspace_anchor(&conn, recorded_by);
    let (invite_eid, invite_key) =
        create_bootstrap_user_invite(&conn, recorded_by, workspace_eid, &workspace_key);
    let (user_eid, user_key) =
        project_valid_user_from_invite(&conn, recorded_by, invite_eid, &invite_key, "alice");
    let user_b64 = event_id_to_base64(&user_eid);

    conn.execute(
        "UPDATE users
         SET public_key = ?1
         WHERE recorded_by = ?2 AND event_id = ?3",
        rusqlite::params![vec![0xBBu8; 31], recorded_by, &user_b64],
    )
    .unwrap();

    let admin = ParsedEvent::Admin(crate::event_modules::AdminEvent {
        created_at_ms: now_ms(),
        public_key: user_key.verifying_key().to_bytes(),
        user_event_id: user_eid,
    });
    let admin_blob = sign_blob(&workspace_key, &workspace_eid, &admin);

    assert_projection_rejection_contains(&conn, recorded_by, &admin_blob, "invalid public_key");
}

#[test]
fn test_peer_shared_rejects_bootstrap_user_mismatch() {
    let conn = setup();
    let recorded_by = "peer1";
    let mut rng = rand::thread_rng();
    let endpoint_shared_event_id = ensure_test_endpoint_shared(&conn);

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
        endpoint_shared_event_id,
        device_name: "device".to_string(),
    });
    let bad_peer_shared_blob = sign_blob(&device_invite_key, &device_invite_eid, &bad_peer_shared);

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
    let endpoint_shared_event_id = ensure_test_endpoint_shared(&conn);

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
        endpoint_shared_event_id,
        device_name: "laptop".to_string(),
    });
    let admin_peer_shared_blob = sign_blob(
        &bootstrap_device_invite_key,
        &bootstrap_device_invite_eid,
        &admin_peer_shared,
    );
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
    });
    let link_device_invite_blob = sign_blob(
        &admin_peer_shared_key,
        &admin_peer_shared_eid,
        &link_device_invite,
    );
    let link_device_invite_eid = insert_event_raw(&conn, recorded_by, &link_device_invite_blob);
    assert_eq!(
        project_one(&conn, recorded_by, &link_device_invite_eid).unwrap(),
        ProjectionDecision::Valid
    );

    let bad_peer_shared = ParsedEvent::PeerShared(crate::event_modules::PeerSharedEvent {
        created_at_ms: now_ms(),
        public_key: SigningKey::generate(&mut rng).verifying_key().to_bytes(),
        user_event_id: user_b_eid,
        endpoint_shared_event_id,
        device_name: "phone".to_string(),
    });
    let bad_peer_shared_blob = sign_blob(
        &link_device_invite_key,
        &link_device_invite_eid,
        &bad_peer_shared,
    );

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
    });
    let bad_invite_blob = sign_blob(&workspace_key, &workspace_eid, &bad_invite);

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
    });
    let user_invite_blob = sign_blob(&admin_peer_shared_key, &admin_peer_shared_eid, &user_invite);
    let user_invite_eid = insert_event_raw(&conn, recorded_by, &user_invite_blob);

    assert_eq!(
        project_one(&conn, recorded_by, &user_invite_eid).unwrap(),
        ProjectionDecision::Valid
    );
}

#[test]
fn test_user_invite_projects_with_workspace_signer_family() {
    let conn = setup();
    let recorded_by = "peer1";

    let (workspace_eid, workspace_key) = setup_workspace_anchor(&conn, recorded_by);
    let (invite_eid, _invite_key) =
        create_bootstrap_user_invite(&conn, recorded_by, workspace_eid, &workspace_key);

    let event_id_b64 = event_id_to_base64(&invite_eid);
    let count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM user_invites WHERE recorded_by = ?1 AND event_id = ?2",
            rusqlite::params![recorded_by, &event_id_b64],
            |row| row.get(0),
        )
        .expect("query projected bootstrap user invite");
    assert_eq!(count, 1, "workspace-signed user_invite should project");
}

#[test]
fn test_user_invite_rejects_wrong_signer_family_at_projection() {
    let conn = setup();
    let recorded_by = "peer1";
    let mut rng = rand::thread_rng();

    let (workspace_eid, workspace_key) = setup_workspace_anchor(&conn, recorded_by);
    let (invite_eid, invite_key) =
        create_bootstrap_user_invite(&conn, recorded_by, workspace_eid, &workspace_key);
    let (user_eid, user_key) =
        project_valid_user_from_invite(&conn, recorded_by, invite_eid, &invite_key, "alice");

    let bad_invite = ParsedEvent::UserInvite(crate::event_modules::UserInviteEvent {
        created_at_ms: now_ms(),
        public_key: SigningKey::generate(&mut rng).verifying_key().to_bytes(),
        workspace_id: workspace_eid,
        authority_event_id: workspace_eid,
    });
    let bad_invite_eid = crate::projection::create::store_signed_event_only(
        &conn,
        recorded_by,
        &user_eid,
        &bad_invite,
        &user_key,
    )
    .expect("store user-signed user invite");

    match project_one(&conn, recorded_by, &bad_invite_eid).unwrap() {
        ProjectionDecision::Reject { reason } => assert!(
            reason.contains("user_invite signer must be workspace or peer_shared"),
            "unexpected reason: {reason}"
        ),
        other => panic!("expected Reject, got {:?}", other),
    }
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
    });
    let bad_invite_blob = sign_blob(&admin_peer_shared_key, &admin_peer_shared_eid, &bad_invite);

    assert_projection_rejection_contains(
        &conn,
        recorded_by,
        &bad_invite_blob,
        "peer-signed user_invite authority does not match signer admin identity",
    );
}

#[test]
fn test_device_invite_projects_with_user_signer_family() {
    let conn = setup();
    let recorded_by = "peer1";

    let (workspace_eid, workspace_key) = setup_workspace_anchor(&conn, recorded_by);
    let (invite_eid, invite_key) =
        create_bootstrap_user_invite(&conn, recorded_by, workspace_eid, &workspace_key);
    let (user_eid, user_key) =
        project_valid_user_from_invite(&conn, recorded_by, invite_eid, &invite_key, "alice");
    let (device_invite_eid, _device_invite_key) =
        project_valid_bootstrap_device_invite(&conn, recorded_by, user_eid, &user_key);

    let event_id_b64 = event_id_to_base64(&device_invite_eid);
    let count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM device_invites WHERE recorded_by = ?1 AND event_id = ?2",
            rusqlite::params![recorded_by, &event_id_b64],
            |row| row.get(0),
        )
        .expect("query projected bootstrap device invite");
    assert_eq!(count, 1, "user-signed device_invite should project");
}

#[test]
fn test_device_invite_rejects_wrong_signer_family_at_projection() {
    let conn = setup();
    let recorded_by = "peer1";
    let mut rng = rand::thread_rng();

    let (workspace_eid, workspace_key) = setup_workspace_anchor(&conn, recorded_by);
    let (invite_eid, invite_key) =
        create_bootstrap_user_invite(&conn, recorded_by, workspace_eid, &workspace_key);
    let (user_eid, _user_key) =
        project_valid_user_from_invite(&conn, recorded_by, invite_eid, &invite_key, "alice");

    let bad_invite = ParsedEvent::DeviceInvite(crate::event_modules::DeviceInviteEvent {
        created_at_ms: now_ms(),
        public_key: SigningKey::generate(&mut rng).verifying_key().to_bytes(),
        authority_event_id: user_eid,
    });
    let bad_invite_eid = crate::projection::create::store_signed_event_only(
        &conn,
        recorded_by,
        &workspace_eid,
        &bad_invite,
        &workspace_key,
    )
    .expect("store workspace-signed device invite");

    match project_one(&conn, recorded_by, &bad_invite_eid).unwrap() {
        ProjectionDecision::Reject { reason } => assert!(
            reason.contains("device_invite signer must be user or peer_shared"),
            "unexpected reason: {reason}"
        ),
        other => panic!("expected Reject, got {:?}", other),
    }
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
    });
    let bad_invite_blob = sign_blob(&user_key, &user_eid, &bad_invite);

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
    });
    let device_invite_blob = sign_blob(
        &admin_peer_shared_key,
        &admin_peer_shared_eid,
        &device_invite,
    );
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
    });
    let bad_invite_blob = sign_blob(&admin_peer_shared_key, &admin_peer_shared_eid, &bad_invite);

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
    let (_del1, del1_blob) = make_deletion_signed(&signing_key, &signer_eid, &msg_eid);
    let del1_eid = insert_event_raw(&conn, recorded_by, &del1_blob);
    let r1 = project_one(&conn, recorded_by, &del1_eid).unwrap();
    assert_eq!(r1, ProjectionDecision::Valid);

    // Second deletion from a different peer_shared signer
    let (wrong_signer_eid, wrong_signing_key) = make_identity_chain(&conn, recorded_by);
    let (_del2, del2_blob) = make_deletion_signed(&wrong_signing_key, &wrong_signer_eid, &msg_eid);
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
fn test_admin_signer_can_delete_other_users_message() {
    let conn = setup();
    let recorded_by = "peer1";

    let (workspace_eid, workspace_key) = setup_workspace_anchor(&conn, recorded_by);
    let (invite_eid, invite_key) =
        create_bootstrap_user_invite(&conn, recorded_by, workspace_eid, &workspace_key);
    let (admin_user_eid, admin_user_key) =
        project_valid_user_from_invite(&conn, recorded_by, invite_eid, &invite_key, "admin-user");
    let admin_eid = project_valid_admin_for_user(
        &conn,
        recorded_by,
        workspace_eid,
        &workspace_key,
        admin_user_eid,
        admin_user_key.verifying_key().to_bytes(),
    );

    let (msg_signer_eid, msg_signing_key) = make_identity_chain(&conn, recorded_by);
    let (_msg, msg_blob) = make_message_signed(&msg_signing_key, &msg_signer_eid, "admin delete");
    let msg_eid = insert_event_raw(&conn, recorded_by, &msg_blob);
    assert_eq!(
        project_one(&conn, recorded_by, &msg_eid).unwrap(),
        ProjectionDecision::Valid
    );

    let del_event = ParsedEvent::MessageDeletion(crate::event_modules::MessageDeletionEvent {
        created_at_ms: now_ms(),
        target_event_id: msg_eid,
    });
    let del_blob = make_signed_encrypted_blob(&admin_user_key, &admin_eid, &del_event);
    let del_eid = insert_event_raw(&conn, recorded_by, &del_blob);
    assert_eq!(
        project_one(&conn, recorded_by, &del_eid).unwrap(),
        ProjectionDecision::Valid
    );

    let msg_b64 = event_id_to_base64(&msg_eid);
    let msg_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM messages WHERE recorded_by = ?1 AND message_id = ?2",
            rusqlite::params![recorded_by, &msg_b64],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(msg_count, 0, "admin delete should purge live message row");

    let tombstone_author: String = conn
        .query_row(
            "SELECT author_id FROM deleted_messages WHERE recorded_by = ?1 AND message_id = ?2",
            rusqlite::params![recorded_by, &msg_b64],
            |row| crate::db::sql_types::get_text(row, 0),
        )
        .unwrap();
    assert_eq!(
        tombstone_author,
        event_id_to_base64(&user_for_signer(&msg_signer_eid)),
        "tombstone should retain the original message author"
    );

    let admin_intent_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM deletion_intents
             WHERE recorded_by = ?1 AND target_id = ?2 AND authorized_by_admin = 1",
            rusqlite::params![recorded_by, &msg_b64],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        admin_intent_count, 1,
        "admin delete should record wildcard intent"
    );
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
            |row| crate::db::sql_types::get_text(row, 0),
        )
        .unwrap();
    assert!(
        rej_reason.contains("invalid signature"),
        "reason: {}",
        rej_reason
    );
}
