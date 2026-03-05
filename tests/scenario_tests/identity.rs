use topo::crypto::event_id_to_base64;
use topo::db::open_connection;
use topo::testutil::{Peer, ScenarioHarness};

// =============================================================================
// Phase 7: Identity bootstrap, trust anchor, and signer chain tests
// =============================================================================

/// Helper: create a full bootstrap chain for a peer, returning all key material and event IDs.
#[allow(dead_code)]
struct BootstrapChain {
    workspace_key: ed25519_dalek::SigningKey,
    workspace_eid: [u8; 32],
    workspace_id: [u8; 32],
    invite_key: ed25519_dalek::SigningKey,
    user_invite_eid: [u8; 32],
    user_key: ed25519_dalek::SigningKey,
    user_eid: [u8; 32],
    device_invite_key: ed25519_dalek::SigningKey,
    device_invite_eid: [u8; 32],
    peer_shared_key: ed25519_dalek::SigningKey,
    peer_shared_eid: [u8; 32],
    admin_key: ed25519_dalek::SigningKey,
    admin_eid: [u8; 32],
    invite_accepted_eid: [u8; 32],
}

fn bootstrap_peer(peer: &Peer) -> BootstrapChain {
    use ed25519_dalek::SigningKey;

    let mut rng = rand::thread_rng();
    let workspace_key = SigningKey::generate(&mut rng);
    let workspace_pubkey = workspace_key.verifying_key().to_bytes();

    // 1. Workspace event
    let workspace_eid = peer.create_workspace(workspace_pubkey);
    let workspace_id = workspace_eid;

    // 2. InviteAccepted (local self-bind to workspace root)
    let invite_accepted_eid = peer.create_invite_accepted(&workspace_eid, workspace_id);

    // 3. UserInvite (signed by workspace)
    let invite_key = SigningKey::generate(&mut rng);
    let invite_pubkey = invite_key.verifying_key().to_bytes();
    let user_invite_eid =
        peer.create_user_invite_with_key(invite_pubkey, &workspace_key, &workspace_eid);

    // 4. User (signed by user_invite)
    let user_key = SigningKey::generate(&mut rng);
    let user_pubkey = user_key.verifying_key().to_bytes();
    let user_eid = peer.create_user(user_pubkey, &invite_key, &user_invite_eid);

    // 5. DeviceInvite (signed by user)
    let device_invite_key = SigningKey::generate(&mut rng);
    let device_invite_pubkey = device_invite_key.verifying_key().to_bytes();
    let device_invite_eid = peer.create_device_invite(device_invite_pubkey, &user_key, &user_eid);

    // 6. PeerShared (signed by device_invite)
    let peer_shared_key = SigningKey::generate(&mut rng);
    let peer_shared_pubkey = peer_shared_key.verifying_key().to_bytes();
    let peer_shared_eid = peer.create_peer_shared(
        peer_shared_pubkey,
        &device_invite_key,
        &device_invite_eid,
        &user_eid,
    );

    // 7. Admin (signed by workspace, dep on user)
    let admin_key = SigningKey::generate(&mut rng);
    let admin_pubkey = admin_key.verifying_key().to_bytes();
    let admin_eid = peer.create_admin(admin_pubkey, &workspace_key, &user_eid, &workspace_eid);

    BootstrapChain {
        workspace_key,
        workspace_eid,
        workspace_id,
        invite_key,
        user_invite_eid,
        user_key,
        user_eid,
        device_invite_key,
        device_invite_eid,
        peer_shared_key,
        peer_shared_eid,
        admin_key,
        admin_eid,
        invite_accepted_eid,
    }
}

/// Helper: bootstrap Bob as a new user joining Alice's workspace.
/// Alice creates a UserInvite for Bob, Bob accepts and builds his own chain.
/// Returns Bob's BootstrapChain (reuses BootstrapChain struct for consistency).
#[allow(dead_code)]
struct JoinChain {
    invite_key: ed25519_dalek::SigningKey,
    user_invite_eid: [u8; 32],
    user_key: ed25519_dalek::SigningKey,
    user_eid: [u8; 32],
    device_invite_key: ed25519_dalek::SigningKey,
    device_invite_eid: [u8; 32],
    peer_shared_key: ed25519_dalek::SigningKey,
    peer_shared_eid: [u8; 32],
    invite_accepted_eid: [u8; 32],
}

fn join_workspace(joiner: &Peer, alice_chain: &BootstrapChain, alice: &Peer) -> JoinChain {
    use ed25519_dalek::SigningKey;

    let mut rng = rand::thread_rng();

    // Alice creates a UserInvite for the joiner (signed by workspace).
    let invite_key = SigningKey::generate(&mut rng);
    let invite_pubkey = invite_key.verifying_key().to_bytes();
    let user_invite_eid = alice.create_user_invite_with_key(
        invite_pubkey,
        &alice_chain.workspace_key,
        &alice_chain.workspace_eid,
    );

    // Joiner accepts the invite (local event, binds trust anchor to Alice's workspace_id)
    let invite_accepted_eid =
        joiner.create_invite_accepted(&user_invite_eid, alice_chain.workspace_id);

    // Joiner creates User (signed by the invite key Alice gave)
    let user_key = SigningKey::generate(&mut rng);
    let user_pubkey = user_key.verifying_key().to_bytes();
    let user_eid = joiner.create_user(user_pubkey, &invite_key, &user_invite_eid);

    // Joiner creates DeviceInvite (signed by joiner's user key)
    let device_invite_key = SigningKey::generate(&mut rng);
    let device_invite_pubkey = device_invite_key.verifying_key().to_bytes();
    let device_invite_eid = joiner.create_device_invite(device_invite_pubkey, &user_key, &user_eid);

    // Joiner creates PeerShared (signed by device invite)
    let peer_shared_key = SigningKey::generate(&mut rng);
    let peer_shared_pubkey = peer_shared_key.verifying_key().to_bytes();
    let peer_shared_eid = joiner.create_peer_shared(
        peer_shared_pubkey,
        &device_invite_key,
        &device_invite_eid,
        &user_eid,
    );

    JoinChain {
        invite_key,
        user_invite_eid,
        user_key,
        user_eid,
        device_invite_key,
        device_invite_eid,
        peer_shared_key,
        peer_shared_eid,
        invite_accepted_eid,
    }
}

#[test]
fn test_bootstrap_sequence() {
    let alice = Peer::new("alice");
    let harness = ScenarioHarness::new();
    harness.track(&alice);
    let chain = bootstrap_peer(&alice);

    let db = open_connection(&alice.db_path).unwrap();

    // Verify trust anchor was set correctly
    let anchor: String = db
        .query_row(
            "SELECT workspace_id FROM invites_accepted WHERE recorded_by = ?1 ORDER BY created_at ASC, event_id ASC LIMIT 1",
            rusqlite::params![&alice.identity],
            |row| row.get(0),
        )
        .expect("trust anchor should exist");
    let expected_nid = event_id_to_base64(&chain.workspace_id);
    assert_eq!(
        anchor, expected_nid,
        "trust anchor should match workspace_id"
    );

    // Verify all events are valid
    let valid_count: i64 = db
        .query_row(
            "SELECT COUNT(*) FROM valid_events WHERE peer_id = ?1",
            rusqlite::params![&alice.identity],
            |row| row.get(0),
        )
        .unwrap();
    // At least the bootstrap chain should be valid.
    assert!(
        valid_count >= 7,
        "at least 7 identity events should be valid, got {}",
        valid_count
    );

    // Verify projection tables
    let net_count: i64 = db
        .query_row(
            "SELECT COUNT(*) FROM workspaces WHERE recorded_by = ?1",
            rusqlite::params![&alice.identity],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        net_count, 1,
        "one trust-anchored workspace should be projected"
    );

    let user_invite_count: i64 = db
        .query_row(
            "SELECT COUNT(*) FROM user_invites WHERE recorded_by = ?1",
            rusqlite::params![&alice.identity],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(user_invite_count, 1);

    let user_count: i64 = db
        .query_row(
            "SELECT COUNT(*) FROM users WHERE recorded_by = ?1",
            rusqlite::params![&alice.identity],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(user_count, 1);

    let di_count: i64 = db
        .query_row(
            "SELECT COUNT(*) FROM device_invites WHERE recorded_by = ?1",
            rusqlite::params![&alice.identity],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(di_count, 1);

    let ps_count: i64 = db
        .query_row(
            "SELECT COUNT(*) FROM peers_shared WHERE recorded_by = ?1",
            rusqlite::params![&alice.identity],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(ps_count, 1);

    let admin_count: i64 = db
        .query_row(
            "SELECT COUNT(*) FROM admins WHERE recorded_by = ?1",
            rusqlite::params![&alice.identity],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(admin_count, 1);

    let ia_count: i64 = db
        .query_row(
            "SELECT COUNT(*) FROM invites_accepted WHERE recorded_by = ?1",
            rusqlite::params![&alice.identity],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(ia_count, 1);

    harness.finish();
}

#[test]
fn test_out_of_order_identity() {
    // Record User BEFORE UserInvite — User blocks on missing dep,
    // then cascades when the full invite chain is created afterward.
    let alice = Peer::new("alice");
    let harness = ScenarioHarness::new();
    harness.track(&alice);
    let db = open_connection(&alice.db_path).unwrap();

    use ed25519_dalek::SigningKey;
    use topo::crypto::hash_event;
    use topo::event_modules::registry;
    use topo::event_modules::{
        encode_event, ParsedEvent, UserEvent, UserInviteEvent, WorkspaceEvent,
    };
    use topo::projection::apply::project_one;
    use topo::projection::signer::sign_event_bytes;

    let mut rng = rand::thread_rng();
    let workspace_key = SigningKey::generate(&mut rng);
    let workspace_pubkey = workspace_key.verifying_key().to_bytes();
    let invite_key = SigningKey::generate(&mut rng);
    let invite_pubkey = invite_key.verifying_key().to_bytes();
    let user_key = SigningKey::generate(&mut rng);
    let user_pubkey = user_key.verifying_key().to_bytes();

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let reg = registry();

    // Pre-build Workspace blob to get workspace_eid
    let net_blob = encode_event(&ParsedEvent::Workspace(WorkspaceEvent {
        created_at_ms: now_ms,
        public_key: workspace_pubkey,
        name: "test-workspace".to_string(),
    }))
    .unwrap();
    let workspace_eid = hash_event(&net_blob);
    let workspace_id = workspace_eid;

    // Pre-build UserInvite blob (signed by workspace) to get user_invite_eid
    let mut uib_blob = encode_event(&ParsedEvent::UserInvite(UserInviteEvent {
        created_at_ms: now_ms + 1,
        public_key: invite_pubkey,
        workspace_id,
        authority_event_id: workspace_eid,
        signed_by: workspace_eid,
        signer_type: 1,
        signature: [0u8; 64],
    }))
    .unwrap();
    let sig_offset = uib_blob.len() - 64;
    let sig = sign_event_bytes(&workspace_key, &uib_blob[..sig_offset]);
    uib_blob[sig_offset..].copy_from_slice(&sig);
    let user_invite_eid = hash_event(&uib_blob);

    // Build User blob (signed by invite_key, signed_by = user_invite_eid)
    let mut ub_blob = encode_event(&ParsedEvent::User(UserEvent {
        created_at_ms: now_ms + 2,
        public_key: user_pubkey,
        username: "test-user".to_string(),
        signed_by: user_invite_eid,
        signer_type: 2,
        signature: [0u8; 64],
    }))
    .unwrap();
    let sig_offset = ub_blob.len() - 64;
    let sig = sign_event_bytes(&invite_key, &ub_blob[..sig_offset]);
    ub_blob[sig_offset..].copy_from_slice(&sig);
    let user_eid = hash_event(&ub_blob);

    // Insert User RAW first (truly out-of-order!)
    let user_b64 = event_id_to_base64(&user_eid);
    let ub_meta = reg.lookup(ub_blob[0]).unwrap();
    db.execute(
        "INSERT OR IGNORE INTO events (event_id, event_type, blob, share_scope, created_at, inserted_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        rusqlite::params![&user_b64, ub_meta.type_name, &ub_blob, ub_meta.share_scope.as_str(), (now_ms + 2) as i64, now_ms as i64],
    ).unwrap();
    db.execute(
        "INSERT OR IGNORE INTO recorded_events (peer_id, event_id, recorded_at, source) VALUES (?1, ?2, ?3, 'test')",
        rusqlite::params![&alice.identity, &user_b64, now_ms as i64],
    ).unwrap();

    // Project User — should Block (signed_by dep user_invite_eid not valid)
    let result = project_one(&db, &alice.identity, &user_eid).unwrap();
    assert!(
        matches!(
            result,
            topo::projection::decision::ProjectionDecision::Block { .. }
        ),
        "User should block when UserInvite is not yet present, got {:?}",
        result,
    );
    let valid_before: bool = db
        .query_row(
            "SELECT COUNT(*) > 0 FROM valid_events WHERE peer_id = ?1 AND event_id = ?2",
            rusqlite::params![&alice.identity, &user_b64],
            |row| row.get(0),
        )
        .unwrap();
    assert!(
        !valid_before,
        "User should not be valid before invite chain"
    );

    // Insert Workspace raw + project → Block (no trust anchor yet)
    let net_b64 = event_id_to_base64(&workspace_eid);
    let net_meta = reg.lookup(net_blob[0]).unwrap();
    db.execute(
        "INSERT OR IGNORE INTO events (event_id, event_type, blob, share_scope, created_at, inserted_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        rusqlite::params![&net_b64, net_meta.type_name, &net_blob, net_meta.share_scope.as_str(), now_ms as i64, now_ms as i64],
    ).unwrap();
    db.execute(
        "INSERT OR IGNORE INTO recorded_events (peer_id, event_id, recorded_at, source) VALUES (?1, ?2, ?3, 'test')",
        rusqlite::params![&alice.identity, &net_b64, now_ms as i64],
    ).unwrap();
    let net_result = project_one(&db, &alice.identity, &workspace_eid).unwrap();
    assert!(
        matches!(
            net_result,
            topo::projection::decision::ProjectionDecision::Block { .. }
        ),
        "Workspace should block (no trust anchor yet), got {:?}",
        net_result,
    );

    // Insert UserInvite raw + project → Block (signed_by = workspace_eid not valid)
    let uib_b64 = event_id_to_base64(&user_invite_eid);
    let uib_meta = reg.lookup(uib_blob[0]).unwrap();
    db.execute(
        "INSERT OR IGNORE INTO events (event_id, event_type, blob, share_scope, created_at, inserted_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        rusqlite::params![&uib_b64, uib_meta.type_name, &uib_blob, uib_meta.share_scope.as_str(), (now_ms + 1) as i64, now_ms as i64],
    ).unwrap();
    db.execute(
        "INSERT OR IGNORE INTO recorded_events (peer_id, event_id, recorded_at, source) VALUES (?1, ?2, ?3, 'test')",
        rusqlite::params![&alice.identity, &uib_b64, now_ms as i64],
    ).unwrap();
    let uib_result = project_one(&db, &alice.identity, &user_invite_eid).unwrap();
    assert!(
        matches!(
            uib_result,
            topo::projection::decision::ProjectionDecision::Block { .. }
        ),
        "UserInvite should block (workspace dep not valid), got {:?}",
        uib_result,
    );

    // Create InviteAccepted → sets trust anchor, triggers retry_guard_blocked_events
    // which re-projects Workspace → Valid → cascades UserInvite → Valid → cascades User → Valid
    let _ia_eid = alice.create_invite_accepted(&user_invite_eid, workspace_id);

    // Assert full cascade completed — User should now be valid
    let valid_after: bool = db
        .query_row(
            "SELECT COUNT(*) > 0 FROM valid_events WHERE peer_id = ?1 AND event_id = ?2",
            rusqlite::params![&alice.identity, &user_b64],
            |row| row.get(0),
        )
        .unwrap();
    assert!(
        valid_after,
        "User should be valid after cascade from invite chain"
    );

    // Verify intermediate events are also valid
    let net_valid: bool = db
        .query_row(
            "SELECT COUNT(*) > 0 FROM valid_events WHERE peer_id = ?1 AND event_id = ?2",
            rusqlite::params![&alice.identity, &net_b64],
            |row| row.get(0),
        )
        .unwrap();
    assert!(
        net_valid,
        "Workspace should be valid after trust anchor set"
    );

    let uib_valid: bool = db
        .query_row(
            "SELECT COUNT(*) > 0 FROM valid_events WHERE peer_id = ?1 AND event_id = ?2",
            rusqlite::params![&alice.identity, &uib_b64],
            |row| row.get(0),
        )
        .unwrap();
    assert!(uib_valid, "UserInvite should be valid after cascade");

    harness.finish();
}

#[test]
fn test_foreign_workspace_excluded() {
    let alice = Peer::new("alice");
    let harness = ScenarioHarness::new();
    harness.track(&alice);
    let _chain = bootstrap_peer(&alice);

    let db = open_connection(&alice.db_path).unwrap();

    // Create a second workspace event with different workspace_id — should be rejected
    let foreign_key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
    let foreign_pubkey = foreign_key.verifying_key().to_bytes();
    let result = alice.try_create_workspace(foreign_pubkey);

    // Should be rejected (trust anchor mismatch)
    match result {
        Err(ref e) => {
            let msg = format!("{}", e);
            assert!(msg.contains("rejected"), "expected rejection, got: {}", msg);
        }
        Ok(eid) => {
            // If it wasn't rejected at creation time, check DB state
            let foreign_b64 = event_id_to_base64(&eid);
            let foreign_valid: bool = db
                .query_row(
                    "SELECT COUNT(*) > 0 FROM valid_events WHERE peer_id = ?1 AND event_id = ?2",
                    rusqlite::params![&alice.identity, &foreign_b64],
                    |row| row.get(0),
                )
                .unwrap();
            assert!(
                !foreign_valid,
                "foreign workspace event should NOT be valid"
            );
        }
    }

    // The event is in rejected_events (stored before rejection)
    let rejected_count: i64 = db.query_row(
        "SELECT COUNT(*) FROM rejected_events WHERE peer_id = ?1 AND reason LIKE '%workspace_id%'",
        rusqlite::params![&alice.identity],
        |row| row.get(0),
    ).unwrap();
    assert!(
        rejected_count > 0,
        "foreign workspace event should be rejected"
    );

    harness.finish();
}

#[test]
fn test_removal_enforcement() {
    let alice = Peer::new("alice");
    let harness = ScenarioHarness::new();
    harness.track(&alice);
    let chain = bootstrap_peer(&alice);

    // Create a "Bob" user event to be removed
    // For simplicity, create a second user (as if Bob joined)
    let bob_user_key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
    let _bob_user_pubkey = bob_user_key.verifying_key().to_bytes();
    // We'll create a second UserInvite for Bob, signed by Alice's PeerShared
    let db = open_connection(&alice.db_path).unwrap();

    // Alice removes her own user (target = user_eid, signed by peer_shared)
    let removal_eid = alice.create_user_removed(
        &chain.peer_shared_key,
        &chain.user_eid,
        &chain.peer_shared_eid,
    );

    let removal_b64 = event_id_to_base64(&removal_eid);
    let valid: bool = db
        .query_row(
            "SELECT COUNT(*) > 0 FROM valid_events WHERE peer_id = ?1 AND event_id = ?2",
            rusqlite::params![&alice.identity, &removal_b64],
            |row| row.get(0),
        )
        .unwrap();
    assert!(valid, "user_removed should be valid");

    // Verify removed_entities table updated
    let removed_count: i64 = db.query_row(
        "SELECT COUNT(*) FROM removed_entities WHERE recorded_by = ?1 AND removal_type = 'user'",
        rusqlite::params![&alice.identity],
        |row| row.get(0),
    ).unwrap();
    assert_eq!(
        removed_count, 1,
        "removed_entities should have one user removal"
    );

    harness.finish();
}

#[test]
fn test_secret_shared_key_wrap() {
    use topo::projection::encrypted::wrap_key_for_recipient;

    let alice = Peer::new("alice");
    let harness = ScenarioHarness::new();
    harness.track(&alice);
    let chain = bootstrap_peer(&alice);

    // Create SecretKey
    let secret_key_bytes: [u8; 32] = rand::random();
    let sk_eid = alice.create_secret_key_deterministic(
        secret_key_bytes,
        topo::event_modules::secret_key::deterministic_secret_key_created_at_ms(&secret_key_bytes),
    );

    // Create local invite_privkey for the bootstrap invite.
    let unwrap_key_eid =
        alice.create_invite_privkey(&chain.user_invite_eid, chain.invite_key.to_bytes());

    // Create SecretShared wrapping to the bootstrap invite.
    let wrapped_key = wrap_key_for_recipient(
        &chain.peer_shared_key,
        &chain.invite_key.verifying_key(),
        &secret_key_bytes,
    );
    let ss_eid = alice.create_secret_shared(
        &chain.peer_shared_key,
        &sk_eid,
        &chain.user_invite_eid,
        &unwrap_key_eid,
        wrapped_key,
        &chain.peer_shared_eid,
    );

    let db = open_connection(&alice.db_path).unwrap();
    let ss_b64 = event_id_to_base64(&ss_eid);
    let valid: bool = db
        .query_row(
            "SELECT COUNT(*) > 0 FROM valid_events WHERE peer_id = ?1 AND event_id = ?2",
            rusqlite::params![&alice.identity, &ss_b64],
            |row| row.get(0),
        )
        .unwrap();
    assert!(valid, "secret_shared should be valid");

    let ss_count: i64 = db
        .query_row(
            "SELECT COUNT(*) FROM secret_shared WHERE recorded_by = ?1",
            rusqlite::params![&alice.identity],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(ss_count, 1, "secret_shared should be in projection table");

    harness.finish();
}

/// Out-of-order test: SecretShared blocks until the local invite_privkey dep exists,
/// then unblocks via normal cascade once invite_privkey is projected.
#[test]
fn test_secret_shared_blocks_until_signer_valid() {
    use topo::event_modules::{ParsedEvent, SecretSharedEvent};
    use topo::projection::create::create_signed_event_staged;
    use topo::projection::encrypted::wrap_key_for_recipient;

    let alice = Peer::new("alice");
    let harness = ScenarioHarness::new();
    harness.track(&alice);

    // Alice bootstraps workspace.
    let chain = bootstrap_peer(&alice);

    // Alice creates a local content key.
    let secret_key_bytes: [u8; 32] = rand::random();
    let sk_eid = alice.create_secret_key_deterministic(
        secret_key_bytes,
        topo::event_modules::secret_key::deterministic_secret_key_created_at_ms(&secret_key_bytes),
    );

    // SecretShared depends on deterministic invite_privkey event id.
    // Do not emit invite_privkey yet, so this should block.
    let invite_privkey_eid =
        topo::event_modules::invite_privkey::deterministic_invite_privkey_event_id(
            &chain.user_invite_eid,
            &chain.invite_key.to_bytes(),
        );
    let wrapped_key = wrap_key_for_recipient(
        &chain.peer_shared_key,
        &chain.invite_key.verifying_key(),
        &secret_key_bytes,
    );
    let ss_event = ParsedEvent::SecretShared(SecretSharedEvent {
        created_at_ms: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64,
        key_event_id: sk_eid,
        recipient_event_id: chain.user_invite_eid,
        unwrap_key_event_id: invite_privkey_eid,
        wrapped_key,
        signed_by: chain.peer_shared_eid,
        signer_type: 5,
        signature: [0u8; 64],
    });
    let alice_db = open_connection(&alice.db_path).unwrap();
    let ss_eid = create_signed_event_staged(
        &alice_db,
        &alice.identity,
        &ss_event,
        &chain.peer_shared_key,
    )
    .expect("staged create should succeed even if blocked");
    let ss_b64 = event_id_to_base64(&ss_eid);

    // SecretShared should be blocked: invite_privkey dep missing.
    let blocked_count: i64 = alice_db
        .query_row(
            "SELECT COUNT(*) FROM blocked_event_deps WHERE peer_id = ?1 AND event_id = ?2",
            rusqlite::params![&alice.identity, &ss_b64],
            |row| row.get(0),
        )
        .unwrap();
    assert!(
        blocked_count >= 1,
        "SecretShared should block until invite_privkey exists"
    );

    // Emit deterministic invite_privkey; normal cascade should unblock secret_shared.
    let _ = alice.create_invite_privkey(&chain.user_invite_eid, chain.invite_key.to_bytes());

    // After invite_privkey projection + cascade, SecretShared should be valid.
    let ss_valid: bool = alice_db
        .query_row(
            "SELECT COUNT(*) > 0 FROM valid_events WHERE peer_id = ?1 AND event_id = ?2",
            rusqlite::params![&alice.identity, &ss_b64],
            |row| row.get(0),
        )
        .unwrap();
    assert!(
        ss_valid,
        "SecretShared should be valid after invite_privkey is projected"
    );

    let ss_projected: i64 = alice_db
        .query_row(
            "SELECT COUNT(*) FROM secret_shared WHERE recorded_by = ?1",
            rusqlite::params![&alice.identity],
            |row| row.get(0),
        )
        .unwrap();
    assert!(
        ss_projected >= 1,
        "SecretShared should be in projection table after cascade"
    );

    harness.finish();
}

/// Out-of-order test: encrypted wrapper arrives before local key materialization,
/// blocks, then unblocks once the deterministic key is created.
#[test]
fn test_encrypted_blocks_then_unblocks_on_key_materialization() {
    let alice = Peer::new_with_identity("alice_enc_ooo");
    let bob = Peer::new_with_identity("bob_enc_ooo");
    let harness = ScenarioHarness::new();
    harness.track(&alice);
    harness.track(&bob);

    // Step 1: Alice creates a key and encrypted message.
    let key_bytes: [u8; 32] = rand::random();
    let fixed_ts = 7_000_000u64;
    let sk_eid = alice.create_secret_key_deterministic(key_bytes, fixed_ts);
    let enc_eid = alice.create_encrypted_message(&sk_eid, "Encrypted before key on bob");

    // Verify alice can decrypt her own message
    assert_eq!(alice.scoped_message_count(), 1);

    // Manually insert the encrypted event blob into Bob's DB (simulating sync arrival
    // of ciphertext BEFORE key materialization).
    let alice_db = open_connection(&alice.db_path).unwrap();
    let enc_b64 = event_id_to_base64(&enc_eid);
    let enc_blob: Vec<u8> = alice_db
        .query_row(
            "SELECT blob FROM events WHERE event_id = ?1",
            rusqlite::params![&enc_b64],
            |row| row.get(0),
        )
        .unwrap();

    let bob_db = open_connection(&bob.db_path).unwrap();
    use topo::event_modules::registry;
    use topo::projection::apply::project_one;
    use topo::projection::decision::ProjectionDecision;
    let reg = registry();
    let enc_meta = reg.lookup(enc_blob[0]).unwrap();
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    bob_db.execute(
        "INSERT OR IGNORE INTO events (event_id, event_type, blob, share_scope, created_at, inserted_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        rusqlite::params![&enc_b64, enc_meta.type_name, &enc_blob, enc_meta.share_scope.as_str(), now_ms as i64, now_ms as i64],
    ).unwrap();
    bob_db.execute(
        "INSERT OR IGNORE INTO recorded_events (peer_id, event_id, recorded_at, source) VALUES (?1, ?2, ?3, 'test')",
        rusqlite::params![&bob.identity, &enc_b64, now_ms as i64],
    ).unwrap();

    // Project the encrypted event on Bob — should block (key_event_id dep not in valid_events).
    let result = project_one(&bob_db, &bob.identity, &enc_eid).unwrap();
    assert!(
        matches!(result, ProjectionDecision::Block { .. }),
        "Encrypted should block when key dep is missing: {:?}",
        result
    );

    // Verify key-dep blocking is recorded.
    let key_b64 = event_id_to_base64(&sk_eid);
    let blocked_on_key: bool = bob_db
        .query_row(
            "SELECT COUNT(*) > 0 FROM blocked_event_deps
         WHERE peer_id = ?1 AND event_id = ?2 AND blocker_event_id = ?3",
            rusqlite::params![&bob.identity, &enc_b64, &key_b64],
            |row| row.get(0),
        )
        .unwrap();
    assert!(
        blocked_on_key,
        "Encrypted should be blocked specifically on key_event_id dep"
    );

    // Step 3: Materialize the same deterministic key on Bob.
    let bob_sk_eid = bob.create_secret_key_deterministic(key_bytes, fixed_ts);
    assert_eq!(
        bob_sk_eid, sk_eid,
        "Deterministic key event IDs must match across peers"
    );

    // After key materialization, re-project the encrypted wrapper once to assert
    // current dependency semantics directly from the projection decision:
    // key dep must be resolved; any remaining block should be on inner deps
    // (for example foreign signer in this cross-workspace setup).
    let result_after_key = project_one(&bob_db, &bob.identity, &enc_eid).unwrap();
    if let ProjectionDecision::Block { missing } = result_after_key {
        assert!(
            !missing.contains(&sk_eid),
            "After key materialization, encrypted must not remain blocked on key_event_id",
        );
    }

    // Bob doesn't see Alice's encrypted message (foreign signer → inner rejected),
    // which is correct cross-workspace behavior.
    assert_eq!(
        bob.scoped_message_count(),
        0,
        "Bob should not see Alice's message (foreign signer in separate workspace)"
    );

    harness.finish();
}

/// Deterministic key event ID test: inviter wraps key, invitee unwraps, both see
/// the same secret_key event ID. This validates the cross-peer key agreement property
/// that underpins the invite key wrap/unwrap bootstrap flow.
#[test]
fn test_deterministic_key_event_id_matches_across_peers() {
    use ed25519_dalek::SigningKey;
    use topo::crypto::hash_event;
    use topo::event_modules::{encode_event, ParsedEvent, SecretKeyEvent};
    use topo::projection::encrypted::{unwrap_key_from_sender, wrap_key_for_recipient};

    let alice = Peer::new_with_identity("alice_det_key");
    let bob = Peer::new_with_identity("bob_det_key");
    let harness = ScenarioHarness::new();
    harness.track(&alice);
    harness.track(&bob);

    // Alice generates a content key.
    let plaintext_key: [u8; 32] = rand::random();

    // Compute deterministic created_at from key bytes (same algorithm as identity_ops).
    use blake2::digest::consts::U8;
    use blake2::{Blake2b, Digest};
    let mut hasher = Blake2b::<U8>::new();
    hasher.update(b"poc7-content-key-created-at-v1");
    hasher.update(&plaintext_key);
    let digest = hasher.finalize();
    let mut ts_bytes = [0u8; 8];
    ts_bytes.copy_from_slice(&digest[..8]);
    let deterministic_ts = u64::from_le_bytes(ts_bytes);

    // Alice creates her local secret_key with deterministic timestamp.
    let alice_sk_eid = alice.create_secret_key_deterministic(plaintext_key, deterministic_ts);

    // Simulate invite wrap/unwrap with fresh key pairs (sender wraps for invite key).
    let mut rng = rand::thread_rng();
    let sender_key = SigningKey::generate(&mut rng);
    let invite_key = SigningKey::generate(&mut rng);
    let wrapped = wrap_key_for_recipient(&sender_key, &invite_key.verifying_key(), &plaintext_key);

    // Bob unwraps using the invite private key and sender's public key.
    let unwrapped = unwrap_key_from_sender(&invite_key, &sender_key.verifying_key(), &wrapped);
    assert_eq!(
        unwrapped, plaintext_key,
        "Unwrapped key must match original plaintext"
    );

    // Bob materializes the deterministic secret_key from unwrapped bytes.
    let bob_sk_eid = bob.create_secret_key_deterministic(unwrapped, deterministic_ts);
    assert_eq!(
        bob_sk_eid, alice_sk_eid,
        "Deterministic key event ID must match between inviter and invitee"
    );

    // Also verify via manual event construction that the event_id matches.
    let sk_evt = ParsedEvent::SecretKey(SecretKeyEvent {
        created_at_ms: deterministic_ts,
        key_bytes: plaintext_key,
    });
    let expected_eid = hash_event(&encode_event(&sk_evt).unwrap());
    assert_eq!(
        expected_eid, alice_sk_eid,
        "Manual hash matches create_secret_key_deterministic"
    );

    harness.finish();
}

/// Full wrap→unwrap→encrypt→decrypt convergence: Alice wraps a key for Bob via invite key,
/// Bob unwraps and materializes local key, then an encrypted message from Alice
/// becomes decryptable (or at least unblocked) on Bob's side.
#[test]
fn test_wrap_unwrap_encrypted_convergence() {
    use ed25519_dalek::SigningKey;
    use topo::projection::encrypted::{unwrap_key_from_sender, wrap_key_for_recipient};

    let alice = Peer::new_with_identity("alice_conv");
    let bob = Peer::new_with_identity("bob_conv");
    let harness = ScenarioHarness::new();
    harness.track(&alice);
    harness.track(&bob);

    // Alice creates a content key.
    let plaintext_key: [u8; 32] = rand::random();

    // Deterministic timestamp from key bytes.
    use blake2::digest::consts::U8;
    use blake2::{Blake2b, Digest};
    let mut hasher = Blake2b::<U8>::new();
    hasher.update(b"poc7-content-key-created-at-v1");
    hasher.update(&plaintext_key);
    let digest = hasher.finalize();
    let mut ts_bytes = [0u8; 8];
    ts_bytes.copy_from_slice(&digest[..8]);
    let deterministic_ts = u64::from_le_bytes(ts_bytes);

    let alice_sk_eid = alice.create_secret_key_deterministic(plaintext_key, deterministic_ts);

    // Alice creates an encrypted message.
    let enc_eid = alice.create_encrypted_message(&alice_sk_eid, "Wrapped key convergence test");
    assert_eq!(
        alice.scoped_message_count(),
        1,
        "Alice should see her encrypted message"
    );

    // Simulate invite wrap/unwrap with fresh key pairs.
    let mut rng = rand::thread_rng();
    let sender_key = SigningKey::generate(&mut rng);
    let invite_key = SigningKey::generate(&mut rng);

    // Alice wraps the content key for the invite key.
    let wrapped = wrap_key_for_recipient(&sender_key, &invite_key.verifying_key(), &plaintext_key);

    // Bob unwraps using the invite private key and sender's public key.
    let unwrapped = unwrap_key_from_sender(&invite_key, &sender_key.verifying_key(), &wrapped);
    assert_eq!(unwrapped, plaintext_key);

    // Bob materializes the deterministic key.
    let bob_sk_eid = bob.create_secret_key_deterministic(unwrapped, deterministic_ts);
    assert_eq!(bob_sk_eid, alice_sk_eid, "Key event IDs match after unwrap");

    // Copy the encrypted event to Bob's DB (simulating sync).
    let alice_db = open_connection(&alice.db_path).unwrap();
    let enc_b64 = event_id_to_base64(&enc_eid);
    let enc_blob: Vec<u8> = alice_db
        .query_row(
            "SELECT blob FROM events WHERE event_id = ?1",
            rusqlite::params![&enc_b64],
            |row| row.get(0),
        )
        .unwrap();

    let bob_db = open_connection(&bob.db_path).unwrap();
    use topo::event_modules::registry;
    use topo::projection::apply::project_one;
    use topo::projection::decision::ProjectionDecision;
    let reg = registry();
    let enc_meta = reg.lookup(enc_blob[0]).unwrap();
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    bob_db.execute(
        "INSERT OR IGNORE INTO events (event_id, event_type, blob, share_scope, created_at, inserted_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        rusqlite::params![&enc_b64, enc_meta.type_name, &enc_blob, enc_meta.share_scope.as_str(), now_ms as i64, now_ms as i64],
    ).unwrap();
    bob_db.execute(
        "INSERT OR IGNORE INTO recorded_events (peer_id, event_id, recorded_at, source) VALUES (?1, ?2, ?3, 'test')",
        rusqlite::params![&bob.identity, &enc_b64, now_ms as i64],
    ).unwrap();

    // Project encrypted event on Bob. Key is available, so any block must be on
    // inner deps/signer, not on key_event_id.
    let result = project_one(&bob_db, &bob.identity, &enc_eid).unwrap();
    if let ProjectionDecision::Block { missing } = result {
        assert!(
            !missing.contains(&alice_sk_eid),
            "Encrypted should not block on key_event_id when local key exists",
        );
    }

    // Explicitly verify no key-dep blocker row exists for this event.
    let blocked_on_key: i64 = bob_db
        .query_row(
            "SELECT COUNT(*) FROM blocked_event_deps
         WHERE peer_id = ?1 AND event_id = ?2 AND blocker_event_id = ?3",
            rusqlite::params![&bob.identity, &enc_b64, &event_id_to_base64(&alice_sk_eid)],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        blocked_on_key, 0,
        "key_event_id blocker should be absent after key materialization"
    );

    harness.finish();
}

#[test]
fn test_identity_replay_invariants() {
    let alice = Peer::new_with_identity("alice");
    let harness = ScenarioHarness::new();
    harness.track(&alice);

    // Create some content after identity chain
    alice.create_message("hello after bootstrap");

    // Verify replay invariants (forward, double, reverse)
    harness.finish();
}

// =============================================================================
// Phase 7 logic fixes: corrected guard and binding semantics
// =============================================================================

/// invite_accepted projects without any prior invite event recorded.
/// This verifies the HasRecordedInvite guard has been removed.
#[test]
fn test_invite_accepted_no_prior_invite_required() {
    let alice = Peer::new("alice");
    let harness = ScenarioHarness::new();
    harness.track(&alice);
    let db = open_connection(&alice.db_path).unwrap();

    let workspace_id: [u8; 32] = rand::random();
    let fake_invite_eid: [u8; 32] = rand::random();

    // Create invite_accepted BEFORE any invite event exists.
    // Under old semantics this would Block; under corrected semantics it should project.
    let ia_eid = alice.create_invite_accepted(&fake_invite_eid, workspace_id);

    let ia_b64 = event_id_to_base64(&ia_eid);
    let valid: bool = db
        .query_row(
            "SELECT COUNT(*) > 0 FROM valid_events WHERE peer_id = ?1 AND event_id = ?2",
            rusqlite::params![&alice.identity, &ia_b64],
            |row| row.get(0),
        )
        .unwrap();
    assert!(
        valid,
        "invite_accepted should be valid without prior invite event (no HasRecordedInvite guard)"
    );

    // Trust anchor should be set from the event's own workspace_id
    let anchor: String = db
        .query_row(
            "SELECT workspace_id FROM invites_accepted WHERE recorded_by = ?1 ORDER BY created_at ASC, event_id ASC LIMIT 1",
            rusqlite::params![&alice.identity],
            |row| row.get(0),
        )
        .expect("trust anchor should exist");
    let expected_nid = event_id_to_base64(&workspace_id);
    assert_eq!(
        anchor, expected_nid,
        "trust anchor should match invite_accepted event's workspace_id"
    );

    harness.finish();
}

/// Accepted-workspace winner immutability: additional invite_accepted rows can project,
/// but winner selection remains earliest (created_at,event_id).
#[test]
fn test_trust_anchor_immutability() {
    let alice = Peer::new("alice");
    // This test intentionally constructs two conflicting InviteAccepted events
    // and asserts first-write-wins immutability behavior. That policy is
    // order-dependent under reverse replay, so skip replay-invariant checks.
    let harness = ScenarioHarness::skip(
        "conflicting invite_accepted first-write-wins semantics are intentionally order-dependent",
    );
    harness.track(&alice);
    let db = open_connection(&alice.db_path).unwrap();

    let workspace_id_1: [u8; 32] = rand::random();
    let workspace_id_2: [u8; 32] = rand::random();
    let fake_invite_1: [u8; 32] = rand::random();
    let fake_invite_2: [u8; 32] = rand::random();

    // First invite_accepted sets the trust anchor
    let ia1_eid = alice.create_invite_accepted(&fake_invite_1, workspace_id_1);
    let ia1_b64 = event_id_to_base64(&ia1_eid);
    let valid1: bool = db
        .query_row(
            "SELECT COUNT(*) > 0 FROM valid_events WHERE peer_id = ?1 AND event_id = ?2",
            rusqlite::params![&alice.identity, &ia1_b64],
            |row| row.get(0),
        )
        .unwrap();
    assert!(valid1, "first invite_accepted should be valid");

    // Second invite_accepted with different workspace_id should still project;
    // the winner is determined when reading invites_accepted.
    let ia2_eid = alice.create_invite_accepted(&fake_invite_2, workspace_id_2);
    let ia2_b64 = event_id_to_base64(&ia2_eid);
    let valid2: bool = db
        .query_row(
            "SELECT COUNT(*) > 0 FROM valid_events WHERE peer_id = ?1 AND event_id = ?2",
            rusqlite::params![&alice.identity, &ia2_b64],
            |row| row.get(0),
        )
        .unwrap();
    assert!(valid2, "second invite_accepted should also be valid");

    // Trust anchor should still be the first one
    let anchor: String = db
        .query_row(
            "SELECT workspace_id FROM invites_accepted WHERE recorded_by = ?1 ORDER BY created_at ASC, event_id ASC LIMIT 1",
            rusqlite::params![&alice.identity],
            |row| row.get(0),
        )
        .expect("trust anchor should still exist");
    let expected_nid = event_id_to_base64(&workspace_id_1);
    assert_eq!(anchor, expected_nid, "trust anchor should not have changed");

    let total_rows: i64 = db
        .query_row(
            "SELECT COUNT(*) FROM invites_accepted WHERE recorded_by = ?1",
            rusqlite::params![&alice.identity],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        total_rows, 2,
        "both invite_accepted rows should be projected"
    );

    harness.finish();
}

/// No pre-projection blob capture influence: manually inserting a malformed
/// invite-like blob into events should not alter trust binding state.
#[test]
fn test_no_blob_capture_trust_influence() {
    let harness =
        ScenarioHarness::skip("raw blob insertion without project_one; no projection to replay");
    let alice = Peer::new("alice");
    let db = open_connection(&alice.db_path).unwrap();

    // Manually craft a blob that looks like a UserInvite (type 10) with a specific
    // workspace_id, and insert it directly into the events table (simulating raw ingress).
    // Under old semantics, a pre-projection capture path could influence trust state.
    // Under corrected semantics, this should have no effect.
    let fake_workspace_id: [u8; 32] = [0xAA; 32];
    let mut fake_blob = vec![10u8]; // type code for UserInvite
    fake_blob.extend_from_slice(&[0u8; 40]); // created_at_ms(8) + public_key(32)
    fake_blob.extend_from_slice(&fake_workspace_id); // workspace_id at [41..73]
    fake_blob.extend_from_slice(&[0u8; 97]); // rest of the 170B blob

    let fake_eid = topo::crypto::hash_event(&fake_blob);
    let fake_b64 = event_id_to_base64(&fake_eid);

    db.execute(
        "INSERT OR IGNORE INTO events (event_id, event_type, blob, share_scope, created_at, inserted_at)
         VALUES (?1, 'user_invite', ?2, 'shared', 0, 0)",
        rusqlite::params![&fake_b64, &fake_blob],
    ).unwrap();
    db.execute(
        "INSERT OR IGNORE INTO recorded_events (peer_id, event_id, recorded_at, source)
         VALUES (?1, ?2, 0, 'test')",
        rusqlite::params![&alice.identity, &fake_b64],
    )
    .unwrap();

    // Trust anchor should be unset
    let anchor_count: i64 = db
        .query_row(
            "SELECT COUNT(*) FROM invites_accepted WHERE recorded_by = ?1",
            rusqlite::params![&alice.identity],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        anchor_count, 0,
        "trust anchor should not be set by raw blob presence"
    );

    harness.finish();
}

/// True out-of-order identity chain: record invite_accepted BEFORE its referenced
/// invite event, then record workspace, then invite event -> cascade resolves everything.
#[test]
fn test_true_out_of_order_identity_chain() {
    let alice = Peer::new("alice");
    let harness = ScenarioHarness::new();
    harness.track(&alice);
    let db = open_connection(&alice.db_path).unwrap();

    use ed25519_dalek::SigningKey;
    use topo::crypto::hash_event;
    use topo::event_modules::{encode_event, ParsedEvent, WorkspaceEvent};
    use topo::projection::create::create_event_staged;
    let mut rng = rand::thread_rng();

    let workspace_key = SigningKey::generate(&mut rng);
    let workspace_pubkey = workspace_key.verifying_key().to_bytes();
    let workspace_event = ParsedEvent::Workspace(WorkspaceEvent {
        created_at_ms: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64,
        public_key: workspace_pubkey,
        name: "test-workspace".to_string(),
    });
    let workspace_id = hash_event(&encode_event(&workspace_event).unwrap());

    // Step 1: Create invite_accepted FIRST (before workspace or invite exist).
    // Under corrected semantics, this sets the trust anchor immediately.
    let invite_key = SigningKey::generate(&mut rng);
    let invite_pubkey = invite_key.verifying_key().to_bytes();

    let dummy_invite_eid = [42u8; 32];
    let ia_eid = alice.create_invite_accepted(&dummy_invite_eid, workspace_id);

    let ia_b64 = event_id_to_base64(&ia_eid);
    let ia_valid: bool = db
        .query_row(
            "SELECT COUNT(*) > 0 FROM valid_events WHERE peer_id = ?1 AND event_id = ?2",
            rusqlite::params![&alice.identity, &ia_b64],
            |row| row.get(0),
        )
        .unwrap();
    assert!(
        ia_valid,
        "invite_accepted should be immediately valid (no HasRecordedInvite guard)"
    );

    // Step 2: Create the precomputed workspace event (same event_id as trust anchor).
    let workspace_eid = create_event_staged(&db, &alice.identity, &workspace_event)
        .expect("workspace should create once trust anchor exists");

    let net_b64 = event_id_to_base64(&workspace_eid);
    let net_valid: bool = db
        .query_row(
            "SELECT COUNT(*) > 0 FROM valid_events WHERE peer_id = ?1 AND event_id = ?2",
            rusqlite::params![&alice.identity, &net_b64],
            |row| row.get(0),
        )
        .unwrap();
    assert!(
        net_valid,
        "workspace event should be valid (trust anchor matches)"
    );

    // Step 3: Create UserInvite (signed by workspace)
    let user_invite_eid =
        alice.create_user_invite_with_key(invite_pubkey, &workspace_key, &workspace_eid);

    let ui_b64 = event_id_to_base64(&user_invite_eid);
    let ui_valid: bool = db
        .query_row(
            "SELECT COUNT(*) > 0 FROM valid_events WHERE peer_id = ?1 AND event_id = ?2",
            rusqlite::params![&alice.identity, &ui_b64],
            |row| row.get(0),
        )
        .unwrap();
    assert!(
        ui_valid,
        "user_invite should be valid (workspace is valid signer)"
    );

    // Step 4: Create User (signed by invite key)
    let user_key = SigningKey::generate(&mut rng);
    let user_pubkey = user_key.verifying_key().to_bytes();
    let user_eid = alice.create_user(user_pubkey, &invite_key, &user_invite_eid);

    let user_b64 = event_id_to_base64(&user_eid);
    let user_valid: bool = db
        .query_row(
            "SELECT COUNT(*) > 0 FROM valid_events WHERE peer_id = ?1 AND event_id = ?2",
            rusqlite::params![&alice.identity, &user_b64],
            |row| row.get(0),
        )
        .unwrap();
    assert!(user_valid, "user should be valid after full chain");

    harness.finish();
}
