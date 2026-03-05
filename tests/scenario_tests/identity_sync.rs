#![allow(dead_code)]

use std::time::Duration;
use topo::crypto::event_id_to_base64;
use topo::db::open_connection;
use topo::testutil::{assert_eventually, start_peers_pinned, Peer, ScenarioHarness};

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

#[tokio::test]
async fn test_two_peer_identity_join_and_sync() {
    let alice = Peer::new("alice");
    let bob = Peer::new("bob");
    let harness = ScenarioHarness::new();
    harness.track(&alice);
    harness.track(&bob);

    // Alice bootstraps her full identity chain
    let alice_chain = bootstrap_peer(&alice);

    // Alice creates a UserInvite for Bob
    // Bob needs the invite to exist on Alice's side; sync will deliver it
    let _bob_join = join_workspace(&bob, &alice_chain, &alice);

    // Sync — shared events flow between peers
    let sync = start_peers_pinned(&alice, &bob);

    // Wait for convergence on projected identity state, not raw event counts
    assert_eventually(
        || alice.peer_shared_count() == 2 && bob.peer_shared_count() == 2,
        Duration::from_secs(15),
        "both peers should converge on 2 peers_shared",
    )
    .await;

    drop(sync);

    // Both peers should have projected the same identity state:
    // - 1 workspace
    // - 2 user_invites (boot + ongoing)
    // - 2 users (Alice's + Bob's)
    // - 2 device_invites
    // - 2 peers_shared
    // - 1 admin (Alice's)
    assert_eq!(
        alice.workspace_count(),
        1,
        "Alice should have 1 trust-anchored workspace"
    );
    assert_eq!(
        bob.workspace_count(),
        1,
        "Bob should have 1 trust-anchored workspace"
    );

    assert_eq!(
        alice.user_invite_count(),
        2,
        "Alice: boot + ongoing invites"
    );
    assert_eq!(bob.user_invite_count(), 2, "Bob: boot + ongoing invites");

    assert_eq!(alice.user_count(), 2, "Alice sees 2 users");
    assert_eq!(bob.user_count(), 2, "Bob sees 2 users");

    assert_eq!(
        alice.device_invite_count(),
        2,
        "Alice sees 2 device invites"
    );
    assert_eq!(bob.device_invite_count(), 2, "Bob sees 2 device invites");

    assert_eq!(alice.peer_shared_count(), 2, "Alice sees 2 peers_shared");
    assert_eq!(bob.peer_shared_count(), 2, "Bob sees 2 peers_shared");

    assert_eq!(alice.admin_count(), 1, "Alice sees 1 admin");
    assert_eq!(bob.admin_count(), 1, "Bob sees 1 admin");

    // Replay invariants hold for both peers
    harness.finish();
}

/// Identity chain events arrive out of order via sync and cascade to valid.
/// Bob creates his own events but they depend on Alice's chain. Sync delivers
/// Alice's events, which unblock Bob's chain via cascade.
#[tokio::test]
async fn test_identity_cascade_via_sync() {
    let alice = Peer::new("alice");
    let bob = Peer::new("bob");
    let harness = ScenarioHarness::new();
    harness.track(&bob);

    // Alice bootstraps
    let alice_chain = bootstrap_peer(&alice);

    // Alice creates an invite for Bob on her side
    let mut rng = rand::thread_rng();
    let invite_key = ed25519_dalek::SigningKey::generate(&mut rng);
    let invite_pubkey = invite_key.verifying_key().to_bytes();
    let user_invite_eid = alice.create_user_invite_with_key(
        invite_pubkey,
        &alice_chain.workspace_key,
        &alice_chain.workspace_eid,
    );

    // Bob accepts the invite locally — this sets his trust anchor
    let _ia_eid = bob.create_invite_accepted(&user_invite_eid, alice_chain.workspace_id);

    // Bob creates User signed by the invite — but the invite event is on
    // Alice's side, not Bob's. So this will block on the signed_by dep.
    let _user_key = ed25519_dalek::SigningKey::generate(&mut rng);
    let user_pubkey = _user_key.verifying_key().to_bytes();
    let user_eid = bob.create_user(user_pubkey, &invite_key, &user_invite_eid);
    let user_eid_b64 = event_id_to_base64(&user_eid);

    // Confirm User is blocked before sync
    assert_eq!(
        bob.user_count(),
        0,
        "Bob's User should be blocked (missing signer dep)"
    );
    assert!(bob.blocked_dep_count() > 0, "Bob should have blocked deps");

    // Sync — Alice's events flow to Bob, unblocking the cascade
    let sync = start_peers_pinned(&alice, &bob);

    // Wait for Bob's specific User event to become valid, not just any user
    assert_eventually(
        || {
            let db = open_connection(&bob.db_path).unwrap();
            let valid: bool = db
                .query_row(
                    "SELECT COUNT(*) > 0 FROM valid_events WHERE peer_id = ?1 AND event_id = ?2",
                    rusqlite::params![&bob.identity, &user_eid_b64],
                    |row| row.get(0),
                )
                .unwrap_or(false);
            valid
        },
        Duration::from_secs(15),
        "Bob's specific User should cascade to valid after sync",
    )
    .await;

    drop(sync);

    // Bob should now have Alice's full identity chain projected plus his own user
    assert_eq!(
        bob.workspace_count(),
        1,
        "Bob should have Alice's workspace"
    );
    assert_eq!(bob.user_invite_count(), 2, "Bob should have both invites");
    assert_eq!(
        bob.user_count(),
        2,
        "Both Alice's and Bob's users should be valid"
    );

    harness.finish();
}

/// After identity join, Alice and Bob can exchange messages. Tests that the
/// full trust chain enables the messaging layer to work across peers.
#[tokio::test]
async fn test_identity_then_messaging() {
    let mut alice = Peer::new("alice");
    let mut bob = Peer::new("bob");

    // Both peers establish identity on the same network
    let alice_chain = bootstrap_peer(&alice);
    let bob_join = join_workspace(&bob, &alice_chain, &alice);

    // Set signing keys and author_id so create_message works
    alice.peer_shared_event_id = Some(alice_chain.peer_shared_eid);
    alice.peer_shared_signing_key = Some(alice_chain.peer_shared_key.clone());
    alice.author_id = alice_chain.user_eid;
    bob.peer_shared_event_id = Some(bob_join.peer_shared_eid);
    bob.peer_shared_signing_key = Some(bob_join.peer_shared_key.clone());
    bob.author_id = bob_join.user_eid;

    let harness = ScenarioHarness::new();
    harness.track(&alice);
    harness.track(&bob);

    // Sync identity events first
    let sync = start_peers_pinned(&alice, &bob);
    assert_eventually(
        || alice.peer_shared_count() == 2 && bob.peer_shared_count() == 2,
        Duration::from_secs(15),
        "identity should converge",
    )
    .await;
    drop(sync);

    // Now both peers send messages
    alice.create_message("Hello from Alice");
    bob.create_message("Hello from Bob");

    // Sync messages
    let sync = start_peers_pinned(&alice, &bob);
    assert_eventually(
        || alice.scoped_message_count() == 2 && bob.scoped_message_count() == 2,
        Duration::from_secs(15),
        "messages should converge after identity sync",
    )
    .await;
    drop(sync);

    harness.finish();
}

/// Alice bootstraps on two devices (Phone and Laptop). Phone creates a DeviceInvite
/// for Laptop, Laptop joins with PeerShared, both sync and converge.
#[tokio::test]
async fn test_device_link_via_sync() {
    use topo::event_modules::{DeviceInviteEvent, ParsedEvent, PeerSharedEvent};
    use topo::projection::create::{create_signed_event_staged, create_signed_event_synchronous};

    let phone = Peer::new("phone");
    let laptop = Peer::new("laptop");
    let harness = ScenarioHarness::new();
    harness.track(&phone);
    harness.track(&laptop);

    let mut rng = rand::thread_rng();

    // Phone bootstraps full identity chain
    let phone_chain = bootstrap_peer(&phone);

    // Phone creates a DeviceInvite for Laptop (signed by Phone's User key).
    let laptop_di_key = ed25519_dalek::SigningKey::generate(&mut rng);
    let laptop_di_pubkey = laptop_di_key.verifying_key().to_bytes();
    let db = open_connection(&phone.db_path).unwrap();
    let di_evt = ParsedEvent::DeviceInvite(DeviceInviteEvent {
        created_at_ms: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64,
        public_key: laptop_di_pubkey,
        signed_by: phone_chain.user_eid,
        signer_type: 4,
        signature: [0u8; 64],
    });
    let laptop_di_eid =
        create_signed_event_synchronous(&db, &phone.identity, &di_evt, &phone_chain.user_key)
            .expect("create device_invite");
    drop(db);

    // Laptop accepts the invite (local, sets trust anchor)
    let _ia_eid = laptop.create_invite_accepted(&laptop_di_eid, phone_chain.workspace_id);

    // Laptop creates PeerShared (signed by the device invite key Phone gave).
    // This will be blocked because the signed_by dep (DeviceInvite) is on Phone.
    // Use staged API since blocking is expected (dep will arrive via sync).
    let laptop_ps_key = ed25519_dalek::SigningKey::generate(&mut rng);
    let laptop_ps_pubkey = laptop_ps_key.verifying_key().to_bytes();
    let db = open_connection(&laptop.db_path).unwrap();
    let ps_evt = ParsedEvent::PeerShared(PeerSharedEvent {
        created_at_ms: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64,
        public_key: laptop_ps_pubkey,
        user_event_id: phone_chain.user_eid,
        device_name: "laptop".to_string(),
        signed_by: laptop_di_eid,
        signer_type: 3,
        signature: [0u8; 64],
    });
    let _laptop_ps_eid = create_signed_event_staged(&db, &laptop.identity, &ps_evt, &laptop_di_key)
        .expect("create peer_shared");
    drop(db);

    // Laptop's PeerShared is blocked — signed_by dep (DeviceInvite) is on Phone
    assert_eq!(
        laptop.peer_shared_count(),
        0,
        "Laptop's peer_shared should be blocked before sync"
    );

    // Sync — Phone's events flow to Laptop, unblocking Laptop's chain
    let sync = start_peers_pinned(&phone, &laptop);

    assert_eventually(
        || phone.peer_shared_count() == 2 && laptop.peer_shared_count() == 2,
        Duration::from_secs(15),
        "both devices should see 2 peers_shared after sync",
    )
    .await;

    drop(sync);

    // Both devices share the same trust-anchored workspace and identity state.
    assert_eq!(phone.workspace_count(), 1);
    assert_eq!(laptop.workspace_count(), 1);
    assert_eq!(phone.device_invite_count(), 2, "Phone: first + ongoing");
    assert_eq!(laptop.device_invite_count(), 2, "Laptop: first + ongoing");

    harness.finish();
}

/// Alice and Bob are on different workspaces. When they sync, Bob's workspace events
/// are rejected by Alice's trust anchor, and vice versa. Neither peer's identity
/// state is corrupted.
#[tokio::test]
async fn test_foreign_workspace_rejected_via_sync() {
    let alice = Peer::new("alice");
    let bob = Peer::new("bob");
    let harness = ScenarioHarness::new();
    harness.track(&alice);
    harness.track(&bob);

    // Both bootstrap independently on DIFFERENT workspaces
    let alice_chain = bootstrap_peer(&alice);
    let bob_chain = bootstrap_peer(&bob);

    // Sanity: different workspace_ids
    assert_ne!(
        alice_chain.workspace_id, bob_chain.workspace_id,
        "workspaces should differ"
    );

    // Before sync: each peer has only its own trust-anchored workspace projected.
    assert_eq!(alice.workspace_count(), 1);
    assert_eq!(bob.workspace_count(), 1);

    // Sync — shared events flow between peers
    let sync = start_peers_pinned(&alice, &bob);

    // Wait for events to transfer — gate on rejected events appearing
    // (foreign workspace events get rejected by the trust anchor guard)
    assert_eventually(
        || alice.rejected_event_count() > 0 && bob.rejected_event_count() > 0,
        Duration::from_secs(15),
        "both peers should have rejected foreign workspace events",
    )
    .await;

    drop(sync);

    // Each peer should still have only its own workspace projected —
    // the foreign bootstrap workspace event is rejected by the trust anchor guard.
    assert_eq!(
        alice.workspace_count(),
        1,
        "Alice should still have exactly 1 workspace (foreign rejected)"
    );
    assert_eq!(
        bob.workspace_count(),
        1,
        "Bob should still have exactly 1 workspace (foreign rejected)"
    );

    // Foreign identity events should be rejected, not just blocked
    assert!(
        alice.rejected_event_count() > 0,
        "Alice should have rejected foreign workspace events"
    );
    assert!(
        bob.rejected_event_count() > 0,
        "Bob should have rejected foreign workspace events"
    );

    // Each peer's own identity state is unaffected
    assert_eq!(alice.user_count(), 1, "Alice's own user unchanged");
    assert_eq!(bob.user_count(), 1, "Bob's own user unchanged");

    harness.finish();
}
