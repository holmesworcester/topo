use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::crypto::EventId;
use crate::db::{open_connection, schema::create_tables};
use crate::events::{
    MessageEvent, MessageDeletionEvent, ReactionEvent, PeerKeyEvent, SecretKeyEvent,
    SignedMemoEvent, ParsedEvent,
    WorkspaceEvent, InviteAcceptedEvent, UserInviteBootEvent, UserInviteOngoingEvent,
    DeviceInviteFirstEvent, UserBootEvent,
    PeerSharedFirstEvent, AdminBootEvent,
    UserRemovedEvent, PeerRemovedEvent, SecretSharedEvent,
    TransportKeyEvent,
};
use crate::transport_identity::{transport_cert_paths_from_db, ensure_transport_peer_id_from_db};
use crate::projection::create::{create_event_sync, create_signed_event_sync, create_encrypted_event_sync, event_id_or_blocked, CreateEventError};
use crate::projection::pipeline::project_one;
use crate::sync::engine::{accept_loop, connect_loop};
use crate::transport::{
    AllowedPeers,
    create_dual_endpoint,
    extract_spki_fingerprint,
    load_or_generate_cert,
};
use ed25519_dalek::SigningKey;

fn current_timestamp_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

/// Timing breakdown returned after sync completes.
#[derive(Debug, Clone)]
pub struct SyncMetrics {
    /// Wall-clock time from start_sync to convergence.
    pub wall_secs: f64,
    /// Total events transferred (sum of both directions).
    pub events_transferred: u64,
    /// Events per second (events_transferred / wall_secs).
    pub events_per_sec: f64,
    /// Total bytes transferred.
    pub bytes_transferred: u64,
    /// Throughput in MiB/s.
    pub throughput_mib_s: f64,
}

impl std::fmt::Display for SyncMetrics {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} events in {:.2}s ({:.0} events/s, {:.2} MiB/s)",
            self.events_transferred,
            self.wall_secs,
            self.events_per_sec,
            self.throughput_mib_s,
        )
    }
}

/// A test peer with its own database and identity.
pub struct Peer {
    pub name: String,
    pub db_path: String,
    pub identity: String,
    pub author_id: [u8; 32],
    pub channel_id: [u8; 32],
    pub workspace_id: EventId,
    /// PeerShared event_id used as signer for content events.
    pub peer_shared_event_id: Option<EventId>,
    /// PeerShared signing key for signing content events.
    pub peer_shared_signing_key: Option<SigningKey>,
    _tempdir: tempfile::TempDir,
}

impl Peer {
    /// Create a new peer with a fresh temp database (no identity chain).
    pub fn new(name: &str, channel_id: [u8; 32]) -> Self {
        let tempdir = tempfile::tempdir().expect("failed to create tempdir");
        let db_path = tempdir.path().join(format!("{}.db", name))
            .to_str().unwrap().to_string();

        let db = open_connection(&db_path).expect("failed to open db");
        create_tables(&db).expect("failed to create tables");

        let identity = ensure_transport_peer_id_from_db(&db_path).expect("failed to compute identity");
        let author_id: [u8; 32] = rand::random();

        Self {
            name: name.to_string(),
            db_path,
            identity,
            author_id,
            channel_id,
            workspace_id: channel_id,
            peer_shared_event_id: None,
            peer_shared_signing_key: None,
            _tempdir: tempdir,
        }
    }

    /// Create a new peer with a full identity chain (Workspace → InviteAccepted →
    /// UserInviteBoot → UserBoot → DeviceInviteFirst → PeerSharedFirst).
    /// Content events (Message, Reaction, etc.) are signed with the PeerShared key.
    pub fn new_with_identity(name: &str, channel_id: [u8; 32]) -> Self {
        let mut peer = Self::new(name, channel_id);
        peer.bootstrap_identity_chain();
        peer
    }

    /// Bootstrap a full identity chain for this peer.
    fn bootstrap_identity_chain(&mut self) {
        let db = open_connection(&self.db_path).expect("failed to open db");
        let mut rng = rand::thread_rng();

        // 1. Workspace
        let workspace_key = SigningKey::generate(&mut rng);
        let workspace_pub = workspace_key.verifying_key().to_bytes();
        let net = ParsedEvent::Workspace(WorkspaceEvent {
            created_at_ms: current_timestamp_ms(),
            public_key: workspace_pub,
        });
        let net_eid = event_id_or_blocked(create_event_sync(&db, &self.identity, &net))
            .expect("failed to create workspace");
        self.workspace_id = net_eid;

        // 2. InviteAccepted (binds trust anchor)
        let ia = ParsedEvent::InviteAccepted(InviteAcceptedEvent {
            created_at_ms: current_timestamp_ms(),
            invite_event_id: net_eid,
            workspace_id: net_eid,
        });
        let _ia_eid = create_event_sync(&db, &self.identity, &ia)
            .expect("failed to create invite_accepted");

        // Re-project Workspace (now trust anchor exists)
        project_one(&db, &self.identity, &net_eid).unwrap();

        // 3. UserInviteBoot (signed by workspace key)
        let invite_key = SigningKey::generate(&mut rng);
        let uib = ParsedEvent::UserInviteBoot(UserInviteBootEvent {
            created_at_ms: current_timestamp_ms(),
            public_key: invite_key.verifying_key().to_bytes(),
            workspace_id: net_eid,
            signed_by: net_eid,
            signer_type: 1,
            signature: [0u8; 64],
        });
        let uib_eid = create_signed_event_sync(&db, &self.identity, &uib, &workspace_key)
            .expect("failed to create user_invite_boot");

        // 4. UserBoot (signed by invite key)
        let user_key = SigningKey::generate(&mut rng);
        let ub = ParsedEvent::UserBoot(UserBootEvent {
            created_at_ms: current_timestamp_ms(),
            public_key: user_key.verifying_key().to_bytes(),
            signed_by: uib_eid,
            signer_type: 2,
            signature: [0u8; 64],
        });
        let ub_eid = create_signed_event_sync(&db, &self.identity, &ub, &invite_key)
            .expect("failed to create user_boot");

        // 5. DeviceInviteFirst (signed by user key)
        let device_invite_key = SigningKey::generate(&mut rng);
        let dif = ParsedEvent::DeviceInviteFirst(DeviceInviteFirstEvent {
            created_at_ms: current_timestamp_ms(),
            public_key: device_invite_key.verifying_key().to_bytes(),
            signed_by: ub_eid,
            signer_type: 4,
            signature: [0u8; 64],
        });
        let dif_eid = create_signed_event_sync(&db, &self.identity, &dif, &user_key)
            .expect("failed to create device_invite_first");

        // 6. PeerSharedFirst (signed by device_invite key)
        let peer_shared_key = SigningKey::generate(&mut rng);
        let psf = ParsedEvent::PeerSharedFirst(PeerSharedFirstEvent {
            created_at_ms: current_timestamp_ms(),
            public_key: peer_shared_key.verifying_key().to_bytes(),
            signed_by: dif_eid,
            signer_type: 3,
            signature: [0u8; 64],
        });
        let psf_eid = create_signed_event_sync(&db, &self.identity, &psf, &device_invite_key)
            .expect("failed to create peer_shared_first");

        self.peer_shared_event_id = Some(psf_eid);
        self.peer_shared_signing_key = Some(peer_shared_key);
    }

    /// Get the PeerShared signer event_id. Panics if no identity chain.
    fn signer_eid(&self) -> EventId {
        self.peer_shared_event_id.expect("Peer has no identity chain; use new_with_identity()")
    }

    /// Get a reference to the PeerShared signing key. Panics if no identity chain.
    fn signing_key(&self) -> &SigningKey {
        self.peer_shared_signing_key.as_ref().expect("Peer has no identity chain; use new_with_identity()")
    }

    /// Create a message and insert it into all relevant tables.
    /// Returns the event ID. Requires identity chain (use new_with_identity).
    pub fn create_message(&self, content: &str) -> EventId {
        let db = open_connection(&self.db_path).expect("failed to open db");
        let msg = ParsedEvent::Message(MessageEvent {
            created_at_ms: current_timestamp_ms(),
            workspace_id: self.workspace_id,
            author_id: self.author_id,
            content: content.to_string(),
            signed_by: self.signer_eid(),
            signer_type: 5,
            signature: [0u8; 64],
        });
        create_signed_event_sync(&db, &self.identity, &msg, self.signing_key())
            .expect("failed to create message")
    }

    /// Create a reaction targeting a message event.
    /// Returns the reaction event ID. Requires identity chain.
    pub fn create_reaction(&self, target_event_id: &EventId, emoji: &str) -> EventId {
        let db = open_connection(&self.db_path).expect("failed to open db");
        let rxn = ParsedEvent::Reaction(ReactionEvent {
            created_at_ms: current_timestamp_ms(),
            target_event_id: *target_event_id,
            author_id: self.author_id,
            emoji: emoji.to_string(),
            signed_by: self.signer_eid(),
            signer_type: 5,
            signature: [0u8; 64],
        });
        event_id_or_blocked(create_signed_event_sync(&db, &self.identity, &rxn, self.signing_key()))
            .expect("failed to create reaction")
    }

    /// DEPRECATED: Create a PeerKey event. New code should use identity chain
    /// (PeerSharedFirst) via `new_with_identity()` instead. Retained for backward-compat tests.
    pub fn create_peer_key(&self, public_key: [u8; 32]) -> EventId {
        let db = open_connection(&self.db_path).expect("failed to open db");
        let pk = ParsedEvent::PeerKey(PeerKeyEvent {
            created_at_ms: current_timestamp_ms(),
            public_key,
        });
        create_event_sync(&db, &self.identity, &pk).expect("failed to create peer_key")
    }

    /// Create a SignedMemo event with proper Ed25519 signature.
    /// Returns the event ID.
    pub fn create_signed_memo(
        &self,
        signer_key_eid: &EventId,
        signing_key: &ed25519_dalek::SigningKey,
        content: &str,
    ) -> EventId {
        let db = open_connection(&self.db_path).expect("failed to open db");
        let memo = ParsedEvent::SignedMemo(SignedMemoEvent {
            created_at_ms: current_timestamp_ms(),
            signed_by: *signer_key_eid,
            signer_type: 5,
            content: content.to_string(),
            signature: [0u8; 64], // placeholder, overwritten by create_signed_event_sync
        });
        create_signed_event_sync(&db, &self.identity, &memo, signing_key)
            .expect("failed to create signed_memo")
    }

    /// Create a SecretKey event with the given key bytes.
    /// Returns the event ID.
    pub fn create_secret_key(&self, key_bytes: [u8; 32]) -> EventId {
        let db = open_connection(&self.db_path).expect("failed to open db");
        let sk = ParsedEvent::SecretKey(SecretKeyEvent {
            created_at_ms: current_timestamp_ms(),
            key_bytes,
        });
        create_event_sync(&db, &self.identity, &sk).expect("failed to create secret_key")
    }

    /// Create a SecretKey event with deterministic key bytes and timestamp.
    /// Two peers calling this with the same args produce the same blob -> same event_id.
    /// This is used for PSK materialization in tests where both peers need the same key.
    pub fn create_secret_key_deterministic(&self, key_bytes: [u8; 32], created_at_ms: u64) -> EventId {
        let db = open_connection(&self.db_path).expect("failed to open db");
        let sk = ParsedEvent::SecretKey(SecretKeyEvent {
            created_at_ms,
            key_bytes,
        });
        create_event_sync(&db, &self.identity, &sk).expect("failed to create secret_key")
    }

    /// Create an encrypted message. The inner message is signed with the PeerShared key,
    /// then encrypted. Returns the encrypted event ID. Requires identity chain.
    pub fn create_encrypted_message(&self, key_event_id: &EventId, content: &str) -> EventId {
        let db = open_connection(&self.db_path).expect("failed to open db");
        let inner = ParsedEvent::Message(MessageEvent {
            created_at_ms: current_timestamp_ms(),
            workspace_id: self.workspace_id,
            author_id: self.author_id,
            content: content.to_string(),
            signed_by: self.signer_eid(),
            signer_type: 5,
            signature: [0u8; 64],
        });
        // Sign the inner event, then encrypt the signed blob
        self.create_encrypted_signed_event_sync(&db, key_event_id, &inner)
    }

    /// Sign an inner event, encrypt the signed blob, wrap in EncryptedEvent, store + project.
    fn create_encrypted_signed_event_sync(
        &self,
        db: &rusqlite::Connection,
        key_event_id: &EventId,
        inner_event: &ParsedEvent,
    ) -> EventId {
        create_encrypted_event_sync(db, &self.identity, key_event_id, inner_event, Some(self.signing_key()))
            .expect("failed to create encrypted signed event")
    }

    /// Create a MessageDeletion event targeting the given message event.
    /// Returns the deletion event ID. Requires identity chain.
    pub fn create_message_deletion(&self, target_event_id: &EventId) -> EventId {
        let db = open_connection(&self.db_path).expect("failed to open db");
        let del = ParsedEvent::MessageDeletion(MessageDeletionEvent {
            created_at_ms: current_timestamp_ms(),
            target_event_id: *target_event_id,
            author_id: self.author_id,
            signed_by: self.signer_eid(),
            signer_type: 5,
            signature: [0u8; 64],
        });
        event_id_or_blocked(create_signed_event_sync(&db, &self.identity, &del, self.signing_key()))
            .expect("failed to create message_deletion")
    }

    /// Create an encrypted MessageDeletion event.
    /// Returns the encrypted event ID. Requires identity chain.
    pub fn create_encrypted_deletion(&self, key_event_id: &EventId, target_event_id: &EventId) -> EventId {
        let db = open_connection(&self.db_path).expect("failed to open db");
        let inner = ParsedEvent::MessageDeletion(MessageDeletionEvent {
            created_at_ms: current_timestamp_ms(),
            target_event_id: *target_event_id,
            author_id: self.author_id,
            signed_by: self.signer_eid(),
            signer_type: 5,
            signature: [0u8; 64],
        });
        self.create_encrypted_signed_event_sync(&db, key_event_id, &inner)
    }

    // --- Identity event helpers ---

    /// Create a Workspace event. Returns the event ID.
    pub fn create_workspace(&self, public_key: [u8; 32]) -> EventId {
        let db = open_connection(&self.db_path).expect("failed to open db");
        let ws = ParsedEvent::Workspace(WorkspaceEvent {
            created_at_ms: current_timestamp_ms(),
            public_key,
        });
        event_id_or_blocked(create_event_sync(&db, &self.identity, &ws))
            .expect("failed to create workspace")
    }

    /// Try to create a Workspace event. Returns Result to allow handling rejection.
    pub fn try_create_workspace(&self, public_key: [u8; 32]) -> Result<EventId, CreateEventError> {
        let db = open_connection(&self.db_path).expect("failed to open db");
        let ws = ParsedEvent::Workspace(WorkspaceEvent {
            created_at_ms: current_timestamp_ms(),
            public_key,
        });
        create_event_sync(&db, &self.identity, &ws)
    }

    /// Create an InviteAccepted event (local). Returns the event ID.
    pub fn create_invite_accepted(&self, invite_event_id: &EventId, workspace_id: [u8; 32]) -> EventId {
        let db = open_connection(&self.db_path).expect("failed to open db");
        let ia = ParsedEvent::InviteAccepted(InviteAcceptedEvent {
            created_at_ms: current_timestamp_ms(),
            invite_event_id: *invite_event_id,
            workspace_id,
        });
        create_event_sync(&db, &self.identity, &ia).expect("failed to create invite_accepted")
    }

    /// Try to create an InviteAccepted event. Returns Result to allow handling rejection.
    pub fn try_create_invite_accepted(&self, invite_event_id: &EventId, workspace_id: [u8; 32]) -> Result<EventId, CreateEventError> {
        let db = open_connection(&self.db_path).expect("failed to open db");
        let ia = ParsedEvent::InviteAccepted(InviteAcceptedEvent {
            created_at_ms: current_timestamp_ms(),
            invite_event_id: *invite_event_id,
            workspace_id,
        });
        create_event_sync(&db, &self.identity, &ia)
    }

    /// Create a UserInviteBoot event (signed by workspace key). Returns the event ID.
    pub fn create_user_invite_boot(
        &self,
        signing_key: &ed25519_dalek::SigningKey,
        workspace_id: &EventId,
    ) -> EventId {
        let db = open_connection(&self.db_path).expect("failed to open db");
        let public_key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng())
            .verifying_key().to_bytes();
        let evt = ParsedEvent::UserInviteBoot(UserInviteBootEvent {
            created_at_ms: current_timestamp_ms(),
            public_key,
            workspace_id: *workspace_id,
            signed_by: *workspace_id,
            signer_type: 1,
            signature: [0u8; 64],
        });
        event_id_or_blocked(create_signed_event_sync(&db, &self.identity, &evt, signing_key))
            .expect("failed to create user_invite_boot")
    }

    /// Create a UserInviteBoot with a specific public key. Returns the event ID.
    pub fn create_user_invite_boot_with_key(
        &self,
        invite_public_key: [u8; 32],
        signing_key: &ed25519_dalek::SigningKey,
        workspace_id: &EventId,
    ) -> EventId {
        let db = open_connection(&self.db_path).expect("failed to open db");
        let evt = ParsedEvent::UserInviteBoot(UserInviteBootEvent {
            created_at_ms: current_timestamp_ms(),
            public_key: invite_public_key,
            workspace_id: *workspace_id,
            signed_by: *workspace_id,
            signer_type: 1,
            signature: [0u8; 64],
        });
        event_id_or_blocked(create_signed_event_sync(&db, &self.identity, &evt, signing_key))
            .expect("failed to create user_invite_boot")
    }

    /// Create a UserInviteOngoing event (signed by PeerShared key, dep on admin).
    /// Used when an existing admin invites a new user.
    pub fn create_user_invite_ongoing(
        &self,
        invite_public_key: [u8; 32],
        signing_key: &ed25519_dalek::SigningKey,
        peer_shared_event_id: &EventId,
        admin_event_id: &EventId,
    ) -> EventId {
        let db = open_connection(&self.db_path).expect("failed to open db");
        let evt = ParsedEvent::UserInviteOngoing(UserInviteOngoingEvent {
            created_at_ms: current_timestamp_ms(),
            public_key: invite_public_key,
            admin_event_id: *admin_event_id,
            signed_by: *peer_shared_event_id,
            signer_type: 5,
            signature: [0u8; 64],
        });
        event_id_or_blocked(create_signed_event_sync(&db, &self.identity, &evt, signing_key))
            .expect("failed to create user_invite_ongoing")
    }

    /// Create a UserBoot event (signed by UserInvite key). Returns the event ID.
    pub fn create_user_boot(
        &self,
        user_public_key: [u8; 32],
        signing_key: &ed25519_dalek::SigningKey,
        user_invite_event_id: &EventId,
    ) -> EventId {
        let db = open_connection(&self.db_path).expect("failed to open db");
        let evt = ParsedEvent::UserBoot(UserBootEvent {
            created_at_ms: current_timestamp_ms(),
            public_key: user_public_key,
            signed_by: *user_invite_event_id,
            signer_type: 2,
            signature: [0u8; 64],
        });
        event_id_or_blocked(create_signed_event_sync(&db, &self.identity, &evt, signing_key))
            .expect("failed to create user_boot")
    }

    /// Create a DeviceInviteFirst event (signed by User key). Returns the event ID.
    pub fn create_device_invite_first(
        &self,
        device_invite_public_key: [u8; 32],
        signing_key: &ed25519_dalek::SigningKey,
        user_event_id: &EventId,
    ) -> EventId {
        let db = open_connection(&self.db_path).expect("failed to open db");
        let evt = ParsedEvent::DeviceInviteFirst(DeviceInviteFirstEvent {
            created_at_ms: current_timestamp_ms(),
            public_key: device_invite_public_key,
            signed_by: *user_event_id,
            signer_type: 4,
            signature: [0u8; 64],
        });
        event_id_or_blocked(create_signed_event_sync(&db, &self.identity, &evt, signing_key))
            .expect("failed to create device_invite_first")
    }

    /// Create a PeerSharedFirst event (signed by DeviceInvite key). Returns the event ID.
    pub fn create_peer_shared_first(
        &self,
        peer_shared_public_key: [u8; 32],
        signing_key: &ed25519_dalek::SigningKey,
        device_invite_event_id: &EventId,
    ) -> EventId {
        let db = open_connection(&self.db_path).expect("failed to open db");
        let evt = ParsedEvent::PeerSharedFirst(PeerSharedFirstEvent {
            created_at_ms: current_timestamp_ms(),
            public_key: peer_shared_public_key,
            signed_by: *device_invite_event_id,
            signer_type: 3,
            signature: [0u8; 64],
        });
        event_id_or_blocked(create_signed_event_sync(&db, &self.identity, &evt, signing_key))
            .expect("failed to create peer_shared_first")
    }

    /// Create an AdminBoot event (signed by Workspace key, dep on User). Returns the event ID.
    pub fn create_admin_boot(
        &self,
        admin_public_key: [u8; 32],
        signing_key: &ed25519_dalek::SigningKey,
        user_event_id: &EventId,
        workspace_id: &EventId,
    ) -> EventId {
        let db = open_connection(&self.db_path).expect("failed to open db");
        let evt = ParsedEvent::AdminBoot(AdminBootEvent {
            created_at_ms: current_timestamp_ms(),
            public_key: admin_public_key,
            user_event_id: *user_event_id,
            signed_by: *workspace_id,
            signer_type: 1,
            signature: [0u8; 64],
        });
        event_id_or_blocked(create_signed_event_sync(&db, &self.identity, &evt, signing_key))
            .expect("failed to create admin_boot")
    }

    /// Create a UserRemoved event (signed by PeerShared key — admin). Returns the event ID.
    pub fn create_user_removed(
        &self,
        signing_key: &ed25519_dalek::SigningKey,
        target_event_id: &EventId,
        peer_shared_event_id: &EventId,
    ) -> EventId {
        let db = open_connection(&self.db_path).expect("failed to open db");
        let evt = ParsedEvent::UserRemoved(UserRemovedEvent {
            created_at_ms: current_timestamp_ms(),
            target_event_id: *target_event_id,
            signed_by: *peer_shared_event_id,
            signer_type: 5,
            signature: [0u8; 64],
        });
        event_id_or_blocked(create_signed_event_sync(&db, &self.identity, &evt, signing_key))
            .expect("failed to create user_removed")
    }

    /// Create a PeerRemoved event (signed by PeerShared key — admin). Returns the event ID.
    pub fn create_peer_removed(
        &self,
        signing_key: &ed25519_dalek::SigningKey,
        target_event_id: &EventId,
        peer_shared_event_id: &EventId,
    ) -> EventId {
        let db = open_connection(&self.db_path).expect("failed to open db");
        let evt = ParsedEvent::PeerRemoved(PeerRemovedEvent {
            created_at_ms: current_timestamp_ms(),
            target_event_id: *target_event_id,
            signed_by: *peer_shared_event_id,
            signer_type: 5,
            signature: [0u8; 64],
        });
        event_id_or_blocked(create_signed_event_sync(&db, &self.identity, &evt, signing_key))
            .expect("failed to create peer_removed")
    }

    /// Create a SecretShared event (signed by PeerShared key). Returns the event ID.
    pub fn create_secret_shared(
        &self,
        signing_key: &ed25519_dalek::SigningKey,
        key_event_id: &EventId,
        recipient_event_id: &EventId,
        wrapped_key: [u8; 32],
        peer_shared_event_id: &EventId,
    ) -> EventId {
        let db = open_connection(&self.db_path).expect("failed to open db");
        let evt = ParsedEvent::SecretShared(SecretSharedEvent {
            created_at_ms: current_timestamp_ms(),
            key_event_id: *key_event_id,
            recipient_event_id: *recipient_event_id,
            wrapped_key,
            signed_by: *peer_shared_event_id,
            signer_type: 5,
            signature: [0u8; 64],
        });
        event_id_or_blocked(create_signed_event_sync(&db, &self.identity, &evt, signing_key))
            .expect("failed to create secret_shared")
    }

    /// Create a TransportKey event (signed by PeerShared key). Returns the event ID.
    pub fn create_transport_key(
        &self,
        spki_fingerprint: [u8; 32],
        signing_key: &ed25519_dalek::SigningKey,
        peer_shared_event_id: &EventId,
    ) -> EventId {
        let db = open_connection(&self.db_path).expect("failed to open db");
        let evt = ParsedEvent::TransportKey(TransportKeyEvent {
            created_at_ms: current_timestamp_ms(),
            spki_fingerprint,
            signed_by: *peer_shared_event_id,
            signer_type: 5,
            signature: [0u8; 64],
        });
        create_signed_event_sync(&db, &self.identity, &evt, signing_key)
            .expect("failed to create transport_key")
    }

    /// Create multiple messages. Uses a transaction for speed at scale.
    /// Requires identity chain.
    pub fn batch_create_messages(&self, count: usize) {
        let db = open_connection(&self.db_path).expect("failed to open db");
        db.execute("BEGIN", []).expect("failed to begin");
        for i in 0..count {
            let msg = ParsedEvent::Message(MessageEvent {
                created_at_ms: current_timestamp_ms(),
                workspace_id: self.workspace_id,
                author_id: self.author_id,
                content: format!("Message {} from {}", i, self.name),
                signed_by: self.signer_eid(),
                signer_type: 5,
                signature: [0u8; 64],
            });
            create_signed_event_sync(&db, &self.identity, &msg, self.signing_key())
                .expect("failed to create message");
        }
        db.execute("COMMIT", []).expect("failed to commit");
    }

    /// Count events in the events table.
    pub fn store_count(&self) -> i64 {
        let db = open_connection(&self.db_path).expect("failed to open db");
        db.query_row("SELECT COUNT(*) FROM events", [], |row| row.get(0))
            .unwrap_or(0)
    }

    /// Count rows in the messages projection table (all, unscoped).
    pub fn message_count(&self) -> i64 {
        let db = open_connection(&self.db_path).expect("failed to open db");
        db.query_row("SELECT COUNT(*) FROM messages", [], |row| row.get(0))
            .unwrap_or(0)
    }

    /// Count rows in the reactions projection table scoped to this peer.
    pub fn reaction_count(&self) -> i64 {
        let db = open_connection(&self.db_path).expect("failed to open db");
        db.query_row(
            "SELECT COUNT(*) FROM reactions WHERE recorded_by = ?1",
            rusqlite::params![&self.identity],
            |row| row.get(0),
        ).unwrap_or(0)
    }

    /// Count rows in the peer_keys projection table scoped to this peer.
    pub fn peer_key_count(&self) -> i64 {
        let db = open_connection(&self.db_path).expect("failed to open db");
        db.query_row(
            "SELECT COUNT(*) FROM peer_keys WHERE recorded_by = ?1",
            rusqlite::params![&self.identity],
            |row| row.get(0),
        ).unwrap_or(0)
    }

    /// Count rows in the signed_memos projection table scoped to this peer.
    pub fn signed_memo_count(&self) -> i64 {
        let db = open_connection(&self.db_path).expect("failed to open db");
        db.query_row(
            "SELECT COUNT(*) FROM signed_memos WHERE recorded_by = ?1",
            rusqlite::params![&self.identity],
            |row| row.get(0),
        ).unwrap_or(0)
    }

    /// Count rows in the secret_keys projection table scoped to this peer.
    pub fn secret_key_count(&self) -> i64 {
        let db = open_connection(&self.db_path).expect("failed to open db");
        db.query_row(
            "SELECT COUNT(*) FROM secret_keys WHERE recorded_by = ?1",
            rusqlite::params![&self.identity],
            |row| row.get(0),
        ).unwrap_or(0)
    }

    /// Count rows in the neg_items table (events advertised for sync).
    pub fn neg_items_count(&self) -> i64 {
        let db = open_connection(&self.db_path).expect("failed to open db");
        db.query_row("SELECT COUNT(*) FROM neg_items", [], |row| row.get(0))
            .unwrap_or(0)
    }

    /// Check if a specific event_id (base64) exists in the events table.
    pub fn has_event(&self, event_id_b64: &str) -> bool {
        let db = open_connection(&self.db_path).expect("failed to open db");
        db.query_row(
            "SELECT COUNT(*) > 0 FROM events WHERE event_id = ?1",
            rusqlite::params![event_id_b64],
            |row| row.get(0),
        ).unwrap_or(false)
    }

    /// Count rows in the deleted_messages projection table scoped to this peer.
    pub fn deleted_message_count(&self) -> i64 {
        let db = open_connection(&self.db_path).expect("failed to open db");
        db.query_row(
            "SELECT COUNT(*) FROM deleted_messages WHERE recorded_by = ?1",
            rusqlite::params![&self.identity],
            |row| row.get(0),
        ).unwrap_or(0)
    }

    /// Count rows in the events table.
    pub fn events_table_count(&self) -> i64 {
        let db = open_connection(&self.db_path).expect("failed to open db");
        db.query_row("SELECT COUNT(*) FROM events", [], |row| row.get(0))
            .unwrap_or(0)
    }

    /// Count rows in recorded_events scoped to this peer's identity.
    pub fn recorded_events_count(&self) -> i64 {
        let db = open_connection(&self.db_path).expect("failed to open db");
        db.query_row(
            "SELECT COUNT(*) FROM recorded_events WHERE peer_id = ?1",
            rusqlite::params![&self.identity],
            |row| row.get(0),
        ).unwrap_or(0)
    }

    /// Return sorted set of all store IDs (base64-encoded).
    pub fn store_ids(&self) -> std::collections::BTreeSet<String> {
        let db = open_connection(&self.db_path).expect("failed to open db");
        let mut stmt = db
            .prepare("SELECT event_id FROM events ORDER BY event_id")
            .expect("prepare");
        let ids = stmt.query_map([], |row| row.get::<_, String>(0))
            .expect("query")
            .collect::<Result<std::collections::BTreeSet<_>, _>>()
            .expect("collect");
        ids
    }

    /// Count messages scoped to this peer's recorded_by identity.
    pub fn scoped_message_count(&self) -> i64 {
        let db = open_connection(&self.db_path).expect("failed to open db");
        db.query_row(
            "SELECT COUNT(*) FROM messages WHERE recorded_by = ?1",
            rusqlite::params![&self.identity],
            |row| row.get(0),
        ).unwrap_or(0)
    }

    // --- Identity projection count helpers ---

    /// Count valid events for this peer.
    pub fn valid_event_count(&self) -> i64 {
        let db = open_connection(&self.db_path).expect("failed to open db");
        db.query_row(
            "SELECT COUNT(*) FROM valid_events WHERE peer_id = ?1",
            rusqlite::params![&self.identity],
            |row| row.get(0),
        ).unwrap_or(0)
    }

    /// Count rejected events for this peer.
    pub fn rejected_event_count(&self) -> i64 {
        let db = open_connection(&self.db_path).expect("failed to open db");
        db.query_row(
            "SELECT COUNT(*) FROM rejected_events WHERE peer_id = ?1",
            rusqlite::params![&self.identity],
            |row| row.get(0),
        ).unwrap_or(0)
    }

    /// Count blocked event deps for this peer.
    pub fn blocked_dep_count(&self) -> i64 {
        let db = open_connection(&self.db_path).expect("failed to open db");
        db.query_row(
            "SELECT COUNT(DISTINCT event_id) FROM blocked_event_deps WHERE peer_id = ?1",
            rusqlite::params![&self.identity],
            |row| row.get(0),
        ).unwrap_or(0)
    }

    /// Count workspaces projected for this peer.
    pub fn workspace_count(&self) -> i64 {
        let db = open_connection(&self.db_path).expect("failed to open db");
        db.query_row(
            "SELECT COUNT(*) FROM workspaces WHERE recorded_by = ?1",
            rusqlite::params![&self.identity],
            |row| row.get(0),
        ).unwrap_or(0)
    }

    /// Count user invites projected for this peer.
    pub fn user_invite_count(&self) -> i64 {
        let db = open_connection(&self.db_path).expect("failed to open db");
        db.query_row(
            "SELECT COUNT(*) FROM user_invites WHERE recorded_by = ?1",
            rusqlite::params![&self.identity],
            |row| row.get(0),
        ).unwrap_or(0)
    }

    /// Count users projected for this peer.
    pub fn user_count(&self) -> i64 {
        let db = open_connection(&self.db_path).expect("failed to open db");
        db.query_row(
            "SELECT COUNT(*) FROM users WHERE recorded_by = ?1",
            rusqlite::params![&self.identity],
            |row| row.get(0),
        ).unwrap_or(0)
    }

    /// Count device invites projected for this peer.
    pub fn device_invite_count(&self) -> i64 {
        let db = open_connection(&self.db_path).expect("failed to open db");
        db.query_row(
            "SELECT COUNT(*) FROM device_invites WHERE recorded_by = ?1",
            rusqlite::params![&self.identity],
            |row| row.get(0),
        ).unwrap_or(0)
    }

    /// Count peers_shared projected for this peer.
    pub fn peer_shared_count(&self) -> i64 {
        let db = open_connection(&self.db_path).expect("failed to open db");
        db.query_row(
            "SELECT COUNT(*) FROM peers_shared WHERE recorded_by = ?1",
            rusqlite::params![&self.identity],
            |row| row.get(0),
        ).unwrap_or(0)
    }

    /// Count admins projected for this peer.
    pub fn admin_count(&self) -> i64 {
        let db = open_connection(&self.db_path).expect("failed to open db");
        db.query_row(
            "SELECT COUNT(*) FROM admins WHERE recorded_by = ?1",
            rusqlite::params![&self.identity],
            |row| row.get(0),
        ).unwrap_or(0)
    }

    /// Count invite_accepted projected for this peer.
    pub fn invite_accepted_count(&self) -> i64 {
        let db = open_connection(&self.db_path).expect("failed to open db");
        db.query_row(
            "SELECT COUNT(*) FROM invite_accepted WHERE recorded_by = ?1",
            rusqlite::params![&self.identity],
            |row| row.get(0),
        ).unwrap_or(0)
    }

    /// Count transport_keys projected for this peer.
    pub fn transport_key_count(&self) -> i64 {
        let db = open_connection(&self.db_path).expect("failed to open db");
        db.query_row(
            "SELECT COUNT(*) FROM transport_keys WHERE recorded_by = ?1",
            rusqlite::params![&self.identity],
            |row| row.get(0),
        ).unwrap_or(0)
    }
}

/// Replay all event blobs from the events table through project_one.
/// Clears projection tables and valid_events, then re-projects all events.
/// Returns (message_count, reaction_count, peer_key_count, signed_memo_count, secret_key_count, deleted_message_count) after replay.
fn replay_projection(db: &rusqlite::Connection, recorded_by: &str) -> (i64, i64, i64, i64, i64, i64) {
    replay_projection_impl(db, recorded_by, "ORDER BY created_at ASC, event_id ASC")
}

/// Replay events in reverse order through the projector.
fn replay_projection_reverse(db: &rusqlite::Connection, recorded_by: &str) -> (i64, i64, i64, i64, i64, i64) {
    replay_projection_impl(db, recorded_by, "ORDER BY created_at DESC, event_id DESC")
}

fn replay_projection_impl(db: &rusqlite::Connection, recorded_by: &str, order: &str) -> (i64, i64, i64, i64, i64, i64) {
    use crate::crypto::event_id_from_base64;

    // Clear projection tables + valid_events for this tenant
    db.execute("DELETE FROM messages WHERE recorded_by = ?1", rusqlite::params![recorded_by])
        .expect("failed to clear messages");
    db.execute("DELETE FROM reactions WHERE recorded_by = ?1", rusqlite::params![recorded_by])
        .expect("failed to clear reactions");
    db.execute("DELETE FROM peer_keys WHERE recorded_by = ?1", rusqlite::params![recorded_by])
        .expect("failed to clear peer_keys");
    db.execute("DELETE FROM signed_memos WHERE recorded_by = ?1", rusqlite::params![recorded_by])
        .expect("failed to clear signed_memos");
    db.execute("DELETE FROM secret_keys WHERE recorded_by = ?1", rusqlite::params![recorded_by])
        .expect("failed to clear secret_keys");
    db.execute("DELETE FROM deleted_messages WHERE recorded_by = ?1", rusqlite::params![recorded_by])
        .expect("failed to clear deleted_messages");
    // Identity tables
    db.execute("DELETE FROM workspaces WHERE recorded_by = ?1", rusqlite::params![recorded_by]).ok();
    db.execute("DELETE FROM invite_accepted WHERE recorded_by = ?1", rusqlite::params![recorded_by]).ok();
    db.execute("DELETE FROM user_invites WHERE recorded_by = ?1", rusqlite::params![recorded_by]).ok();
    db.execute("DELETE FROM device_invites WHERE recorded_by = ?1", rusqlite::params![recorded_by]).ok();
    db.execute("DELETE FROM users WHERE recorded_by = ?1", rusqlite::params![recorded_by]).ok();
    db.execute("DELETE FROM peers_shared WHERE recorded_by = ?1", rusqlite::params![recorded_by]).ok();
    db.execute("DELETE FROM admins WHERE recorded_by = ?1", rusqlite::params![recorded_by]).ok();
    db.execute("DELETE FROM removed_entities WHERE recorded_by = ?1", rusqlite::params![recorded_by]).ok();
    db.execute("DELETE FROM secret_shared WHERE recorded_by = ?1", rusqlite::params![recorded_by]).ok();
    db.execute("DELETE FROM trust_anchors WHERE peer_id = ?1", rusqlite::params![recorded_by]).ok();
    db.execute("DELETE FROM invite_workspace_bindings WHERE peer_id = ?1", rusqlite::params![recorded_by]).ok();
    db.execute("DELETE FROM peer_transport_bindings WHERE recorded_by = ?1", rusqlite::params![recorded_by]).ok();
    db.execute("DELETE FROM transport_keys WHERE recorded_by = ?1", rusqlite::params![recorded_by]).ok();
    db.execute("DELETE FROM valid_events WHERE peer_id = ?1", rusqlite::params![recorded_by])
        .expect("failed to clear valid_events");
    db.execute("DELETE FROM blocked_event_deps WHERE peer_id = ?1", rusqlite::params![recorded_by])
        .expect("failed to clear blocked_event_deps");
    db.execute("DELETE FROM rejected_events WHERE peer_id = ?1", rusqlite::params![recorded_by])
        .expect("failed to clear rejected_events");
    db.execute("DELETE FROM project_queue WHERE peer_id = ?1", rusqlite::params![recorded_by]).ok();

    // Pre-seed the deterministic Peer::new workspace event as valid (it was originally
    // inserted directly, bypassing projection). Identified by blob having created_at_ms=0
    // and public_key=[0;32] (the Peer::new deterministic workspace sentinel).
    {
        let mut ws_stmt = db.prepare(
            "SELECT event_id, blob FROM events WHERE event_type = 'workspace'"
        ).expect("prepare ws query");
        let ws_rows: Vec<(String, Vec<u8>)> = ws_stmt
            .query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?)))
            .expect("query ws")
            .collect::<Result<Vec<_>, _>>()
            .expect("collect ws");
        for (ws_b64, ws_blob) in &ws_rows {
            if let Ok(parsed) = crate::events::parse_event(ws_blob) {
                if let crate::events::ParsedEvent::Workspace(ws) = parsed {
                    // Only pre-seed the Peer::new deterministic workspace (created_at_ms=0, public_key=zeros)
                    if ws.created_at_ms == 0 && ws.public_key == [0u8; 32] {
                        db.execute(
                            "INSERT OR IGNORE INTO valid_events (peer_id, event_id) VALUES (?1, ?2)",
                            rusqlite::params![recorded_by, ws_b64],
                        ).expect("seed ws valid");
                        db.execute(
                            "INSERT OR IGNORE INTO workspaces (recorded_by, event_id, workspace_id, public_key)
                             VALUES (?1, ?2, ?3, ?4)",
                            rusqlite::params![recorded_by, ws_b64, ws_b64, ws.public_key.as_slice()],
                        ).expect("seed ws projection");
                    }
                }
            }
        }
    }

    let query = format!(
        "SELECT e.event_id FROM events e
         WHERE e.event_id IN (SELECT event_id FROM recorded_events WHERE peer_id = ?1)
         {}",
        order
    );
    let mut stmt = db.prepare(&query).expect("failed to prepare events query");
    let event_ids: Vec<String> = stmt.query_map(rusqlite::params![recorded_by], |row| row.get::<_, String>(0))
        .expect("failed to query events")
        .collect::<Result<Vec<_>, _>>()
        .expect("failed to collect events");

    for eid_b64 in &event_ids {
        if let Some(eid) = event_id_from_base64(eid_b64) {
            let _ = project_one(db, recorded_by, &eid);
        }
    }

    let msg_count: i64 = db.query_row(
        "SELECT COUNT(*) FROM messages WHERE recorded_by = ?1",
        rusqlite::params![recorded_by],
        |row| row.get(0),
    ).unwrap_or(0);
    let rxn_count: i64 = db.query_row(
        "SELECT COUNT(*) FROM reactions WHERE recorded_by = ?1",
        rusqlite::params![recorded_by],
        |row| row.get(0),
    ).unwrap_or(0);
    let pk_count: i64 = db.query_row(
        "SELECT COUNT(*) FROM peer_keys WHERE recorded_by = ?1",
        rusqlite::params![recorded_by],
        |row| row.get(0),
    ).unwrap_or(0);
    let sm_count: i64 = db.query_row(
        "SELECT COUNT(*) FROM signed_memos WHERE recorded_by = ?1",
        rusqlite::params![recorded_by],
        |row| row.get(0),
    ).unwrap_or(0);
    let sk_count: i64 = db.query_row(
        "SELECT COUNT(*) FROM secret_keys WHERE recorded_by = ?1",
        rusqlite::params![recorded_by],
        |row| row.get(0),
    ).unwrap_or(0);
    let del_count: i64 = db.query_row(
        "SELECT COUNT(*) FROM deleted_messages WHERE recorded_by = ?1",
        rusqlite::params![recorded_by],
        |row| row.get(0),
    ).unwrap_or(0);

    (msg_count, rxn_count, pk_count, sm_count, sk_count, del_count)
}

/// Verify projection invariants for a peer:
/// 1. Forward replay matches original state
/// 2. Double replay (idempotency) matches
/// 3. Reverse-order replay matches (order-independence)
pub fn verify_projection_invariants(peer: &Peer) {
    let db = open_connection(&peer.db_path).expect("failed to open db");

    // Capture original counts
    let orig_msg: i64 = db.query_row(
        "SELECT COUNT(*) FROM messages WHERE recorded_by = ?1",
        rusqlite::params![&peer.identity],
        |row| row.get(0),
    ).unwrap_or(0);
    let orig_rxn: i64 = db.query_row(
        "SELECT COUNT(*) FROM reactions WHERE recorded_by = ?1",
        rusqlite::params![&peer.identity],
        |row| row.get(0),
    ).unwrap_or(0);
    let orig_pk: i64 = db.query_row(
        "SELECT COUNT(*) FROM peer_keys WHERE recorded_by = ?1",
        rusqlite::params![&peer.identity],
        |row| row.get(0),
    ).unwrap_or(0);
    let orig_sm: i64 = db.query_row(
        "SELECT COUNT(*) FROM signed_memos WHERE recorded_by = ?1",
        rusqlite::params![&peer.identity],
        |row| row.get(0),
    ).unwrap_or(0);
    let orig_sk: i64 = db.query_row(
        "SELECT COUNT(*) FROM secret_keys WHERE recorded_by = ?1",
        rusqlite::params![&peer.identity],
        |row| row.get(0),
    ).unwrap_or(0);
    let orig_del: i64 = db.query_row(
        "SELECT COUNT(*) FROM deleted_messages WHERE recorded_by = ?1",
        rusqlite::params![&peer.identity],
        |row| row.get(0),
    ).unwrap_or(0);

    // 1. Forward replay
    let (fwd_msg, fwd_rxn, fwd_pk, fwd_sm, fwd_sk, fwd_del) = replay_projection(&db, &peer.identity);
    assert_eq!(fwd_msg, orig_msg,
        "Forward replay message count mismatch: expected {}, got {}", orig_msg, fwd_msg);
    assert_eq!(fwd_rxn, orig_rxn,
        "Forward replay reaction count mismatch: expected {}, got {}", orig_rxn, fwd_rxn);
    assert_eq!(fwd_pk, orig_pk,
        "Forward replay peer_key count mismatch: expected {}, got {}", orig_pk, fwd_pk);
    assert_eq!(fwd_sm, orig_sm,
        "Forward replay signed_memo count mismatch: expected {}, got {}", orig_sm, fwd_sm);
    assert_eq!(fwd_sk, orig_sk,
        "Forward replay secret_key count mismatch: expected {}, got {}", orig_sk, fwd_sk);
    assert_eq!(fwd_del, orig_del,
        "Forward replay deleted_message count mismatch: expected {}, got {}", orig_del, fwd_del);

    // 2. Idempotency: replay again over existing projected state (double replay)
    let (double_msg, double_rxn, double_pk, double_sm, double_sk, double_del) = replay_projection(&db, &peer.identity);
    assert_eq!(double_msg, orig_msg,
        "Double replay message count mismatch: expected {}, got {}", orig_msg, double_msg);
    assert_eq!(double_rxn, orig_rxn,
        "Double replay reaction count mismatch: expected {}, got {}", orig_rxn, double_rxn);
    assert_eq!(double_pk, orig_pk,
        "Double replay peer_key count mismatch: expected {}, got {}", orig_pk, double_pk);
    assert_eq!(double_sm, orig_sm,
        "Double replay signed_memo count mismatch: expected {}, got {}", orig_sm, double_sm);
    assert_eq!(double_sk, orig_sk,
        "Double replay secret_key count mismatch: expected {}, got {}", orig_sk, double_sk);
    assert_eq!(double_del, orig_del,
        "Double replay deleted_message count mismatch: expected {}, got {}", orig_del, double_del);

    // 3. Reverse-order replay
    let (rev_msg, rev_rxn, rev_pk, rev_sm, rev_sk, rev_del) = replay_projection_reverse(&db, &peer.identity);
    assert_eq!(rev_msg, orig_msg,
        "Reverse replay message count mismatch: expected {}, got {}", orig_msg, rev_msg);
    assert_eq!(rev_rxn, orig_rxn,
        "Reverse replay reaction count mismatch: expected {}, got {}", orig_rxn, rev_rxn);
    assert_eq!(rev_pk, orig_pk,
        "Reverse replay peer_key count mismatch: expected {}, got {}", orig_pk, rev_pk);
    assert_eq!(rev_sm, orig_sm,
        "Reverse replay signed_memo count mismatch: expected {}, got {}", orig_sm, rev_sm);
    assert_eq!(rev_sk, orig_sk,
        "Reverse replay secret_key count mismatch: expected {}, got {}", orig_sk, rev_sk);
    assert_eq!(rev_del, orig_del,
        "Reverse replay deleted_message count mismatch: expected {}, got {}", orig_del, rev_del);

    // Restore forward projection for subsequent assertions
    let _ = replay_projection(&db, &peer.identity);
}

/// Start continuous sync between two peers with mutual mTLS pinning.
pub fn start_peers(
    peer_a: &Peer,
    peer_b: &Peer,
) -> (std::thread::JoinHandle<()>, std::thread::JoinHandle<()>) {
    let (cert_path_a, key_path_a) = transport_cert_paths_from_db(&peer_a.db_path);
    let (cert_a, key_a) = load_or_generate_cert(&cert_path_a, &key_path_a)
        .expect("failed to load cert for peer A");
    let (cert_path_b, key_path_b) = transport_cert_paths_from_db(&peer_b.db_path);
    let (cert_b, key_b) = load_or_generate_cert(&cert_path_b, &key_path_b)
        .expect("failed to load cert for peer B");

    let fp_a = extract_spki_fingerprint(cert_a.as_ref()).expect("failed to extract fp for A");
    let fp_b = extract_spki_fingerprint(cert_b.as_ref()).expect("failed to extract fp for B");

    let allowed_for_a = Arc::new(AllowedPeers::from_fingerprints(vec![fp_b]));
    let allowed_for_b = Arc::new(AllowedPeers::from_fingerprints(vec![fp_a]));

    let listener_endpoint = create_dual_endpoint(
        "127.0.0.1:0".parse().unwrap(),
        cert_a,
        key_a,
        allowed_for_a,
    ).expect("failed to create dual endpoint for A");

    let listener_addr = listener_endpoint.local_addr().expect("failed to get listener addr");

    let connector_endpoint = create_dual_endpoint(
        "127.0.0.1:0".parse().unwrap(),
        cert_b,
        key_b,
        allowed_for_b,
    ).expect("failed to create dual endpoint for B");

    let a_db = peer_a.db_path.clone();
    let a_identity = peer_a.identity.clone();
    let b_db = peer_b.db_path.clone();
    let b_identity = peer_b.identity.clone();

    let a_handle = std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async move {
            if let Err(e) = accept_loop(&a_db, &a_identity, listener_endpoint, None).await {
                tracing::warn!("accept_loop exited: {}", e);
            }
        });
    });

    let b_handle = std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async move {
            if let Err(e) = connect_loop(&b_db, &b_identity, connector_endpoint, listener_addr, None).await {
                tracing::warn!("connect_loop exited: {}", e);
            }
        });
    });

    (a_handle, b_handle)
}

/// Start sync, wait for convergence, return metrics.
pub async fn sync_until_converged(
    peer_a: &Peer,
    peer_b: &Peer,
    expected_count: i64,
    timeout: Duration,
) -> SyncMetrics {
    let a_before = peer_a.store_count();
    let b_before = peer_b.store_count();
    let events_to_transfer =
        (expected_count - a_before) + (expected_count - b_before);

    let start = Instant::now();
    let sync = start_peers(peer_a, peer_b);

    assert_eventually(
        || peer_a.store_count() >= expected_count && peer_b.store_count() >= expected_count,
        timeout,
        &format!(
            "convergence to {} events (a={}, b={})",
            expected_count,
            peer_a.store_count(),
            peer_b.store_count(),
        ),
    ).await;

    let wall_secs = start.elapsed().as_secs_f64();
    drop(sync);

    let events_transferred = events_to_transfer as u64;
    // Variable-length events — estimate ~100 bytes per event
    let bytes_transferred = events_transferred * 100;
    let events_per_sec = if wall_secs > 0.0 { events_transferred as f64 / wall_secs } else { 0.0 };
    let throughput_mib_s = (bytes_transferred as f64) / (1024.0 * 1024.0) / wall_secs.max(0.001);

    SyncMetrics {
        wall_secs,
        events_transferred,
        events_per_sec,
        bytes_transferred,
        throughput_mib_s,
    }
}

/// Poll a condition until it's true or timeout expires.
pub async fn assert_eventually<F>(check: F, timeout: Duration, msg: &str)
where
    F: Fn() -> bool,
{
    let start = Instant::now();
    loop {
        if check() {
            return;
        }
        if start.elapsed() >= timeout {
            panic!("assert_eventually timed out: {}", msg);
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}
