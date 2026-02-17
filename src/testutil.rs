use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::crypto::{event_id_from_base64, event_id_to_base64, EventId};
use crate::db::{
    open_connection,
    schema::create_tables,
    store::{insert_event, insert_recorded_event, parse_share_scope},
};
use crate::events::{
    MessageEvent, MessageDeletionEvent, ReactionEvent, SecretKeyEvent,
    SignedMemoEvent, ParsedEvent,
    WorkspaceEvent, InviteAcceptedEvent, UserInviteBootEvent, UserInviteOngoingEvent,
    DeviceInviteFirstEvent, UserBootEvent,
    PeerSharedFirstEvent, AdminBootEvent,
    UserRemovedEvent, PeerRemovedEvent, SecretSharedEvent,
    TransportKeyEvent,
};
use crate::transport_identity::{ensure_transport_peer_id, ensure_transport_cert};
use crate::projection::create::{create_event_sync, create_event_staged, create_signed_event_sync, create_signed_event_staged, create_encrypted_event_sync, CreateEventError};
use crate::projection::pipeline::project_one;
use crate::sync::SyncMessage;
use crate::sync::engine::{accept_loop, connect_loop, download_from_sources, run_sync_initiator_dual, SYNC_SESSION_TIMEOUT_SECS};
use crate::transport::{
    AllowedPeers,
    DualConnection,
    create_client_endpoint,
    create_dual_endpoint,
    create_dual_endpoint_dynamic,
    create_server_endpoint,
    extract_spki_fingerprint,
    peer_identity_from_connection,
};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
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
    pub workspace_id: EventId,
    /// PeerShared event_id used as signer for content events.
    pub peer_shared_event_id: Option<EventId>,
    /// PeerShared signing key for signing content events.
    pub peer_shared_signing_key: Option<SigningKey>,
    /// Workspace signing key (only set for workspace creators).
    pub workspace_signing_key: Option<SigningKey>,
    _tempdir: tempfile::TempDir,
}

/// Delegate to the shared bootstrap responder in sync::bootstrap.
fn start_test_sync_endpoint(
    inviter_db_path: &str,
    inviter_identity: &str,
    invite_key: &SigningKey,
) -> Result<(SocketAddr, quinn::Endpoint), Box<dyn std::error::Error + Send + Sync>> {
    crate::sync::bootstrap::start_bootstrap_responder(inviter_db_path, inviter_identity, invite_key)
}

impl Peer {
    /// Create a new peer with a fresh temp database (no identity chain).
    pub fn new(name: &str) -> Self {
        let tempdir = tempfile::tempdir().expect("failed to create tempdir");
        let db_path = tempdir.path().join(format!("{}.db", name))
            .to_str().unwrap().to_string();

        let db = open_connection(&db_path).expect("failed to open db");
        create_tables(&db).expect("failed to create tables");

        let identity = ensure_transport_peer_id(&db).expect("failed to compute identity");
        let author_id: [u8; 32] = rand::random();

        Self {
            name: name.to_string(),
            db_path,
            identity,
            author_id,
            workspace_id: [0u8; 32],
            peer_shared_event_id: None,
            peer_shared_signing_key: None,
            workspace_signing_key: None,
            _tempdir: tempdir,
        }
    }

    /// Create a new peer with a full identity chain via the production
    /// `bootstrap_workspace` flow (Workspace → UserInviteBoot → InviteAccepted →
    /// UserBoot → DeviceInviteFirst → PeerSharedFirst → AdminBoot → TransportKey).
    /// Content events (Message, Reaction, etc.) are signed with the PeerShared key.
    pub fn new_with_identity(name: &str) -> Self {
        let mut peer = Self::new(name);
        peer.bootstrap_identity_chain();
        peer
    }

    /// Bootstrap a full identity chain using the production `bootstrap_workspace` flow.
    fn bootstrap_identity_chain(&mut self) {
        use crate::identity_ops::bootstrap_workspace;

        let db = open_connection(&self.db_path).expect("failed to open db");
        let chain = bootstrap_workspace(&db, &self.identity)
            .expect("failed to bootstrap workspace");

        self.workspace_id = chain.workspace_id;
        self.peer_shared_event_id = Some(chain.peer_shared_event_id);
        self.peer_shared_signing_key = Some(chain.peer_shared_key);
        self.workspace_signing_key = Some(chain.workspace_key);
    }

    /// Create a new peer that joins an existing workspace created by `creator`
    /// using the production invite flow with real QUIC bootstrap sync:
    /// creator issues `create_user_invite`, starts a temp sync endpoint,
    /// joiner fetches prerequisite events via bootstrap sync, then calls
    /// `accept_user_invite`. No direct DB-to-DB event copying.
    pub async fn new_in_workspace(name: &str, creator: &Peer) -> Self {
        use crate::identity_ops::create_user_invite;
        use crate::invite_link::create_invite_link;
        use crate::transport_identity::expected_invite_bootstrap_spki_from_invite_key;
        use crate::db::transport_trust::record_pending_invite_bootstrap_trust;

        // Create a bare peer with DB tables but NO transport identity.
        // svc_accept_invite will install the invite-derived identity.
        let tempdir = tempfile::tempdir().expect("failed to create tempdir");
        let db_path = tempdir.path().join(format!("{}.db", name))
            .to_str().unwrap().to_string();
        {
            let db = open_connection(&db_path).expect("failed to open db");
            create_tables(&db).expect("failed to create tables");
        }
        let mut peer = Self {
            name: name.to_string(),
            db_path,
            identity: String::new(),
            author_id: rand::random(),
            workspace_id: [0u8; 32],
            peer_shared_event_id: None,
            peer_shared_signing_key: None,
            workspace_signing_key: None,
            _tempdir: tempdir,
        };
        let creator_db = open_connection(&creator.db_path).expect("failed to open creator db");
        let workspace_key = creator.workspace_signing_key.as_ref()
            .expect("creator has no workspace_signing_key; use new_with_identity()");

        // Creator issues an invite (creates UserInviteOngoing on creator's DB)
        let invite = create_user_invite(
            &creator_db, &creator.identity, workspace_key, &creator.workspace_id,
        ).expect("failed to create user invite");

        // Register pending bootstrap trust so creator's endpoint allows the joiner
        let pending_spki = expected_invite_bootstrap_spki_from_invite_key(&invite.invite_key)
            .expect("failed to derive invite SPKI");
        record_pending_invite_bootstrap_trust(
            &creator_db,
            &creator.identity,
            &event_id_to_base64(&invite.invite_event_id),
            &event_id_to_base64(&creator.workspace_id),
            &pending_spki,
        ).expect("failed to record pending bootstrap trust");
        drop(creator_db);

        // Start a temp sync endpoint for the creator
        let (sync_addr, sync_endpoint) = start_test_sync_endpoint(
            &creator.db_path,
            &creator.identity,
            &invite.invite_key,
        ).expect("failed to start temp sync endpoint");

        // Build invite link with creator's bootstrap address and SPKI
        let creator_spki = creator.spki_fingerprint();
        let invite_link = create_invite_link(&invite, &sync_addr.to_string(), &creator_spki)
            .expect("failed to create invite link");

        // Joiner accepts via real bootstrap sync + identity chain creation
        let result = crate::service::svc_accept_invite(
            &peer.db_path, &invite_link, name, "device",
        ).await.expect("failed to accept invite via bootstrap sync");

        // Clean up sync endpoint
        sync_endpoint.close(0u32.into(), b"bootstrap done");

        // Update peer state from service result
        peer.identity = result.peer_id.clone();
        peer.workspace_id = creator.workspace_id;

        // Load signing key from DB (service layer persisted it)
        let db = open_connection(&peer.db_path).expect("failed to open db");
        if let Ok(Some((eid, key))) = crate::service::load_local_peer_signer_pub(&db, &result.peer_id) {
            peer.peer_shared_event_id = Some(eid);
            peer.peer_shared_signing_key = Some(key);
        }

        peer
    }

    /// Get the PeerShared signer event_id. Panics if no identity chain.
    fn signer_eid(&self) -> EventId {
        self.peer_shared_event_id.expect("Peer has no identity chain; use new_with_identity()")
    }

    /// Get a reference to the PeerShared signing key. Panics if no identity chain.
    fn signing_key(&self) -> &SigningKey {
        self.peer_shared_signing_key.as_ref().expect("Peer has no identity chain; use new_with_identity()")
    }

    /// Load (or generate) the transport certificate and private key for this peer.
    pub fn cert_and_key(&self) -> (CertificateDer<'static>, PrivatePkcs8KeyDer<'static>) {
        let db = open_connection(&self.db_path).expect("failed to open db");
        let (_, cert, key) = ensure_transport_cert(&db).expect("failed to load cert");
        (cert, key)
    }

    /// Extract the SPKI fingerprint (SHA-256) from this peer's transport certificate.
    pub fn spki_fingerprint(&self) -> [u8; 32] {
        let (cert, _) = self.cert_and_key();
        extract_spki_fingerprint(cert.as_ref()).expect("failed to extract fingerprint")
    }

    /// Publish a TransportKey event binding this peer's transport cert to its identity chain.
    /// Requires identity chain (use new_with_identity).
    pub fn publish_transport_key(&self) -> EventId {
        let fp = self.spki_fingerprint();
        self.create_transport_key(fp, self.signing_key(), &self.signer_eid())
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
        create_signed_event_staged(&db, &self.identity, &rxn, self.signing_key())
            .expect("failed to create reaction")
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
        create_signed_event_sync(&db, &self.identity, &del, self.signing_key())
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
        create_event_staged(&db, &self.identity, &ws)
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
        create_signed_event_staged(&db, &self.identity, &evt, signing_key)
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
        create_signed_event_staged(&db, &self.identity, &evt, signing_key)
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
        create_signed_event_sync(&db, &self.identity, &evt, signing_key)
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
        create_signed_event_staged(&db, &self.identity, &evt, signing_key)
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
        create_signed_event_staged(&db, &self.identity, &evt, signing_key)
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
        create_signed_event_staged(&db, &self.identity, &evt, signing_key)
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
        create_signed_event_sync(&db, &self.identity, &evt, signing_key)
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
        create_signed_event_sync(&db, &self.identity, &evt, signing_key)
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
        create_signed_event_sync(&db, &self.identity, &evt, signing_key)
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
        create_signed_event_sync(&db, &self.identity, &evt, signing_key)
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
    /// Returns -1 if the database can't be opened (transient contention).
    pub fn store_count(&self) -> i64 {
        let db = match open_connection(&self.db_path) {
            Ok(db) => db,
            Err(_) => return -1,
        };
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

    /// Get the recorded_at timestamp for a specific event (by base64 event_id).
    pub fn recorded_at_for_event(&self, event_id_b64: &str) -> Option<i64> {
        let db = open_connection(&self.db_path).expect("failed to open db");
        db.query_row(
            "SELECT recorded_at FROM recorded_events WHERE peer_id = ?1 AND event_id = ?2",
            rusqlite::params![&self.identity, event_id_b64],
            |row| row.get(0),
        ).ok()
    }

    /// Get a random sample of event IDs (base64) from the events table.
    pub fn sample_event_ids(&self, count: usize) -> Vec<String> {
        let db = open_connection(&self.db_path).expect("failed to open db");
        let mut stmt = db.prepare(
            "SELECT event_id FROM events ORDER BY RANDOM() LIMIT ?1"
        ).expect("prepare");
        stmt.query_map(rusqlite::params![count as i64], |row| row.get::<_, String>(0))
            .expect("query")
            .collect::<Result<Vec<_>, _>>()
            .expect("collect")
    }

    /// Insert `count` synthetic transport_keys rows for this peer.
    /// Returns the generated SPKI fingerprints.
    pub fn seed_transport_keys(&self, count: usize) -> Vec<[u8; 32]> {
        let db = open_connection(&self.db_path).expect("failed to open db");
        db.execute("BEGIN", []).expect("failed to begin");
        let mut fps = Vec::with_capacity(count);
        for i in 0..count {
            let mut fp = [0u8; 32];
            let bytes = (i as u64).to_le_bytes();
            fp[..8].copy_from_slice(&bytes);
            fp[8] = 0xFE; // sentinel to distinguish synthetic keys
            fps.push(fp);
            db.execute(
                "INSERT OR IGNORE INTO transport_keys (recorded_by, event_id, spki_fingerprint) VALUES (?1, ?2, ?3)",
                rusqlite::params![&self.identity, format!("synthetic_tk_{}", i), fp.as_slice()],
            ).expect("failed to insert transport_key");
        }
        db.execute("COMMIT", []).expect("failed to commit");
        fps
    }
}

/// Copy all events from `src` peer's DB into `dest` peer's DB and project them.
/// Simulates a completed sync session. Events are inserted in `created_at ASC`
/// order so identity chain dependencies resolve correctly.
pub fn replicate_all_events(src: &Peer, dest: &Peer) {
    let src_db = open_connection(&src.db_path).expect("failed to open src db");
    let dest_db = open_connection(&dest.db_path).expect("failed to open dest db");

    let mut stmt = src_db.prepare(
        "SELECT event_id, event_type, blob, share_scope, created_at, inserted_at
         FROM events ORDER BY created_at ASC, event_id ASC"
    ).expect("failed to prepare events query");

    let rows: Vec<(String, String, Vec<u8>, String, i64, i64)> = stmt.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, Vec<u8>>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, i64>(4)?,
            row.get::<_, i64>(5)?,
        ))
    }).expect("failed to query events")
      .collect::<Result<Vec<_>, _>>()
      .expect("failed to collect events");

    let now_ms = current_timestamp_ms() as i64;

    for (event_id, event_type, blob, share_scope_str, created_at, inserted_at) in &rows {
        let eid = event_id_from_base64(event_id).expect("invalid event_id in source events table");
        let share_scope = parse_share_scope(share_scope_str).expect("invalid share_scope in source events table");

        insert_event(
            &dest_db,
            &eid,
            event_type,
            blob,
            share_scope,
            *created_at,
            *inserted_at,
        )
        .expect("failed to insert event");
        insert_recorded_event(&dest_db, &dest.identity, &eid, now_ms, "test")
            .expect("failed to insert recorded_event");

        // Project the event
        let _ = project_one(&dest_db, &dest.identity, &eid);
    }
}

/// Replay all event blobs from the events table through project_one.
/// Clears projection tables and valid_events, then re-projects all events.
/// Returns (message_count, reaction_count, signed_memo_count, secret_key_count, deleted_message_count) after replay.
fn replay_projection(db: &rusqlite::Connection, recorded_by: &str) -> (i64, i64, i64, i64, i64) {
    replay_projection_impl(db, recorded_by, "ORDER BY created_at ASC, event_id ASC")
}

/// Replay events in reverse order through the projector.
fn replay_projection_reverse(db: &rusqlite::Connection, recorded_by: &str) -> (i64, i64, i64, i64, i64) {
    replay_projection_impl(db, recorded_by, "ORDER BY created_at DESC, event_id DESC")
}

fn replay_projection_impl(db: &rusqlite::Connection, recorded_by: &str, order: &str) -> (i64, i64, i64, i64, i64) {
    use crate::crypto::event_id_from_base64;

    // Clear projection tables + valid_events for this tenant
    db.execute("DELETE FROM messages WHERE recorded_by = ?1", rusqlite::params![recorded_by])
        .expect("failed to clear messages");
    db.execute("DELETE FROM reactions WHERE recorded_by = ?1", rusqlite::params![recorded_by])
        .expect("failed to clear reactions");
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
    db.execute("DELETE FROM peer_transport_bindings WHERE recorded_by = ?1", rusqlite::params![recorded_by]).ok();
    db.execute("DELETE FROM transport_keys WHERE recorded_by = ?1", rusqlite::params![recorded_by]).ok();
    db.execute("DELETE FROM valid_events WHERE peer_id = ?1", rusqlite::params![recorded_by])
        .expect("failed to clear valid_events");
    db.execute("DELETE FROM blocked_event_deps WHERE peer_id = ?1", rusqlite::params![recorded_by])
        .expect("failed to clear blocked_event_deps");
    db.execute("DELETE FROM blocked_events WHERE peer_id = ?1", rusqlite::params![recorded_by]).ok();
    db.execute("DELETE FROM rejected_events WHERE peer_id = ?1", rusqlite::params![recorded_by])
        .expect("failed to clear rejected_events");
    db.execute("DELETE FROM project_queue WHERE peer_id = ?1", rusqlite::params![recorded_by]).ok();

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

    (msg_count, rxn_count, sm_count, sk_count, del_count)
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
    let (fwd_msg, fwd_rxn, fwd_sm, fwd_sk, fwd_del) = replay_projection(&db, &peer.identity);
    assert_eq!(fwd_msg, orig_msg,
        "Forward replay message count mismatch: expected {}, got {}", orig_msg, fwd_msg);
    assert_eq!(fwd_rxn, orig_rxn,
        "Forward replay reaction count mismatch: expected {}, got {}", orig_rxn, fwd_rxn);
    assert_eq!(fwd_sm, orig_sm,
        "Forward replay signed_memo count mismatch: expected {}, got {}", orig_sm, fwd_sm);
    assert_eq!(fwd_sk, orig_sk,
        "Forward replay secret_key count mismatch: expected {}, got {}", orig_sk, fwd_sk);
    assert_eq!(fwd_del, orig_del,
        "Forward replay deleted_message count mismatch: expected {}, got {}", orig_del, fwd_del);

    // 2. Idempotency: replay again over existing projected state (double replay)
    let (double_msg, double_rxn, double_sm, double_sk, double_del) = replay_projection(&db, &peer.identity);
    assert_eq!(double_msg, orig_msg,
        "Double replay message count mismatch: expected {}, got {}", orig_msg, double_msg);
    assert_eq!(double_rxn, orig_rxn,
        "Double replay reaction count mismatch: expected {}, got {}", orig_rxn, double_rxn);
    assert_eq!(double_sm, orig_sm,
        "Double replay signed_memo count mismatch: expected {}, got {}", orig_sm, double_sm);
    assert_eq!(double_sk, orig_sk,
        "Double replay secret_key count mismatch: expected {}, got {}", orig_sk, double_sk);
    assert_eq!(double_del, orig_del,
        "Double replay deleted_message count mismatch: expected {}, got {}", orig_del, double_del);

    // 3. Reverse-order replay
    let (rev_msg, rev_rxn, rev_sm, rev_sk, rev_del) = replay_projection_reverse(&db, &peer.identity);
    assert_eq!(rev_msg, orig_msg,
        "Reverse replay message count mismatch: expected {}, got {}", orig_msg, rev_msg);
    assert_eq!(rev_rxn, orig_rxn,
        "Reverse replay reaction count mismatch: expected {}, got {}", orig_rxn, rev_rxn);
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
    let (cert_a, key_a) = peer_a.cert_and_key();
    let (cert_b, key_b) = peer_b.cert_and_key();

    let fp_a = peer_a.spki_fingerprint();
    let fp_b = peer_b.spki_fingerprint();

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
            if let Err(e) = accept_loop(&a_db, &a_identity, listener_endpoint).await {
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
            if let Err(e) = connect_loop(&b_db, &b_identity, connector_endpoint, listener_addr).await {
                tracing::warn!("connect_loop exited: {}", e);
            }
        });
    });

    (a_handle, b_handle)
}

/// Start continuous sync between two peers using identity-derived trust.
/// Reads `AllowedPeers` from each peer's `transport_keys` projection table
/// via `allowed_peers_from_db()`. Caller must have called `publish_transport_key()`
/// and `replicate_all_events()` first so each peer's DB has the other's TransportKey.
pub fn start_peers_identity_trust(
    peer_a: &Peer,
    peer_b: &Peer,
) -> (std::thread::JoinHandle<()>, std::thread::JoinHandle<()>) {
    use crate::db::transport_trust::allowed_peers_from_db;

    let (cert_a, key_a) = peer_a.cert_and_key();
    let (cert_b, key_b) = peer_b.cert_and_key();

    let db_a = open_connection(&peer_a.db_path).expect("failed to open db for A");
    let allowed_for_a = allowed_peers_from_db(&db_a, &peer_a.identity)
        .expect("failed to read allowed peers for A");
    assert!(!allowed_for_a.is_empty(), "A has no identity-derived trust; call publish_transport_key() + replicate_all_events() first");
    drop(db_a);

    let db_b = open_connection(&peer_b.db_path).expect("failed to open db for B");
    let allowed_for_b = allowed_peers_from_db(&db_b, &peer_b.identity)
        .expect("failed to read allowed peers for B");
    assert!(!allowed_for_b.is_empty(), "B has no identity-derived trust; call publish_transport_key() + replicate_all_events() first");
    drop(db_b);

    let listener_endpoint = create_dual_endpoint(
        "127.0.0.1:0".parse().unwrap(),
        cert_a,
        key_a,
        Arc::new(allowed_for_a),
    ).expect("failed to create dual endpoint for A");

    let listener_addr = listener_endpoint.local_addr().expect("failed to get listener addr");

    let connector_endpoint = create_dual_endpoint(
        "127.0.0.1:0".parse().unwrap(),
        cert_b,
        key_b,
        Arc::new(allowed_for_b),
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
            if let Err(e) = accept_loop(&a_db, &a_identity, listener_endpoint).await {
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
            if let Err(e) = connect_loop(&b_db, &b_identity, connector_endpoint, listener_addr).await {
                tracing::warn!("connect_loop exited: {}", e);
            }
        });
    });

    (a_handle, b_handle)
}

/// Start continuous sync between two peers using dynamic DB trust lookup.
/// Trust is resolved from SQL at each TLS handshake, matching production
/// behavior (`is_peer_allowed`). Caller must have seeded trust rows
/// (via `publish_transport_key` + sync, `import_cli_pins_to_sql`, or invite
/// bootstrap) before peers will accept connections.
pub fn start_peers_dynamic(
    peer_a: &Peer,
    peer_b: &Peer,
) -> (std::thread::JoinHandle<()>, std::thread::JoinHandle<()>) {
    use crate::db::transport_trust::is_peer_allowed;

    let (cert_a, key_a) = peer_a.cert_and_key();
    let (cert_b, key_b) = peer_b.cert_and_key();

    let a_db_path = peer_a.db_path.clone();
    let a_recorded_by = peer_a.identity.clone();
    let dynamic_allow_a: Arc<crate::transport::DynamicAllowFn> =
        Arc::new(move |peer_fp: &[u8; 32]| {
            let db = open_connection(&a_db_path)?;
            is_peer_allowed(&db, &a_recorded_by, peer_fp)
        });

    let b_db_path = peer_b.db_path.clone();
    let b_recorded_by = peer_b.identity.clone();
    let dynamic_allow_b: Arc<crate::transport::DynamicAllowFn> =
        Arc::new(move |peer_fp: &[u8; 32]| {
            let db = open_connection(&b_db_path)?;
            is_peer_allowed(&db, &b_recorded_by, peer_fp)
        });

    let listener_endpoint = create_dual_endpoint_dynamic(
        "127.0.0.1:0".parse().unwrap(),
        cert_a,
        key_a,
        dynamic_allow_a,
    )
    .expect("failed to create dynamic dual endpoint for A");

    let listener_addr = listener_endpoint
        .local_addr()
        .expect("failed to get listener addr");

    let connector_endpoint = create_dual_endpoint_dynamic(
        "127.0.0.1:0".parse().unwrap(),
        cert_b,
        key_b,
        dynamic_allow_b,
    )
    .expect("failed to create dynamic dual endpoint for B");

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
            if let Err(e) = accept_loop(&a_db, &a_identity, listener_endpoint).await {
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
            if let Err(e) =
                connect_loop(&b_db, &b_identity, connector_endpoint, listener_addr).await
            {
                tracing::warn!("connect_loop exited: {}", e);
            }
        });
    });

    (a_handle, b_handle)
}

/// Create a QUIC endpoint with dynamic DB trust lookup for a test peer.
/// Returns the endpoint (dual-role: accepts and connects).
/// Trust is resolved from SQL at each TLS handshake, matching production behavior.
pub fn create_dynamic_endpoint_for_peer(
    peer: &Peer,
) -> quinn::Endpoint {
    use crate::db::transport_trust::is_peer_allowed;

    let (cert, key) = peer.cert_and_key();
    let db_path = peer.db_path.clone();
    let recorded_by = peer.identity.clone();
    let dynamic_allow: Arc<crate::transport::DynamicAllowFn> =
        Arc::new(move |peer_fp: &[u8; 32]| {
            let db = open_connection(&db_path)?;
            is_peer_allowed(&db, &recorded_by, peer_fp)
        });

    create_dual_endpoint_dynamic(
        "127.0.0.1:0".parse().unwrap(),
        cert,
        key,
        dynamic_allow,
    )
    .expect("failed to create dynamic endpoint for peer")
}

/// Start sync, wait for a caller-defined convergence check, return metrics.
pub async fn sync_until_converged<F: Fn() -> bool>(
    peer_a: &Peer,
    peer_b: &Peer,
    check: F,
    timeout: Duration,
) -> SyncMetrics {
    let a_before = peer_a.store_count();
    let b_before = peer_b.store_count();

    let start = Instant::now();
    let sync = start_peers(peer_a, peer_b);

    assert_eventually(check, timeout, "sync convergence").await;

    let wall_secs = start.elapsed().as_secs_f64();
    drop(sync);

    let a_after = peer_a.store_count();
    let b_after = peer_b.store_count();
    let events_transferred = ((a_after - a_before) + (b_after - b_before)) as u64;
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

/// Start a chain topology: P0 <-> P1 <-> ... <-> P_{n-1}.
///
/// Each adjacent pair has a bidirectional sync link:
/// - P_i runs accept_loop (server) for P_{i+1}
/// - P_{i+1} runs connect_loop (client) to P_i
///
/// Returns thread handles for all accept and connect loops.
pub fn start_chain(peers: &[Peer]) -> Vec<std::thread::JoinHandle<()>> {
    let n = peers.len();
    assert!(n >= 2, "chain requires at least 2 peers");

    // Extract fingerprints for all peers (needed before creating endpoints)
    let mut fingerprints: Vec<[u8; 32]> = Vec::new();
    for peer in peers {
        fingerprints.push(peer.spki_fingerprint());
    }

    // Create server endpoints for peers 0..n-2 (each accepts from its right neighbor)
    let mut server_addrs: Vec<SocketAddr> = Vec::new();
    let mut server_endpoints: Vec<quinn::Endpoint> = Vec::new();
    for i in 0..n-1 {
        let (cert, key) = peers[i].cert_and_key();
        let allowed = Arc::new(AllowedPeers::from_fingerprints(vec![fingerprints[i+1]]));
        let endpoint = create_server_endpoint(
            "127.0.0.1:0".parse().unwrap(),
            cert, key, allowed,
        ).expect("failed to create chain server endpoint");
        let addr = endpoint.local_addr().expect("failed to get local addr");
        server_addrs.push(addr);
        server_endpoints.push(endpoint);
    }

    // Create client endpoints for peers 1..n-1 (each connects to its left neighbor)
    let mut client_endpoints: Vec<quinn::Endpoint> = Vec::new();
    for i in 1..n {
        let (cert, key) = peers[i].cert_and_key();
        let allowed = Arc::new(AllowedPeers::from_fingerprints(vec![fingerprints[i-1]]));
        let endpoint = create_client_endpoint(
            "0.0.0.0:0".parse().unwrap(),
            cert, key, allowed,
        ).expect("failed to create chain client endpoint");
        client_endpoints.push(endpoint);
    }

    let mut handles = Vec::new();

    // Spawn accept_loop for peers 0..n-2
    for (i, endpoint) in server_endpoints.into_iter().enumerate() {
        let db_path = peers[i].db_path.clone();
        let identity = peers[i].identity.clone();
        handles.push(std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async move {
                if let Err(e) = accept_loop(&db_path, &identity, endpoint).await {
                    tracing::warn!("chain accept_loop[{}] exited: {}", i, e);
                }
            });
        }));
    }

    // Spawn connect_loop for peers 1..n-1
    for (idx, endpoint) in client_endpoints.into_iter().enumerate() {
        let i = idx + 1;
        let db_path = peers[i].db_path.clone();
        let identity = peers[i].identity.clone();
        let remote = server_addrs[idx];
        handles.push(std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async move {
                if let Err(e) = connect_loop(&db_path, &identity, endpoint, remote).await {
                    tracing::warn!("chain connect_loop[{}] exited: {}", i, e);
                }
            });
        }));
    }

    handles
}

/// Start a multi-source topology: sources S0..Sn all connect to a single sink.
///
/// The sink runs accept_loop (serialized — one connection at a time with current code).
/// Each source runs connect_loop to the sink.
///
/// Returns thread handles for sink accept and all source connect loops.
pub fn start_multi_source(sources: &[Peer], sink: &Peer) -> Vec<std::thread::JoinHandle<()>> {
    assert!(!sources.is_empty(), "need at least one source");

    // Extract source fingerprints
    let mut source_fps: Vec<[u8; 32]> = Vec::new();
    for source in sources {
        source_fps.push(source.spki_fingerprint());
    }

    // Sink server endpoint allows all sources
    let (sink_cert, sink_key) = sink.cert_and_key();
    let sink_fp = sink.spki_fingerprint();

    let allowed_for_sink = Arc::new(AllowedPeers::from_fingerprints(source_fps));
    let server_endpoint = create_server_endpoint(
        "127.0.0.1:0".parse().unwrap(),
        sink_cert, sink_key, allowed_for_sink,
    ).expect("failed to create sink server endpoint");
    let sink_addr = server_endpoint.local_addr().expect("failed to get sink addr");

    let mut handles = Vec::new();

    // Spawn accept_loop for sink
    let sink_db = sink.db_path.clone();
    let sink_identity = sink.identity.clone();
    handles.push(std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async move {
            if let Err(e) = accept_loop(&sink_db, &sink_identity, server_endpoint).await {
                tracing::warn!("sink accept_loop exited: {}", e);
            }
        });
    }));

    // Spawn connect_loop for each source
    for (i, source) in sources.iter().enumerate() {
        let (cert, key) = source.cert_and_key();
        let allowed = Arc::new(AllowedPeers::from_fingerprints(vec![sink_fp]));
        let endpoint = create_client_endpoint(
            "0.0.0.0:0".parse().unwrap(),
            cert, key, allowed,
        ).expect("failed to create source client endpoint");

        let db_path = source.db_path.clone();
        let identity = source.identity.clone();
        handles.push(std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async move {
                if let Err(e) = connect_loop(&db_path, &identity, endpoint, sink_addr).await {
                    tracing::warn!("source connect_loop[{}] exited: {}", i, e);
                }
            });
        }));
    }

    handles
}

/// Start a sink-driven download topology: sink connects to all sources.
///
/// Each source runs accept_loop (responder). The sink runs download_from_sources
/// (initiator) connecting to all sources simultaneously with coordinated
/// round-based assignment. A coordinator thread assigns events to peers using
/// greedy load balancing; undelivered events get reassigned next round.
///
/// Returns thread handles for all source accept_loops and the sink download task.
pub fn start_sink_download(sources: &[Peer], sink: &Peer) -> Vec<std::thread::JoinHandle<()>> {
    assert!(!sources.is_empty(), "need at least one source");

    // Extract sink fingerprint for sources to allow
    let (sink_cert, sink_key) = sink.cert_and_key();
    let sink_fp = sink.spki_fingerprint();

    let mut handles = Vec::new();
    let mut source_addrs = Vec::new();

    // Start accept_loop for each source
    for source in sources {
        let (cert, key) = source.cert_and_key();

        let allowed = Arc::new(AllowedPeers::from_fingerprints(vec![sink_fp]));
        let server_endpoint = create_server_endpoint(
            "127.0.0.1:0".parse().unwrap(),
            cert, key, allowed,
        ).expect("failed to create source server endpoint");
        let addr = server_endpoint.local_addr().expect("failed to get source addr");
        source_addrs.push(addr);

        let db_path = source.db_path.clone();
        let identity = source.identity.clone();
        handles.push(std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async move {
                if let Err(e) = accept_loop(&db_path, &identity, server_endpoint).await {
                    tracing::warn!("source accept_loop exited: {}", e);
                }
            });
        }));
    }

    // Build per-source client endpoints for the sink
    let mut endpoint_pairs = Vec::new();
    for (i, source) in sources.iter().enumerate() {
        let source_fp = source.spki_fingerprint();

        let allowed = Arc::new(AllowedPeers::from_fingerprints(vec![source_fp]));
        let client_endpoint = create_client_endpoint(
            "0.0.0.0:0".parse().unwrap(),
            sink_cert.clone(), sink_key.clone_key(), allowed,
        ).expect("failed to create sink client endpoint");

        endpoint_pairs.push((client_endpoint, source_addrs[i]));
    }

    // Spawn download_from_sources for the sink
    let sink_db = sink.db_path.clone();
    let sink_identity = sink.identity.clone();
    handles.push(std::thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async move {
            if let Err(e) = download_from_sources(
                &sink_db, &sink_identity, endpoint_pairs,
            ).await {
                tracing::warn!("sink download_from_sources exited: {}", e);
            }
        });
    }));

    handles
}

/// Connect to a remote peer, run one sync session, and close the connection.
///
/// Used for B0 multi-source baseline testing where sources connect sequentially
/// (one session each) to a sink running accept_loop.
pub async fn connect_sync_once(
    db_path: &str,
    identity: &str,
    remote_addr: SocketAddr,
    remote_fp: [u8; 32],
) -> Result<crate::runtime::SyncStats, Box<dyn std::error::Error + Send + Sync>> {
    let (_, cert, key) = ensure_transport_cert(
        &open_connection(db_path)?
    )?;
    let allowed = Arc::new(AllowedPeers::from_fingerprints(vec![remote_fp]));
    let endpoint = create_client_endpoint("0.0.0.0:0".parse().unwrap(), cert, key, allowed)?;

    let connection = endpoint.connect(remote_addr, "localhost")?.await?;
    let peer_id = peer_identity_from_connection(&connection)
        .ok_or_else(|| "could not extract peer identity".to_string())?;

    let (ctrl_send, ctrl_recv) = connection.open_bi().await?;
    let (data_send, data_recv) = connection.open_bi().await?;
    let mut conn = DualConnection::new(ctrl_send, ctrl_recv, data_send, data_recv);

    // Send markers to materialize lazy QUIC streams on the receiver
    conn.control.send(&SyncMessage::HaveList { ids: vec![] }).await?;
    conn.data_send.send(&SyncMessage::HaveList { ids: vec![] }).await?;
    conn.flush_control().await?;
    conn.flush_data().await?;

    let stats = run_sync_initiator_dual(
        conn, db_path, SYNC_SESSION_TIMEOUT_SECS, &peer_id, identity, None, None,
    ).await?;

    connection.close(0u32.into(), b"done");
    endpoint.close(0u32.into(), b"done");

    Ok(stats)
}

/// Start a sink's accept_loop and return the handle and listen address.
/// `allowed_fps` is the list of source fingerprints allowed to connect.
pub fn start_sink_accept(
    sink: &Peer,
    allowed_fps: Vec<[u8; 32]>,
) -> (std::thread::JoinHandle<()>, SocketAddr) {
    let (cert, key) = sink.cert_and_key();
    let allowed = Arc::new(AllowedPeers::from_fingerprints(allowed_fps));
    let endpoint = create_server_endpoint(
        "127.0.0.1:0".parse().unwrap(),
        cert, key, allowed,
    ).expect("failed to create sink server endpoint");
    let addr = endpoint.local_addr().expect("failed to get sink addr");

    let db_path = sink.db_path.clone();
    let identity = sink.identity.clone();
    let handle = std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async move {
            if let Err(e) = accept_loop(&db_path, &identity, endpoint).await {
                tracing::warn!("sink accept_loop exited: {}", e);
            }
        });
    });

    (handle, addr)
}

/// Extract the SPKI fingerprint for a peer.
pub fn peer_fingerprint(peer: &Peer) -> [u8; 32] {
    peer.spki_fingerprint()
}

/// A multi-tenant node: multiple peers sharing a single database.
///
/// Each tenant has its own transport identity but they all use the same DB file.
/// This mirrors the production `run_node` setup where tenant discovery comes from
/// the join of `trust_anchors` and `local_transport_creds`.
pub struct SharedDbNode {
    pub db_path: String,
    pub tenants: Vec<Peer>,
    _tempdir: tempfile::TempDir,
}

impl SharedDbNode {
    /// Create a shared-DB node with N tenants, each bootstrapped with a full identity chain.
    pub fn new(n: usize) -> Self {
        assert!(n >= 1, "need at least 1 tenant");
        let tempdir = tempfile::tempdir().expect("failed to create tempdir");
        let db_path = tempdir.path().join("shared.db").to_str().unwrap().to_string();

        // Initialize DB once
        {
            let db = open_connection(&db_path).expect("failed to open shared db");
            create_tables(&db).expect("failed to create tables");
        }

        let mut tenants = Vec::with_capacity(n);
        for i in 0..n {
            let name = format!("tenant-{}", i);
            // Create a Peer that uses the shared db_path
            let peer = Self::create_tenant(&db_path, &name);
            tenants.push(peer);
        }

        Self {
            db_path,
            tenants,
            _tempdir: tempdir,
        }
    }

    /// Create a single tenant within the shared DB.
    fn create_tenant(db_path: &str, name: &str) -> Peer {
        // Ensure tables exist (idempotent)
        let db = open_connection(db_path).expect("failed to open db");
        create_tables(&db).expect("failed to create tables");
        drop(db);

        // We need a separate identity for each tenant. The first call to
        // ensure_transport_peer_id generates one cert; subsequent tenants
        // need distinct certs. Generate a new cert for this tenant.
        let (cert, key) = crate::transport::generate_self_signed_cert()
            .expect("failed to generate cert");
        let fp = extract_spki_fingerprint(cert.as_ref()).expect("failed to extract SPKI");
        let tenant_identity = hex::encode(fp);

        // Store this tenant's creds in the shared DB
        let db = open_connection(db_path).expect("failed to open db");
        crate::db::transport_creds::store_local_creds(
            &db,
            &tenant_identity,
            cert.as_ref(),
            key.secret_pkcs8_der(),
        ).expect("failed to store creds");

        let author_id: [u8; 32] = rand::random();

        // Build a Peer struct pointing to the shared db
        // We need a dummy tempdir since Peer owns one, but for SharedDbNode
        // the real DB is in the node's tempdir
        let dummy_tempdir = tempfile::tempdir().expect("failed to create dummy tempdir");

        let mut peer = Peer {
            name: name.to_string(),
            db_path: db_path.to_string(),
            identity: tenant_identity,
            author_id,
            workspace_id: [0u8; 32],
            peer_shared_event_id: None,
            peer_shared_signing_key: None,
            workspace_signing_key: None,
            _tempdir: dummy_tempdir,
        };

        // Bootstrap full identity chain
        peer.bootstrap_identity_chain();
        peer
    }

    /// Add a new tenant that joins an existing tenant's workspace (same DB)
    /// using the production `create_user_invite` + `accept_user_invite` flow.
    pub fn add_tenant_in_workspace(&mut self, name: &str, creator_index: usize) {
        use crate::identity_ops::{create_user_invite, accept_user_invite};
        use crate::projection::pipeline::project_one;

        let creator = &self.tenants[creator_index];
        let workspace_id = creator.workspace_id;
        let workspace_key = creator.workspace_signing_key.as_ref()
            .expect("creator has no workspace_signing_key")
            .clone();
        let creator_identity = creator.identity.clone();

        // Create a new transport identity in the shared DB
        let (cert, key) = crate::transport::generate_self_signed_cert()
            .expect("failed to generate cert");
        let fp = extract_spki_fingerprint(cert.as_ref()).expect("failed to extract SPKI");
        let tenant_identity = hex::encode(fp);

        let db = open_connection(&self.db_path).expect("failed to open db");
        crate::db::transport_creds::store_local_creds(
            &db,
            &tenant_identity,
            cert.as_ref(),
            key.secret_pkcs8_der(),
        ).expect("failed to store creds");

        // Creator issues an invite
        let invite = create_user_invite(
            &db, &creator_identity, &workspace_key, &workspace_id,
        ).expect("failed to create user invite");

        // The Workspace and UserInviteBoot events already exist in the shared DB.
        // Record them for this new tenant and project.
        let now_ms = current_timestamp_ms() as i64;
        insert_recorded_event(&db, &tenant_identity, &workspace_id, now_ms, "test")
            .expect("failed to record workspace event");
        let _ = project_one(&db, &tenant_identity, &workspace_id);

        insert_recorded_event(&db, &tenant_identity, &invite.invite_event_id, now_ms, "test")
            .expect("failed to record invite event");
        let _ = project_one(&db, &tenant_identity, &invite.invite_event_id);

        // Accept the invite (production flow)
        let join = accept_user_invite(
            &db, &tenant_identity, &invite.invite_key,
            &invite.invite_event_id, workspace_id,
        ).expect("failed to accept user invite");

        let author_id: [u8; 32] = rand::random();
        let dummy_tempdir = tempfile::tempdir().expect("failed to create dummy tempdir");

        let peer = Peer {
            name: name.to_string(),
            db_path: self.db_path.clone(),
            identity: tenant_identity,
            author_id,
            workspace_id,
            peer_shared_event_id: Some(join.peer_shared_event_id),
            peer_shared_signing_key: Some(join.peer_shared_key),
            workspace_signing_key: None,
            _tempdir: dummy_tempdir,
        };

        self.tenants.push(peer);
    }

    /// Get the list of tenant peer_ids.
    pub fn tenant_ids(&self) -> Vec<String> {
        self.tenants.iter().map(|t| t.identity.clone()).collect()
    }

    /// Verify projection invariants for all tenants and assert no cross-tenant leakage.
    pub fn verify_all_invariants(&self) {
        for tenant in &self.tenants {
            verify_projection_invariants(tenant);
        }
        let tenant_workspaces: Vec<(String, String)> = self.tenants.iter()
            .map(|t| (t.identity.clone(), hex::encode(t.workspace_id)))
            .collect();
        assert_no_cross_tenant_leakage(&self.db_path, &tenant_workspaces);
    }
}

/// Assert that no cross-tenant leakage exists in the shared database.
///
/// `tenant_workspaces` is a list of (peer_id, workspace_id) pairs. Checks:
/// 1. For tenants in different workspaces: recorded_events and valid_events
///    event_id sets are pairwise disjoint (no cross-workspace leakage).
///    For tenants in the same workspace: overlap is expected after sync.
/// 2. No unexpected peer_ids appear in recorded_events, valid_events, or
///    projection tables.
pub fn assert_no_cross_tenant_leakage(db_path: &str, tenant_workspaces: &[(String, String)]) {
    let db = open_connection(db_path).expect("failed to open db");

    let tenant_ids: Vec<&str> = tenant_workspaces.iter().map(|(id, _)| id.as_str()).collect();
    let known_ids: std::collections::HashSet<&str> = tenant_ids.iter().copied().collect();

    // Collect recorded event_ids per tenant
    let mut recorded_per_tenant: std::collections::HashMap<&str, std::collections::HashSet<String>> = std::collections::HashMap::new();
    for tid in &tenant_ids {
        let mut stmt = db.prepare(
            "SELECT event_id FROM recorded_events WHERE peer_id = ?1"
        ).expect("failed to prepare stmt");
        let events: std::collections::HashSet<String> = stmt
            .query_map([tid], |row| row.get::<_, String>(0))
            .expect("failed to query")
            .collect::<Result<std::collections::HashSet<_>, _>>()
            .expect("failed to collect");
        recorded_per_tenant.insert(tid, events);
    }

    // Verify pairwise disjointness of recorded_events for tenants in DIFFERENT workspaces
    for i in 0..tenant_workspaces.len() {
        for j in (i + 1)..tenant_workspaces.len() {
            let (id_a, ws_a) = &tenant_workspaces[i];
            let (id_b, ws_b) = &tenant_workspaces[j];
            if ws_a == ws_b {
                continue; // same workspace — overlap is expected after sync
            }
            let a = recorded_per_tenant.get(id_a.as_str()).unwrap();
            let b = recorded_per_tenant.get(id_b.as_str()).unwrap();
            let overlap: Vec<&String> = a.intersection(b).collect();
            assert!(overlap.is_empty(),
                "Cross-workspace leakage in recorded_events between {} and {}: {:?}",
                &id_a[..16], &id_b[..16], overlap);
        }
    }

    // Collect valid event_ids per tenant
    let mut valid_per_tenant: std::collections::HashMap<&str, std::collections::HashSet<String>> = std::collections::HashMap::new();
    for tid in &tenant_ids {
        let mut stmt = db.prepare(
            "SELECT event_id FROM valid_events WHERE peer_id = ?1"
        ).expect("failed to prepare stmt");
        let events: std::collections::HashSet<String> = stmt
            .query_map([tid], |row| row.get::<_, String>(0))
            .expect("failed to query")
            .collect::<Result<std::collections::HashSet<_>, _>>()
            .expect("failed to collect");
        valid_per_tenant.insert(tid, events);
    }

    for i in 0..tenant_workspaces.len() {
        for j in (i + 1)..tenant_workspaces.len() {
            let (id_a, ws_a) = &tenant_workspaces[i];
            let (id_b, ws_b) = &tenant_workspaces[j];
            if ws_a == ws_b {
                continue; // same workspace — overlap is expected after sync
            }
            let a = valid_per_tenant.get(id_a.as_str()).unwrap();
            let b = valid_per_tenant.get(id_b.as_str()).unwrap();
            let overlap: Vec<&String> = a.intersection(b).collect();
            assert!(overlap.is_empty(),
                "Cross-workspace leakage in valid_events between {} and {}: {:?}",
                &id_a[..16], &id_b[..16], overlap);
        }
    }

    // Verify no unexpected peer_ids in key scoped tables
    for table in &["recorded_events", "valid_events"] {
        let query = format!("SELECT DISTINCT peer_id FROM {}", table);
        let mut stmt = db.prepare(&query).expect("failed to prepare");
        let found_ids: Vec<String> = stmt
            .query_map([], |row| row.get::<_, String>(0))
            .expect("failed to query")
            .collect::<Result<Vec<_>, _>>()
            .expect("failed to collect");
        for found_id in &found_ids {
            assert!(known_ids.contains(found_id.as_str()),
                "Unknown peer_id '{}...' in {} table",
                &found_id[..16.min(found_id.len())], table);
        }
    }

    // Verify no unexpected peer_ids in projection tables
    for table in &["messages", "reactions", "signed_memos", "secret_keys", "deleted_messages"] {
        let query = format!("SELECT DISTINCT recorded_by FROM {}", table);
        let mut stmt = db.prepare(&query).expect("failed to prepare");
        let found_ids: Vec<String> = stmt
            .query_map([], |row| row.get::<_, String>(0))
            .expect("failed to query")
            .collect::<Result<Vec<_>, _>>()
            .expect("failed to collect");
        for found_id in &found_ids {
            assert!(known_ids.contains(found_id.as_str()),
                "Unknown peer_id '{}...' in {} table",
                &found_id[..16.min(found_id.len())], table);
        }
    }
}

/// Copy all events and neg_items from a source peer's database to target peers.
///
/// This creates identical data at each target so that concurrent sync tests can
/// verify dedup behavior when multiple sources offer the same events.
pub fn clone_events_to(source: &Peer, targets: &[&Peer]) {
    let src_db = open_connection(&source.db_path).expect("failed to open source db");

    // Read all events
    let mut events_stmt = src_db.prepare(
        "SELECT event_id, event_type, blob, share_scope, created_at, inserted_at FROM events"
    ).expect("failed to prepare events query");
    let events: Vec<(String, String, Vec<u8>, String, i64, i64)> = events_stmt
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, i64>(5)?,
            ))
        })
        .expect("failed to query events")
        .collect::<Result<Vec<_>, _>>()
        .expect("failed to collect events");

    // Read all neg_items
    let mut neg_stmt = src_db.prepare("SELECT ts, id FROM neg_items").expect("failed to prepare neg_items query");
    let neg_items: Vec<(i64, Vec<u8>)> = neg_stmt
        .query_map([], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?))
        })
        .expect("failed to query neg_items")
        .collect::<Result<Vec<_>, _>>()
        .expect("failed to collect neg_items");

    for target in targets {
        let tgt_db = open_connection(&target.db_path).expect("failed to open target db");
        tgt_db.execute("BEGIN", []).expect("failed to begin");

        for (event_id, event_type, blob, share_scope, created_at, inserted_at) in &events {
            tgt_db.execute(
                "INSERT OR IGNORE INTO events (event_id, event_type, blob, share_scope, created_at, inserted_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                rusqlite::params![event_id, event_type, blob.as_slice(), share_scope, created_at, inserted_at],
            ).expect("failed to insert event");
        }

        for (ts, id) in &neg_items {
            tgt_db.execute(
                "INSERT OR IGNORE INTO neg_items (ts, id) VALUES (?1, ?2)",
                rusqlite::params![ts, id.as_slice()],
            ).expect("failed to insert neg_item");
        }

        tgt_db.execute("COMMIT", []).expect("failed to commit");
    }
}
