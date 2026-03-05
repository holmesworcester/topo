pub mod bootstrap;

use std::net::SocketAddr;
use std::process::Child;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// RAII guard that kills a daemon process on drop, preventing leaked processes
/// when tests panic before reaching manual cleanup.
pub struct DaemonGuard {
    child: Option<Child>,
}

impl DaemonGuard {
    /// Wrap an already-spawned daemon `Child` process.
    pub fn new(child: Child) -> Self {
        Self { child: Some(child) }
    }

    /// Access the underlying `Child` (e.g. for `try_wait` or `id`).
    pub fn child(&mut self) -> &mut Child {
        self.child.as_mut().expect("DaemonGuard already consumed")
    }
}

impl Drop for DaemonGuard {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

use crate::crypto::{event_id_from_base64, event_id_to_base64, EventId};
use crate::db::{open_connection, schema::create_tables, store::insert_recorded_event};
use crate::event_modules::{
    AdminEvent, DeviceInviteEvent, FileSliceEvent, InviteAcceptedEvent, MessageAttachmentEvent,
    MessageDeletionEvent, MessageEvent, ParsedEvent, PeerEvent, PeerRemovedEvent, PeerSharedEvent,
    ReactionEvent, SecretKeyEvent, SecretSharedEvent, TenantEvent, UserEvent, UserInviteEvent,
    UserRemovedEvent, WorkspaceEvent,
};
use crate::peering::loops::{
    accept_loop, connect_loop, connect_loop_with_shared_ingest,
    connect_loop_with_shared_ingest_until_cancel,
};
use crate::projection::apply::project_one;
use crate::projection::create::{
    create_encrypted_event_synchronous, create_event_staged, create_event_synchronous,
    create_signed_event_staged, create_signed_event_synchronous, CreateEventError,
};
use crate::transport::identity::{ensure_transport_cert, ensure_transport_peer_id};
use crate::transport::{create_dual_endpoint_dynamic, extract_spki_fingerprint, AllowedPeers};
use ed25519_dalek::SigningKey;
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};

/// No-op intro spawner for tests that don't need holepunch.
pub fn noop_intro_spawner(
    _conn: quinn::Connection,
    _db_path: String,
    _recorded_by: String,
    _peer_id: String,
    _endpoint: quinn::Endpoint,
    _client_config: Option<quinn::ClientConfig>,
    _shared_ingest: tokio::sync::mpsc::Sender<
        crate::contracts::event_pipeline_contract::IngestItem,
    >,
) -> tokio::task::JoinHandle<()> {
    tokio::task::spawn_local(async {})
}

/// Convenience: production `IngestFns` for tests.
pub fn test_ingest_fns() -> crate::contracts::event_pipeline_contract::IngestFns {
    crate::contracts::event_pipeline_contract::IngestFns {
        batch_writer: crate::event_pipeline::batch_writer,
        drain_queue: crate::event_pipeline::drain_project_queue,
    }
}

fn current_timestamp_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

/// Open a lightweight connection for polling counts during active sync.
/// Avoids reapplying full connection pragmas on each poll, which can
/// contend with writers and cause transient open failures.
fn open_count_connection(db_path: &str) -> Option<rusqlite::Connection> {
    let db = match rusqlite::Connection::open(db_path) {
        Ok(db) => db,
        Err(_) => return None,
    };
    let _ = db.busy_timeout(Duration::from_millis(200));
    Some(db)
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
            self.events_transferred, self.wall_secs, self.events_per_sec, self.throughput_mib_s,
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

/// Delegate to the test bootstrap responder.
fn start_test_sync_endpoint(
    inviter_db_path: &str,
    inviter_identity: &str,
    invite_key: &SigningKey,
) -> Result<(SocketAddr, quinn::Endpoint), Box<dyn std::error::Error + Send + Sync>> {
    bootstrap::start_bootstrap_responder(
        inviter_db_path,
        inviter_identity,
        invite_key,
        crate::event_pipeline::batch_writer,
    )
}

impl Peer {
    /// Create a new peer with a fresh temp database (no identity chain).
    pub fn new(name: &str) -> Self {
        let tempdir = tempfile::tempdir().expect("failed to create tempdir");
        let db_path = tempdir
            .path()
            .join(format!("{}.db", name))
            .to_str()
            .unwrap()
            .to_string();

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
    /// `create_workspace` flow (Workspace → InviteAccepted → UserInvite →
    /// User → DeviceInvite → PeerShared + local signer secrets).
    /// Content events (Message, Reaction, etc.) are signed with the PeerShared key.
    pub fn new_with_identity(name: &str) -> Self {
        let mut peer = Self::new(name);
        peer.bootstrap_identity_chain();
        peer
    }

    /// Bootstrap a full identity chain using the production `create_workspace` flow.
    fn bootstrap_identity_chain(&mut self) {
        use crate::event_modules::workspace::commands::create_workspace;

        let db = open_connection(&self.db_path).expect("failed to open db");
        let old_identity = self.identity.clone();
        let result = create_workspace(
            &db,
            &old_identity,
            "test-workspace",
            "test-user",
            "test-device",
        )
        .expect("failed to bootstrap workspace");

        // create_workspace pre-derives the PeerShared transport identity and writes
        // all events under it, so no finalize_identity rewrite is needed.
        let new_identity = crate::transport::identity::load_transport_peer_id(&db)
            .expect("failed to load transport peer_id after create_workspace");
        self.identity = new_identity.clone();

        self.workspace_id = result.workspace_id;
        // Look up user_event_id from the created identity chain
        if let Ok(uid) = crate::service::resolve_user_event_id_for_signer(
            &db,
            &new_identity,
            &result.peer_shared_event_id,
        ) {
            self.author_id = uid;
        }
        self.peer_shared_event_id = Some(result.peer_shared_event_id);
        self.peer_shared_signing_key = Some(result.peer_shared_key);
        // Load workspace signing key from local signer material
        if let Ok(Some((_ws_eid, ws_key))) =
            crate::event_modules::workspace::commands::load_workspace_signing_key(
                &db,
                &new_identity,
            )
        {
            self.workspace_signing_key = Some(ws_key);
        }
    }

    /// Create a new peer that joins an existing workspace created by `creator`
    /// using the production invite flow with real QUIC bootstrap sync:
    /// creator issues `create_user_invite`, starts a temp sync endpoint,
    /// joiner fetches prerequisite events via bootstrap sync, then calls
    /// `accept_user_invite`. No direct DB-to-DB event copying.
    pub async fn new_in_workspace(name: &str, creator: &Peer) -> Self {
        use crate::db::transport_trust::record_pending_invite_bootstrap_trust;
        use crate::event_modules::workspace::commands::create_user_invite_raw;
        use crate::event_modules::workspace::identity_ops::expected_invite_bootstrap_spki_from_invite_key;
        use crate::event_modules::workspace::invite_link::create_invite_link;

        // Create a bare peer with DB tables but NO transport identity.
        // svc_accept_invite will install the invite-derived identity.
        let tempdir = tempfile::tempdir().expect("failed to create tempdir");
        let db_path = tempdir
            .path()
            .join(format!("{}.db", name))
            .to_str()
            .unwrap()
            .to_string();
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
        let workspace_key = creator
            .workspace_signing_key
            .as_ref()
            .expect("creator has no workspace_signing_key; use new_with_identity()");
        let creator_peer_key = creator
            .peer_shared_signing_key
            .as_ref()
            .expect("creator has no peer_shared_signing_key; use new_with_identity()");
        let creator_peer_eid = creator
            .peer_shared_event_id
            .expect("creator has no peer_shared_event_id; use new_with_identity()");

        // Creator issues an invite via workspace::commands API
        let invite = create_user_invite_raw(
            &creator_db,
            &creator.identity,
            workspace_key,
            &creator.workspace_id,
            Some(creator_peer_key),
            Some(&creator_peer_eid),
        )
        .expect("failed to create user invite");

        // Register pending bootstrap trust so creator's endpoint allows the joiner
        let pending_spki = expected_invite_bootstrap_spki_from_invite_key(&invite.invite_key)
            .expect("failed to derive invite SPKI");
        record_pending_invite_bootstrap_trust(
            &creator_db,
            &creator.identity,
            &event_id_to_base64(&invite.invite_event_id),
            &event_id_to_base64(&creator.workspace_id),
            &pending_spki,
        )
        .expect("failed to record pending bootstrap trust");
        drop(creator_db);

        // Start a temp sync endpoint for the creator
        let (sync_addr, sync_endpoint) =
            start_test_sync_endpoint(&creator.db_path, &creator.identity, &invite.invite_key)
                .expect("failed to start temp sync endpoint");

        // Build invite link with creator's bootstrap address and SPKI
        let creator_spki = creator.spki_fingerprint();
        let invite_link = create_invite_link(&invite, &sync_addr.to_string(), &creator_spki)
            .expect("failed to create invite link");

        // Step 1: Accept invite — stores events (may block), materializes bootstrap trust
        let result = crate::event_modules::workspace::commands::accept_invite(
            &peer.db_path,
            &invite_link,
            name,
            "device",
        )
        .expect("failed to accept invite");

        // Step 2: Bootstrap sync — fetches prerequisites from creator.
        // In production this is done by the autodial loop; in tests we trigger
        // it directly. The batch_writer handles projection cascade.
        crate::testutil::bootstrap::bootstrap_sync_from_invite(
            &peer.db_path,
            &result.peer_id,
            sync_addr,
            &creator_spki,
            10,
            crate::event_pipeline::batch_writer,
        )
        .await
        .expect("failed bootstrap sync");

        // Allow batch_writer to finish draining projection cascade.
        tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;

        // Clean up sync endpoint
        sync_endpoint.close(0u32.into(), b"bootstrap done");

        // Step 3: With pre-derive, the peer_id is already the final
        // PeerShared-derived identity — no finalize_identity needed.
        let db = open_connection(&peer.db_path).expect("failed to open db");
        let scoped_peer_id = result.peer_id.clone();
        peer.identity = scoped_peer_id.clone();
        peer.workspace_id = creator.workspace_id;

        // Load signing key and user_event_id from DB
        if let Ok(Some((eid, key))) =
            crate::service::load_local_peer_signer_pub(&db, &scoped_peer_id)
        {
            peer.peer_shared_event_id = Some(eid);
            peer.peer_shared_signing_key = Some(key);
            if let Ok(uid) =
                crate::service::resolve_user_event_id_for_signer(&db, &scoped_peer_id, &eid)
            {
                peer.author_id = uid;
            }
        }

        peer
    }

    /// Get the PeerShared signer event_id. Panics if no identity chain.
    fn signer_eid(&self) -> EventId {
        self.peer_shared_event_id
            .expect("Peer has no identity chain; use new_with_identity()")
    }

    /// Get a reference to the PeerShared signing key. Panics if no identity chain.
    fn signing_key(&self) -> &SigningKey {
        self.peer_shared_signing_key
            .as_ref()
            .expect("Peer has no identity chain; use new_with_identity()")
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
        create_signed_event_synchronous(&db, &self.identity, &msg, self.signing_key())
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

    /// Create a SecretKey event with the given key bytes.
    /// Returns the event ID.
    pub fn create_secret_key(&self, key_bytes: [u8; 32]) -> EventId {
        let db = open_connection(&self.db_path).expect("failed to open db");
        let sk = ParsedEvent::SecretKey(SecretKeyEvent {
            created_at_ms: current_timestamp_ms(),
            key_bytes,
        });
        create_event_synchronous(&db, &self.identity, &sk).expect("failed to create secret_key")
    }

    /// Create a SecretKey event with deterministic key bytes and timestamp.
    /// Two peers calling this with the same args produce the same blob -> same event_id.
    /// This is used for PSK materialization in tests where both peers need the same key.
    pub fn create_secret_key_deterministic(
        &self,
        key_bytes: [u8; 32],
        created_at_ms: u64,
    ) -> EventId {
        let db = open_connection(&self.db_path).expect("failed to open db");
        let sk = ParsedEvent::SecretKey(SecretKeyEvent {
            created_at_ms,
            key_bytes,
        });
        create_event_synchronous(&db, &self.identity, &sk).expect("failed to create secret_key")
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
        self.create_encrypted_signed_event_synchronous(&db, key_event_id, &inner)
    }

    /// Sign an inner event, encrypt the signed blob, wrap in EncryptedEvent, store + project.
    fn create_encrypted_signed_event_synchronous(
        &self,
        db: &rusqlite::Connection,
        key_event_id: &EventId,
        inner_event: &ParsedEvent,
    ) -> EventId {
        create_encrypted_event_synchronous(
            db,
            &self.identity,
            key_event_id,
            inner_event,
            Some(self.signing_key()),
        )
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
        create_signed_event_synchronous(&db, &self.identity, &del, self.signing_key())
            .expect("failed to create message_deletion")
    }

    /// Create an encrypted MessageDeletion event.
    /// Returns the encrypted event ID. Requires identity chain.
    pub fn create_encrypted_deletion(
        &self,
        key_event_id: &EventId,
        target_event_id: &EventId,
    ) -> EventId {
        let db = open_connection(&self.db_path).expect("failed to open db");
        let inner = ParsedEvent::MessageDeletion(MessageDeletionEvent {
            created_at_ms: current_timestamp_ms(),
            target_event_id: *target_event_id,
            author_id: self.author_id,
            signed_by: self.signer_eid(),
            signer_type: 5,
            signature: [0u8; 64],
        });
        self.create_encrypted_signed_event_synchronous(&db, key_event_id, &inner)
    }

    // --- Identity event helpers ---

    /// Create a Workspace event. Returns the event ID.
    ///
    /// Pre-seeds the trust anchor so that neg_items gets the correct
    /// workspace_id from the start (same pattern as commands::create_workspace).
    pub fn create_workspace(&self, public_key: [u8; 32]) -> EventId {
        let db = open_connection(&self.db_path).expect("failed to open db");
        let ws = ParsedEvent::Workspace(WorkspaceEvent {
            created_at_ms: current_timestamp_ms(),
            public_key,
            name: "test-workspace".to_string(),
        });
        // Pre-compute event_id and seed trust anchor before storing
        let ws_blob =
            crate::event_modules::encode_event(&ws).expect("failed to encode workspace event");
        let ws_eid = crate::crypto::hash_event(&ws_blob);
        let ws_eid_b64 = event_id_to_base64(&ws_eid);
        db.execute(
            "INSERT OR IGNORE INTO trust_anchors (peer_id, workspace_id) VALUES (?1, ?2)",
            rusqlite::params![&self.identity, &ws_eid_b64],
        )
        .expect("failed to seed trust anchor");
        let ws_eid2 =
            create_event_staged(&db, &self.identity, &ws).expect("failed to create workspace");
        assert_eq!(ws_eid, ws_eid2, "pre-computed workspace event_id mismatch");
        ws_eid
    }

    /// Try to create a Workspace event. Returns Result to allow handling rejection.
    pub fn try_create_workspace(&self, public_key: [u8; 32]) -> Result<EventId, CreateEventError> {
        let db = open_connection(&self.db_path).expect("failed to open db");
        let ws = ParsedEvent::Workspace(WorkspaceEvent {
            created_at_ms: current_timestamp_ms(),
            public_key,
            name: "test-workspace".to_string(),
        });
        create_event_synchronous(&db, &self.identity, &ws)
    }

    /// Create an InviteAccepted event (local). Returns the event ID.
    pub fn create_invite_accepted(
        &self,
        invite_event_id: &EventId,
        workspace_id: [u8; 32],
    ) -> EventId {
        let db = open_connection(&self.db_path).expect("failed to open db");
        let tenant_event_id = self.ensure_local_tenant_event_id(&db);
        let ia = ParsedEvent::InviteAccepted(InviteAcceptedEvent {
            created_at_ms: current_timestamp_ms(),
            tenant_event_id,
            invite_event_id: *invite_event_id,
            workspace_id,
        });
        create_event_synchronous(&db, &self.identity, &ia)
            .expect("failed to create invite_accepted")
    }

    /// Try to create an InviteAccepted event. Returns Result to allow handling rejection.
    pub fn try_create_invite_accepted(
        &self,
        invite_event_id: &EventId,
        workspace_id: [u8; 32],
    ) -> Result<EventId, CreateEventError> {
        let db = open_connection(&self.db_path).expect("failed to open db");
        let tenant_event_id = self.ensure_local_tenant_event_id(&db);
        let ia = ParsedEvent::InviteAccepted(InviteAcceptedEvent {
            created_at_ms: current_timestamp_ms(),
            tenant_event_id,
            invite_event_id: *invite_event_id,
            workspace_id,
        });
        create_event_synchronous(&db, &self.identity, &ia)
    }

    fn ensure_local_tenant_event_id(&self, db: &rusqlite::Connection) -> EventId {
        let existing: Option<String> = db
            .query_row(
                "SELECT event_id FROM tenants WHERE recorded_by = ?1 ORDER BY created_at ASC, event_id ASC LIMIT 1",
                rusqlite::params![&self.identity],
                |row| row.get(0),
            )
            .ok();
        if let Some(eid_b64) = existing {
            return event_id_from_base64(&eid_b64).expect("invalid tenants.event_id base64");
        }

        let peer_key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
        let tenant_evt = ParsedEvent::Tenant(TenantEvent {
            created_at_ms: current_timestamp_ms(),
            public_key: peer_key.verifying_key().to_bytes(),
        });
        let tenant_event_id = create_event_synchronous(db, &self.identity, &tenant_evt)
            .expect("failed to create tenant");

        let peer_evt = ParsedEvent::Peer(PeerEvent {
            created_at_ms: current_timestamp_ms(),
            tenant_event_id,
            public_key: peer_key.verifying_key().to_bytes(),
        });
        let _peer_event_id =
            create_event_synchronous(db, &self.identity, &peer_evt).expect("failed to create peer");
        tenant_event_id
    }

    /// Create a UserInvite event (signed by workspace key). Returns the event ID.
    pub fn create_user_invite(
        &self,
        signing_key: &ed25519_dalek::SigningKey,
        workspace_id: &EventId,
    ) -> EventId {
        let db = open_connection(&self.db_path).expect("failed to open db");
        let public_key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng())
            .verifying_key()
            .to_bytes();
        let evt = ParsedEvent::UserInvite(UserInviteEvent {
            created_at_ms: current_timestamp_ms(),
            public_key,
            workspace_id: *workspace_id,
            signed_by: *workspace_id,
            signer_type: 1,
            signature: [0u8; 64],
        });
        create_signed_event_staged(&db, &self.identity, &evt, signing_key)
            .expect("failed to create user_invite")
    }

    /// Create a UserInvite with a specific public key. Returns the event ID.
    pub fn create_user_invite_with_key(
        &self,
        invite_public_key: [u8; 32],
        signing_key: &ed25519_dalek::SigningKey,
        workspace_id: &EventId,
    ) -> EventId {
        let db = open_connection(&self.db_path).expect("failed to open db");
        let evt = ParsedEvent::UserInvite(UserInviteEvent {
            created_at_ms: current_timestamp_ms(),
            public_key: invite_public_key,
            workspace_id: *workspace_id,
            signed_by: *workspace_id,
            signer_type: 1,
            signature: [0u8; 64],
        });
        create_signed_event_staged(&db, &self.identity, &evt, signing_key)
            .expect("failed to create user_invite")
    }

    /// Create a deterministic local invite_privkey event for an invite.
    pub fn create_invite_privkey(
        &self,
        invite_event_id: &EventId,
        invite_private_key: [u8; 32],
    ) -> EventId {
        let db = open_connection(&self.db_path).expect("failed to open db");
        let evt = crate::event_modules::invite_privkey::deterministic_invite_privkey_event(
            *invite_event_id,
            invite_private_key,
        );
        create_event_staged(&db, &self.identity, &evt).expect("failed to create invite_privkey")
    }

    /// Create a User event (signed by UserInvite key). Returns the event ID.
    pub fn create_user(
        &self,
        user_public_key: [u8; 32],
        signing_key: &ed25519_dalek::SigningKey,
        user_invite_event_id: &EventId,
    ) -> EventId {
        let db = open_connection(&self.db_path).expect("failed to open db");
        let evt = ParsedEvent::User(UserEvent {
            created_at_ms: current_timestamp_ms(),
            public_key: user_public_key,
            username: "test-user".to_string(),
            signed_by: *user_invite_event_id,
            signer_type: 2,
            signature: [0u8; 64],
        });
        create_signed_event_staged(&db, &self.identity, &evt, signing_key)
            .expect("failed to create user")
    }

    /// Create a DeviceInvite event (signed by User key). Returns the event ID.
    pub fn create_device_invite(
        &self,
        device_invite_public_key: [u8; 32],
        signing_key: &ed25519_dalek::SigningKey,
        user_event_id: &EventId,
    ) -> EventId {
        let db = open_connection(&self.db_path).expect("failed to open db");
        let evt = ParsedEvent::DeviceInvite(DeviceInviteEvent {
            created_at_ms: current_timestamp_ms(),
            public_key: device_invite_public_key,
            signed_by: *user_event_id,
            signer_type: 4,
            signature: [0u8; 64],
        });
        create_signed_event_staged(&db, &self.identity, &evt, signing_key)
            .expect("failed to create device_invite")
    }

    /// Create a PeerShared event (signed by DeviceInvite key). Returns the event ID.
    pub fn create_peer_shared(
        &self,
        peer_shared_public_key: [u8; 32],
        signing_key: &ed25519_dalek::SigningKey,
        device_invite_event_id: &EventId,
        user_event_id: &EventId,
    ) -> EventId {
        let db = open_connection(&self.db_path).expect("failed to open db");
        let evt = ParsedEvent::PeerShared(PeerSharedEvent {
            created_at_ms: current_timestamp_ms(),
            public_key: peer_shared_public_key,
            user_event_id: *user_event_id,
            device_name: "test-device".to_string(),
            signed_by: *device_invite_event_id,
            signer_type: 3,
            signature: [0u8; 64],
        });
        create_signed_event_staged(&db, &self.identity, &evt, signing_key)
            .expect("failed to create peer_shared")
    }

    /// Create an Admin event (signed by Workspace key, dep on User). Returns the event ID.
    pub fn create_admin(
        &self,
        admin_public_key: [u8; 32],
        signing_key: &ed25519_dalek::SigningKey,
        user_event_id: &EventId,
        workspace_id: &EventId,
    ) -> EventId {
        let db = open_connection(&self.db_path).expect("failed to open db");
        let evt = ParsedEvent::Admin(AdminEvent {
            created_at_ms: current_timestamp_ms(),
            public_key: admin_public_key,
            user_event_id: *user_event_id,
            signed_by: *workspace_id,
            signer_type: 1,
            signature: [0u8; 64],
        });
        create_signed_event_synchronous(&db, &self.identity, &evt, signing_key)
            .expect("failed to create admin")
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
        create_signed_event_synchronous(&db, &self.identity, &evt, signing_key)
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
        create_signed_event_synchronous(&db, &self.identity, &evt, signing_key)
            .expect("failed to create peer_removed")
    }

    /// Create a SecretShared event (signed by PeerShared key). Returns the event ID.
    pub fn create_secret_shared(
        &self,
        signing_key: &ed25519_dalek::SigningKey,
        key_event_id: &EventId,
        recipient_event_id: &EventId,
        unwrap_key_event_id: &EventId,
        wrapped_key: [u8; 32],
        peer_shared_event_id: &EventId,
    ) -> EventId {
        let db = open_connection(&self.db_path).expect("failed to open db");
        let evt = ParsedEvent::SecretShared(SecretSharedEvent {
            created_at_ms: current_timestamp_ms(),
            key_event_id: *key_event_id,
            recipient_event_id: *recipient_event_id,
            unwrap_key_event_id: *unwrap_key_event_id,
            wrapped_key,
            signed_by: *peer_shared_event_id,
            signer_type: 5,
            signature: [0u8; 64],
        });
        create_signed_event_synchronous(&db, &self.identity, &evt, signing_key)
            .expect("failed to create secret_shared")
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
            create_signed_event_synchronous(&db, &self.identity, &msg, self.signing_key())
                .expect("failed to create message");
        }
        db.execute("COMMIT", []).expect("failed to commit");
    }

    /// Create a file consisting of `total_slices` file slices.
    ///
    /// Builds all required prerequisites (message, secret_key, attachment
    /// descriptor) and then batch-creates the slices. Returns the file_id
    /// used for all slices. Requires identity chain (use new_with_identity).
    pub fn batch_create_file_slices(&self, total_slices: usize) -> [u8; 32] {
        use crate::event_modules::file_slice::FILE_SLICE_CIPHERTEXT_BYTES;
        use crate::projection::signer::sign_event_bytes;

        let db = open_connection(&self.db_path).expect("failed to open db");
        let workspace_id = crate::db::store::lookup_workspace_id(&db, &self.identity)
            .expect("missing trust anchor workspace_id for file-slice benchmark");

        // Parent message
        let msg = ParsedEvent::Message(MessageEvent {
            created_at_ms: current_timestamp_ms(),
            workspace_id: self.workspace_id,
            author_id: self.author_id,
            content: format!("file-parent-{}", self.name),
            signed_by: self.signer_eid(),
            signer_type: 5,
            signature: [0u8; 64],
        });
        let msg_eid = create_signed_event_staged(&db, &self.identity, &msg, self.signing_key())
            .expect("failed to create parent message");

        // Secret key for attachment
        let sk = ParsedEvent::SecretKey(SecretKeyEvent {
            created_at_ms: current_timestamp_ms(),
            key_bytes: [0xBB; 32],
        });
        let sk_eid =
            create_event_staged(&db, &self.identity, &sk).expect("failed to create secret_key");

        let file_id: [u8; 32] = {
            use std::hash::{Hash, Hasher};
            let mut hasher = std::collections::hash_map::DefaultHasher::new();
            self.name.hash(&mut hasher);
            current_timestamp_ms().hash(&mut hasher);
            let h = hasher.finish().to_le_bytes();
            let mut fid = [0u8; 32];
            fid[..8].copy_from_slice(&h);
            fid[8..16].copy_from_slice(&h);
            fid
        };

        let slice_size = FILE_SLICE_CIPHERTEXT_BYTES;
        let file_bytes = total_slices * slice_size;

        // Message attachment descriptor
        let att = ParsedEvent::MessageAttachment(MessageAttachmentEvent {
            created_at_ms: current_timestamp_ms(),
            message_id: msg_eid,
            file_id,
            blob_bytes: file_bytes as u64,
            total_slices: total_slices as u32,
            slice_bytes: slice_size as u32,
            root_hash: [0xAA; 32],
            key_event_id: sk_eid,
            filename: format!("bench-{}.bin", self.name),
            mime_type: "application/octet-stream".to_string(),
            signed_by: self.signer_eid(),
            signer_type: 5,
            signature: [0u8; 64],
        });
        let att_eid = create_signed_event_staged(&db, &self.identity, &att, self.signing_key())
            .expect("failed to create message_attachment");
        project_one(&db, &self.identity, &att_eid).expect("failed to project attachment");

        // Batch-create file slices inside a transaction
        let ciphertext: Vec<u8> = vec![0xAB; FILE_SLICE_CIPHERTEXT_BYTES];
        let signing_key = self.signing_key().clone();

        db.execute("BEGIN", []).expect("failed to begin");
        for i in 0..total_slices as u32 {
            // Use a single timestamp for both the blob's created_at and the
            // neg_items ts. If these diverge, the sink's batch_writer (which
            // extracts created_at from the blob) inserts a different neg_items
            // key than the source, causing negentropy to never converge.
            let created_at = current_timestamp_ms();
            let fs = ParsedEvent::FileSlice(FileSliceEvent {
                created_at_ms: created_at,
                file_id,
                slice_number: i,
                ciphertext: ciphertext.clone(),
                signed_by: self.signer_eid(),
                signer_type: 5,
                signature: [0u8; 64],
            });
            let mut blob =
                crate::event_modules::encode_event(&fs).expect("failed to encode file_slice");
            let blob_len = blob.len();
            let sig = sign_event_bytes(&signing_key, &blob[..blob_len - 64]);
            blob[blob_len - 64..].copy_from_slice(&sig);

            let event_id = crate::crypto::hash_event(&blob);
            let event_id_b64 = event_id_to_base64(&event_id);

            // Insert into events, neg_items, recorded_events — all use the
            // same created_at that is embedded in the blob so that the
            // neg_items (ts, id) key matches what a receiving batch_writer
            // would extract from the blob.
            db.execute(
                "INSERT OR IGNORE INTO events (event_id, event_type, blob, share_scope, created_at, inserted_at)
                 VALUES (?1, ?2, ?3, 'shared', ?4, ?5)",
                rusqlite::params![&event_id_b64, "file_slice", blob.as_slice(), created_at as i64, created_at as i64],
            ).expect("failed to insert file_slice event");
            db.execute(
                "INSERT OR IGNORE INTO neg_items (workspace_id, ts, id) VALUES (?1, ?2, ?3)",
                rusqlite::params![&workspace_id, created_at as i64, event_id.as_slice()],
            )
            .expect("failed to insert neg_item");
            db.execute(
                "INSERT OR IGNORE INTO recorded_events (peer_id, event_id, recorded_at, source)
                 VALUES (?1, ?2, ?3, 'local')",
                rusqlite::params![&self.identity, &event_id_b64, created_at as i64],
            )
            .expect("failed to insert recorded_event");

            // Project (validates the signature + authorization chain)
            project_one(&db, &self.identity, &event_id).expect("failed to project file_slice");
        }
        db.execute("COMMIT", []).expect("failed to commit");

        file_id
    }

    /// Query file-slice event counts grouped by ingest source.
    ///
    /// Returns a map of source_peer → event_count. Uses events + recorded_events
    /// tables (no projection required). Module-local query helper.
    pub fn file_slice_event_counts_by_source(&self) -> std::collections::HashMap<String, i64> {
        let db = open_connection(&self.db_path).expect("failed to open db");
        crate::event_modules::file_slice::file_slice_event_counts_by_source(&db, &self.identity)
    }

    /// Count file_slice events received by this peer (no projection required).
    pub fn file_slice_event_count(&self) -> i64 {
        let db = open_connection(&self.db_path).expect("failed to open db");
        crate::event_modules::file_slice::file_slice_event_count(&db, &self.identity)
    }

    /// Count events in the events table.
    /// Returns -1 if the database can't be opened (transient contention).
    pub fn store_count(&self) -> i64 {
        let db = match open_count_connection(&self.db_path) {
            Some(db) => db,
            None => return -1,
        };
        db.query_row("SELECT COUNT(*) FROM events", [], |row| row.get(0))
            .unwrap_or(0)
    }

    /// Count sync-eligible shared-scope events in the events table.
    /// Returns -1 if the database can't be opened (transient contention).
    pub fn shared_store_count(&self) -> i64 {
        let db = match open_count_connection(&self.db_path) {
            Some(db) => db,
            None => return -1,
        };
        db.query_row(
            "SELECT COUNT(*) FROM events WHERE share_scope = 'shared'",
            [],
            |row| row.get(0),
        )
        .unwrap_or(0)
    }

    /// Count rows in the messages projection table (all, unscoped).
    pub fn message_count(&self) -> i64 {
        let db = match open_count_connection(&self.db_path) {
            Some(db) => db,
            None => return -1,
        };
        db.query_row("SELECT COUNT(*) FROM messages", [], |row| row.get(0))
            .unwrap_or(0)
    }

    /// Count stored message events from canonical `events` by event_type.
    /// Includes local and synced remote message events.
    pub fn stored_message_event_count(&self) -> i64 {
        let db = match open_count_connection(&self.db_path) {
            Some(db) => db,
            None => return -1,
        };
        db.query_row(
            "SELECT COUNT(*) FROM events WHERE event_type = 'message'",
            [],
            |row| row.get(0),
        )
        .unwrap_or(0)
    }

    /// Count rows in the reactions projection table scoped to this peer.
    pub fn reaction_count(&self) -> i64 {
        let db = open_connection(&self.db_path).expect("failed to open db");
        db.query_row(
            "SELECT COUNT(*) FROM reactions WHERE recorded_by = ?1",
            rusqlite::params![&self.identity],
            |row| row.get(0),
        )
        .unwrap_or(0)
    }

    /// Count rows in the secret_keys projection table scoped to this peer.
    pub fn secret_key_count(&self) -> i64 {
        let db = open_connection(&self.db_path).expect("failed to open db");
        db.query_row(
            "SELECT COUNT(*) FROM secret_keys WHERE recorded_by = ?1",
            rusqlite::params![&self.identity],
            |row| row.get(0),
        )
        .unwrap_or(0)
    }

    /// Count rows in the neg_items table (events advertised for sync).
    pub fn neg_items_count(&self) -> i64 {
        let db = open_connection(&self.db_path).expect("failed to open db");
        db.query_row("SELECT COUNT(*) FROM neg_items", [], |row| row.get(0))
            .unwrap_or(0)
    }

    /// Check if a specific event_id (base64) exists in the events table.
    pub fn has_event(&self, event_id_b64: &str) -> bool {
        let db = match open_count_connection(&self.db_path) {
            Some(db) => db,
            None => return false,
        };
        db.query_row(
            "SELECT COUNT(*) > 0 FROM events WHERE event_id = ?1",
            rusqlite::params![event_id_b64],
            |row| row.get(0),
        )
        .unwrap_or(false)
    }

    /// Count rows in the deleted_messages projection table scoped to this peer.
    pub fn deleted_message_count(&self) -> i64 {
        let db = open_connection(&self.db_path).expect("failed to open db");
        db.query_row(
            "SELECT COUNT(*) FROM deleted_messages WHERE recorded_by = ?1",
            rusqlite::params![&self.identity],
            |row| row.get(0),
        )
        .unwrap_or(0)
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
        )
        .unwrap_or(0)
    }

    /// Count recorded events by `source` for a given event type.
    ///
    /// Uses `source LIKE '<prefix>%'` so callers can isolate transport-ingest
    /// rows (e.g. `quic_recv:`) from local-created rows.
    pub fn recorded_event_type_counts_by_source(
        &self,
        event_type: &str,
        source_prefix: &str,
    ) -> std::collections::BTreeMap<String, i64> {
        let db = open_connection(&self.db_path).expect("failed to open db");
        let like = format!("{}%", source_prefix);
        let mut stmt = db
            .prepare(
                "SELECT re.source, COUNT(*)
                   FROM recorded_events re
                   JOIN events e ON e.event_id = re.event_id
                  WHERE re.peer_id = ?1
                    AND e.event_type = ?2
                    AND re.source LIKE ?3
               GROUP BY re.source
               ORDER BY re.source",
            )
            .expect("prepare source histogram query");

        stmt.query_map(rusqlite::params![&self.identity, event_type, like], |row| {
            let source: String = row.get(0)?;
            let count: i64 = row.get(1)?;
            Ok((source, count))
        })
        .expect("query source histogram")
        .collect::<Result<std::collections::BTreeMap<_, _>, _>>()
        .expect("collect source histogram")
    }

    /// Return sorted set of all store IDs (base64-encoded).
    pub fn store_ids(&self) -> std::collections::BTreeSet<String> {
        let db = open_connection(&self.db_path).expect("failed to open db");
        let mut stmt = db
            .prepare("SELECT event_id FROM events ORDER BY event_id")
            .expect("prepare");
        let ids = stmt
            .query_map([], |row| row.get::<_, String>(0))
            .expect("query")
            .collect::<Result<std::collections::BTreeSet<_>, _>>()
            .expect("collect");
        ids
    }

    /// Return sorted set of all shared-scope store IDs (base64-encoded).
    pub fn shared_store_ids(&self) -> std::collections::BTreeSet<String> {
        let db = open_connection(&self.db_path).expect("failed to open db");
        let mut stmt = db
            .prepare("SELECT event_id FROM events WHERE share_scope = 'shared' ORDER BY event_id")
            .expect("prepare");
        stmt.query_map([], |row| row.get::<_, String>(0))
            .expect("query")
            .collect::<Result<std::collections::BTreeSet<_>, _>>()
            .expect("collect")
    }

    /// Return sorted set of event IDs for a specific `event_type`.
    pub fn event_ids_by_type(&self, event_type: &str) -> std::collections::BTreeSet<String> {
        let db = open_connection(&self.db_path).expect("failed to open db");
        let mut stmt = db
            .prepare("SELECT event_id FROM events WHERE event_type = ?1 ORDER BY event_id")
            .expect("prepare");
        stmt.query_map(rusqlite::params![event_type], |row| row.get::<_, String>(0))
            .expect("query")
            .collect::<Result<std::collections::BTreeSet<_>, _>>()
            .expect("collect")
    }

    /// Count messages scoped to this peer's recorded_by identity.
    pub fn scoped_message_count(&self) -> i64 {
        let db = open_connection(&self.db_path).expect("failed to open db");
        db.query_row(
            "SELECT COUNT(*) FROM messages WHERE recorded_by = ?1",
            rusqlite::params![&self.identity],
            |row| row.get(0),
        )
        .unwrap_or(0)
    }

    // --- Identity projection count helpers ---

    /// Count valid events for this peer.
    pub fn valid_event_count(&self) -> i64 {
        let db = open_connection(&self.db_path).expect("failed to open db");
        db.query_row(
            "SELECT COUNT(*) FROM valid_events WHERE peer_id = ?1",
            rusqlite::params![&self.identity],
            |row| row.get(0),
        )
        .unwrap_or(0)
    }

    /// Count rejected events for this peer.
    pub fn rejected_event_count(&self) -> i64 {
        let db = open_connection(&self.db_path).expect("failed to open db");
        db.query_row(
            "SELECT COUNT(*) FROM rejected_events WHERE peer_id = ?1",
            rusqlite::params![&self.identity],
            |row| row.get(0),
        )
        .unwrap_or(0)
    }

    /// Count blocked event deps for this peer.
    pub fn blocked_dep_count(&self) -> i64 {
        let db = open_connection(&self.db_path).expect("failed to open db");
        db.query_row(
            "SELECT COUNT(DISTINCT event_id) FROM blocked_event_deps WHERE peer_id = ?1",
            rusqlite::params![&self.identity],
            |row| row.get(0),
        )
        .unwrap_or(0)
    }

    /// Count workspaces projected for this peer.
    pub fn workspace_count(&self) -> i64 {
        let db = open_connection(&self.db_path).expect("failed to open db");
        db.query_row(
            "SELECT COUNT(*) FROM workspaces WHERE recorded_by = ?1",
            rusqlite::params![&self.identity],
            |row| row.get(0),
        )
        .unwrap_or(0)
    }

    /// Count user invites projected for this peer.
    pub fn user_invite_count(&self) -> i64 {
        let db = open_connection(&self.db_path).expect("failed to open db");
        db.query_row(
            "SELECT COUNT(*) FROM user_invites WHERE recorded_by = ?1",
            rusqlite::params![&self.identity],
            |row| row.get(0),
        )
        .unwrap_or(0)
    }

    /// Count users projected for this peer.
    pub fn user_count(&self) -> i64 {
        let db = open_connection(&self.db_path).expect("failed to open db");
        db.query_row(
            "SELECT COUNT(*) FROM users WHERE recorded_by = ?1",
            rusqlite::params![&self.identity],
            |row| row.get(0),
        )
        .unwrap_or(0)
    }

    /// Count device invites projected for this peer.
    pub fn device_invite_count(&self) -> i64 {
        let db = open_connection(&self.db_path).expect("failed to open db");
        db.query_row(
            "SELECT COUNT(*) FROM device_invites WHERE recorded_by = ?1",
            rusqlite::params![&self.identity],
            |row| row.get(0),
        )
        .unwrap_or(0)
    }

    /// Count peers_shared projected for this peer.
    pub fn peer_shared_count(&self) -> i64 {
        let db = open_connection(&self.db_path).expect("failed to open db");
        db.query_row(
            "SELECT COUNT(*) FROM peers_shared WHERE recorded_by = ?1",
            rusqlite::params![&self.identity],
            |row| row.get(0),
        )
        .unwrap_or(0)
    }

    /// Count admins projected for this peer.
    pub fn admin_count(&self) -> i64 {
        let db = open_connection(&self.db_path).expect("failed to open db");
        db.query_row(
            "SELECT COUNT(*) FROM admins WHERE recorded_by = ?1",
            rusqlite::params![&self.identity],
            |row| row.get(0),
        )
        .unwrap_or(0)
    }

    /// Count invite_accepted projected for this peer.
    pub fn invite_accepted_count(&self) -> i64 {
        let db = open_connection(&self.db_path).expect("failed to open db");
        db.query_row(
            "SELECT COUNT(*) FROM invite_accepted WHERE recorded_by = ?1",
            rusqlite::params![&self.identity],
            |row| row.get(0),
        )
        .unwrap_or(0)
    }

    /// Get the recorded_at timestamp for a specific event (by base64 event_id).
    pub fn recorded_at_for_event(&self, event_id_b64: &str) -> Option<i64> {
        let db = open_connection(&self.db_path).expect("failed to open db");
        db.query_row(
            "SELECT recorded_at FROM recorded_events WHERE peer_id = ?1 AND event_id = ?2",
            rusqlite::params![&self.identity, event_id_b64],
            |row| row.get(0),
        )
        .ok()
    }

    /// Get a random sample of event IDs (base64) from the events table.
    pub fn sample_event_ids(&self, count: usize) -> Vec<String> {
        let db = open_connection(&self.db_path).expect("failed to open db");
        let mut stmt = db
            .prepare("SELECT event_id FROM events ORDER BY RANDOM() LIMIT ?1")
            .expect("prepare");
        stmt.query_map(rusqlite::params![count as i64], |row| {
            row.get::<_, String>(0)
        })
        .expect("query")
        .collect::<Result<Vec<_>, _>>()
        .expect("collect")
    }

    /// Get a random sample of sync-eligible (shared-scope) event IDs (base64).
    pub fn sample_shared_event_ids(&self, count: usize) -> Vec<String> {
        let db = open_connection(&self.db_path).expect("failed to open db");
        let mut stmt = db
            .prepare(
                "SELECT event_id
             FROM events
             WHERE share_scope = 'shared'
             ORDER BY RANDOM()
             LIMIT ?1",
            )
            .expect("prepare");
        stmt.query_map(rusqlite::params![count as i64], |row| {
            row.get::<_, String>(0)
        })
        .expect("query")
        .collect::<Result<Vec<_>, _>>()
        .expect("collect")
    }

    /// Insert `count` synthetic pending_invite_bootstrap_trust rows for this peer.
    /// Returns the generated SPKI fingerprints.
    pub fn seed_pending_bootstrap_trust(&self, count: usize) -> Vec<[u8; 32]> {
        use std::time::{SystemTime, UNIX_EPOCH};
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64;
        let expires_at = now + 24 * 60 * 60 * 1000;
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
                "INSERT OR IGNORE INTO pending_invite_bootstrap_trust
                 (recorded_by, invite_event_id, workspace_id, expected_bootstrap_spki_fingerprint, created_at, expires_at)
                 VALUES (?1, ?2, 'synthetic_ws', ?3, ?4, ?5)",
                rusqlite::params![&self.identity, format!("synthetic_inv_{}", i), fp.as_slice(), now, expires_at],
            ).expect("failed to insert pending_invite_bootstrap_trust");
        }
        db.execute("COMMIT", []).expect("failed to commit");
        fps
    }
}

// ---------------------------------------------------------------------------
// Deterministic projection fingerprinting
// ---------------------------------------------------------------------------

/// Projection tables included in deterministic fingerprinting.
/// Covers all content and identity projection tables.
/// Excludes operational/transient tables per PLAN §12.4.
const FINGERPRINT_TABLES: &[FingerprintTable] = &[
    // Content projections
    FingerprintTable {
        name: "messages",
        scope: Scope::RecordedBy,
        order: "ORDER BY message_id",
    },
    FingerprintTable {
        name: "reactions",
        scope: Scope::RecordedBy,
        order: "ORDER BY event_id",
    },
    FingerprintTable {
        name: "secret_keys",
        scope: Scope::RecordedBy,
        order: "ORDER BY event_id",
    },
    FingerprintTable {
        name: "deleted_messages",
        scope: Scope::RecordedBy,
        order: "ORDER BY message_id",
    },
    FingerprintTable {
        name: "message_attachments",
        scope: Scope::RecordedBy,
        order: "ORDER BY event_id",
    },
    FingerprintTable {
        name: "file_slices",
        scope: Scope::RecordedBy,
        order: "ORDER BY file_id, slice_number",
    },
    // Identity projections
    FingerprintTable {
        name: "workspaces",
        scope: Scope::RecordedBy,
        order: "ORDER BY event_id",
    },
    FingerprintTable {
        name: "invite_accepted",
        scope: Scope::RecordedBy,
        order: "ORDER BY event_id",
    },
    FingerprintTable {
        name: "user_invites",
        scope: Scope::RecordedBy,
        order: "ORDER BY event_id",
    },
    FingerprintTable {
        name: "device_invites",
        scope: Scope::RecordedBy,
        order: "ORDER BY event_id",
    },
    FingerprintTable {
        name: "users",
        scope: Scope::RecordedBy,
        order: "ORDER BY event_id",
    },
    FingerprintTable {
        name: "peers_shared",
        scope: Scope::RecordedBy,
        order: "ORDER BY event_id",
    },
    FingerprintTable {
        name: "admins",
        scope: Scope::RecordedBy,
        order: "ORDER BY event_id",
    },
    FingerprintTable {
        name: "removed_entities",
        scope: Scope::RecordedBy,
        order: "ORDER BY event_id",
    },
    FingerprintTable {
        name: "secret_shared",
        scope: Scope::RecordedBy,
        order: "ORDER BY event_id",
    },
    // Trust anchor (uses peer_id as scope key, written by identity projector)
    FingerprintTable {
        name: "trust_anchors",
        scope: Scope::PeerId,
        order: "ORDER BY peer_id",
    },
];

struct FingerprintTable {
    name: &'static str,
    scope: Scope,
    order: &'static str,
}

#[derive(Clone, Copy)]
enum Scope {
    RecordedBy,
    PeerId,
}

/// Per-table fingerprint diagnostic record.
#[derive(Debug)]
struct TableDigest {
    table: &'static str,
    hash: [u8; 32],
    row_count: i64,
}

/// Full projection fingerprint with per-table diagnostics.
#[derive(Debug)]
struct ProjectionFingerprint {
    overall: [u8; 32],
    tables: Vec<TableDigest>,
}

impl ProjectionFingerprint {
    /// Format per-table diagnostics for assertion failure messages.
    fn diff_report(
        &self,
        other: &ProjectionFingerprint,
        self_label: &str,
        other_label: &str,
    ) -> String {
        let mut lines = Vec::new();
        for (a, b) in self.tables.iter().zip(other.tables.iter()) {
            if a.hash != b.hash || a.row_count != b.row_count {
                lines.push(format!(
                    "  {}: {} rows={} hash={} | {} rows={} hash={}",
                    a.table,
                    self_label,
                    a.row_count,
                    hex(&a.hash[..8]),
                    other_label,
                    b.row_count,
                    hex(&b.hash[..8]),
                ));
            }
        }
        if lines.is_empty() {
            "(per-table hashes match but overall differs — internal error)".to_string()
        } else {
            lines.join("\n")
        }
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Compute deterministic projection fingerprint for a tenant.
/// Hashes all projection table rows using Blake2b-256 with type-tagged,
/// length-prefixed column encoding for unambiguous serialization.
fn compute_projection_fingerprint(
    db: &rusqlite::Connection,
    recorded_by: &str,
) -> ProjectionFingerprint {
    use blake2::digest::consts::U32;
    use blake2::{Blake2b, Digest};
    type Blake2b256 = Blake2b<U32>;

    let mut overall = Blake2b256::new();
    let mut tables = Vec::with_capacity(FINGERPRINT_TABLES.len());

    for ft in FINGERPRINT_TABLES {
        let mut table_hasher = Blake2b256::new();
        // Domain separator: table name
        table_hasher.update(ft.name.as_bytes());
        table_hasher.update(b"\x00");

        let where_clause = match ft.scope {
            Scope::RecordedBy => "WHERE recorded_by = ?1",
            Scope::PeerId => "WHERE peer_id = ?1",
        };
        let query = format!("SELECT * FROM {} {} {}", ft.name, where_clause, ft.order);
        let mut row_count: i64 = 0;

        if let Ok(mut stmt) = db.prepare(&query) {
            let col_count = stmt.column_count();
            if let Ok(mut rows) = stmt.query(rusqlite::params![recorded_by]) {
                while let Ok(Some(row)) = rows.next() {
                    row_count += 1;
                    for i in 0..col_count {
                        match row.get_ref(i) {
                            Ok(rusqlite::types::ValueRef::Null) => {
                                table_hasher.update(b"\x00");
                            }
                            Ok(rusqlite::types::ValueRef::Integer(v)) => {
                                table_hasher.update(b"\x01");
                                table_hasher.update(&v.to_le_bytes());
                            }
                            Ok(rusqlite::types::ValueRef::Real(v)) => {
                                table_hasher.update(b"\x02");
                                table_hasher.update(&v.to_le_bytes());
                            }
                            Ok(rusqlite::types::ValueRef::Text(v)) => {
                                table_hasher.update(b"\x03");
                                table_hasher.update(&(v.len() as u32).to_le_bytes());
                                table_hasher.update(v);
                            }
                            Ok(rusqlite::types::ValueRef::Blob(v)) => {
                                table_hasher.update(b"\x04");
                                table_hasher.update(&(v.len() as u32).to_le_bytes());
                                table_hasher.update(v);
                            }
                            Err(_) => {
                                table_hasher.update(b"\xfe");
                            }
                        }
                    }
                    table_hasher.update(b"\xff"); // row separator
                }
            }
        }

        let table_result = table_hasher.finalize();
        let mut table_hash = [0u8; 32];
        table_hash.copy_from_slice(&table_result);

        // Feed per-table hash into overall fingerprint
        overall.update(&table_hash);

        tables.push(TableDigest {
            table: ft.name,
            hash: table_hash,
            row_count,
        });
    }

    let result = overall.finalize();
    let mut fp = [0u8; 32];
    fp.copy_from_slice(&result);
    ProjectionFingerprint {
        overall: fp,
        tables,
    }
}

// ---------------------------------------------------------------------------
// Replay helpers
// ---------------------------------------------------------------------------

/// Clear all projection and operational tables for a tenant so that
/// re-projection from events produces a fresh state.
fn clear_projection_tables(db: &rusqlite::Connection, recorded_by: &str) {
    // — Content projections
    db.execute(
        "DELETE FROM messages WHERE recorded_by = ?1",
        rusqlite::params![recorded_by],
    )
    .expect("failed to clear messages");
    db.execute(
        "DELETE FROM reactions WHERE recorded_by = ?1",
        rusqlite::params![recorded_by],
    )
    .expect("failed to clear reactions");
    db.execute(
        "DELETE FROM secret_keys WHERE recorded_by = ?1",
        rusqlite::params![recorded_by],
    )
    .expect("failed to clear secret_keys");
    db.execute(
        "DELETE FROM deleted_messages WHERE recorded_by = ?1",
        rusqlite::params![recorded_by],
    )
    .expect("failed to clear deleted_messages");
    db.execute(
        "DELETE FROM message_attachments WHERE recorded_by = ?1",
        rusqlite::params![recorded_by],
    )
    .ok();
    db.execute(
        "DELETE FROM file_slices WHERE recorded_by = ?1",
        rusqlite::params![recorded_by],
    )
    .ok();
    // — Identity projections
    db.execute(
        "DELETE FROM workspaces WHERE recorded_by = ?1",
        rusqlite::params![recorded_by],
    )
    .ok();
    db.execute(
        "DELETE FROM invite_accepted WHERE recorded_by = ?1",
        rusqlite::params![recorded_by],
    )
    .ok();
    db.execute(
        "DELETE FROM user_invites WHERE recorded_by = ?1",
        rusqlite::params![recorded_by],
    )
    .ok();
    db.execute(
        "DELETE FROM device_invites WHERE recorded_by = ?1",
        rusqlite::params![recorded_by],
    )
    .ok();
    db.execute(
        "DELETE FROM users WHERE recorded_by = ?1",
        rusqlite::params![recorded_by],
    )
    .ok();
    db.execute(
        "DELETE FROM peers_shared WHERE recorded_by = ?1",
        rusqlite::params![recorded_by],
    )
    .ok();
    db.execute(
        "DELETE FROM admins WHERE recorded_by = ?1",
        rusqlite::params![recorded_by],
    )
    .ok();
    db.execute(
        "DELETE FROM removed_entities WHERE recorded_by = ?1",
        rusqlite::params![recorded_by],
    )
    .ok();
    db.execute(
        "DELETE FROM secret_shared WHERE recorded_by = ?1",
        rusqlite::params![recorded_by],
    )
    .ok();
    db.execute(
        "DELETE FROM trust_anchors WHERE peer_id = ?1",
        rusqlite::params![recorded_by],
    )
    .ok();
    db.execute(
        "DELETE FROM peer_transport_bindings WHERE recorded_by = ?1",
        rusqlite::params![recorded_by],
    )
    .ok();
    // — Deletion intents (deterministic projection state, must be cleared for replay)
    db.execute(
        "DELETE FROM deletion_intents WHERE recorded_by = ?1",
        rusqlite::params![recorded_by],
    )
    .ok();
    // — Operational state (must be cleared for correct re-projection)
    db.execute(
        "DELETE FROM valid_events WHERE peer_id = ?1",
        rusqlite::params![recorded_by],
    )
    .expect("failed to clear valid_events");
    db.execute(
        "DELETE FROM blocked_event_deps WHERE peer_id = ?1",
        rusqlite::params![recorded_by],
    )
    .expect("failed to clear blocked_event_deps");
    db.execute(
        "DELETE FROM blocked_events WHERE peer_id = ?1",
        rusqlite::params![recorded_by],
    )
    .ok();
    db.execute(
        "DELETE FROM rejected_events WHERE peer_id = ?1",
        rusqlite::params![recorded_by],
    )
    .expect("failed to clear rejected_events");
    db.execute(
        "DELETE FROM project_queue WHERE peer_id = ?1",
        rusqlite::params![recorded_by],
    )
    .ok();
}

/// Clear all projection and operational tables for a tenant, then re-project
/// all recorded events through `project_one` in the given order.
fn replay_and_fingerprint(
    db: &rusqlite::Connection,
    recorded_by: &str,
    order: &str,
) -> ProjectionFingerprint {
    use crate::crypto::event_id_from_base64;

    clear_projection_tables(db, recorded_by);

    // Re-project all recorded events in the requested order
    let query = format!(
        "SELECT e.event_id FROM events e
         WHERE e.event_id IN (SELECT event_id FROM recorded_events WHERE peer_id = ?1)
         {}",
        order
    );
    let mut stmt = db.prepare(&query).expect("failed to prepare events query");
    let event_ids: Vec<String> = stmt
        .query_map(rusqlite::params![recorded_by], |row| {
            row.get::<_, String>(0)
        })
        .expect("failed to query events")
        .collect::<Result<Vec<_>, _>>()
        .expect("failed to collect events");

    for eid_b64 in &event_ids {
        if let Some(eid) = event_id_from_base64(eid_b64) {
            let _ = project_one(db, recorded_by, &eid);
        }
    }

    compute_projection_fingerprint(db, recorded_by)
}

/// Re-project all recorded events on top of existing state (no clearing).
/// Used for idempotency testing: project_one must be a no-op for already-valid events.
fn replay_no_clear_and_fingerprint(
    db: &rusqlite::Connection,
    recorded_by: &str,
) -> ProjectionFingerprint {
    use crate::crypto::event_id_from_base64;

    let query = "SELECT e.event_id FROM events e
         WHERE e.event_id IN (SELECT event_id FROM recorded_events WHERE peer_id = ?1)
         ORDER BY created_at ASC, event_id ASC";
    let mut stmt = db.prepare(query).expect("failed to prepare events query");
    let event_ids: Vec<String> = stmt
        .query_map(rusqlite::params![recorded_by], |row| {
            row.get::<_, String>(0)
        })
        .expect("failed to query events")
        .collect::<Result<Vec<_>, _>>()
        .expect("failed to collect events");

    for eid_b64 in &event_ids {
        if let Some(eid) = event_id_from_base64(eid_b64) {
            let _ = project_one(db, recorded_by, &eid);
        }
    }

    compute_projection_fingerprint(db, recorded_by)
}

/// Clear projection tables and re-project all recorded events in random-shuffled
/// order. Tests PLAN §12.4 item 5: out-of-order ingest converges to the same
/// projected end state as canonical-order replay.
fn replay_shuffled_and_fingerprint(
    db: &rusqlite::Connection,
    recorded_by: &str,
) -> ProjectionFingerprint {
    use crate::crypto::event_id_from_base64;
    use rand::seq::SliceRandom;

    // Collect event IDs in canonical order, then shuffle
    let query = "SELECT e.event_id FROM events e
         WHERE e.event_id IN (SELECT event_id FROM recorded_events WHERE peer_id = ?1)
         ORDER BY created_at ASC, event_id ASC";
    let mut stmt = db.prepare(query).expect("failed to prepare events query");
    let mut event_ids: Vec<String> = stmt
        .query_map(rusqlite::params![recorded_by], |row| {
            row.get::<_, String>(0)
        })
        .expect("failed to query events")
        .collect::<Result<Vec<_>, _>>()
        .expect("failed to collect events");

    event_ids.shuffle(&mut rand::thread_rng());

    clear_projection_tables(db, recorded_by);

    // Re-project in shuffled order
    for eid_b64 in &event_ids {
        if let Some(eid) = event_id_from_base64(eid_b64) {
            let _ = project_one(db, recorded_by, &eid);
        }
    }

    compute_projection_fingerprint(db, recorded_by)
}

/// Verify projection invariants for a peer using deterministic fingerprints
/// (PLAN §12.4):
/// 1. Forward replay: clear + re-project forward → must match original state.
/// 2. Replay idempotency: re-project on already-projected state → no state change.
/// 3. Reverse-order replay: clear + re-project in reverse order → must match original state.
/// 4. Shuffle-reorder replay: clear + re-project in random order → must match original state.
///
/// On failure, per-table diagnostics are printed showing which tables diverged.
pub fn verify_projection_invariants(peer: &Peer) {
    let db = open_connection(&peer.db_path).expect("failed to open db");

    // Capture original full-state fingerprint
    let orig = compute_projection_fingerprint(&db, &peer.identity);

    // 1. Forward replay (reproject invariance: wipe + reproject yields same state)
    let fwd = replay_and_fingerprint(&db, &peer.identity, "ORDER BY created_at ASC, event_id ASC");
    assert!(
        orig.overall == fwd.overall,
        "Forward replay fingerprint mismatch for peer '{}':\n{}",
        peer.name,
        orig.diff_report(&fwd, "original", "forward"),
    );

    // 2. Idempotency: re-project on top of existing projected state (no clear)
    let idem = replay_no_clear_and_fingerprint(&db, &peer.identity);
    assert!(
        fwd.overall == idem.overall,
        "Idempotency replay fingerprint mismatch for peer '{}':\n{}",
        peer.name,
        fwd.diff_report(&idem, "forward", "idempotent"),
    );

    // 3. Reverse-order replay
    let rev = replay_and_fingerprint(
        &db,
        &peer.identity,
        "ORDER BY created_at DESC, event_id DESC",
    );
    assert!(
        fwd.overall == rev.overall,
        "Reverse replay fingerprint mismatch for peer '{}':\n{}",
        peer.name,
        fwd.diff_report(&rev, "forward", "reverse"),
    );

    // 4. Shuffle-reorder replay (PLAN §12.4 item 5: out-of-order ingest converges)
    let shuf = replay_shuffled_and_fingerprint(&db, &peer.identity);
    assert!(
        fwd.overall == shuf.overall,
        "Shuffle-reorder replay fingerprint mismatch for peer '{}':\n{}",
        peer.name,
        fwd.diff_report(&shuf, "forward", "shuffled"),
    );

    // Restore forward projection for subsequent assertions
    let _ = replay_and_fingerprint(&db, &peer.identity, "ORDER BY created_at ASC, event_id ASC");
}

// ---------------------------------------------------------------------------
// REALISM SYNC HELPERS
// ---------------------------------------------------------------------------

/// Start continuous sync between two peers with dynamic DB trust lookup.
///
/// Uses production-matching dynamic trust (`is_peer_allowed` at each TLS
/// handshake). Automatically seeds mutual trust via CLI pin import so callers
/// don't need to manually cross-register trust rows.
/// Start sync between two peers in the same workspace with PeerShared-derived trust.
/// Both peers must already have each other's PeerShared events projected (from
/// invite-based workspace join or bootstrap). No CLI pin seeding.
pub fn start_peers(
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
            if let Err(e) = accept_loop(
                &a_db,
                &a_identity,
                listener_endpoint,
                noop_intro_spawner,
                test_ingest_fns(),
            )
            .await
            {
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
            if let Err(e) = connect_loop(
                &b_db,
                &b_identity,
                connector_endpoint,
                listener_addr,
                None,
                noop_intro_spawner,
                test_ingest_fns(),
            )
            .await
            {
                tracing::warn!("connect_loop exited: {}", e);
            }
        });
    });

    (a_handle, b_handle)
}

// PINNING BOUNDARY: uses CLI pin import for cross-workspace trust setup.
// Use `start_peers` instead when both peers share a workspace with PeerShared-derived trust.
pub fn start_peers_pinned(
    peer_a: &Peer,
    peer_b: &Peer,
) -> (std::thread::JoinHandle<()>, std::thread::JoinHandle<()>) {
    use crate::db::transport_trust::import_cli_pins_to_sql;
    use crate::db::transport_trust::is_peer_allowed;

    let (cert_a, key_a) = peer_a.cert_and_key();
    let (cert_b, key_b) = peer_b.cert_and_key();

    let fp_a = peer_a.spki_fingerprint();
    let fp_b = peer_b.spki_fingerprint();

    // Seed mutual trust: A trusts B, B trusts A (via CLI pin import)
    {
        let db_a = open_connection(&peer_a.db_path).expect("failed to open A db");
        let pins_for_a = AllowedPeers::from_fingerprints(vec![fp_b]);
        import_cli_pins_to_sql(&db_a, &peer_a.identity, &pins_for_a)
            .expect("failed to import pins for A");
    }
    {
        let db_b = open_connection(&peer_b.db_path).expect("failed to open B db");
        let pins_for_b = AllowedPeers::from_fingerprints(vec![fp_a]);
        import_cli_pins_to_sql(&db_b, &peer_b.identity, &pins_for_b)
            .expect("failed to import pins for B");
    }

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
            if let Err(e) = accept_loop(
                &a_db,
                &a_identity,
                listener_endpoint,
                noop_intro_spawner,
                test_ingest_fns(),
            )
            .await
            {
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
            if let Err(e) = connect_loop(
                &b_db,
                &b_identity,
                connector_endpoint,
                listener_addr,
                None,
                noop_intro_spawner,
                test_ingest_fns(),
            )
            .await
            {
                tracing::warn!("connect_loop exited: {}", e);
            }
        });
    });

    (a_handle, b_handle)
}

/// Start continuous sync between two peers using dynamic DB trust lookup.
/// Trust is resolved from SQL at each TLS handshake, matching production
/// behavior (`is_peer_allowed`). Caller must have seeded trust rows
/// (via `import_cli_pins_to_sql`, or invite
/// bootstrap) before peers will accept connections.
///
/// REALISM HELPER: production-matching dynamic trust. Used in holepunch
/// integration tests.
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
            if let Err(e) = accept_loop(
                &a_db,
                &a_identity,
                listener_endpoint,
                noop_intro_spawner,
                test_ingest_fns(),
            )
            .await
            {
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
            if let Err(e) = connect_loop(
                &b_db,
                &b_identity,
                connector_endpoint,
                listener_addr,
                None,
                noop_intro_spawner,
                test_ingest_fns(),
            )
            .await
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
pub fn create_dynamic_endpoint_for_peer(peer: &Peer) -> quinn::Endpoint {
    create_dynamic_endpoint_for_peer_bind(peer, "127.0.0.1:0".parse().unwrap())
}

/// Like [`create_dynamic_endpoint_for_peer`] but with a caller-specified bind
/// address. Use `0.0.0.0:0` when mDNS-resolved addresses may be non-loopback.
pub fn create_dynamic_endpoint_for_peer_bind(
    peer: &Peer,
    bind_addr: std::net::SocketAddr,
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

    create_dual_endpoint_dynamic(bind_addr, cert, key, dynamic_allow)
        .expect("failed to create dynamic endpoint for peer")
}

/// Start sync, wait for a caller-defined convergence check, return metrics.
pub async fn sync_until_converged<F: Fn() -> bool>(
    peer_a: &Peer,
    peer_b: &Peer,
    check: F,
    timeout: Duration,
) -> SyncMetrics {
    let a_before = peer_a.shared_store_count();
    let b_before = peer_b.shared_store_count();

    let start = Instant::now();
    let sync = start_peers_pinned(peer_a, peer_b);

    assert_eventually(check, timeout, "sync convergence").await;

    let wall_secs = start.elapsed().as_secs_f64();
    drop(sync);

    let a_after = peer_a.shared_store_count();
    let b_after = peer_b.shared_store_count();
    let events_transferred = ((a_after - a_before) + (b_after - b_before)) as u64;
    let bytes_transferred = events_transferred * 100;
    let events_per_sec = if wall_secs > 0.0 {
        events_transferred as f64 / wall_secs
    } else {
        0.0
    };
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
    use crate::db::transport_trust::{import_cli_pins_to_sql, is_peer_allowed};

    let n = peers.len();
    assert!(n >= 2, "chain requires at least 2 peers");

    // Extract fingerprints for all peers
    let mut fingerprints: Vec<[u8; 32]> = Vec::new();
    for peer in peers {
        fingerprints.push(peer.spki_fingerprint());
    }

    // Seed mutual trust between adjacent peers via CLI pin import
    for i in 0..n - 1 {
        let db_left = open_connection(&peers[i].db_path).expect("failed to open db");
        let pins = AllowedPeers::from_fingerprints(vec![fingerprints[i + 1]]);
        import_cli_pins_to_sql(&db_left, &peers[i].identity, &pins).expect("failed to import pins");

        let db_right = open_connection(&peers[i + 1].db_path).expect("failed to open db");
        let pins = AllowedPeers::from_fingerprints(vec![fingerprints[i]]);
        import_cli_pins_to_sql(&db_right, &peers[i + 1].identity, &pins)
            .expect("failed to import pins");
    }

    // Create server endpoints for peers 0..n-2 with dynamic trust
    let mut server_addrs: Vec<SocketAddr> = Vec::new();
    let mut server_endpoints: Vec<quinn::Endpoint> = Vec::new();
    for i in 0..n - 1 {
        let (cert, key) = peers[i].cert_and_key();
        let db_path = peers[i].db_path.clone();
        let recorded_by = peers[i].identity.clone();
        let allow_fn: Arc<crate::transport::DynamicAllowFn> = Arc::new(move |fp: &[u8; 32]| {
            let db = open_connection(&db_path)?;
            is_peer_allowed(&db, &recorded_by, fp)
        });
        let endpoint =
            create_dual_endpoint_dynamic("127.0.0.1:0".parse().unwrap(), cert, key, allow_fn)
                .expect("failed to create chain server endpoint");
        let addr = endpoint.local_addr().expect("failed to get local addr");
        server_addrs.push(addr);
        server_endpoints.push(endpoint);
    }

    // Create client endpoints for peers 1..n-1 with dynamic trust
    let mut client_endpoints: Vec<quinn::Endpoint> = Vec::new();
    for i in 1..n {
        let (cert, key) = peers[i].cert_and_key();
        let db_path = peers[i].db_path.clone();
        let recorded_by = peers[i].identity.clone();
        let allow_fn: Arc<crate::transport::DynamicAllowFn> = Arc::new(move |fp: &[u8; 32]| {
            let db = open_connection(&db_path)?;
            is_peer_allowed(&db, &recorded_by, fp)
        });
        let endpoint =
            create_dual_endpoint_dynamic("0.0.0.0:0".parse().unwrap(), cert, key, allow_fn)
                .expect("failed to create chain client endpoint");
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
                if let Err(e) = accept_loop(
                    &db_path,
                    &identity,
                    endpoint,
                    noop_intro_spawner,
                    test_ingest_fns(),
                )
                .await
                {
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
                if let Err(e) = connect_loop(
                    &db_path,
                    &identity,
                    endpoint,
                    remote,
                    None,
                    noop_intro_spawner,
                    test_ingest_fns(),
                )
                .await
                {
                    tracing::warn!("chain connect_loop[{}] exited: {}", i, e);
                }
            });
        }));
    }

    handles
}

/// Start a sink-driven download topology: sink connects to all sources.
///
/// Each source runs accept_loop (responder). The sink runs one
/// `connect_loop_with_shared_ingest` per source with a shared
/// `CoordinationManager`, matching the production runtime path used by
/// bootstrap/mDNS autodial.
///
/// Returns thread handles for all source accept_loops and sink connect loops.
pub fn start_sink_download(sources: &[Peer], sink: &Peer) -> Vec<std::thread::JoinHandle<()>> {
    use crate::db::transport_trust::{import_cli_pins_to_sql, is_peer_allowed};

    assert!(!sources.is_empty(), "need at least one source");

    let (sink_cert, sink_key) = sink.cert_and_key();
    let sink_fp = sink.spki_fingerprint();

    // Seed mutual trust
    let source_fps: Vec<[u8; 32]> = sources.iter().map(|s| s.spki_fingerprint()).collect();
    {
        let db_sink = open_connection(&sink.db_path).expect("failed to open sink db");
        let pins = AllowedPeers::from_fingerprints(source_fps);
        import_cli_pins_to_sql(&db_sink, &sink.identity, &pins)
            .expect("failed to import pins for sink");
    }
    for source in sources {
        let db_src = open_connection(&source.db_path).expect("failed to open source db");
        let pins = AllowedPeers::from_fingerprints(vec![sink_fp]);
        import_cli_pins_to_sql(&db_src, &source.identity, &pins)
            .expect("failed to import pins for source");
    }

    let mut handles = Vec::new();
    let mut source_addrs = Vec::new();

    // Start accept_loop for each source with dynamic trust
    for source in sources {
        let (cert, key) = source.cert_and_key();
        let src_db_path = source.db_path.clone();
        let src_recorded_by = source.identity.clone();
        let allow_fn: Arc<crate::transport::DynamicAllowFn> = Arc::new(move |fp: &[u8; 32]| {
            let db = open_connection(&src_db_path)?;
            is_peer_allowed(&db, &src_recorded_by, fp)
        });
        let server_endpoint =
            create_dual_endpoint_dynamic("127.0.0.1:0".parse().unwrap(), cert, key, allow_fn)
                .expect("failed to create source server endpoint");
        let addr = server_endpoint
            .local_addr()
            .expect("failed to get source addr");
        source_addrs.push(addr);

        let db_path = source.db_path.clone();
        let identity = source.identity.clone();
        handles.push(std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async move {
                if let Err(e) = accept_loop(
                    &db_path,
                    &identity,
                    server_endpoint,
                    noop_intro_spawner,
                    test_ingest_fns(),
                )
                .await
                {
                    tracing::warn!("source accept_loop exited: {}", e);
                }
            });
        }));
    }

    // Build per-source client endpoints for the sink with dynamic trust.
    // These are driven by coordinated connect loops (runtime-faithful path).
    let mut sink_connectors = Vec::new();
    for (i, _source) in sources.iter().enumerate() {
        let sink_db_path = sink.db_path.clone();
        let sink_recorded_by = sink.identity.clone();
        let allow_fn: Arc<crate::transport::DynamicAllowFn> = Arc::new(move |fp: &[u8; 32]| {
            let db = open_connection(&sink_db_path)?;
            is_peer_allowed(&db, &sink_recorded_by, fp)
        });
        let client_endpoint = create_dual_endpoint_dynamic(
            "0.0.0.0:0".parse().unwrap(),
            sink_cert.clone(),
            sink_key.clone_key(),
            allow_fn,
        )
        .expect("failed to create sink client endpoint");

        sink_connectors.push((client_endpoint, source_addrs[i]));
    }

    // Spawn ONE shared batch_writer for the sink so events from all sources
    // interleave in a single channel.  Without this, each connect_loop spawns
    // its own writer and concurrent writers race on INSERT OR IGNORE, causing
    // one source to dominate attribution.
    let ingest_fns = test_ingest_fns();
    let ingest_cap = crate::tuning::shared_ingest_cap();
    let (shared_tx, shared_rx) = tokio::sync::mpsc::channel::<
        crate::contracts::event_pipeline_contract::IngestItem,
    >(ingest_cap);
    let writer_db = sink.db_path.clone();
    let writer_events = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let batch_writer_fn = ingest_fns.batch_writer;
    let _writer_handle = std::thread::spawn(move || {
        batch_writer_fn(writer_db, shared_rx, writer_events);
    });

    // Pre-register ALL peers before spawning threads. This ensures
    // total_peers is correct from the very first reconciliation round,
    // preventing race conditions where fast threads see total_peers=1
    // and request all events.
    let coord_manager = Arc::new(crate::sync::CoordinationManager::new());
    let peer_coords: Vec<_> = (0..sink_connectors.len())
        .map(|_| coord_manager.register_peer())
        .collect();
    for ((endpoint, remote), coordination) in sink_connectors.into_iter().zip(peer_coords) {
        let sink_db = sink.db_path.clone();
        let sink_identity = sink.identity.clone();
        let sink_ingest = shared_tx.clone();
        handles.push(std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async move {
                let _ = connect_loop_with_shared_ingest(
                    &sink_db,
                    &sink_identity,
                    endpoint,
                    remote,
                    noop_intro_spawner,
                    test_ingest_fns(),
                    coordination,
                    sink_ingest,
                )
                .await;
            });
        }));
    }

    handles
}

/// Handles from a sink-driven download topology with per-source shutdown control.
pub struct SinkDownloadHandles {
    pub thread_handles: Vec<std::thread::JoinHandle<()>>,
    /// Source server endpoints (cloned); close to simulate source failure.
    pub source_endpoints: Vec<crate::transport::TransportEndpoint>,
    /// Per-connect-loop cancellation tokens; cancel to stop a sink's connect loop.
    pub connect_shutdowns: Vec<tokio_util::sync::CancellationToken>,
}

impl SinkDownloadHandles {
    /// Shut down a specific source's accept loop by closing its QUIC endpoint,
    /// and cancel the corresponding connect loop so it stops retrying.
    pub fn shutdown_source(&self, idx: usize) {
        self.source_endpoints[idx].close(0u32.into(), b"test-shutdown");
        self.connect_shutdowns[idx].cancel();
    }
}

/// Like [`start_sink_download`] but returns [`SinkDownloadHandles`] with
/// per-source shutdown control for simulating peer dropout.
pub fn start_sink_download_with_shutdown(sources: &[Peer], sink: &Peer) -> SinkDownloadHandles {
    use crate::db::transport_trust::{import_cli_pins_to_sql, is_peer_allowed};

    assert!(!sources.is_empty(), "need at least one source");

    let (sink_cert, sink_key) = sink.cert_and_key();
    let sink_fp = sink.spki_fingerprint();

    // Seed mutual trust
    let source_fps: Vec<[u8; 32]> = sources.iter().map(|s| s.spki_fingerprint()).collect();
    {
        let db_sink = open_connection(&sink.db_path).expect("failed to open sink db");
        let pins = AllowedPeers::from_fingerprints(source_fps);
        import_cli_pins_to_sql(&db_sink, &sink.identity, &pins)
            .expect("failed to import pins for sink");
    }
    for source in sources {
        let db_src = open_connection(&source.db_path).expect("failed to open source db");
        let pins = AllowedPeers::from_fingerprints(vec![sink_fp]);
        import_cli_pins_to_sql(&db_src, &source.identity, &pins)
            .expect("failed to import pins for source");
    }

    let mut handles = Vec::new();
    let mut source_addrs = Vec::new();
    let mut source_endpoints = Vec::new();

    // Start accept_loop for each source with dynamic trust
    for source in sources {
        let (cert, key) = source.cert_and_key();
        let src_db_path = source.db_path.clone();
        let src_recorded_by = source.identity.clone();
        let allow_fn: Arc<crate::transport::DynamicAllowFn> = Arc::new(move |fp: &[u8; 32]| {
            let db = open_connection(&src_db_path)?;
            is_peer_allowed(&db, &src_recorded_by, fp)
        });
        let server_endpoint =
            create_dual_endpoint_dynamic("127.0.0.1:0".parse().unwrap(), cert, key, allow_fn)
                .expect("failed to create source server endpoint");
        let addr = server_endpoint
            .local_addr()
            .expect("failed to get source addr");
        source_addrs.push(addr);
        source_endpoints.push(server_endpoint.clone());

        let db_path = source.db_path.clone();
        let identity = source.identity.clone();
        handles.push(std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async move {
                if let Err(e) = accept_loop(
                    &db_path,
                    &identity,
                    server_endpoint,
                    noop_intro_spawner,
                    test_ingest_fns(),
                )
                .await
                {
                    tracing::warn!("source accept_loop exited: {}", e);
                }
            });
        }));
    }

    // Build per-source client endpoints for the sink with dynamic trust.
    let mut sink_connectors = Vec::new();
    for (i, _source) in sources.iter().enumerate() {
        let sink_db_path = sink.db_path.clone();
        let sink_recorded_by = sink.identity.clone();
        let allow_fn: Arc<crate::transport::DynamicAllowFn> = Arc::new(move |fp: &[u8; 32]| {
            let db = open_connection(&sink_db_path)?;
            is_peer_allowed(&db, &sink_recorded_by, fp)
        });
        let client_endpoint = create_dual_endpoint_dynamic(
            "0.0.0.0:0".parse().unwrap(),
            sink_cert.clone(),
            sink_key.clone_key(),
            allow_fn,
        )
        .expect("failed to create sink client endpoint");

        sink_connectors.push((client_endpoint, source_addrs[i]));
    }

    // Shared batch_writer for the sink
    let ingest_fns = test_ingest_fns();
    let ingest_cap = crate::tuning::shared_ingest_cap();
    let (shared_tx, shared_rx) = tokio::sync::mpsc::channel::<
        crate::contracts::event_pipeline_contract::IngestItem,
    >(ingest_cap);
    let writer_db = sink.db_path.clone();
    let writer_events = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let batch_writer_fn = ingest_fns.batch_writer;
    let _writer_handle = std::thread::spawn(move || {
        batch_writer_fn(writer_db, shared_rx, writer_events);
    });

    // Pre-register ALL peers before spawning threads.
    let coord_manager = Arc::new(crate::sync::CoordinationManager::new());
    let peer_coords: Vec<_> = (0..sink_connectors.len())
        .map(|_| coord_manager.register_peer())
        .collect();

    let mut connect_shutdowns = Vec::new();
    for ((endpoint, remote), coordination) in sink_connectors.into_iter().zip(peer_coords) {
        let shutdown = tokio_util::sync::CancellationToken::new();
        connect_shutdowns.push(shutdown.clone());
        let sink_db = sink.db_path.clone();
        let sink_identity = sink.identity.clone();
        let sink_ingest = shared_tx.clone();
        handles.push(std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async move {
                let _ = connect_loop_with_shared_ingest_until_cancel(
                    &sink_db,
                    &sink_identity,
                    endpoint,
                    remote,
                    noop_intro_spawner,
                    test_ingest_fns(),
                    coordination,
                    sink_ingest,
                    shutdown,
                )
                .await;
            });
        }));
    }

    SinkDownloadHandles {
        thread_handles: handles,
        source_endpoints,
        connect_shutdowns,
    }
}

/// Start a sink's accept_loop and return the handle and listen address.
///
/// Uses dynamic trust (`is_peer_allowed`) at each TLS handshake. The supplied
/// `allowed_fps` are seeded as CLI pins into the sink's DB so the handshake
/// succeeds, matching the pattern used by other topology helpers.
pub fn start_sink_accept(
    sink: &Peer,
    allowed_fps: Vec<[u8; 32]>,
) -> (std::thread::JoinHandle<()>, SocketAddr) {
    use crate::db::transport_trust::{import_cli_pins_to_sql, is_peer_allowed};

    // Seed trust for all allowed fingerprints
    {
        let db = open_connection(&sink.db_path).expect("failed to open sink db");
        let pins = AllowedPeers::from_fingerprints(allowed_fps);
        import_cli_pins_to_sql(&db, &sink.identity, &pins).expect("failed to import pins for sink");
    }

    let (cert, key) = sink.cert_and_key();
    let sink_db_path = sink.db_path.clone();
    let sink_recorded_by = sink.identity.clone();
    let allow_fn: Arc<crate::transport::DynamicAllowFn> = Arc::new(move |fp: &[u8; 32]| {
        let db = open_connection(&sink_db_path)?;
        is_peer_allowed(&db, &sink_recorded_by, fp)
    });
    let endpoint =
        create_dual_endpoint_dynamic("127.0.0.1:0".parse().unwrap(), cert, key, allow_fn)
            .expect("failed to create sink server endpoint");
    let addr = endpoint.local_addr().expect("failed to get sink addr");

    let db_path = sink.db_path.clone();
    let identity = sink.identity.clone();
    let handle = std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async move {
            if let Err(e) = accept_loop(
                &db_path,
                &identity,
                endpoint,
                noop_intro_spawner,
                test_ingest_fns(),
            )
            .await
            {
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

/// Record pre-existing events for a new tenant in a shared-DB context.
///
/// In separate-DB peers, prerequisite events arrive via bootstrap sync
/// (see `Peer::new_in_workspace`). In shared-DB multi-tenant mode, the
/// events are already in the events table; this helper records them for
/// the new tenant and projects them, equivalent to what the sync engine's
/// batch writer does after receiving events.
///
/// WHITE-BOX HELPER: used only in SharedDbNode (shared-DB multi-tenant
/// projection tests), not in realism/integration test paths.
fn record_shared_db_events_for_tenant(
    db: &rusqlite::Connection,
    tenant_id: &str,
    event_ids: &[EventId],
) {
    use crate::projection::apply::project_one;

    let now_ms = current_timestamp_ms() as i64;
    for eid in event_ids {
        insert_recorded_event(db, tenant_id, eid, now_ms, "test")
            .expect("failed to record event for tenant");
        let _ = project_one(db, tenant_id, eid);
    }
}

// ---------------------------------------------------------------------------
// WHITE-BOX: multi-tenant shared-DB projection tests
// ---------------------------------------------------------------------------

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
        let db_path = tempdir
            .path()
            .join("shared.db")
            .to_str()
            .unwrap()
            .to_string();

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

        // create_workspace installs PeerShared-derived transport identity via
        // `DELETE FROM local_transport_creds` + insert.  In a shared-DB with
        // multiple tenants each bootstrap wipes the previous tenants' creds.
        // Re-install all tenants' PeerShared-derived certs so discover_local_tenants works.
        if n > 1 {
            let db = open_connection(&db_path).expect("failed to open shared db for cred restore");
            for tenant in &tenants {
                let ps_key = tenant
                    .peer_shared_signing_key
                    .as_ref()
                    .expect("tenant missing peer_shared_signing_key after bootstrap");
                let (cert, key) =
                    crate::transport::generate_self_signed_cert_from_signing_key(ps_key)
                        .expect("failed to regenerate PeerShared cert");
                crate::db::transport_creds::store_local_creds(
                    &db,
                    &tenant.identity,
                    cert.as_ref(),
                    key.secret_pkcs8_der(),
                )
                .expect("failed to re-store tenant transport creds");
            }
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
        let (cert, key) =
            crate::transport::generate_self_signed_cert().expect("failed to generate cert");
        let fp = extract_spki_fingerprint(cert.as_ref()).expect("failed to extract SPKI");
        let tenant_identity = hex::encode(fp);

        // Store this tenant's creds in the shared DB
        let db = open_connection(db_path).expect("failed to open db");
        crate::db::transport_creds::store_local_creds(
            &db,
            &tenant_identity,
            cert.as_ref(),
            key.secret_pkcs8_der(),
        )
        .expect("failed to store creds");

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
    /// using the production workspace command APIs.
    pub fn add_tenant_in_workspace(&mut self, name: &str, creator_index: usize) {
        use crate::event_modules::workspace::commands::{
            create_user_invite_raw, join_workspace_as_new_user,
        };

        let creator = &self.tenants[creator_index];
        let workspace_id = creator.workspace_id;
        let workspace_key = creator
            .workspace_signing_key
            .as_ref()
            .expect("creator has no workspace_signing_key")
            .clone();
        let creator_peer_key = creator
            .peer_shared_signing_key
            .as_ref()
            .expect("creator has no peer_shared_signing_key")
            .clone();
        let creator_peer_eid = creator
            .peer_shared_event_id
            .expect("creator has no peer_shared_event_id");
        let creator_identity = creator.identity.clone();

        // Create a new transport identity in the shared DB
        let (cert, key) =
            crate::transport::generate_self_signed_cert().expect("failed to generate cert");
        let fp = extract_spki_fingerprint(cert.as_ref()).expect("failed to extract SPKI");
        let tenant_identity = hex::encode(fp);

        let db = open_connection(&self.db_path).expect("failed to open db");
        crate::db::transport_creds::store_local_creds(
            &db,
            &tenant_identity,
            cert.as_ref(),
            key.secret_pkcs8_der(),
        )
        .expect("failed to store creds");

        // Creator issues an invite via workspace::commands API
        let invite = create_user_invite_raw(
            &db,
            &creator_identity,
            &workspace_key,
            &workspace_id,
            Some(&creator_peer_key),
            Some(&creator_peer_eid),
        )
        .expect("failed to create user invite");

        // The Workspace and UserInvite events already exist in the shared DB.
        // Record them for this new tenant and project (white-box shared-DB prerequisite).
        record_shared_db_events_for_tenant(
            &db,
            &tenant_identity,
            &[workspace_id, invite.invite_event_id],
        );

        // Accept the invite (production flow via workspace commands)
        let peer_shared_key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
        let join = join_workspace_as_new_user(
            &db,
            &tenant_identity,
            &invite.invite_key,
            &invite.invite_event_id,
            workspace_id,
            "test-user",
            "test-device",
            peer_shared_key,
        )
        .expect("failed to accept user invite");

        let dummy_tempdir = tempfile::tempdir().expect("failed to create dummy tempdir");

        let peer = Peer {
            name: name.to_string(),
            db_path: self.db_path.clone(),
            identity: tenant_identity,
            author_id: join.user_event_id,
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
        let tenant_workspaces: Vec<(String, String)> = self
            .tenants
            .iter()
            .map(|t| (t.identity.clone(), hex::encode(t.workspace_id)))
            .collect();
        assert_no_cross_tenant_leakage(&self.db_path, &tenant_workspaces);
    }
}

/// Lightweight harness that ensures every scenario test runs projection replay
/// invariant checks. Tracks `&Peer` and `&SharedDbNode` references, runs
/// `verify_projection_invariants` (and `verify_all_invariants` for nodes)
/// when `.finish()` is called. A `Drop` safety-net panics if `.finish()` was
/// never called, preventing silent omission.
///
/// **Declaration order**: peers/nodes must be declared **before** the harness
/// so they are dropped **after** it (Rust drops in reverse declaration order).
pub struct ScenarioHarness<'a> {
    peers: std::cell::RefCell<Vec<&'a Peer>>,
    shared_db_nodes: std::cell::RefCell<Vec<&'a SharedDbNode>>,
    skip_reason: Option<String>,
    finished: std::cell::Cell<bool>,
}

impl<'a> ScenarioHarness<'a> {
    /// Create a new harness that will verify replay invariants on `.finish()`.
    pub fn new() -> Self {
        Self {
            peers: std::cell::RefCell::new(Vec::new()),
            shared_db_nodes: std::cell::RefCell::new(Vec::new()),
            skip_reason: None,
            finished: std::cell::Cell::new(false),
        }
    }

    /// Create a harness that skips replay checks with a documented reason.
    pub fn skip(reason: &str) -> Self {
        Self {
            peers: std::cell::RefCell::new(Vec::new()),
            shared_db_nodes: std::cell::RefCell::new(Vec::new()),
            skip_reason: Some(reason.to_string()),
            finished: std::cell::Cell::new(false),
        }
    }

    /// Track a `Peer` for replay invariant checks.
    pub fn track(&self, peer: &'a Peer) {
        self.peers.borrow_mut().push(peer);
    }

    /// Track a `SharedDbNode` for replay invariant checks.
    pub fn track_node(&self, node: &'a SharedDbNode) {
        self.shared_db_nodes.borrow_mut().push(node);
    }

    /// Run replay invariant checks on all tracked peers and nodes.
    /// Must be called exactly once before the harness is dropped.
    pub fn finish(&self) {
        self.finished.set(true);
        if let Some(reason) = &self.skip_reason {
            eprintln!("ScenarioHarness: skipping replay invariants — {}", reason);
            return;
        }
        let tracked = self.peers.borrow().len() + self.shared_db_nodes.borrow().len();
        if tracked == 0 {
            panic!(
                "ScenarioHarness::finish() with zero tracked subjects. \
                    Use ScenarioHarness::skip(reason) to opt out."
            );
        }
        for peer in self.peers.borrow().iter() {
            verify_projection_invariants(peer);
        }
        for node in self.shared_db_nodes.borrow().iter() {
            node.verify_all_invariants();
        }
    }
}

impl Drop for ScenarioHarness<'_> {
    fn drop(&mut self) {
        if !self.finished.get() && !std::thread::panicking() {
            panic!("ScenarioHarness::finish() was never called! Add harness.finish() at the end of the test.");
        }
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

    let tenant_ids: Vec<&str> = tenant_workspaces
        .iter()
        .map(|(id, _)| id.as_str())
        .collect();
    let known_ids: std::collections::HashSet<&str> = tenant_ids.iter().copied().collect();

    // Collect recorded event_ids per tenant
    let mut recorded_per_tenant: std::collections::HashMap<
        &str,
        std::collections::HashSet<String>,
    > = std::collections::HashMap::new();
    for tid in &tenant_ids {
        let mut stmt = db
            .prepare("SELECT event_id FROM recorded_events WHERE peer_id = ?1")
            .expect("failed to prepare stmt");
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
            assert!(
                overlap.is_empty(),
                "Cross-workspace leakage in recorded_events between {} and {}: {:?}",
                &id_a[..16],
                &id_b[..16],
                overlap
            );
        }
    }

    // Collect valid event_ids per tenant
    let mut valid_per_tenant: std::collections::HashMap<&str, std::collections::HashSet<String>> =
        std::collections::HashMap::new();
    for tid in &tenant_ids {
        let mut stmt = db
            .prepare("SELECT event_id FROM valid_events WHERE peer_id = ?1")
            .expect("failed to prepare stmt");
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
            assert!(
                overlap.is_empty(),
                "Cross-workspace leakage in valid_events between {} and {}: {:?}",
                &id_a[..16],
                &id_b[..16],
                overlap
            );
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
            assert!(
                known_ids.contains(found_id.as_str()),
                "Unknown peer_id '{}...' in {} table",
                &found_id[..16.min(found_id.len())],
                table
            );
        }
    }

    // Verify no unexpected peer_ids in projection tables
    for table in &["messages", "reactions", "secret_keys", "deleted_messages"] {
        let query = format!("SELECT DISTINCT recorded_by FROM {}", table);
        let mut stmt = db.prepare(&query).expect("failed to prepare");
        let found_ids: Vec<String> = stmt
            .query_map([], |row| row.get::<_, String>(0))
            .expect("failed to query")
            .collect::<Result<Vec<_>, _>>()
            .expect("failed to collect");
        for found_id in &found_ids {
            assert!(
                known_ids.contains(found_id.as_str()),
                "Unknown peer_id '{}...' in {} table",
                &found_id[..16.min(found_id.len())],
                table
            );
        }
    }
}

// ---------------------------------------------------------------------------
// WHITE-BOX: deliberately copies events DB-to-DB for dedup/overlap benchmarks
// ---------------------------------------------------------------------------

/// Copy all events and neg_items from a source peer's database to target peers.
///
/// This creates identical data at each target so that concurrent sync tests can
/// verify dedup behavior when multiple sources offer the same events.
///
/// WHITE-BOX HELPER: intentional DB-to-DB copy for sync_graph_test benchmarks
/// that need identical pre-seeded data across multiple peers. Not used in
/// realism/integration test paths.
pub fn clone_events_to(source: &Peer, targets: &[&Peer]) {
    let src_db = open_connection(&source.db_path).expect("failed to open source db");

    // Read all events
    let mut events_stmt = src_db
        .prepare(
            "SELECT event_id, event_type, blob, share_scope, created_at, inserted_at FROM events",
        )
        .expect("failed to prepare events query");
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

    // Read all neg_items (including workspace_id)
    let mut neg_stmt = src_db
        .prepare("SELECT workspace_id, ts, id FROM neg_items")
        .expect("failed to prepare neg_items query");
    let neg_items: Vec<(String, i64, Vec<u8>)> = neg_stmt
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, Vec<u8>>(2)?,
            ))
        })
        .expect("failed to query neg_items")
        .collect::<Result<Vec<_>, _>>()
        .expect("failed to collect neg_items");

    for target in targets {
        let tgt_db = open_connection(&target.db_path).expect("failed to open target db");
        // Use target's workspace_id so neg_items entries match the target's
        // neg_storage scope and don't create duplicates when the target later
        // receives the same events from sync (which inserts with target ws_id).
        let tgt_ws_id = crate::db::store::lookup_workspace_id(&tgt_db, &target.identity);
        tgt_db.execute("BEGIN", []).expect("failed to begin");

        for (event_id, event_type, blob, share_scope, created_at, inserted_at) in &events {
            tgt_db.execute(
                "INSERT OR IGNORE INTO events (event_id, event_type, blob, share_scope, created_at, inserted_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                rusqlite::params![event_id, event_type, blob.as_slice(), share_scope, created_at, inserted_at],
            ).expect("failed to insert event");
        }

        for (_workspace_id, ts, id) in &neg_items {
            tgt_db
                .execute(
                    "INSERT OR IGNORE INTO neg_items (workspace_id, ts, id) VALUES (?1, ?2, ?3)",
                    rusqlite::params![&tgt_ws_id, ts, id.as_slice()],
                )
                .expect("failed to insert neg_item");
        }

        tgt_db.execute("COMMIT", []).expect("failed to commit");
    }
}

// ---------------------------------------------------------------------------
// Unit tests for deterministic fingerprinting
// ---------------------------------------------------------------------------
#[cfg(test)]
mod fingerprint_tests {
    use super::*;
    use crate::db::{open_connection, schema::create_tables};

    /// Helper: create a fresh in-memory DB with full schema.
    fn fresh_db() -> (tempfile::TempDir, String, rusqlite::Connection) {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("test.db").to_str().unwrap().to_string();
        let db = open_connection(&path).unwrap();
        create_tables(&db).unwrap();
        (dir, path, db)
    }

    #[test]
    fn fingerprint_deterministic_on_repeated_calls() {
        let (_dir, _path, db) = fresh_db();
        let peer_id = "fp-test-peer";

        // Insert a workspace event to seed identity
        db.execute(
            "INSERT INTO workspaces (recorded_by, event_id, workspace_id, public_key)
             VALUES (?1, 'eid1', 'ws1', X'00')",
            rusqlite::params![peer_id],
        )
        .unwrap();

        let fp1 = compute_projection_fingerprint(&db, peer_id);
        let fp2 = compute_projection_fingerprint(&db, peer_id);
        assert_eq!(
            fp1.overall, fp2.overall,
            "fingerprint must be deterministic"
        );
        for (a, b) in fp1.tables.iter().zip(fp2.tables.iter()) {
            assert_eq!(
                a.hash, b.hash,
                "table {} hash must be deterministic",
                a.table
            );
            assert_eq!(a.row_count, b.row_count);
        }
    }

    #[test]
    fn fingerprint_changes_with_projection() {
        let (_dir, _path, db) = fresh_db();
        let peer_id = "fp-test-peer";

        let fp_empty = compute_projection_fingerprint(&db, peer_id);

        // Add a message row
        db.execute(
            "INSERT INTO messages (recorded_by, message_id, workspace_id, author_id, content, created_at)
             VALUES (?1, 'msg1', 'ws1', 'author1', 'hello', 1000)",
            rusqlite::params![peer_id],
        ).unwrap();

        let fp_one_msg = compute_projection_fingerprint(&db, peer_id);
        assert_ne!(
            fp_empty.overall, fp_one_msg.overall,
            "fingerprint must change when projection state changes"
        );

        // The messages table hash should differ
        let msg_idx = fp_empty
            .tables
            .iter()
            .position(|t| t.table == "messages")
            .unwrap();
        assert_ne!(
            fp_empty.tables[msg_idx].hash,
            fp_one_msg.tables[msg_idx].hash
        );
        assert_eq!(fp_one_msg.tables[msg_idx].row_count, 1);

        // Add another message
        db.execute(
            "INSERT INTO messages (recorded_by, message_id, workspace_id, author_id, content, created_at)
             VALUES (?1, 'msg2', 'ws1', 'author1', 'world', 2000)",
            rusqlite::params![peer_id],
        ).unwrap();

        let fp_two_msg = compute_projection_fingerprint(&db, peer_id);
        assert_ne!(
            fp_one_msg.overall, fp_two_msg.overall,
            "fingerprint must change when more rows are added"
        );
        assert_eq!(fp_two_msg.tables[msg_idx].row_count, 2);
    }

    #[test]
    fn fingerprint_detects_content_difference_at_same_count() {
        let (_dir, _path, db) = fresh_db();
        let peer_id = "fp-test-peer";

        db.execute(
            "INSERT INTO messages (recorded_by, message_id, workspace_id, author_id, content, created_at)
             VALUES (?1, 'msg1', 'ws1', 'author1', 'hello', 1000)",
            rusqlite::params![peer_id],
        ).unwrap();

        let fp_hello = compute_projection_fingerprint(&db, peer_id);

        // Change content but keep same count
        db.execute(
            "UPDATE messages SET content = 'goodbye' WHERE recorded_by = ?1 AND message_id = 'msg1'",
            rusqlite::params![peer_id],
        ).unwrap();

        let fp_goodbye = compute_projection_fingerprint(&db, peer_id);

        let msg_idx = fp_hello
            .tables
            .iter()
            .position(|t| t.table == "messages")
            .unwrap();
        assert_eq!(
            fp_hello.tables[msg_idx].row_count, fp_goodbye.tables[msg_idx].row_count,
            "row counts should be equal"
        );
        assert_ne!(
            fp_hello.overall, fp_goodbye.overall,
            "fingerprint must detect content changes that count-only checks miss"
        );
    }

    #[test]
    fn fingerprint_excludes_operational_tables() {
        let (_dir, _path, db) = fresh_db();
        let peer_id = "fp-test-peer";

        // Seed a message so fingerprint is non-trivial
        db.execute(
            "INSERT INTO messages (recorded_by, message_id, workspace_id, author_id, content, created_at)
             VALUES (?1, 'msg1', 'ws1', 'author1', 'hello', 1000)",
            rusqlite::params![peer_id],
        ).unwrap();

        let fp_before = compute_projection_fingerprint(&db, peer_id);

        // Modify operational tables that should NOT affect fingerprint
        db.execute(
            "INSERT INTO valid_events (peer_id, event_id) VALUES (?1, 'eid-op-test')",
            rusqlite::params![peer_id],
        )
        .unwrap();
        db.execute(
            "INSERT INTO blocked_event_deps (peer_id, event_id, blocker_event_id)
             VALUES (?1, 'eid-blocked', 'eid-blocker')",
            rusqlite::params![peer_id],
        )
        .unwrap();
        db.execute(
            "INSERT INTO rejected_events (peer_id, event_id, reason, rejected_at)
             VALUES (?1, 'eid-rej', 'bad', 1000)",
            rusqlite::params![peer_id],
        )
        .unwrap();

        let fp_after = compute_projection_fingerprint(&db, peer_id);
        assert_eq!(
            fp_before.overall, fp_after.overall,
            "operational table changes must not affect projection fingerprint"
        );
    }

    #[test]
    fn fingerprint_includes_identity_projections() {
        let (_dir, _path, db) = fresh_db();
        let peer_id = "fp-test-peer";

        let fp_empty = compute_projection_fingerprint(&db, peer_id);

        // Add identity projection rows
        db.execute(
            "INSERT INTO workspaces (recorded_by, event_id, workspace_id, public_key)
             VALUES (?1, 'ws-eid', 'ws1', X'AABB')",
            rusqlite::params![peer_id],
        )
        .unwrap();
        db.execute(
            "INSERT INTO users (recorded_by, event_id, public_key)
             VALUES (?1, 'user-eid', X'CCDD')",
            rusqlite::params![peer_id],
        )
        .unwrap();
        db.execute(
            "INSERT INTO peers_shared (recorded_by, event_id, public_key)
             VALUES (?1, 'ps-eid', X'EEFF')",
            rusqlite::params![peer_id],
        )
        .unwrap();

        let fp_identity = compute_projection_fingerprint(&db, peer_id);
        assert_ne!(
            fp_empty.overall, fp_identity.overall,
            "identity projection tables must be included in fingerprint"
        );

        // Verify per-table: workspaces, users, peers_shared all changed
        for name in &["workspaces", "users", "peers_shared"] {
            let idx = fp_empty
                .tables
                .iter()
                .position(|t| t.table == *name)
                .unwrap();
            assert_ne!(
                fp_empty.tables[idx].hash, fp_identity.tables[idx].hash,
                "table {} must contribute to fingerprint",
                name
            );
        }
    }

    #[test]
    fn fingerprint_tenant_scoped() {
        let (_dir, _path, db) = fresh_db();

        // Peer A has a message
        db.execute(
            "INSERT INTO messages (recorded_by, message_id, workspace_id, author_id, content, created_at)
             VALUES ('peer-a', 'msg1', 'ws1', 'author1', 'hello', 1000)",
            [],
        ).unwrap();

        let fp_a = compute_projection_fingerprint(&db, "peer-a");
        let fp_b = compute_projection_fingerprint(&db, "peer-b");

        // Peer A's fingerprint should differ from peer B's (which is empty)
        assert_ne!(
            fp_a.overall, fp_b.overall,
            "fingerprints must be tenant-scoped"
        );

        // Peer B's fingerprint should match an empty DB fingerprint
        let (_dir2, _path2, db2) = fresh_db();
        let fp_empty = compute_projection_fingerprint(&db2, "peer-b");
        assert_eq!(
            fp_b.overall, fp_empty.overall,
            "empty-scoped fingerprint should be identical across DBs"
        );
    }

    #[test]
    fn fingerprint_covers_all_expected_tables() {
        // Verify that FINGERPRINT_TABLES covers all projection tables
        // and excludes operational tables.
        let projection_tables = [
            "messages",
            "reactions",
            "secret_keys",
            "deleted_messages",
            "message_attachments",
            "file_slices",
            "workspaces",
            "invite_accepted",
            "user_invites",
            "device_invites",
            "users",
            "peers_shared",
            "admins",
            "removed_entities",
            "secret_shared",
            "trust_anchors",
        ];
        let excluded_tables = [
            "valid_events",
            "rejected_events",
            "blocked_event_deps",
            "blocked_events",
            "project_queue",
            "egress_queue",
            "peer_endpoint_observations",
            "intro_attempts",
            "peer_transport_bindings",
            "invite_bootstrap_trust",
            "pending_invite_bootstrap_trust",
            "local_transport_creds",
            "file_slice_guard_blocks",
            "neg_items",
            "events",
            "recorded_events",
        ];

        let table_names: Vec<&str> = FINGERPRINT_TABLES.iter().map(|t| t.name).collect();

        for expected in &projection_tables {
            assert!(
                table_names.contains(expected),
                "projection table '{}' must be in FINGERPRINT_TABLES",
                expected
            );
        }
        for excluded in &excluded_tables {
            assert!(
                !table_names.contains(excluded),
                "operational table '{}' must NOT be in FINGERPRINT_TABLES",
                excluded
            );
        }
    }
}
