use super::*;

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
    pub(crate) _tempdir: tempfile::TempDir,
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
    pub(crate) fn bootstrap_identity_chain(&mut self) {
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

        // Derive identity directly from the returned PeerShared signer key.
        // This avoids singleton transport-identity assumptions in multi-tenant DBs.
        let new_identity = hex::encode(crate::crypto::spki_fingerprint_from_ed25519_pubkey(
            &result.peer_shared_key.verifying_key().to_bytes(),
        ));
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
        use crate::event_modules::workspace::invite_link::{
            create_invite_link, parse_bootstrap_address,
        };

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
            _tempdir: tempdir,
        };
        let creator_db = open_connection(&creator.db_path).expect("failed to open creator db");
        let creator_peer_key = creator
            .peer_shared_signing_key
            .as_ref()
            .expect("creator has no peer_shared_signing_key; use new_with_identity()");
        let creator_peer_eid = creator
            .peer_shared_event_id
            .expect("creator has no peer_shared_event_id; use new_with_identity()");
        let creator_admin_eid: EventId = creator_db
            .query_row(
                "SELECT event_id
                 FROM admins
                 WHERE recorded_by = ?1
                 ORDER BY event_id ASC
                 LIMIT 1",
                rusqlite::params![&creator.identity],
                |row| row.get::<_, String>(0),
            )
            .ok()
            .and_then(|b64| event_id_from_base64(&b64))
            .expect("creator has no admin event; use new_with_identity()");

        // Creator issues an invite via workspace::commands API
        let invite = create_user_invite_raw(
            &creator_db,
            &creator.identity,
            creator_peer_key,
            &creator_peer_eid,
            &creator_admin_eid,
            &creator.workspace_id,
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

        // Start a real dynamic-trust sync endpoint for the creator and use its
        // address in the invite link. The same endpoint then serves the
        // bootstrap sync loops below.
        let sync_endpoint = create_dynamic_endpoint_for_peer(creator);
        let sync_addr = sync_endpoint.local_addr().expect("failed to get sync addr");

        // Build invite link with creator's bootstrap address and SPKI
        let creator_spki = creator.spki_fingerprint();
        let bootstrap_addr = parse_bootstrap_address(&sync_addr.to_string())
            .expect("failed to parse bootstrap addr");
        let invite_link = create_invite_link(&invite, &[bootstrap_addr], &creator_spki)
            .expect("failed to create invite link");

        // Step 1: Accept invite — stores events (may block), materializes bootstrap trust
        let result = crate::event_modules::workspace::commands::accept_invite(
            &peer.db_path,
            &invite_link,
            name,
            "device",
        )
        .expect("failed to accept invite");

        let scoped_peer_id = result.peer_id.clone();
        peer.identity = scoped_peer_id.clone();
        peer.workspace_id = creator.workspace_id;
        let db = open_connection(&peer.db_path).expect("failed to open db");
        let creator_db = open_connection(&creator.db_path).expect("failed to reopen creator db");

        let creator_peer_b64 = event_id_to_base64(&creator_peer_eid);
        let creator_peer_blob: Vec<u8> = creator_db
            .query_row(
                "SELECT blob FROM events WHERE event_id = ?1",
                rusqlite::params![&creator_peer_b64],
                |row| row.get(0),
            )
            .expect("failed to load creator peer_shared blob");
        let creator_device_invite_eid = match crate::event_modules::parse_event(&creator_peer_blob)
            .expect("failed to parse creator peer_shared")
        {
            ParsedEvent::PeerShared(ps) => ps.signed_by,
            _ => panic!("creator peer_shared event has unexpected type"),
        };

        let creator_user_b64 = event_id_to_base64(&creator.author_id);
        let creator_user_blob: Vec<u8> = creator_db
            .query_row(
                "SELECT blob FROM events WHERE event_id = ?1",
                rusqlite::params![&creator_user_b64],
                |row| row.get(0),
            )
            .expect("failed to load creator user blob");
        let creator_user_invite_eid = match crate::event_modules::parse_event(&creator_user_blob)
            .expect("failed to parse creator user")
        {
            ParsedEvent::User(u) => u.signed_by,
            _ => panic!("creator user event has unexpected type"),
        };

        copy_projected_events_for_tenant(
            &creator_db,
            &db,
            &scoped_peer_id,
            &[
                creator.workspace_id,
                creator_user_invite_eid,
                creator.author_id,
                creator_device_invite_eid,
                creator_peer_eid,
                creator_admin_eid,
                invite.invite_event_id,
            ],
        );
        let creator_shared_event_ids =
            list_shared_event_ids_for_tenant(&creator_db, &creator.identity);
        copy_projected_events_for_tenant(
            &creator_db,
            &db,
            &scoped_peer_id,
            &creator_shared_event_ids,
        );
        let joiner_shared_event_ids = list_shared_event_ids_for_tenant(&db, &scoped_peer_id);
        copy_projected_events_for_tenant(
            &db,
            &creator_db,
            &creator.identity,
            &joiner_shared_event_ids,
        );

        // Step 2: Run the same ongoing sync loops the runtime would use until
        // the bootstrap chain materializes the joiner's local signer.
        let creator_ep = sync_endpoint.clone();
        let creator_db = creator.db_path.clone();
        let creator_id = creator.identity.clone();
        let _creator_handle = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async move {
                if let Err(err) = accept_loop(
                    &creator_db,
                    &creator_id,
                    creator_ep,
                    noop_intro_spawner,
                    test_ingest_fns(),
                )
                .await
                {
                    eprintln!("bootstrap accept_loop exited: {err}");
                }
            });
        });

        let peer_endpoint = create_dynamic_endpoint_for_peer(&peer);
        let peer_ep = peer_endpoint.clone();
        let peer_db = peer.db_path.clone();
        let peer_id = scoped_peer_id.clone();
        let creator_target_peer_id = hex::encode(creator.spki_fingerprint());
        let creator_target_peer_id_for_thread = creator_target_peer_id.clone();
        let invite_event_id_b64 = event_id_to_base64(&invite.invite_event_id);
        let _connector_handle = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async move {
                if let Err(err) =
                    connect_loop_with_coordination_until_cancel_with_fallback_with_auth(
                        &peer_db,
                        &peer_id,
                        peer_ep,
                        sync_addr,
                        &creator_target_peer_id_for_thread,
                        &creator_target_peer_id_for_thread,
                        OutboundSessionAuthPlan::InviteBootstrap {
                            invite_event_id: invite_event_id_b64,
                        },
                        None,
                        noop_intro_spawner,
                        test_ingest_fns(),
                        CancellationToken::new(),
                        None,
                        None,
                    )
                    .await
                {
                    eprintln!("bootstrap connect_loop exited: {err}");
                }
            });
        });

        // Load signing key and user_event_id from DB in a read-your-writes step.
        let (eid, key) = wait_for_materialized_local_peer_signer(
            &peer.db_path,
            &scoped_peer_id,
            Duration::from_secs(10),
        )
        .await;
        let local_transport_peer_id = wait_for_any_tenant_transport_target(
            &peer.db_path,
            &scoped_peer_id,
            Duration::from_secs(10),
        )
        .await;
        wait_for_projected_peer_transport(
            &peer.db_path,
            &scoped_peer_id,
            &creator.transport_peer_id(),
            Duration::from_secs(10),
        )
        .await;
        wait_for_projected_peer_transport(
            &creator.db_path,
            &creator.identity,
            &local_transport_peer_id,
            Duration::from_secs(10),
        )
        .await;
        peer_endpoint.close(0u32.into(), b"bootstrap done");
        sync_endpoint.close(0u32.into(), b"bootstrap done");

        peer.peer_shared_event_id = Some(eid);
        peer.peer_shared_signing_key = Some(key);
        if let Ok(uid) =
            crate::service::resolve_user_event_id_for_signer(&db, &scoped_peer_id, &eid)
        {
            peer.author_id = uid;
        }

        peer
    }

    /// Create a new device for an existing workspace user using the production
    /// device-link flow with real QUIC bootstrap sync.
    pub async fn new_device_in_workspace(name: &str, creator: &Peer) -> Self {
        use crate::db::transport_trust::record_pending_invite_bootstrap_trust;
        use crate::event_modules::workspace::commands::create_device_link_invite_raw;
        use crate::event_modules::workspace::identity_ops::expected_invite_bootstrap_spki_from_invite_key;
        use crate::event_modules::workspace::invite_link::{
            create_invite_link, parse_bootstrap_address,
        };

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
            _tempdir: tempdir,
        };

        let creator_db = open_connection(&creator.db_path).expect("failed to open creator db");
        let creator_peer_key = creator
            .peer_shared_signing_key
            .as_ref()
            .expect("creator has no peer_shared_signing_key; use new_with_identity()");
        let creator_peer_eid = creator
            .peer_shared_event_id
            .expect("creator has no peer_shared_event_id; use new_with_identity()");
        let creator_admin_eid: EventId = creator_db
            .query_row(
                "SELECT event_id
                 FROM admins
                 WHERE recorded_by = ?1
                 ORDER BY event_id ASC
                 LIMIT 1",
                rusqlite::params![&creator.identity],
                |row| row.get::<_, String>(0),
            )
            .ok()
            .and_then(|b64| event_id_from_base64(&b64))
            .expect("creator has no admin event; use new_with_identity()");
        let invite = create_device_link_invite_raw(
            &creator_db,
            &creator.identity,
            creator_peer_key,
            &creator_peer_eid,
            &creator.author_id,
            &creator.workspace_id,
        )
        .expect("failed to create device link invite");

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

        let sync_endpoint = create_dynamic_endpoint_for_peer(creator);
        let sync_addr = sync_endpoint.local_addr().expect("failed to get sync addr");

        let creator_spki = creator.spki_fingerprint();
        let bootstrap_addr = parse_bootstrap_address(&sync_addr.to_string())
            .expect("failed to parse bootstrap addr");
        let invite_link = create_invite_link(&invite, &[bootstrap_addr], &creator_spki)
            .expect("failed to create device-link invite link");

        let result = crate::event_modules::workspace::commands::accept_device_link(
            &peer.db_path,
            &invite_link,
            name,
        )
        .expect("failed to accept device link");

        let scoped_peer_id = result.peer_id.clone();
        peer.identity = scoped_peer_id.clone();
        peer.workspace_id = creator.workspace_id;
        let db = open_connection(&peer.db_path).expect("failed to open db");
        let creator_db = open_connection(&creator.db_path).expect("failed to reopen creator db");

        let creator_peer_b64 = event_id_to_base64(&creator_peer_eid);
        let creator_peer_blob: Vec<u8> = creator_db
            .query_row(
                "SELECT blob FROM events WHERE event_id = ?1",
                rusqlite::params![&creator_peer_b64],
                |row| row.get(0),
            )
            .expect("failed to load creator peer_shared blob");
        let creator_device_invite_eid = match crate::event_modules::parse_event(&creator_peer_blob)
            .expect("failed to parse creator peer_shared")
        {
            ParsedEvent::PeerShared(ps) => ps.signed_by,
            _ => panic!("creator peer_shared event has unexpected type"),
        };

        let creator_user_b64 = event_id_to_base64(&creator.author_id);
        let creator_user_blob: Vec<u8> = creator_db
            .query_row(
                "SELECT blob FROM events WHERE event_id = ?1",
                rusqlite::params![&creator_user_b64],
                |row| row.get(0),
            )
            .expect("failed to load creator user blob");
        let creator_user_invite_eid = match crate::event_modules::parse_event(&creator_user_blob)
            .expect("failed to parse creator user")
        {
            ParsedEvent::User(u) => u.signed_by,
            _ => panic!("creator user event has unexpected type"),
        };

        copy_projected_events_for_tenant(
            &creator_db,
            &db,
            &scoped_peer_id,
            &[
                creator.workspace_id,
                creator_user_invite_eid,
                creator.author_id,
                creator_device_invite_eid,
                creator_peer_eid,
                creator_admin_eid,
                invite.invite_event_id,
            ],
        );
        let creator_shared_event_ids =
            list_shared_event_ids_for_tenant(&creator_db, &creator.identity);
        copy_projected_events_for_tenant(
            &creator_db,
            &db,
            &scoped_peer_id,
            &creator_shared_event_ids,
        );
        let joiner_shared_event_ids = list_shared_event_ids_for_tenant(&db, &scoped_peer_id);
        copy_projected_events_for_tenant(
            &db,
            &creator_db,
            &creator.identity,
            &joiner_shared_event_ids,
        );

        let creator_ep = sync_endpoint.clone();
        let creator_db = creator.db_path.clone();
        let creator_id = creator.identity.clone();
        let _creator_handle = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async move {
                if let Err(err) = accept_loop(
                    &creator_db,
                    &creator_id,
                    creator_ep,
                    noop_intro_spawner,
                    test_ingest_fns(),
                )
                .await
                {
                    eprintln!("device bootstrap accept_loop exited: {err}");
                }
            });
        });

        let peer_endpoint = create_dynamic_endpoint_for_peer(&peer);
        let peer_ep = peer_endpoint.clone();
        let peer_db = peer.db_path.clone();
        let peer_id = scoped_peer_id.clone();
        let creator_target_peer_id = hex::encode(creator.spki_fingerprint());
        let creator_target_peer_id_for_thread = creator_target_peer_id.clone();
        let invite_event_id_b64 = event_id_to_base64(&invite.invite_event_id);
        let _connector_handle = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async move {
                if let Err(err) =
                    connect_loop_with_coordination_until_cancel_with_fallback_with_auth(
                        &peer_db,
                        &peer_id,
                        peer_ep,
                        sync_addr,
                        &creator_target_peer_id_for_thread,
                        &creator_target_peer_id_for_thread,
                        OutboundSessionAuthPlan::InviteBootstrap {
                            invite_event_id: invite_event_id_b64,
                        },
                        None,
                        noop_intro_spawner,
                        test_ingest_fns(),
                        CancellationToken::new(),
                        None,
                        None,
                    )
                    .await
                {
                    eprintln!("device bootstrap connect_loop exited: {err}");
                }
            });
        });

        let (eid, key) = wait_for_materialized_local_peer_signer(
            &peer.db_path,
            &scoped_peer_id,
            Duration::from_secs(10),
        )
        .await;
        let local_transport_peer_id = wait_for_any_tenant_transport_target(
            &peer.db_path,
            &scoped_peer_id,
            Duration::from_secs(10),
        )
        .await;
        wait_for_projected_peer_transport(
            &peer.db_path,
            &scoped_peer_id,
            &creator.transport_peer_id(),
            Duration::from_secs(10),
        )
        .await;
        wait_for_projected_peer_transport(
            &creator.db_path,
            &creator.identity,
            &local_transport_peer_id,
            Duration::from_secs(10),
        )
        .await;
        peer_endpoint.close(0u32.into(), b"bootstrap done");
        sync_endpoint.close(0u32.into(), b"bootstrap done");

        peer.peer_shared_event_id = Some(eid);
        peer.peer_shared_signing_key = Some(key);
        if let Ok(uid) =
            crate::service::resolve_user_event_id_for_signer(&db, &scoped_peer_id, &eid)
        {
            peer.author_id = uid;
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
        if let Some(signing_key) = self.peer_shared_signing_key.as_ref() {
            return crate::transport::generate_self_signed_cert_from_signing_key(signing_key)
                .expect("failed to derive cert from peer_shared signer");
        }

        let db = open_connection(&self.db_path).expect("failed to open db");
        let transport_peer_id =
            crate::state::db::transport_creds::resolve_tenant_transport_target(&db, &self.identity)
                .expect("failed to resolve tenant transport target")
                .map(|target| target.transport_peer_id)
                .unwrap_or_else(|| self.identity.clone());
        let (cert, key) =
            load_transport_cert(&db, &transport_peer_id).expect("failed to load cert");
        (cert, key)
    }

    /// Extract the SPKI fingerprint (SHA-256) from this peer's transport certificate.
    pub fn spki_fingerprint(&self) -> [u8; 32] {
        let (cert, _) = self.cert_and_key();
        extract_spki_fingerprint(cert.as_ref()).expect("failed to extract fingerprint")
    }

    /// Return the current exact transport target id (hex SPKI fingerprint) for this peer.
    pub fn transport_peer_id(&self) -> String {
        hex::encode(self.spki_fingerprint())
    }

    /// Create a message and insert it into all relevant tables.
    /// Returns the event ID. Requires identity chain (use new_with_identity).
    pub fn create_message(&self, content: &str) -> EventId {
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
        self.create_encrypted_signed_event_synchronous(&self.content_key_event_id(&db), &inner)
    }

    /// Create a reaction targeting a message event.
    /// Returns the reaction event ID. Requires identity chain.
    pub fn create_reaction(&self, target_event_id: &EventId, emoji: &str) -> EventId {
        let db = open_connection(&self.db_path).expect("failed to open db");
        let inner = ParsedEvent::Reaction(ReactionEvent {
            created_at_ms: current_timestamp_ms(),
            target_event_id: *target_event_id,
            author_id: self.author_id,
            emoji: emoji.to_string(),
            signed_by: self.signer_eid(),
            signer_type: 5,
            signature: [0u8; 64],
        });
        self.create_encrypted_signed_event_synchronous(&self.content_key_event_id(&db), &inner)
    }

    /// Create a reaction, tolerating blocked projection when the target message
    /// is not valid locally yet. Returns the encrypted wrapper event_id.
    pub fn create_reaction_staged(&self, target_event_id: &EventId, emoji: &str) -> EventId {
        let db = open_connection(&self.db_path).expect("failed to open db");
        let inner = ParsedEvent::Reaction(ReactionEvent {
            created_at_ms: current_timestamp_ms(),
            target_event_id: *target_event_id,
            author_id: self.author_id,
            emoji: emoji.to_string(),
            signed_by: self.signer_eid(),
            signer_type: 5,
            signature: [0u8; 64],
        });
        create_encrypted_event_staged(
            &db,
            &self.identity,
            &self.content_key_event_id(&db),
            &inner,
            Some(self.signing_key()),
        )
        .expect("failed to create staged encrypted reaction")
    }

    /// Create a KeySecret event with the given key bytes.
    /// Returns the event ID.
    pub fn create_key_secret(&self, key_bytes: [u8; 32]) -> EventId {
        let db = open_connection(&self.db_path).expect("failed to open db");
        let sk = ParsedEvent::KeySecret(KeySecretEvent {
            created_at_ms: current_timestamp_ms(),
            key_bytes,
        });
        create_event_synchronous(&db, &self.identity, &sk).expect("failed to create key_secret")
    }

    /// Create a KeySecret event with deterministic key bytes and timestamp.
    /// Two peers calling this with the same args produce the same blob -> same event_id.
    /// This is used for PSK materialization in tests where both peers need the same key.
    pub fn create_key_secret_deterministic(
        &self,
        key_bytes: [u8; 32],
        created_at_ms: u64,
    ) -> EventId {
        let db = open_connection(&self.db_path).expect("failed to open db");
        let sk = ParsedEvent::KeySecret(KeySecretEvent {
            created_at_ms,
            key_bytes,
        });
        create_event_synchronous(&db, &self.identity, &sk).expect("failed to create key_secret")
    }

    /// Create an encrypted message. The inner message is signed with the PeerShared key,
    /// then encrypted. Returns the encrypted event ID. Requires identity chain.
    pub fn create_encrypted_message(&self, key_event_id: &EventId, content: &str) -> EventId {
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
        self.create_encrypted_signed_event_synchronous(key_event_id, &inner)
    }

    /// Sign an inner event, encrypt the signed blob, wrap in EncryptedEvent, store + project.
    /// Uses event_id_or_blocked so events whose deps are missing are stored in blocked
    /// state rather than panicking, mirroring real ingestion behaviour.
    fn create_encrypted_signed_event_synchronous(
        &self,
        key_event_id: &EventId,
        inner_event: &ParsedEvent,
    ) -> EventId {
        for attempt in 0..TESTUTIL_SQLITE_BUSY_RETRY_ATTEMPTS {
            let db = open_connection(&self.db_path).expect("failed to open db");
            // Full-suite sync_graph runs can create substantial writer
            // contention on a single test DB. Use a fresh connection per
            // attempt and give it a longer wait budget before surfacing
            // SQLITE_BUSY so realistic graph tests remain stable under the
            // default cargo scheduler.
            let _ = db.busy_timeout(Duration::from_secs(30));
            match event_id_or_blocked(create_encrypted_event_synchronous(
                &db,
                &self.identity,
                key_event_id,
                inner_event,
                Some(self.signing_key()),
            )) {
                Ok(event_id) => return event_id,
                Err(CreateEventError::DbError(err))
                    if err.contains("database is locked")
                        && attempt + 1 < TESTUTIL_SQLITE_BUSY_RETRY_ATTEMPTS =>
                {
                    std::thread::sleep(Duration::from_millis(SQLITE_BUSY_RETRY_BASE_MS << attempt));
                }
                Err(err) => panic!("failed to create encrypted signed event: {err}"),
            }
        }

        unreachable!("loop returns on success or final error")
    }

    fn content_key_event_id(&self, db: &rusqlite::Connection) -> EventId {
        crate::event_modules::workspace::identity_ops::ensure_content_key_for_peer(
            db,
            &self.identity,
        )
        .expect("failed to ensure content key")
    }

    pub fn ensure_content_key_event_id(&self) -> EventId {
        let db = open_connection(&self.db_path).expect("failed to open db");
        self.content_key_event_id(&db)
    }

    /// Create a MessageDeletion event targeting the given message event.
    /// Returns the deletion event ID. Requires identity chain.
    pub fn create_message_deletion(&self, target_event_id: &EventId) -> EventId {
        let db = open_connection(&self.db_path).expect("failed to open db");
        let inner = ParsedEvent::MessageDeletion(MessageDeletionEvent {
            created_at_ms: current_timestamp_ms(),
            target_event_id: *target_event_id,
            author_id: self.author_id,
            signed_by: self.signer_eid(),
            signer_type: 5,
            signature: [0u8; 64],
        });
        self.create_encrypted_signed_event_synchronous(&self.content_key_event_id(&db), &inner)
    }

    /// Create an encrypted MessageDeletion event.
    /// Returns the encrypted event ID. Requires identity chain.
    pub fn create_encrypted_deletion(
        &self,
        key_event_id: &EventId,
        target_event_id: &EventId,
    ) -> EventId {
        let inner = ParsedEvent::MessageDeletion(MessageDeletionEvent {
            created_at_ms: current_timestamp_ms(),
            target_event_id: *target_event_id,
            author_id: self.author_id,
            signed_by: self.signer_eid(),
            signer_type: 5,
            signature: [0u8; 64],
        });
        self.create_encrypted_signed_event_synchronous(key_event_id, &inner)
    }

    // --- Identity event helpers ---

    /// Create a Workspace event. Returns the event ID.
    ///
    /// Uses staged projection; workspace validity unblocks after invite_accepted
    /// projects and emits a retry command.
    pub fn create_workspace(&self, public_key: [u8; 32]) -> EventId {
        let db = open_connection(&self.db_path).expect("failed to open db");
        let ws = ParsedEvent::Workspace(WorkspaceEvent {
            created_at_ms: current_timestamp_ms(),
            public_key,
            name: "test-workspace".to_string(),
        });
        // Pre-compute event_id to assert deterministic staged write identity.
        let ws_blob =
            crate::event_modules::encode_event(&ws).expect("failed to encode workspace event");
        let ws_eid = crate::crypto::hash_event(&ws_blob);
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

    /// Record the local invite-link workspace binding that InviteAccepted
    /// projection uses to self-validate external accepts in tests.
    pub fn record_invite_link_workspace(&self, invite_event_id: &EventId, workspace_id: [u8; 32]) {
        let db = open_connection(&self.db_path).expect("failed to open db");
        let invite_event_id_b64 = event_id_to_base64(invite_event_id);
        let workspace_id_b64 = event_id_to_base64(&workspace_id);
        crate::db::transport_trust::append_bootstrap_context(
            &db,
            &self.identity,
            &invite_event_id_b64,
            &workspace_id_b64,
            "",
            &[0xAB; 32],
        )
        .expect("failed to record invite-link workspace binding");
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
        create_event_synchronous(db, &self.identity, &tenant_evt).expect("failed to create tenant")
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
            authority_event_id: *workspace_id,
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
            authority_event_id: *workspace_id,
            signed_by: *workspace_id,
            signer_type: 1,
            signature: [0u8; 64],
        });
        create_signed_event_staged(&db, &self.identity, &evt, signing_key)
            .expect("failed to create user_invite")
    }

    /// Create a deterministic local invite_secret event for an invite.
    pub fn create_invite_secret(
        &self,
        invite_event_id: &EventId,
        invite_private_key: [u8; 32],
    ) -> EventId {
        let db = open_connection(&self.db_path).expect("failed to open db");
        let evt = crate::event_modules::invite_secret::deterministic_invite_secret_event(
            *invite_event_id,
            invite_private_key,
        );
        create_event_staged(&db, &self.identity, &evt).expect("failed to create invite_secret")
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
            authority_event_id: *user_event_id,
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

    /// Create a KeyShared event (signed by PeerShared key). Returns the event ID.
    pub fn create_key_shared(
        &self,
        signing_key: &ed25519_dalek::SigningKey,
        key_event_id: &EventId,
        recipient_event_id: &EventId,
        unwrap_key_event_id: &EventId,
        wrapped_key: [u8; 32],
        peer_shared_event_id: &EventId,
    ) -> EventId {
        let db = open_connection(&self.db_path).expect("failed to open db");
        let evt = ParsedEvent::KeyShared(KeySharedEvent {
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
            .expect("failed to create key_shared")
    }

    /// Create multiple messages. Uses a transaction for speed at scale.
    /// Requires identity chain.
    pub fn batch_create_messages(&self, count: usize) {
        let db = open_connection(&self.db_path).expect("failed to open db");
        let key_event_id = self.content_key_event_id(&db);
        db.execute("BEGIN", []).expect("failed to begin");
        for i in 0..count {
            let inner = ParsedEvent::Message(MessageEvent {
                created_at_ms: current_timestamp_ms(),
                workspace_id: self.workspace_id,
                author_id: self.author_id,
                content: format!("Message {} from {}", i, self.name),
                signed_by: self.signer_eid(),
                signer_type: 5,
                signature: [0u8; 64],
            });
            event_id_or_blocked(create_encrypted_event_synchronous(
                &db,
                &self.identity,
                &key_event_id,
                &inner,
                Some(self.signing_key()),
            ))
            .expect("failed to create batch message");
        }
        db.execute("COMMIT", []).expect("failed to commit");
    }

    /// Create multiple messages whose `created_at_ms` values are spread across
    /// a wall-clock span. Requires identity chain.
    pub fn batch_create_messages_spread(&self, count: usize, start_ms: u64, spread_ms: u64) {
        let db = open_connection(&self.db_path).expect("failed to open db");
        let key_event_id = self.content_key_event_id(&db);
        db.execute("BEGIN", []).expect("failed to begin");
        for i in 0..count {
            let offset_ms = if count <= 1 {
                0
            } else {
                spread_ms.saturating_mul(i as u64) / (count.saturating_sub(1) as u64)
            };
            let inner = ParsedEvent::Message(MessageEvent {
                created_at_ms: start_ms.saturating_add(offset_ms),
                workspace_id: self.workspace_id,
                author_id: self.author_id,
                content: format!("Spread message {} from {}", i, self.name),
                signed_by: self.signer_eid(),
                signer_type: 5,
                signature: [0u8; 64],
            });
            event_id_or_blocked(create_encrypted_event_synchronous(
                &db,
                &self.identity,
                &key_event_id,
                &inner,
                Some(self.signing_key()),
            ))
            .expect("failed to create spread batch message");
        }
        db.execute("COMMIT", []).expect("failed to commit");
    }

    /// Create a file consisting of `total_slices` file slices.
    ///
    /// Builds all required prerequisites (message, key_secret, attachment
    /// descriptor) and then batch-creates the slices. Returns the file_id
    /// used for all slices. Requires identity chain (use new_with_identity).
    pub fn batch_create_file_slices(&self, total_slices: usize) -> [u8; 32] {
        use crate::event_modules::file_slice::FILE_SLICE_CIPHERTEXT_BYTES;
        use crate::projection::signer::sign_event_bytes;

        let db = open_connection(&self.db_path).expect("failed to open db");
        let workspace_id = crate::db::store::lookup_workspace_id(&db, &self.identity)
            .expect("missing trust anchor workspace_id for file-slice benchmark");

        // Parent message
        let key_event_id = self.content_key_event_id(&db);

        let msg = ParsedEvent::Message(MessageEvent {
            created_at_ms: current_timestamp_ms(),
            workspace_id: self.workspace_id,
            author_id: self.author_id,
            content: format!("file-parent-{}", self.name),
            signed_by: self.signer_eid(),
            signer_type: 5,
            signature: [0u8; 64],
        });
        let msg_eid = self.create_encrypted_signed_event_synchronous(&key_event_id, &msg);

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
        let att = ParsedEvent::File(FileEvent {
            created_at_ms: current_timestamp_ms(),
            message_id: msg_eid,
            file_id,
            blob_bytes: file_bytes as u64,
            total_slices: total_slices as u32,
            slice_bytes: slice_size as u32,
            root_hash: [0xAA; 32],
            key_event_id,
            filename: format!("bench-{}.bin", self.name),
            mime_type: "application/octet-stream".to_string(),
            signed_by: self.signer_eid(),
            signer_type: 5,
            signature: [0u8; 64],
        });
        let _att_eid = self.create_encrypted_signed_event_synchronous(&key_event_id, &att);

        // Batch-create file slices inside a transaction
        let ciphertext: Vec<u8> = vec![0xAB; FILE_SLICE_CIPHERTEXT_BYTES];
        let signing_key = self.signing_key().clone();

        db.execute("BEGIN", []).expect("failed to begin");
        for i in 0..total_slices as u32 {
            // Use a single timestamp for both the blob's created_at and the
            // shared_event_index ts. If these diverge, the sink's batch_writer (which
            // extracts created_at from the blob) inserts a different shared_event_index
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
            let mut inner_blob =
                crate::event_modules::encode_event(&fs).expect("failed to encode file_slice");
            let blob_len = inner_blob.len();
            let sig = sign_event_bytes(&signing_key, &inner_blob[..blob_len - 64]);
            inner_blob[blob_len - 64..].copy_from_slice(&sig);

            let key_bytes: Vec<u8> = db
                .query_row(
                    "SELECT key_bytes FROM key_secrets WHERE recorded_by = ?1 AND event_id = ?2",
                    rusqlite::params![&self.identity, event_id_to_base64(&key_event_id)],
                    |row| row.get(0),
                )
                .expect("failed to load content key bytes");
            let mut key_arr = [0u8; 32];
            key_arr.copy_from_slice(&key_bytes);
            let (nonce, ciphertext, auth_tag) =
                crate::projection::encrypted::encrypt_event_blob(&key_arr, &inner_blob)
                    .expect("failed to encrypt file_slice");
            let enc = ParsedEvent::Encrypted(crate::event_modules::EncryptedEvent {
                created_at_ms: current_timestamp_ms(),
                key_event_id,
                inner_type_code: crate::event_modules::EVENT_TYPE_FILE_SLICE,
                nonce,
                ciphertext,
                auth_tag,
            });
            let blob =
                crate::event_modules::encode_event(&enc).expect("failed to encode encrypted");

            let event_id = crate::crypto::hash_event(&blob);
            let event_id_b64 = event_id_to_base64(&event_id);

            // Insert into events, shared_event_index, recorded_events — all use the
            // same created_at that is embedded in the blob so that the
            // shared_event_index (workspace_id, ts, id) key matches what a
            // receiving batch_writer would extract from the blob.
            db.execute(
                "INSERT OR IGNORE INTO events (event_id, event_type, blob, share_scope, created_at, inserted_at)
                 VALUES (?1, ?2, ?3, 'shared', ?4, ?5)",
                rusqlite::params![&event_id_b64, "encrypted", blob.as_slice(), created_at as i64, created_at as i64],
            ).expect("failed to insert file_slice event");
            db.execute(
                "INSERT OR IGNORE INTO shared_event_index (workspace_id, ts, id) VALUES (?1, ?2, ?3)",
                rusqlite::params![&workspace_id, created_at as i64, event_id.as_slice()],
            )
            .expect("failed to insert neg_item");
            db.execute(
                "INSERT OR IGNORE INTO recorded_events (peer_id, event_id, recorded_at, source)
                 VALUES (?1, ?2, ?3, 'local')",
                rusqlite::params![&self.identity, &event_id_b64, created_at as i64],
            )
            .expect("failed to insert recorded_event");

            // Project (validates decryption, signature, and authorization chain)
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
            "SELECT COUNT(*) FROM valid_events WHERE peer_id = ?1 AND semantic_type_code = ?2",
            rusqlite::params![
                &self.identity,
                i64::from(crate::event_modules::EVENT_TYPE_MESSAGE)
            ],
            |row| row.get(0),
        )
        .unwrap_or(0)
    }

    /// Count recorded message events using the encrypted wrapper's exposed
    /// inner semantic type. This works even when the local tenant cannot
    /// decrypt or validate another workspace's message payloads.
    pub fn recorded_message_event_count(&self) -> i64 {
        let db = match open_count_connection(&self.db_path) {
            Some(db) => db,
            None => return -1,
        };
        db.query_row(
            "SELECT COUNT(*)
             FROM recorded_events re
             JOIN events e ON e.event_id = re.event_id
             WHERE re.peer_id = ?1
               AND (
                    e.event_type = 'message'
                    OR (
                        e.event_type = 'encrypted'
                        AND substr(e.blob, 42, 1) = ?2
                    )
               )",
            rusqlite::params![
                &self.identity,
                vec![crate::event_modules::EVENT_TYPE_MESSAGE]
            ],
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

    /// Count rows in the key_secrets projection table scoped to this peer.
    pub fn key_secret_count(&self) -> i64 {
        let db = open_connection(&self.db_path).expect("failed to open db");
        db.query_row(
            "SELECT COUNT(*) FROM key_secrets WHERE recorded_by = ?1",
            rusqlite::params![&self.identity],
            |row| row.get(0),
        )
        .unwrap_or(0)
    }

    /// Count rows in the shared_event_index table (events advertised for sync).
    pub fn shared_event_index_count(&self) -> i64 {
        let db = open_connection(&self.db_path).expect("failed to open db");
        db.query_row("SELECT COUNT(*) FROM shared_event_index", [], |row| {
            row.get(0)
        })
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
        if let Some(meta) = crate::event_modules::registry().lookup_by_name(event_type) {
            let mut stmt = db
                .prepare(
                    "SELECT event_id
                     FROM valid_events
                     WHERE peer_id = ?1 AND semantic_type_code = ?2
                     ORDER BY event_id",
                )
                .expect("prepare");
            return stmt
                .query_map(
                    rusqlite::params![&self.identity, i64::from(meta.type_code)],
                    |row| row.get::<_, String>(0),
                )
                .expect("query")
                .collect::<Result<std::collections::BTreeSet<_>, _>>()
                .expect("collect");
        }

        let mut stmt = db
            .prepare("SELECT event_id FROM events WHERE event_type = ?1 ORDER BY event_id")
            .expect("prepare");
        stmt.query_map(rusqlite::params![event_type], |row| row.get::<_, String>(0))
            .expect("query")
            .collect::<Result<std::collections::BTreeSet<_>, _>>()
            .expect("collect")
    }

    /// Return recorded message event IDs using the encrypted wrapper's
    /// inner semantic type rather than decrypted validity.
    pub fn recorded_message_event_ids(&self) -> std::collections::BTreeSet<String> {
        let db = open_connection(&self.db_path).expect("failed to open db");
        let mut stmt = db
            .prepare(
                "SELECT re.event_id
                 FROM recorded_events re
                 JOIN events e ON e.event_id = re.event_id
                 WHERE re.peer_id = ?1
                   AND (
                        e.event_type = 'message'
                        OR (
                            e.event_type = 'encrypted'
                            AND substr(e.blob, 42, 1) = ?2
                        )
                   )
                 ORDER BY re.event_id",
            )
            .expect("prepare");
        stmt.query_map(
            rusqlite::params![
                &self.identity,
                vec![crate::event_modules::EVENT_TYPE_MESSAGE]
            ],
            |row| row.get::<_, String>(0),
        )
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
            "SELECT COUNT(*) FROM invites_accepted WHERE recorded_by = ?1",
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
