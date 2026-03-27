use super::fingerprint::verify_projection_invariants;
use super::peer::Peer;
use super::*;

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

pub(super) fn copy_projected_events_for_tenant(
    src_db: &rusqlite::Connection,
    dst_db: &rusqlite::Connection,
    tenant_id: &str,
    event_ids: &[EventId],
) {
    use crate::db::store::{insert_event, parse_share_scope};

    let now_ms = current_timestamp_ms() as i64;
    for eid in event_ids {
        let eid_b64 = event_id_to_base64(eid);
        let (event_type, blob, share_scope, created_at, inserted_at): (
            String,
            Vec<u8>,
            String,
            i64,
            i64,
        ) = src_db
            .query_row(
                "SELECT event_type, blob, share_scope, created_at, inserted_at
                 FROM events
                 WHERE event_id = ?1",
                rusqlite::params![&eid_b64],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                },
            )
            .unwrap_or_else(|err| panic!("failed to load event {eid_b64} from source db: {err}"));
        let share_scope = parse_share_scope(&share_scope)
            .unwrap_or_else(|| panic!("unknown share scope `{share_scope}` for event {eid_b64}"));
        insert_event(
            dst_db,
            eid,
            &event_type,
            &blob,
            share_scope,
            created_at,
            inserted_at,
        )
        .expect("failed to copy event into destination db");
        insert_recorded_event(dst_db, tenant_id, eid, now_ms, "test-bootstrap")
            .expect("failed to record copied event for tenant");
        project_one(dst_db, tenant_id, eid).unwrap_or_else(|err| {
            panic!(
                "failed to project copied event {} for tenant {}: {}",
                eid_b64, tenant_id, err
            )
        });
    }
}

pub(super) fn list_shared_event_ids_for_tenant(
    db: &rusqlite::Connection,
    tenant_id: &str,
) -> Vec<EventId> {
    db.prepare(
        "SELECT re.event_id
         FROM recorded_events re
         JOIN events e ON e.event_id = re.event_id
         WHERE re.peer_id = ?1
           AND e.share_scope = 'shared'
         ORDER BY e.created_at ASC, re.event_id ASC",
    )
    .and_then(|mut stmt| {
        stmt.query_map(rusqlite::params![tenant_id], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()
    })
    .expect("failed to list shared events")
    .into_iter()
    .filter_map(|b64| event_id_from_base64(&b64))
    .collect()
}

// ---------------------------------------------------------------------------
// WHITE-BOX: multi-tenant shared-DB projection tests
// ---------------------------------------------------------------------------

/// A multi-tenant node: multiple peers sharing a single database.
///
/// Each tenant has its own transport identity but they all use the same DB file.
/// This mirrors the production `run_node` setup where tenant discovery comes from
/// the join of `invites_accepted` and `local_transport_creds`.
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
        let creator_admin_eid: EventId = db
            .query_row(
                "SELECT event_id
                 FROM admins
                 WHERE recorded_by = ?1
                 ORDER BY event_id ASC
                 LIMIT 1",
                rusqlite::params![&creator_identity],
                |row| row.get::<_, String>(0),
            )
            .ok()
            .and_then(|b64| event_id_from_base64(&b64))
            .expect("creator has no admin event");
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
            &creator_peer_key,
            &creator_peer_eid,
            &creator_admin_eid,
            &workspace_id,
        )
        .expect("failed to create user invite");

        // Mirror creator identity prerequisites needed to validate peer-signed invites
        // under the new tenant scope (workspace + signer/admin lineage + invite).
        let creator_peer_b64 = event_id_to_base64(&creator_peer_eid);
        let creator_peer_blob: Vec<u8> = db
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
        let creator_user_blob: Vec<u8> = db
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

        // Record prerequisites for this new tenant and project (white-box shared-DB prerequisite).
        record_shared_db_events_for_tenant(
            &db,
            &tenant_identity,
            &[
                workspace_id,
                creator_user_invite_eid,
                creator.author_id,
                creator_device_invite_eid,
                creator_peer_eid,
                creator_admin_eid,
                invite.invite_event_id,
            ],
        );

        crate::db::transport_trust::append_bootstrap_context(
            &db,
            &tenant_identity,
            &event_id_to_base64(&invite.invite_event_id),
            &event_id_to_base64(&workspace_id),
            "",
            &[0xAB; 32],
        )
        .expect("failed to record invite-link workspace binding");

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
            let overlap_details: Vec<(String, String, Vec<String>)> = overlap
                .iter()
                .map(|event_id| {
                    let event_type: String = db
                        .query_row(
                            "SELECT event_type FROM events WHERE event_id = ?1",
                            rusqlite::params![event_id.as_str()],
                            |row| row.get(0),
                        )
                        .unwrap_or_else(|_| "<missing>".to_string());
                    let mut stmt = db
                        .prepare(
                            "SELECT peer_id || ':' || source
                             FROM recorded_events
                             WHERE event_id = ?1
                             ORDER BY peer_id, source",
                        )
                        .expect("prepare overlap source query");
                    let sources = stmt
                        .query_map(rusqlite::params![event_id.as_str()], |row| row.get(0))
                        .expect("query overlap sources")
                        .collect::<Result<Vec<String>, _>>()
                        .expect("collect overlap sources");
                    ((*event_id).clone(), event_type, sources)
                })
                .collect();
            assert!(
                overlap.is_empty(),
                "Cross-workspace leakage in recorded_events between {} ({}) and {} ({}): {:?}",
                &id_a[..16],
                &ws_a[..16.min(ws_a.len())],
                &id_b[..16],
                &ws_b[..16.min(ws_b.len())],
                overlap_details
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
    for table in &[
        "messages",
        "reactions",
        "key_secrets",
        "deleted_messages",
        "deleted_files",
    ] {
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

/// Copy all events and shared_event_index from a source peer's database to target peers.
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

    // Read all shared_event_index (including workspace_id)
    let mut shared_event_index_stmt = src_db
        .prepare("SELECT workspace_id, ts, id FROM shared_event_index")
        .expect("failed to prepare shared_event_index query");
    let shared_event_index: Vec<(String, i64, Vec<u8>)> = shared_event_index_stmt
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, Vec<u8>>(2)?,
            ))
        })
        .expect("failed to query shared_event_index")
        .collect::<Result<Vec<_>, _>>()
        .expect("failed to collect shared_event_index");

    for target in targets {
        let tgt_db = open_connection(&target.db_path).expect("failed to open target db");
        // Use target's workspace_id so shared_event_index entries match the target's
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

        for (_workspace_id, ts, id) in &shared_event_index {
            tgt_db
                .execute(
                    "INSERT OR IGNORE INTO shared_event_index (workspace_id, ts, id) VALUES (?1, ?2, ?3)",
                    rusqlite::params![&tgt_ws_id, ts, id.as_slice()],
                )
                .expect("failed to insert shared_event_index entry");
        }

        tgt_db.execute("COMMIT", []).expect("failed to commit");
    }
}
