use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::crypto::{hash_event, event_id_to_base64, EventId};
use crate::db::{open_connection, schema::create_tables};
use crate::events::{self, MessageEvent, ReactionEvent, ParsedEvent, registry};
use crate::identity::{cert_paths_from_db, local_identity_from_db};
use crate::sync::engine::{accept_loop, connect_loop};
use crate::transport::{
    AllowedPeers,
    create_client_endpoint,
    create_server_endpoint,
    extract_spki_fingerprint,
    load_or_generate_cert,
};

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
    _tempdir: tempfile::TempDir,
}

impl Peer {
    /// Create a new peer with a fresh temp database.
    pub fn new(name: &str, channel_id: [u8; 32]) -> Self {
        let tempdir = tempfile::tempdir().expect("failed to create tempdir");
        let db_path = tempdir.path().join(format!("{}.db", name))
            .to_str().unwrap().to_string();

        let db = open_connection(&db_path).expect("failed to open db");
        create_tables(&db).expect("failed to create tables");

        let identity = local_identity_from_db(&db_path).expect("failed to compute identity");
        let author_id: [u8; 32] = rand::random();

        Self {
            name: name.to_string(),
            db_path,
            identity,
            author_id,
            channel_id,
            _tempdir: tempdir,
        }
    }

    /// Create a message and insert it into all relevant tables.
    /// Returns the event ID.
    pub fn create_message(&self, content: &str) -> EventId {
        let created_at_ms = current_timestamp_ms();
        let msg_event = MessageEvent {
            created_at_ms,
            channel_id: self.channel_id,
            author_id: self.author_id,
            content: content.to_string(),
        };
        let blob = events::encode_event(&ParsedEvent::Message(msg_event))
            .expect("failed to encode message");
        let event_id = hash_event(&blob);

        let db = open_connection(&self.db_path).expect("failed to open db");

        // Insert into neg_items
        db.execute(
            "INSERT OR IGNORE INTO neg_items (ts, id) VALUES (?1, ?2)",
            rusqlite::params![created_at_ms as i64, event_id.as_slice()],
        ).expect("failed to insert neg_items");

        // Insert into messages projection
        let event_id_b64 = event_id_to_base64(&event_id);
        let channel_id_b64 = event_id_to_base64(&self.channel_id);
        let author_id_b64 = event_id_to_base64(&self.author_id);
        db.execute(
            "INSERT OR IGNORE INTO messages (message_id, channel_id, author_id, content, created_at, recorded_by)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params![event_id_b64, channel_id_b64, author_id_b64, content, created_at_ms as i64, &self.identity],
        ).expect("failed to insert message");

        // Insert into events table
        db.execute(
            "INSERT OR IGNORE INTO events (event_id, event_type, blob, share_scope, created_at, inserted_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params![event_id_b64, "message", blob.as_slice(), "shared", created_at_ms as i64, current_timestamp_ms() as i64],
        ).expect("failed to insert into events");

        // Insert into recorded_events (use local wall clock, not event created_at)
        let recorded_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64;
        db.execute(
            "INSERT OR IGNORE INTO recorded_events (peer_id, event_id, recorded_at, source)
             VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![&self.identity, &event_id_b64, recorded_at, "local_create"],
        ).expect("failed to insert recorded_event");

        event_id
    }

    /// Create a reaction targeting a message event.
    /// Returns the reaction event ID.
    pub fn create_reaction(&self, target_event_id: &EventId, emoji: &str) -> EventId {
        let created_at_ms = current_timestamp_ms();
        let rxn_event = ReactionEvent {
            created_at_ms,
            target_event_id: *target_event_id,
            author_id: self.author_id,
            emoji: emoji.to_string(),
        };
        let blob = events::encode_event(&ParsedEvent::Reaction(rxn_event))
            .expect("failed to encode reaction");
        let event_id = hash_event(&blob);

        let db = open_connection(&self.db_path).expect("failed to open db");

        db.execute(
            "INSERT OR IGNORE INTO neg_items (ts, id) VALUES (?1, ?2)",
            rusqlite::params![created_at_ms as i64, event_id.as_slice()],
        ).expect("failed to insert neg_items");

        let event_id_b64 = event_id_to_base64(&event_id);
        let target_id_b64 = event_id_to_base64(target_event_id);
        let author_id_b64 = event_id_to_base64(&self.author_id);
        db.execute(
            "INSERT OR IGNORE INTO reactions (event_id, target_event_id, author_id, emoji, created_at, recorded_by)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params![event_id_b64, target_id_b64, author_id_b64, emoji, created_at_ms as i64, &self.identity],
        ).expect("failed to insert reaction");

        db.execute(
            "INSERT OR IGNORE INTO events (event_id, event_type, blob, share_scope, created_at, inserted_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params![event_id_b64, "reaction", blob.as_slice(), "shared", created_at_ms as i64, current_timestamp_ms() as i64],
        ).expect("failed to insert into events");

        let recorded_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64;
        db.execute(
            "INSERT OR IGNORE INTO recorded_events (peer_id, event_id, recorded_at, source)
             VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![&self.identity, &event_id_b64, recorded_at, "local_create"],
        ).expect("failed to insert recorded_event");

        event_id
    }

    /// Create multiple messages. Uses a transaction for speed at scale.
    pub fn batch_create_messages(&self, count: usize) {
        let db = open_connection(&self.db_path).expect("failed to open db");

        let mut neg_stmt = db.prepare(
            "INSERT OR IGNORE INTO neg_items (ts, id) VALUES (?1, ?2)"
        ).expect("failed to prepare neg_items stmt");
        let mut msg_stmt = db.prepare(
            "INSERT OR IGNORE INTO messages (message_id, channel_id, author_id, content, created_at, recorded_by)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)"
        ).expect("failed to prepare messages stmt");
        let mut rec_stmt = db.prepare(
            "INSERT OR IGNORE INTO recorded_events (peer_id, event_id, recorded_at, source)
             VALUES (?1, ?2, ?3, ?4)"
        ).expect("failed to prepare recorded_events stmt");
        let mut events_stmt = db.prepare(
            "INSERT OR IGNORE INTO events (event_id, event_type, blob, share_scope, created_at, inserted_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)"
        ).expect("failed to prepare events stmt");

        db.execute("BEGIN", []).expect("failed to begin");
        for i in 0..count {
            let content = format!("Message {} from {}", i, self.name);
            let created_at_ms = current_timestamp_ms();
            let msg_event = MessageEvent {
                created_at_ms,
                channel_id: self.channel_id,
                author_id: self.author_id,
                content: content.clone(),
            };
            let blob = events::encode_event(&ParsedEvent::Message(msg_event))
                .expect("failed to encode message");
            let event_id = hash_event(&blob);

            neg_stmt.execute(rusqlite::params![
                created_at_ms as i64,
                event_id.as_slice()
            ]).expect("neg_items insert");

            let event_id_b64 = event_id_to_base64(&event_id);
            let channel_id_b64 = event_id_to_base64(&self.channel_id);
            let author_id_b64 = event_id_to_base64(&self.author_id);
            msg_stmt.execute(rusqlite::params![
                event_id_b64, channel_id_b64, author_id_b64, content, created_at_ms as i64, &self.identity
            ]).expect("messages insert");

            events_stmt.execute(rusqlite::params![
                event_id_b64, "message", blob.as_slice(), "shared", created_at_ms as i64, current_timestamp_ms() as i64
            ]).expect("events insert");

            let recorded_at = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis() as i64;
            rec_stmt.execute(rusqlite::params![
                &self.identity, &event_id_b64, recorded_at, "local_create"
            ]).expect("recorded_events insert");
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
}

/// Replay all event blobs from the events table through registry-based projection.
/// Clears projection tables, then re-projects all events.
/// Returns (message_count, reaction_count) after replay.
fn replay_projection(db: &rusqlite::Connection, recorded_by: &str) -> (i64, i64) {
    // Clear projection tables for this tenant
    db.execute("DELETE FROM messages WHERE recorded_by = ?1", rusqlite::params![recorded_by])
        .expect("failed to clear messages");
    db.execute("DELETE FROM reactions WHERE recorded_by = ?1", rusqlite::params![recorded_by])
        .expect("failed to clear reactions");

    // Read all blobs from events table
    let mut stmt = db.prepare("SELECT event_id, blob FROM events ORDER BY created_at ASC, event_id ASC")
        .expect("failed to prepare events query");
    let rows: Vec<(String, Vec<u8>)> = stmt.query_map([], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?))
    }).expect("failed to query events")
        .collect::<Result<Vec<_>, _>>()
        .expect("failed to collect events");

    let reg = registry();

    for (event_id_b64, blob) in &rows {
        if let Some(type_code) = events::extract_event_type(blob) {
            if let Some(meta) = reg.lookup(type_code) {
                if let Ok(parsed) = (meta.parse)(blob) {
                    match &parsed {
                        ParsedEvent::Message(msg) => {
                            let channel_id_b64 = event_id_to_base64(&msg.channel_id);
                            let author_id_b64 = event_id_to_base64(&msg.author_id);
                            db.execute(
                                "INSERT OR IGNORE INTO messages (message_id, channel_id, author_id, content, created_at, recorded_by) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                                rusqlite::params![event_id_b64, channel_id_b64, author_id_b64, &msg.content, msg.created_at_ms as i64, recorded_by],
                            ).expect("failed to project message");
                        }
                        ParsedEvent::Reaction(rxn) => {
                            let target_id_b64 = event_id_to_base64(&rxn.target_event_id);
                            let author_id_b64 = event_id_to_base64(&rxn.author_id);
                            db.execute(
                                "INSERT OR IGNORE INTO reactions (event_id, target_event_id, author_id, emoji, created_at, recorded_by) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                                rusqlite::params![event_id_b64, target_id_b64, author_id_b64, &rxn.emoji, rxn.created_at_ms as i64, recorded_by],
                            ).expect("failed to project reaction");
                        }
                    }
                }
            }
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

    (msg_count, rxn_count)
}

/// Replay events in reverse order through the projector.
fn replay_projection_reverse(db: &rusqlite::Connection, recorded_by: &str) -> (i64, i64) {
    db.execute("DELETE FROM messages WHERE recorded_by = ?1", rusqlite::params![recorded_by])
        .expect("failed to clear messages");
    db.execute("DELETE FROM reactions WHERE recorded_by = ?1", rusqlite::params![recorded_by])
        .expect("failed to clear reactions");

    let mut stmt = db.prepare("SELECT event_id, blob FROM events ORDER BY created_at DESC, event_id DESC")
        .expect("failed to prepare events query");
    let rows: Vec<(String, Vec<u8>)> = stmt.query_map([], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?))
    }).expect("failed to query events")
        .collect::<Result<Vec<_>, _>>()
        .expect("failed to collect events");

    let reg = registry();

    for (event_id_b64, blob) in &rows {
        if let Some(type_code) = events::extract_event_type(blob) {
            if let Some(meta) = reg.lookup(type_code) {
                if let Ok(parsed) = (meta.parse)(blob) {
                    match &parsed {
                        ParsedEvent::Message(msg) => {
                            let channel_id_b64 = event_id_to_base64(&msg.channel_id);
                            let author_id_b64 = event_id_to_base64(&msg.author_id);
                            db.execute(
                                "INSERT OR IGNORE INTO messages (message_id, channel_id, author_id, content, created_at, recorded_by) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                                rusqlite::params![event_id_b64, channel_id_b64, author_id_b64, &msg.content, msg.created_at_ms as i64, recorded_by],
                            ).expect("failed to project message");
                        }
                        ParsedEvent::Reaction(rxn) => {
                            let target_id_b64 = event_id_to_base64(&rxn.target_event_id);
                            let author_id_b64 = event_id_to_base64(&rxn.author_id);
                            db.execute(
                                "INSERT OR IGNORE INTO reactions (event_id, target_event_id, author_id, emoji, created_at, recorded_by) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                                rusqlite::params![event_id_b64, target_id_b64, author_id_b64, &rxn.emoji, rxn.created_at_ms as i64, recorded_by],
                            ).expect("failed to project reaction");
                        }
                    }
                }
            }
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

    (msg_count, rxn_count)
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

    // 1. Forward replay
    let (fwd_msg, fwd_rxn) = replay_projection(&db, &peer.identity);
    assert_eq!(fwd_msg, orig_msg,
        "Forward replay message count mismatch: expected {}, got {}", orig_msg, fwd_msg);
    assert_eq!(fwd_rxn, orig_rxn,
        "Forward replay reaction count mismatch: expected {}, got {}", orig_rxn, fwd_rxn);

    // 2. Idempotency: replay again over existing projected state (double replay)
    let (double_msg, double_rxn) = replay_projection(&db, &peer.identity);
    assert_eq!(double_msg, orig_msg,
        "Double replay message count mismatch: expected {}, got {}", orig_msg, double_msg);
    assert_eq!(double_rxn, orig_rxn,
        "Double replay reaction count mismatch: expected {}, got {}", orig_rxn, double_rxn);

    // 3. Reverse-order replay
    let (rev_msg, rev_rxn) = replay_projection_reverse(&db, &peer.identity);
    assert_eq!(rev_msg, orig_msg,
        "Reverse replay message count mismatch: expected {}, got {}", orig_msg, rev_msg);
    assert_eq!(rev_rxn, orig_rxn,
        "Reverse replay reaction count mismatch: expected {}, got {}", orig_rxn, rev_rxn);

    // Restore forward projection for subsequent assertions
    let _ = replay_projection(&db, &peer.identity);
}

/// Start continuous sync between two peers with mutual mTLS pinning.
pub fn start_peers(
    peer_a: &Peer,
    peer_b: &Peer,
) -> (std::thread::JoinHandle<()>, std::thread::JoinHandle<()>) {
    let (cert_path_a, key_path_a) = cert_paths_from_db(&peer_a.db_path);
    let (cert_a, key_a) = load_or_generate_cert(&cert_path_a, &key_path_a)
        .expect("failed to load cert for peer A");
    let (cert_path_b, key_path_b) = cert_paths_from_db(&peer_b.db_path);
    let (cert_b, key_b) = load_or_generate_cert(&cert_path_b, &key_path_b)
        .expect("failed to load cert for peer B");

    let fp_a = extract_spki_fingerprint(cert_a.as_ref()).expect("failed to extract fp for A");
    let fp_b = extract_spki_fingerprint(cert_b.as_ref()).expect("failed to extract fp for B");

    let allowed_for_a = Arc::new(AllowedPeers::from_fingerprints(vec![fp_b]));
    let allowed_for_b = Arc::new(AllowedPeers::from_fingerprints(vec![fp_a]));

    let listener_endpoint = create_server_endpoint(
        "127.0.0.1:0".parse().unwrap(),
        cert_a,
        key_a,
        allowed_for_a,
    ).expect("failed to create server endpoint");

    let listener_addr = listener_endpoint.local_addr().expect("failed to get listener addr");

    let connector_endpoint = create_client_endpoint(
        "0.0.0.0:0".parse().unwrap(),
        cert_b,
        key_b,
        allowed_for_b,
    ).expect("failed to create client endpoint");

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
        || peer_a.store_count() == expected_count && peer_b.store_count() == expected_count,
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
