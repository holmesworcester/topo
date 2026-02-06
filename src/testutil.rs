use std::time::{Duration, Instant};

use crate::crypto::{hash_event, event_id_to_base64, EventId};
use crate::db::{open_connection, schema::create_tables, shareable::Shareable, store::Store};
use crate::sync::engine::{accept_loop, connect_loop};
use crate::transport::{
    create_client_endpoint,
    create_server_endpoint,
    generate_keypair,
    generate_self_signed_cert,
};
use crate::wire::Envelope;

/// Timing breakdown returned after sync completes.
#[derive(Debug, Clone)]
pub struct SyncMetrics {
    /// Wall-clock time from start_sync to convergence.
    pub wall_secs: f64,
    /// Total events transferred (sum of both directions).
    pub events_transferred: u64,
    /// Events per second (events_transferred / wall_secs).
    pub events_per_sec: f64,
    /// Total bytes transferred (events * 512 bytes each).
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

        let author_id: [u8; 32] = rand::random();

        Self {
            name: name.to_string(),
            db_path,
            author_id,
            channel_id,
            _tempdir: tempdir,
        }
    }

    /// Create a message and insert it into all relevant tables.
    /// Returns the event ID.
    pub fn create_message(&self, content: &str) -> EventId {
        let envelope = Envelope::new_message(
            self.channel_id,
            self.author_id,
            content.to_string(),
        );

        let blob = envelope.encode();
        let event_id = hash_event(&blob);
        let created_at_ms = envelope.payload.created_at_ms;

        let db = open_connection(&self.db_path).expect("failed to open db");
        let store = Store::new(&db);
        let shareable = Shareable::new(&db);

        store.put(&event_id, &blob).expect("failed to store event");
        shareable.insert(&event_id).expect("failed to insert shareable");

        // Insert into neg_items
        db.execute(
            "INSERT OR IGNORE INTO neg_items (ts, id) VALUES (?1, ?2)",
            rusqlite::params![created_at_ms as i64, event_id.as_slice()],
        ).expect("failed to insert neg_items");

        // Insert into messages projection
        let message_id = event_id_to_base64(&event_id);
        let channel_id_b64 = event_id_to_base64(&self.channel_id);
        let author_id_b64 = event_id_to_base64(&self.author_id);
        db.execute(
            "INSERT OR IGNORE INTO messages (message_id, channel_id, author_id, content, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![message_id, channel_id_b64, author_id_b64, content, created_at_ms as i64],
        ).expect("failed to insert message");

        event_id
    }

    /// Create multiple messages. Uses a transaction for speed at scale.
    pub fn batch_create_messages(&self, count: usize) {
        let db = open_connection(&self.db_path).expect("failed to open db");
        let store = Store::new(&db);
        let shareable = Shareable::new(&db);

        let mut neg_stmt = db.prepare(
            "INSERT OR IGNORE INTO neg_items (ts, id) VALUES (?1, ?2)"
        ).expect("failed to prepare neg_items stmt");
        let mut msg_stmt = db.prepare(
            "INSERT OR IGNORE INTO messages (message_id, channel_id, author_id, content, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5)"
        ).expect("failed to prepare messages stmt");

        db.execute("BEGIN", []).expect("failed to begin");
        for i in 0..count {
            let content = format!("Message {} from {}", i, self.name);
            let envelope = Envelope::new_message(
                self.channel_id,
                self.author_id,
                content.clone(),
            );

            let blob = envelope.encode();
            let event_id = hash_event(&blob);
            let created_at_ms = envelope.payload.created_at_ms;

            store.put(&event_id, &blob).expect("store.put");
            shareable.insert(&event_id).expect("shareable.insert");

            neg_stmt.execute(rusqlite::params![
                created_at_ms as i64,
                event_id.as_slice()
            ]).expect("neg_items insert");

            let message_id = event_id_to_base64(&event_id);
            let channel_id_b64 = event_id_to_base64(&self.channel_id);
            let author_id_b64 = event_id_to_base64(&self.author_id);
            msg_stmt.execute(rusqlite::params![
                message_id, channel_id_b64, author_id_b64, content, created_at_ms as i64
            ]).expect("messages insert");
        }
        db.execute("COMMIT", []).expect("failed to commit");
    }

    /// Count events in the store table.
    pub fn store_count(&self) -> i64 {
        let db = open_connection(&self.db_path).expect("failed to open db");
        db.query_row("SELECT COUNT(*) FROM store", [], |row| row.get(0))
            .unwrap_or(0)
    }

    /// Count rows in the messages projection table.
    pub fn message_count(&self) -> i64 {
        let db = open_connection(&self.db_path).expect("failed to open db");
        db.query_row("SELECT COUNT(*) FROM messages", [], |row| row.get(0))
            .unwrap_or(0)
    }
}

/// Start continuous sync between two peers.
///
/// Spawns two threads — one running accept_loop (peer A listens),
/// one running connect_loop (peer B connects). Each thread has its own
/// single-threaded tokio runtime (rusqlite::Connection is not Send).
///
/// Returns two JoinHandles (accept, connect).
pub fn start_peers(
    peer_a: &Peer,
    peer_b: &Peer,
) -> (std::thread::JoinHandle<()>, std::thread::JoinHandle<()>) {
    let (signing_key, _) = generate_keypair();
    let (cert, key) = generate_self_signed_cert(&signing_key).expect("failed to generate cert");

    let listener_endpoint = create_server_endpoint(
        "127.0.0.1:0".parse().unwrap(),
        cert,
        key,
    ).expect("failed to create server endpoint");

    let listener_addr = listener_endpoint.local_addr().expect("failed to get listener addr");

    let connector_endpoint = create_client_endpoint(
        "0.0.0.0:0".parse().unwrap(),
    ).expect("failed to create client endpoint");

    let a_db = peer_a.db_path.clone();
    let b_db = peer_b.db_path.clone();

    let a_handle = std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async move {
            if let Err(e) = accept_loop(&a_db, listener_endpoint).await {
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
            if let Err(e) = connect_loop(&b_db, connector_endpoint, listener_addr).await {
                tracing::warn!("connect_loop exited: {}", e);
            }
        });
    });

    (a_handle, b_handle)
}

/// Start sync, wait for convergence, return metrics.
///
/// Both peers should already have their events loaded before calling this.
/// `expected_count` is the total events each peer should end up with.
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
    let bytes_transferred = events_transferred * 512;
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
