//! Topo-sort cascade performance benchmarks.
//!
//! Measures how the blocking/unblocking cascade in the projection pipeline
//! performs under worst-case conditions: each event has 10 dependencies on
//! previous events, injected in reverse order to maximize cascade depth.
//!
//! Run default (N=10000): cargo test --release --test topo_cascade_test -- --nocapture
//! Run all sizes:         cargo test --release --test topo_cascade_test -- --nocapture --include-ignored

use std::time::Instant;

use rusqlite::Connection;
use tempfile::NamedTempFile;
use topo::crypto::{event_id_to_base64, hash_event, EventId};
use topo::db::{open_connection, schema::create_tables};
use topo::event_modules::{self as events, BenchDepEvent, ParsedEvent};
use topo::projection::apply::project_one;

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

fn setup() -> (Connection, NamedTempFile) {
    let tmp = NamedTempFile::new().unwrap();
    let conn = open_connection(tmp.path()).unwrap();
    create_tables(&conn).unwrap();
    (conn, tmp)
}

fn insert_event_raw(conn: &Connection, recorded_by: &str, blob: &[u8]) -> EventId {
    let event_id = hash_event(blob);
    let event_id_b64 = event_id_to_base64(&event_id);
    let ts = now_ms();
    let type_code = blob[0];
    let type_name = events::registry()
        .lookup(type_code)
        .map(|m| m.type_name)
        .unwrap_or("unknown");

    conn.execute(
        "INSERT OR IGNORE INTO events (event_id, event_type, blob, share_scope, created_at, inserted_at)
         VALUES (?1, ?2, ?3, 'shared', ?4, ?5)",
        rusqlite::params![&event_id_b64, type_name, blob, ts as i64, ts as i64],
    )
    .unwrap();
    conn.execute(
        "INSERT OR IGNORE INTO neg_items (ts, id) VALUES (?1, ?2)",
        rusqlite::params![ts as i64, event_id.as_slice()],
    )
    .unwrap();
    conn.execute(
        "INSERT OR IGNORE INTO recorded_events (peer_id, event_id, recorded_at, source)
         VALUES (?1, ?2, ?3, 'test')",
        rusqlite::params![recorded_by, &event_id_b64, ts as i64],
    )
    .unwrap();

    event_id
}

fn peak_rss_mib() -> f64 {
    let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    for line in status.lines() {
        if line.starts_with("VmHWM:") {
            let kb: f64 = line
                .split_whitespace()
                .nth(1)
                .and_then(|s| s.parse().ok())
                .unwrap_or(0.0);
            return kb / 1024.0;
        }
    }
    0.0
}

fn run_topo_cascade(n: usize) {
    let deps_per_event = 10usize;
    let (conn, _tmp) = setup();
    let recorded_by = "peer1";

    // === Setup phase ===
    let setup_start = Instant::now();

    // Pre-compute all event blobs and event IDs.
    // E_0 has no deps.
    // E_1..E_9 have gradually increasing deps (E_i has min(i, 10) deps).
    // E_10..E_{N-1} each has 10 deps = [E_{i-10}, ..., E_{i-1}].
    let mut blobs: Vec<Vec<u8>> = Vec::with_capacity(n);
    let mut event_ids: Vec<EventId> = Vec::with_capacity(n);

    for i in 0..n {
        let num_deps = if i < deps_per_event {
            i
        } else {
            deps_per_event
        };
        let mut dep_ids = Vec::with_capacity(num_deps);
        for j in 0..num_deps {
            dep_ids.push(event_ids[i - num_deps + j]);
        }

        let event = ParsedEvent::BenchDep(BenchDepEvent {
            created_at_ms: now_ms(),
            dep_ids,
            payload: [0xAB; 16],
        });
        let blob = events::encode_event(&event).unwrap();
        let eid = hash_event(&blob);
        blobs.push(blob);
        event_ids.push(eid);
    }

    // Insert all events into the database in a single transaction.
    conn.execute_batch("BEGIN").unwrap();
    for i in 0..n {
        insert_event_raw(&conn, recorded_by, &blobs[i]);
    }
    conn.execute_batch("COMMIT").unwrap();

    let dep_rows_total: usize = (0..n)
        .map(|i| {
            if i < deps_per_event {
                i
            } else {
                deps_per_event
            }
        })
        .sum();
    let setup_secs = setup_start.elapsed().as_secs_f64();

    // === Blocking phase ===
    // Project in reverse order: E_{N-1}, E_{N-2}, ..., E_10
    // Each finds deps missing → blocks, inserts dep rows.
    let blocking_start = Instant::now();
    let blocked_count = n - deps_per_event;
    for i in (deps_per_event..n).rev() {
        let result = project_one(&conn, recorded_by, &event_ids[i]).unwrap();
        assert!(
            matches!(
                result,
                topo::projection::decision::ProjectionDecision::Block { .. }
            ),
            "event {} should block, got {:?}",
            i,
            result
        );
    }
    let blocking_secs = blocking_start.elapsed().as_secs_f64();

    // === Root + cascade phase ===
    // Project E_0..E_9. E_0 has no deps → valid immediately.
    // E_1..E_9 each have deps on already-valid events → valid immediately.
    // When E_9 becomes valid, cascade fires: E_10 has all 10 deps valid → projects → E_11 → ...
    let cascade_start = Instant::now();
    for i in 0..deps_per_event {
        let result = project_one(&conn, recorded_by, &event_ids[i]).unwrap();
        assert!(
            matches!(
                result,
                topo::projection::decision::ProjectionDecision::Valid
            ),
            "root event {} should be valid, got {:?}",
            i,
            result
        );
    }
    let cascade_secs = cascade_start.elapsed().as_secs_f64();

    let total_secs = setup_start.elapsed().as_secs_f64();
    let rss = peak_rss_mib();

    // === Verification ===
    let valid_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM valid_events WHERE peer_id = ?1",
            rusqlite::params![recorded_by],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        valid_count, n as i64,
        "expected {} valid events, got {}",
        n, valid_count
    );

    let blocked_remaining: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM blocked_event_deps WHERE peer_id = ?1",
            rusqlite::params![recorded_by],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        blocked_remaining, 0,
        "expected 0 blocked deps remaining, got {}",
        blocked_remaining
    );

    let blocked_events_remaining: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM blocked_events WHERE peer_id = ?1",
            rusqlite::params![recorded_by],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        blocked_events_remaining, 0,
        "expected 0 blocked_events remaining, got {}",
        blocked_events_remaining
    );

    let cascade_rate = blocked_count as f64 / cascade_secs.max(0.001);

    eprintln!();
    eprintln!(
        "=== Topo cascade (N={}, deps_per_event={}) ===",
        n, deps_per_event
    );
    eprintln!(
        "  Setup:         {:.3}s  ({} events, {} dep rows)",
        setup_secs, n, dep_rows_total
    );
    eprintln!(
        "  Blocking:      {:.3}s  ({} events blocked via project_one)",
        blocking_secs, blocked_count
    );
    eprintln!(
        "  Cascade:       {:.3}s  ({} events resolved)",
        cascade_secs, blocked_count
    );
    eprintln!("  Cascade rate:  {:.0} events/s", cascade_rate);
    eprintln!("  Total:         {:.3}s", total_secs);
    eprintln!("  Peak RSS:      {:.1} MiB", rss);
    eprintln!();
}

#[test]
fn topo_cascade_10k() {
    run_topo_cascade(10_000);
}

#[test]
#[ignore]
fn topo_cascade_50k() {
    run_topo_cascade(50_000);
}

#[test]
#[ignore]
fn topo_cascade_200k() {
    run_topo_cascade(200_000);
}

#[test]
#[ignore]
fn topo_cascade_500k() {
    run_topo_cascade(500_000);
}
