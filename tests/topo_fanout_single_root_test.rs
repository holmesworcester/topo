//! Topo fan-out unblock performance benchmarks.
//!
//! Scenario:
//! - Create one root event `R` (no deps).
//! - Create `N` fan-out events, each depending only on `R`.
//! - Replay all fan-out events first (all block on missing `R`).
//! - Replay `R` last, triggering a large simultaneous unblock.
//!
//! Run default (N=10000):
//!   cargo test --release --test topo_fanout_single_root_test -- --nocapture
//! Run all sizes:
//!   cargo test --release --test topo_fanout_single_root_test -- --nocapture --include-ignored

use std::time::Instant;

use poc_7::crypto::{event_id_to_base64, hash_event, EventId};
use poc_7::db::{open_connection, schema::create_tables};
use poc_7::events::{self, BenchDepEvent, ParsedEvent};
use poc_7::projection::pipeline::project_one;
use rusqlite::Connection;
use tempfile::NamedTempFile;

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

fn fanout_payload(i: usize) -> [u8; 16] {
    let mut payload = [0u8; 16];
    payload[..8].copy_from_slice(&(i as u64).to_le_bytes());
    payload
}

fn run_topo_fanout_single_root(n: usize) {
    let (conn, _tmp) = setup();
    let recorded_by = "peer1";

    let setup_start = Instant::now();

    // Root event R (no deps). Replayed last.
    let root_event = ParsedEvent::BenchDep(BenchDepEvent {
        created_at_ms: now_ms(),
        dep_ids: vec![],
        payload: [0xAA; 16],
    });
    let root_blob = events::encode_event(&root_event).unwrap();
    let root_id = insert_event_raw(&conn, recorded_by, &root_blob);

    // N fan-out events, each depending only on R.
    let mut fanout_ids: Vec<EventId> = Vec::with_capacity(n);
    conn.execute_batch("BEGIN").unwrap();
    for i in 0..n {
        let event = ParsedEvent::BenchDep(BenchDepEvent {
            created_at_ms: now_ms(),
            dep_ids: vec![root_id],
            payload: fanout_payload(i),
        });
        let blob = events::encode_event(&event).unwrap();
        let eid = insert_event_raw(&conn, recorded_by, &blob);
        fanout_ids.push(eid);
    }
    conn.execute_batch("COMMIT").unwrap();

    let setup_secs = setup_start.elapsed().as_secs_f64();

    // Replay fan-out first: all should block.
    let blocking_start = Instant::now();
    for (i, eid) in fanout_ids.iter().enumerate() {
        let result = project_one(&conn, recorded_by, eid).unwrap();
        assert!(
            matches!(
                result,
                poc_7::projection::decision::ProjectionDecision::Block { .. }
            ),
            "fanout event {} should block, got {:?}",
            i,
            result
        );
    }
    let blocking_secs = blocking_start.elapsed().as_secs_f64();

    // Replay root last: should unblock all fan-out events.
    let cascade_start = Instant::now();
    let root_result = project_one(&conn, recorded_by, &root_id).unwrap();
    assert!(
        matches!(
            root_result,
            poc_7::projection::decision::ProjectionDecision::Valid
        ),
        "root event should be valid, got {:?}",
        root_result
    );
    let cascade_secs = cascade_start.elapsed().as_secs_f64();

    let total_secs = setup_start.elapsed().as_secs_f64();
    let rss = peak_rss_mib();

    let expected_valid = (n + 1) as i64;
    let valid_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM valid_events WHERE peer_id = ?1",
            rusqlite::params![recorded_by],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        valid_count, expected_valid,
        "expected {} valid events, got {}",
        expected_valid, valid_count
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

    let cascade_rate = n as f64 / cascade_secs.max(0.001);

    eprintln!();
    eprintln!("=== Topo fan-out single root (N={}) ===", n);
    eprintln!("  Setup:         {:.3}s  ({} fanout + 1 root)", setup_secs, n);
    eprintln!("  Blocking:      {:.3}s  ({} events blocked)", blocking_secs, n);
    eprintln!("  Cascade:       {:.3}s  ({} events unblocked)", cascade_secs, n);
    eprintln!("  Cascade rate:  {:.0} events/s", cascade_rate);
    eprintln!("  Total:         {:.3}s", total_secs);
    eprintln!("  Peak RSS:      {:.1} MiB", rss);
    eprintln!();
}

#[test]
fn topo_fanout_single_root_10k() {
    run_topo_fanout_single_root(10_000);
}

#[test]
#[ignore]
fn topo_fanout_single_root_100k() {
    run_topo_fanout_single_root(100_000);
}

#[test]
#[ignore]
fn topo_fanout_single_root_200k() {
    run_topo_fanout_single_root(200_000);
}

#[test]
#[ignore]
fn topo_fanout_single_root_500k() {
    run_topo_fanout_single_root(500_000);
}
