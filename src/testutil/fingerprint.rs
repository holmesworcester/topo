use super::peer::Peer;
use super::*;

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
        columns: None,
    },
    FingerprintTable {
        name: "reactions",
        scope: Scope::RecordedBy,
        order: "ORDER BY event_id",
        columns: None,
    },
    FingerprintTable {
        name: "key_secrets",
        scope: Scope::RecordedBy,
        order: "ORDER BY event_id",
        columns: None,
    },
    FingerprintTable {
        name: "deleted_messages",
        scope: Scope::RecordedBy,
        order: "ORDER BY message_id",
        columns: None,
    },
    FingerprintTable {
        name: "files",
        scope: Scope::RecordedBy,
        order: "ORDER BY event_id",
        columns: None,
    },
    FingerprintTable {
        name: "file_slices",
        scope: Scope::RecordedBy,
        order: "ORDER BY file_id, slice_number",
        columns: None,
    },
    // Identity projections
    FingerprintTable {
        name: "workspaces",
        scope: Scope::RecordedBy,
        order: "ORDER BY event_id",
        columns: None,
    },
    FingerprintTable {
        name: "invites_accepted",
        scope: Scope::RecordedBy,
        order: "ORDER BY event_id",
        columns: None,
    },
    FingerprintTable {
        name: "user_invites",
        scope: Scope::RecordedBy,
        order: "ORDER BY event_id",
        columns: None,
    },
    FingerprintTable {
        name: "device_invites",
        scope: Scope::RecordedBy,
        order: "ORDER BY event_id",
        columns: None,
    },
    FingerprintTable {
        name: "users",
        scope: Scope::RecordedBy,
        order: "ORDER BY event_id",
        columns: None,
    },
    FingerprintTable {
        name: "peers_shared",
        scope: Scope::RecordedBy,
        order: "ORDER BY event_id",
        columns: None,
    },
    FingerprintTable {
        name: "admins",
        scope: Scope::RecordedBy,
        order: "ORDER BY event_id",
        columns: None,
    },
    FingerprintTable {
        name: "key_shared",
        scope: Scope::RecordedBy,
        order: "ORDER BY event_id",
        columns: None,
    },
    // Transport identity (replay-derived via MaterializeTransportIdentity).
    // `created_at` is a wall-clock timestamp — excluded from fingerprint to
    // ensure replay produces identical hashes regardless of when it runs.
    FingerprintTable {
        name: "local_transport_targets",
        scope: Scope::TenantId,
        order: "ORDER BY tenant_id",
        columns: Some("tenant_id, transport_peer_id, source"),
    },
];

struct FingerprintTable {
    name: &'static str,
    scope: Scope,
    order: &'static str,
    /// Explicit column list for SELECT. `None` means `SELECT *`.
    /// Use when a table has non-deterministic columns (e.g. wall-clock `created_at`)
    /// that should be excluded from the fingerprint.
    columns: Option<&'static str>,
}

#[derive(Clone, Copy)]
enum Scope {
    RecordedBy,
    TenantId,
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
            Scope::TenantId => "WHERE tenant_id = ?1",
        };
        let select = ft.columns.unwrap_or("*");
        let query = format!(
            "SELECT {} FROM {} {} {}",
            select, ft.name, where_clause, ft.order
        );
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
        "DELETE FROM key_secrets WHERE recorded_by = ?1",
        rusqlite::params![recorded_by],
    )
    .expect("failed to clear key_secrets");
    db.execute(
        "DELETE FROM deleted_messages WHERE recorded_by = ?1",
        rusqlite::params![recorded_by],
    )
    .expect("failed to clear deleted_messages");
    db.execute(
        "DELETE FROM files WHERE recorded_by = ?1",
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
        "DELETE FROM key_shared WHERE recorded_by = ?1",
        rusqlite::params![recorded_by],
    )
    .ok();
    db.execute(
        "DELETE FROM invites_accepted WHERE recorded_by = ?1",
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
    // — Transport identity (replay-derived via MaterializeTransportIdentity command)
    db.execute(
        "DELETE FROM local_transport_creds WHERE peer_id IN (SELECT transport_peer_id FROM local_transport_targets WHERE tenant_id = ?1)",
        rusqlite::params![recorded_by],
    )
    .ok();
    db.execute(
        "DELETE FROM local_transport_targets WHERE tenant_id = ?1",
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
    use rand::{rngs::StdRng, seq::SliceRandom, SeedableRng};

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

    let mut rng = StdRng::seed_from_u64(0);
    event_ids.shuffle(&mut rng);

    clear_projection_tables(db, recorded_by);

    let mut last = None;
    for _ in 0..8 {
        for eid_b64 in &event_ids {
            if let Some(eid) = event_id_from_base64(eid_b64) {
                let _ = project_one(db, recorded_by, &eid);
            }
        }
        let fp = compute_projection_fingerprint(db, recorded_by);
        if last.as_ref().is_some_and(|prev: &ProjectionFingerprint| prev.overall == fp.overall) {
            return fp;
        }
        last = Some(fp);
    }

    last.expect("shuffled replay fingerprint missing final state")
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
// Public replay API for CLI `topo replay` command
// ---------------------------------------------------------------------------

/// Result of a single replay pass, suitable for serialization.
#[derive(Debug, serde::Serialize)]
pub struct ReplayResult {
    pub pass: String,
    pub event_count: usize,
    pub fingerprint: String,
}

/// Run a single replay pass on the given DB and return the result.
/// `pass` must be one of: "forward", "idempotent", "reverse", "shuffle".
pub fn run_replay_pass(
    db: &rusqlite::Connection,
    recorded_by: &str,
    pass: &str,
) -> Result<ReplayResult, String> {
    let fp = match pass {
        "forward" => {
            replay_and_fingerprint(db, recorded_by, "ORDER BY created_at ASC, event_id ASC")
        }
        "idempotent" => replay_no_clear_and_fingerprint(db, recorded_by),
        "reverse" => {
            replay_and_fingerprint(db, recorded_by, "ORDER BY created_at DESC, event_id DESC")
        }
        "shuffle" => replay_shuffled_and_fingerprint(db, recorded_by),
        other => return Err(format!("unknown replay pass: '{}' (expected: forward, idempotent, reverse, shuffle)", other)),
    };
    let event_count = fp.tables.iter().map(|t| t.row_count as usize).sum::<usize>();
    // Use total recorded events as the count (more meaningful than sum of table rows)
    let event_count_actual: usize = db
        .query_row(
            "SELECT COUNT(*) FROM recorded_events WHERE peer_id = ?1",
            rusqlite::params![recorded_by],
            |row| row.get::<_, i64>(0),
        )
        .unwrap_or(0) as usize;
    Ok(ReplayResult {
        pass: pass.to_string(),
        event_count: event_count_actual,
        fingerprint: hex(&fp.overall),
    })
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
            "key_secrets",
            "deleted_messages",
            "files",
            "file_slices",
            "workspaces",
            "invites_accepted",
            "user_invites",
            "device_invites",
            "users",
            "peers_shared",
            "admins",
            "key_shared",
            "local_transport_targets",
        ];
        let excluded_tables = [
            "valid_events",
            "rejected_events",
            "blocked_event_deps",
            "blocked_events",
            "project_queue",
            "peer_endpoint_observations",
            "intro_attempts",
            "peer_transport_bindings",
            "invite_bootstrap_trust",
            "pending_invite_bootstrap_trust",
            "local_transport_creds",
            "file_slice_guard_blocks",
            "shared_event_index",
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
