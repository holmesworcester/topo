//! Assert system: predicate parsing, field querying, and polling assertions.

use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::crypto::event_id_to_base64;
use crate::db::{open_connection, schema::create_tables};
use crate::event_modules::{message, reaction};
use crate::transport::identity::load_transport_peer_id;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy)]
pub enum Op {
    Eq,
    Ne,
    Ge,
    Le,
    Gt,
    Lt,
}

impl Op {
    pub fn eval(self, actual: i64, expected: i64) -> bool {
        match self {
            Op::Eq => actual == expected,
            Op::Ne => actual != expected,
            Op::Ge => actual >= expected,
            Op::Le => actual <= expected,
            Op::Gt => actual > expected,
            Op::Lt => actual < expected,
        }
    }

    pub fn symbol(self) -> &'static str {
        match self {
            Op::Eq => "==",
            Op::Ne => "!=",
            Op::Ge => ">=",
            Op::Le => "<=",
            Op::Gt => ">",
            Op::Lt => "<",
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AssertResponse {
    pub pass: bool,
    pub field: String,
    pub actual: i64,
    pub op: String,
    pub expected: i64,
    pub timed_out: bool,
}

// ---------------------------------------------------------------------------
// Predicate parsing
// ---------------------------------------------------------------------------

pub fn parse_predicate(s: &str) -> Result<(String, Op, i64), String> {
    let parts: Vec<&str> = s.split_whitespace().collect();
    if parts.len() != 3 {
        return Err(format!(
            "predicate must be \"field op value\", got {} parts: {:?}",
            parts.len(),
            s
        ));
    }
    let field = parts[0].to_string();
    let op = match parts[1] {
        "==" => Op::Eq,
        "!=" => Op::Ne,
        ">=" => Op::Ge,
        "<=" => Op::Le,
        ">" => Op::Gt,
        "<" => Op::Lt,
        other => return Err(format!("unknown operator: {}", other)),
    };
    let value: i64 = parts[2]
        .parse()
        .map_err(|e| format!("invalid value '{}': {}", parts[2], e))?;
    Ok((field, op, value))
}

// ---------------------------------------------------------------------------
// Field querying
// ---------------------------------------------------------------------------

pub fn query_field(
    db: &rusqlite::Connection,
    field: &str,
    recorded_by: &str,
) -> Result<i64, String> {
    match field {
        "store_count" | "events_count" => db
            .query_row("SELECT COUNT(*) FROM events", [], |row| row.get(0))
            .map_err(|e| format!("query failed: {}", e)),
        "message_count" => {
            message::count(db, recorded_by).map_err(|e| format!("query failed: {}", e))
        }
        "reaction_count" => {
            reaction::count(db, recorded_by).map_err(|e| format!("query failed: {}", e))
        }
        "neg_items_count" => db
            .query_row("SELECT COUNT(*) FROM neg_items", [], |row| row.get(0))
            .map_err(|e| format!("query failed: {}", e)),
        "recorded_events_count" => db
            .query_row(
                "SELECT COUNT(*) FROM recorded_events WHERE peer_id = ?1",
                rusqlite::params![recorded_by],
                |row| row.get(0),
            )
            .map_err(|e| format!("query failed: {}", e)),
        other if other.starts_with("has_event:") => {
            let event_id = &other["has_event:".len()..];
            let direct_count: i64 = db
                .query_row(
                    "SELECT COUNT(*) FROM recorded_events WHERE peer_id = ?1 AND event_id = ?2",
                    rusqlite::params![recorded_by, event_id],
                    |row| row.get(0),
                )
                .map_err(|e| format!("query failed: {}", e))?;
            if direct_count > 0 {
                return Ok(direct_count);
            }
            if let Ok(event_id_bytes) = hex::decode(event_id) {
                if event_id_bytes.len() == 32 {
                    let mut eid = [0u8; 32];
                    eid.copy_from_slice(&event_id_bytes);
                    return db
                        .query_row(
                            "SELECT COUNT(*) FROM recorded_events WHERE peer_id = ?1 AND event_id = ?2",
                            rusqlite::params![recorded_by, event_id_to_base64(&eid)],
                            |row| row.get(0),
                        )
                        .map_err(|e| format!("query failed: {}", e));
                }
            }
            Ok(0)
        }
        other => Err(format!("unknown field: {}", other)),
    }
}

fn resolve_assert_recorded_by(
    db: &rusqlite::Connection,
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    // Prefer tenant scope resolution from invites_accepted. This stays stable
    // when local_transport_creds contains multiple identities.
    let scoped_peers: Vec<String> = {
        let mut stmt =
            db.prepare("SELECT DISTINCT recorded_by FROM invites_accepted ORDER BY recorded_by")?;
        let peers = stmt
            .query_map([], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        peers
    };
    if scoped_peers.len() == 1 {
        return Ok(scoped_peers[0].clone());
    }
    if scoped_peers.len() > 1 {
        return Err("no active tenant — run `topo use-tenant <N>`".into());
    }

    // Pre-workspace fallback: singleton transport identity.
    let transport_peer_id = load_transport_peer_id(db)?;
    Ok(transport_peer_id)
}

// ---------------------------------------------------------------------------
// Polling assertion
// ---------------------------------------------------------------------------

/// Poll a predicate until it passes or times out.
/// Re-resolves tenant scope each iteration.
pub fn assert_eventually(
    db_path: &str,
    predicate_str: &str,
    timeout_ms: u64,
    interval_ms: u64,
) -> Result<AssertResponse, Box<dyn std::error::Error + Send + Sync>> {
    let db = open_connection(db_path)?;
    create_tables(&db)?;
    let (field, op, expected) = parse_predicate(predicate_str)?;
    let start = Instant::now();
    let timeout = Duration::from_millis(timeout_ms);
    let interval = Duration::from_millis(interval_ms);

    loop {
        let recorded_by = resolve_assert_recorded_by(&db)?;
        let actual = query_field(&db, &field, &recorded_by)?;
        if op.eval(actual, expected) {
            return Ok(AssertResponse {
                pass: true,
                field,
                actual,
                op: op.symbol().to_string(),
                expected,
                timed_out: false,
            });
        }
        if start.elapsed() >= timeout {
            return Ok(AssertResponse {
                pass: false,
                field,
                actual,
                op: op.symbol().to_string(),
                expected,
                timed_out: true,
            });
        }
        std::thread::sleep(interval);
    }
}
