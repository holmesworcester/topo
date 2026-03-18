//! Batch projection pipeline: gather → map → reduce → apply.
//!
//! Processes events from all tenants in one batch, scoping by tenant_id
//! internally. Total DB round-trips: O(tables) not O(events).
//!
//! Stage 1 (Gather): batch-read blobs, terminal state, context tables,
//!                    signer keys, dep presence — ~6 queries total.
//! Stage 2 (Map):    parse, verify signatures, check deps, build context,
//!                    dispatch pure projectors — pure CPU, no DB.
//! Stage 3 (Reduce): partition into valid/blocked/rejected/fallback.
//! Stage 4 (Apply):  one transaction for all WriteOps + valid_events.
//!                    then cascade-unblock + emit commands.

use std::collections::{HashMap, HashSet};

use rusqlite::Connection;

use crate::crypto::{event_id_from_base64, event_id_to_base64, EventId};
use crate::db::queue::current_timestamp_ms;
use crate::db::timeline::EventTimeline;
use crate::event_modules::{self as events, registry, ParsedEvent};
use crate::state::projection::contract::{ContextSnapshot, DeletionIntentInfo, ProjectorResult};
use crate::state::projection::decision::ProjectionDecision;
use crate::state::projection::signer::verify_ed25519_signature;

use super::cascade::cascade_unblocked;
use super::dispatch::dispatch_pure_projector;
use super::project_one::project_one;
use super::stages::record_rejection;
use super::write_exec::{execute_emit_commands, execute_write_ops};

/// Batch-project events for a single tenant.
/// Returns the number that reached a terminal state.
pub fn project_batch(
    conn: &Connection,
    tenant_id: &str,
    event_id_b64s: &[String],
) -> Result<usize, Box<dyn std::error::Error>> {
    if event_id_b64s.is_empty() {
        return Ok(0);
    }

    // ── Stage 1: Gather ──────────────────────────────────────────────

    let terminal = gather_terminal(conn, tenant_id, event_id_b64s)?;
    let pending: Vec<&str> = event_id_b64s
        .iter()
        .filter(|id| !terminal.contains(id.as_str()))
        .map(String::as_str)
        .collect();
    if pending.is_empty() {
        return Ok(terminal.len());
    }

    let blobs = gather_blobs(conn, &pending)?;
    let peers_shared = gather_peers_shared(conn, tenant_id)?;
    let msg_ids: Vec<&str> = pending.iter().copied().collect(); // all pending — filter to messages after parse
    let del_intents = gather_deletion_intents(conn, tenant_id, &msg_ids)?;

    // Parse all blobs (CPU only)
    let mut parsed_events: Vec<ParsedInput> = Vec::with_capacity(pending.len());
    let mut terminal_count = terminal.len();
    for &eid_b64 in &pending {
        let Some(eid) = event_id_from_base64(eid_b64) else { continue };
        let Some(blob) = blobs.get(eid_b64).cloned() else {
            record_rejection(conn, tenant_id, eid_b64, "not found in events table");
            terminal_count += 1;
            continue;
        };
        match events::parse_event(&blob) {
            Ok(parsed) => parsed_events.push(ParsedInput { eid_b64, eid, blob, parsed }),
            Err(e) => {
                record_rejection(conn, tenant_id, eid_b64, &format!("parse: {e}"));
                terminal_count += 1;
            }
        }
    }

    // Gather signer keys and dep validity in batch
    let reg = registry();
    let mut signer_ids: HashSet<String> = HashSet::new();
    let mut dep_ids: HashSet<String> = HashSet::new();
    for ev in &parsed_events {
        if let Some(meta) = reg.lookup(ev.parsed.event_type_code()) {
            if meta.signer_required {
                if let Some((sid, _)) = ev.parsed.signer_fields() {
                    signer_ids.insert(event_id_to_base64(&sid));
                }
            }
        }
        for (_, did) in ev.parsed.dep_field_values() {
            dep_ids.insert(event_id_to_base64(&did));
        }
    }
    let signer_keys = gather_signer_keys(conn, tenant_id, &signer_ids)?;
    let valid_deps = gather_valid_set(conn, tenant_id, &dep_ids)?;

    // ── Stage 2: Map (pure — no DB access) ───────────────────────────

    let mut valids: Vec<MappedValid> = Vec::new();
    let mut fallbacks: Vec<EventId> = Vec::new();

    for ev in &parsed_events {
        match map_event(ev, tenant_id, reg, &signer_keys, &valid_deps, &peers_shared, &del_intents) {
            MapResult::Valid(result) => valids.push(MappedValid { eid_b64: ev.eid_b64, parsed: &ev.parsed, result }),
            MapResult::Blocked(missing) => write_block_rows(conn, tenant_id, ev.eid_b64, &missing),
            MapResult::Rejected(reason) => { record_rejection(conn, tenant_id, ev.eid_b64, &reason); terminal_count += 1; }
            MapResult::Fallback => fallbacks.push(ev.eid),
            MapResult::BlockWithCommands(result) => {
                let _ = execute_emit_commands(conn, tenant_id, &result.emit_commands);
                let _ = EventTimeline::new(conn).mark_blocked_b64(ev.eid_b64, current_timestamp_ms());
            }
        }
    }

    // ── Stage 3: Reduce (partition is already done by map) ───────────
    // valids, fallbacks, and terminal_count are the reduced output.

    // ── Stage 4: Apply (one transaction) ─────────────────────────────

    if !valids.is_empty() {
        conn.execute_batch("SAVEPOINT batch_project")?;
        let r = (|| -> Result<(), Box<dyn std::error::Error>> {
            for v in &valids {
                execute_write_ops(conn, &v.result.write_ops)?;
                execute_emit_commands(conn, tenant_id, &v.result.emit_commands)?;
            }
            let mut stmt = conn.prepare(
                "INSERT OR IGNORE INTO valid_events (peer_id, event_id, semantic_type_code) VALUES (?1, ?2, ?3)",
            )?;
            for v in &valids {
                stmt.execute(rusqlite::params![tenant_id, v.eid_b64, i64::from(v.parsed.event_type_code())])?;
                crate::state::subscriptions::on_projected_event(conn, tenant_id, v.eid_b64, v.parsed)?;
            }
            let now = current_timestamp_ms();
            let tl = EventTimeline::new(conn);
            for v in &valids { let _ = tl.mark_projected_b64(v.eid_b64, now); }
            Ok(())
        })();
        match r {
            Ok(()) => conn.execute_batch("RELEASE batch_project")?,
            Err(e) => {
                let _ = conn.execute_batch("ROLLBACK TO batch_project");
                let _ = conn.execute_batch("RELEASE batch_project");
                return Err(e);
            }
        }
    }

    // Cascade-unblock all newly valid events
    for v in &valids {
        cascade_unblocked(conn, tenant_id, v.eid_b64, Some(v.parsed))?;
    }

    // Fallback: per-event path for encrypted/custom-context types
    for eid in &fallbacks {
        let _ = project_one(conn, tenant_id, eid);
    }

    terminal_count += valids.len() + fallbacks.len();
    Ok(terminal_count)
}

// ── Internal types ──────────────────────────────────────────────────

struct ParsedInput<'a> {
    eid_b64: &'a str,
    eid: EventId,
    blob: Vec<u8>,
    parsed: ParsedEvent,
}

struct MappedValid<'a> {
    eid_b64: &'a str,
    parsed: &'a ParsedEvent,
    result: ProjectorResult,
}

enum MapResult {
    Valid(ProjectorResult),
    Blocked(Vec<EventId>),
    Rejected(String),
    Fallback,
    BlockWithCommands(ProjectorResult),
}

// ── Stage 2: Map (pure function) ────────────────────────────────────

fn map_event(
    ev: &ParsedInput,
    tenant_id: &str,
    reg: &crate::event_modules::registry::EventRegistry,
    signer_keys: &HashMap<String, Result<[u8; 32], String>>,
    valid_deps: &HashSet<String>,
    peers_shared: &HashMap<String, String>,
    del_intents: &HashMap<String, Vec<DeletionIntentInfo>>,
) -> MapResult {
    // Encrypted → fallback
    if matches!(ev.parsed, ParsedEvent::Encrypted(_)) {
        return MapResult::Fallback;
    }

    let Some(meta) = reg.lookup(ev.parsed.event_type_code()) else {
        return MapResult::Rejected(format!("unknown type code {}", ev.parsed.event_type_code()));
    };

    // Custom context loader → fallback
    if !matches!(ev.parsed, ParsedEvent::Message(_)) && !meta.has_empty_context_loader() {
        return MapResult::Fallback;
    }

    // Dep check
    let deps = ev.parsed.dep_field_values();
    let missing: Vec<EventId> = deps.iter()
        .filter(|(_, did)| !valid_deps.contains(&event_id_to_base64(did)))
        .map(|(_, did)| *did)
        .collect();
    if !missing.is_empty() {
        return MapResult::Blocked(missing);
    }

    // Signer verification
    if meta.signer_required {
        if let Some((sid, _)) = ev.parsed.signer_fields() {
            let sb64 = event_id_to_base64(&sid);
            match signer_keys.get(&sb64) {
                None => return MapResult::Rejected("signer not found".into()),
                Some(Err(r)) => return MapResult::Rejected(r.clone()),
                Some(Ok(key)) => {
                    let sig_len = meta.signature_byte_len;
                    if ev.blob.len() < sig_len {
                        return MapResult::Rejected("blob too short for signature".into());
                    }
                    if !verify_ed25519_signature(key, &ev.blob[..ev.blob.len() - sig_len], &ev.blob[ev.blob.len() - sig_len..]) {
                        return MapResult::Rejected("invalid signature".into());
                    }
                }
            }
        }
    }

    // Build context from cache, dispatch pure projector
    let ctx = build_context(ev, peers_shared, del_intents);
    let result = dispatch_pure_projector(tenant_id, ev.eid_b64, &ev.parsed, &ctx);

    match &result.decision {
        ProjectionDecision::Valid => MapResult::Valid(result),
        ProjectionDecision::Reject { reason } => MapResult::Rejected(reason.clone()),
        ProjectionDecision::Block { .. } if !result.emit_commands.is_empty() => MapResult::BlockWithCommands(result),
        ProjectionDecision::Block { .. } => MapResult::Blocked(vec![]),
        ProjectionDecision::AlreadyProcessed => MapResult::Rejected("already processed".into()),
    }
}

fn build_context(
    ev: &ParsedInput,
    peers_shared: &HashMap<String, String>,
    del_intents: &HashMap<String, Vec<DeletionIntentInfo>>,
) -> ContextSnapshot {
    let mut ctx = ContextSnapshot::default();
    if let ParsedEvent::Message(msg) = &ev.parsed {
        let sb = event_id_to_base64(&msg.signed_by);
        let ab = event_id_to_base64(&msg.author_id);
        ctx.signer_user_mismatch_reason = match peers_shared.get(&sb) {
            Some(u) if u.is_empty() => Some(format!("signer {} has no user_event_id", sb)),
            Some(u) if *u != ab => Some(format!("signer {} user {} != author {}", sb, u, ab)),
            Some(_) => None,
            None => Some(format!("no peers_shared for signer {}", sb)),
        };
        if let Some(intents) = del_intents.get(ev.eid_b64) {
            ctx.deletion_intents = intents.clone();
        }
    }
    ctx
}

// ── Gather helpers (DB reads) ───────────────────────────────────────

fn write_block_rows(conn: &Connection, tenant_id: &str, eid_b64: &str, missing: &[EventId]) {
    if missing.is_empty() {
        let _ = EventTimeline::new(conn).mark_blocked_b64(eid_b64, current_timestamp_ms());
        return;
    }
    let mut sorted = missing.to_vec();
    sorted.sort_unstable();
    sorted.dedup();
    for dep in &sorted {
        let db64 = event_id_to_base64(dep);
        let _ = conn.execute(
            "INSERT OR IGNORE INTO blocked_event_deps (peer_id, event_id, blocker_event_id) VALUES (?1, ?2, ?3)",
            rusqlite::params![tenant_id, eid_b64, &db64],
        );
    }
    let _ = conn.execute(
        "INSERT OR IGNORE INTO blocked_events (peer_id, event_id, deps_remaining) VALUES (?1, ?2, ?3)",
        rusqlite::params![tenant_id, eid_b64, sorted.len() as i64],
    );
    let _ = crate::db::wanted::WantedEvents::new(conn).insert_many_for_local(tenant_id, &sorted);
    let _ = EventTimeline::new(conn).mark_blocked_b64(eid_b64, current_timestamp_ms());
}

fn gather_terminal(conn: &Connection, tenant_id: &str, ids: &[String]) -> Result<HashSet<String>, rusqlite::Error> {
    let mut set = HashSet::new();
    for chunk in ids.chunks(900) {
        let ph = placeholders(chunk.len());
        for table in &["valid_events", "rejected_events"] {
            let sql = format!("SELECT event_id FROM {table} WHERE peer_id = ?1 AND event_id IN ({ph})");
            let mut s = conn.prepare(&sql)?;
            s.raw_bind_parameter(1, tenant_id)?;
            for (i, id) in chunk.iter().enumerate() { s.raw_bind_parameter(i + 2, id.as_str())?; }
            let mut r = s.raw_query();
            while let Some(row) = r.next()? { set.insert(row.get::<_, String>(0)?); }
        }
    }
    Ok(set)
}

fn gather_blobs(conn: &Connection, ids: &[&str]) -> Result<HashMap<String, Vec<u8>>, rusqlite::Error> {
    let mut m = HashMap::with_capacity(ids.len());
    for chunk in ids.chunks(900) {
        let ph = placeholders(chunk.len());
        let sql = format!("SELECT event_id, blob FROM events WHERE event_id IN ({ph})");
        let mut s = conn.prepare(&sql)?;
        for (i, id) in chunk.iter().enumerate() { s.raw_bind_parameter(i + 1, *id)?; }
        let mut r = s.raw_query();
        while let Some(row) = r.next()? { m.insert(row.get(0)?, row.get(1)?); }
    }
    Ok(m)
}

fn gather_peers_shared(conn: &Connection, tenant_id: &str) -> Result<HashMap<String, String>, rusqlite::Error> {
    let mut m = HashMap::new();
    let mut s = conn.prepare("SELECT event_id, COALESCE(user_event_id, '') FROM peers_shared WHERE recorded_by = ?1")?;
    let mut r = s.query(rusqlite::params![tenant_id])?;
    while let Some(row) = r.next()? { m.insert(row.get(0)?, row.get(1)?); }
    Ok(m)
}

fn gather_deletion_intents(conn: &Connection, tenant_id: &str, ids: &[&str]) -> Result<HashMap<String, Vec<DeletionIntentInfo>>, rusqlite::Error> {
    let mut m: HashMap<String, Vec<DeletionIntentInfo>> = HashMap::new();
    if ids.is_empty() { return Ok(m); }
    for chunk in ids.chunks(900) {
        let ph = placeholders(chunk.len());
        let sql = format!("SELECT target_id, deletion_event_id, author_id, created_at FROM deletion_intents WHERE recorded_by = ?1 AND target_kind = 'message' AND target_id IN ({ph})");
        let mut s = conn.prepare(&sql)?;
        s.raw_bind_parameter(1, tenant_id)?;
        for (i, id) in chunk.iter().enumerate() { s.raw_bind_parameter(i + 2, *id)?; }
        let mut r = s.raw_query();
        while let Some(row) = r.next()? {
            m.entry(row.get::<_, String>(0)?).or_default().push(DeletionIntentInfo {
                deletion_event_id: row.get(1)?, author_id: row.get(2)?, created_at: row.get(3)?,
            });
        }
    }
    Ok(m)
}

fn gather_signer_keys(conn: &Connection, tenant_id: &str, ids: &HashSet<String>) -> Result<HashMap<String, Result<[u8; 32], String>>, rusqlite::Error> {
    let mut keys: HashMap<String, Result<[u8; 32], String>> = HashMap::new();
    if ids.is_empty() { return Ok(keys); }
    let id_vec: Vec<&str> = ids.iter().map(String::as_str).collect();
    for chunk in id_vec.chunks(900) {
        let ph = placeholders(chunk.len());
        let sql = format!("SELECT e.event_id, e.blob FROM events e INNER JOIN valid_events v ON e.event_id = v.event_id WHERE v.peer_id = ?1 AND e.event_id IN ({ph})");
        let mut s = conn.prepare(&sql)?;
        s.raw_bind_parameter(1, tenant_id)?;
        for (i, id) in chunk.iter().enumerate() { s.raw_bind_parameter(i + 2, *id)?; }
        let mut r = s.raw_query();
        while let Some(row) = r.next()? {
            let eid: String = row.get(0)?;
            let blob: Vec<u8> = row.get(1)?;
            keys.insert(eid, if blob.len() < 41 {
                Err(format!("signer blob too short: {} bytes", blob.len()))
            } else {
                let mut key = [0u8; 32];
                key.copy_from_slice(&blob[9..41]);
                Ok(key)
            });
        }
    }
    for id in ids { keys.entry(id.clone()).or_insert(Err("signer not found".into())); }
    Ok(keys)
}

fn gather_valid_set(conn: &Connection, tenant_id: &str, ids: &HashSet<String>) -> Result<HashSet<String>, rusqlite::Error> {
    let mut present = HashSet::new();
    if ids.is_empty() { return Ok(present); }
    let id_vec: Vec<&str> = ids.iter().map(String::as_str).collect();
    for chunk in id_vec.chunks(900) {
        let ph = placeholders(chunk.len());
        let sql = format!("SELECT event_id FROM valid_events WHERE peer_id = ?1 AND event_id IN ({ph})");
        let mut s = conn.prepare(&sql)?;
        s.raw_bind_parameter(1, tenant_id)?;
        for (i, id) in chunk.iter().enumerate() { s.raw_bind_parameter(i + 2, *id)?; }
        let mut r = s.raw_query();
        while let Some(row) = r.next()? { present.insert(row.get::<_, String>(0)?); }
    }
    Ok(present)
}

fn placeholders(n: usize) -> String {
    (0..n).map(|_| "?").collect::<Vec<_>>().join(",")
}
