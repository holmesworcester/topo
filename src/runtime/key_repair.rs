use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use ed25519_dalek::VerifyingKey;
use rusqlite::{Connection, OptionalExtension};
use serde::Serialize;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::crypto::{event_id_from_base64, event_id_to_base64, EventId};
use crate::db::open_connection;
use crate::event_modules::key_request::{delivery_target_id, KeyRequestEvent};
use crate::event_modules::key_shared::KeySharedEvent;
use crate::event_modules::removal::{
    canonicalize_frontier_refs, frontier_hash_from_refs, frontier_refs_from_slots,
    MAX_REMOVAL_FRONTIER_REFS,
};
use crate::event_modules::workspace::identity_ops::current_removal_frontier_for_peer;
use crate::event_modules::workspace::load_local_authoring_context;
use crate::event_modules::{self as events, ParsedEvent};
use crate::projection::create::create_signed_event_synchronous;
use crate::projection::encrypted::wrap_key_for_recipient;
use crate::runtime::repeated_warning::{should_emit_globally, RepeatedWarningGate};
use crate::state::db::transport_creds::discover_local_tenants;

type KeyRepairResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

const KEY_REPAIR_LOOP_INTERVAL: Duration = Duration::from_millis(250);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum KeyResponsePolicy {
    AllEligible,
    BestObservedOnly,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct KeyRepairEmitStats {
    pub scanned_peers: usize,
    pub emitted_requests: usize,
    pub emitted_responses: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct RepairTarget {
    key_event_id: EventId,
    frontier_hash: EventId,
    recipient_event_id: EventId,
    unwrap_key_event_id: EventId,
}

#[derive(Clone, Copy, Debug)]
struct RequestRow {
    created_at_ms: u64,
    target: RepairTarget,
}

#[derive(Clone, Copy, Debug)]
struct KeySharedSummary {
    event_id: EventId,
    target: RepairTarget,
    signer_event_id: EventId,
}

#[derive(Clone, Debug)]
pub(crate) struct RotationFrontier {
    pub(crate) frontier_hash: EventId,
    pub(crate) frontier_refs: Vec<EventId>,
}

pub fn emit_key_requests_for_dbs(db_paths: &[String]) -> KeyRepairResult<KeyRepairEmitStats> {
    let mut stats = KeyRepairEmitStats::default();
    for db_path in db_paths {
        accumulate_request_stats(&mut stats, db_path)?;
    }
    Ok(stats)
}

pub fn emit_key_requests_for_peers(
    peers: &[(String, String)],
) -> KeyRepairResult<KeyRepairEmitStats> {
    let mut stats = KeyRepairEmitStats::default();
    for (db_path, recorded_by) in peers {
        stats.scanned_peers = stats.scanned_peers.saturating_add(1);
        stats.emitted_requests = stats
            .emitted_requests
            .saturating_add(emit_key_requests_for_peer(db_path, recorded_by)?);
    }
    Ok(stats)
}

pub fn emit_key_shared_responses_for_dbs(
    db_paths: &[String],
    policy: KeyResponsePolicy,
) -> KeyRepairResult<KeyRepairEmitStats> {
    let mut stats = KeyRepairEmitStats::default();
    for db_path in db_paths {
        accumulate_response_stats(&mut stats, db_path, policy)?;
    }
    Ok(stats)
}

pub fn emit_key_shared_responses_for_peers(
    peers: &[(String, String)],
    policy: KeyResponsePolicy,
) -> KeyRepairResult<KeyRepairEmitStats> {
    let mut stats = KeyRepairEmitStats::default();
    for (db_path, recorded_by) in peers {
        stats.scanned_peers = stats.scanned_peers.saturating_add(1);
        stats.emitted_responses =
            stats
                .emitted_responses
                .saturating_add(emit_key_shared_responses_for_peer(
                    db_path,
                    recorded_by,
                    policy,
                )?);
    }
    Ok(stats)
}

pub(crate) async fn run_periodic_key_repair(
    db_path: String,
    shutdown: CancellationToken,
) -> Result<(), String> {
    let mut warning_gate = RepeatedWarningGate::new(Duration::from_secs(300));
    loop {
        if shutdown.is_cancelled() {
            break;
        }

        match emit_key_repair_round(&db_path, KeyResponsePolicy::BestObservedOnly) {
            Ok((request_stats, response_stats)) => {
                warning_gate.clear();
                if request_stats.emitted_requests > 0 || response_stats.emitted_responses > 0 {
                    info!(
                        "key repair round db={} requests={} responses={}",
                        db_path, request_stats.emitted_requests, response_stats.emitted_responses
                    );
                }
            }
            Err(err) => {
                let message = format!("KEY REPAIR LOOP failed for {}: {}", db_path, err);
                if warning_gate.should_emit(message.clone())
                    && should_emit_globally(format!("runtime:{message}"))
                {
                    warn!("{}", message);
                }
            }
        }

        tokio::select! {
            _ = shutdown.cancelled() => break,
            _ = tokio::time::sleep(KEY_REPAIR_LOOP_INTERVAL) => {}
        }
    }

    Ok(())
}

pub(crate) fn response_rank(target: RepairTarget, signer_event_id: EventId) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"poc7-key-response-rank-v1");
    hasher.update(&target.key_event_id);
    hasher.update(&target.frontier_hash);
    hasher.update(&target.recipient_event_id);
    hasher.update(&target.unwrap_key_event_id);
    hasher.update(&signer_event_id);
    *hasher.finalize().as_bytes()
}

pub(crate) fn shared_sendable_event_id(
    conn: &Connection,
    recorded_by: &str,
    event_id: &EventId,
) -> KeyRepairResult<bool> {
    let event_id_b64 = event_id_to_base64(event_id);
    let suppressed: Option<i64> = conn
        .query_row(
            "SELECT suppress_sharing
             FROM valid_events
             WHERE peer_id = ?1 AND event_id = ?2
             LIMIT 1",
            rusqlite::params![recorded_by, &event_id_b64],
            |row| row.get(0),
        )
        .optional()?;
    Ok(!matches!(suppressed, Some(value) if value != 0))
}

pub(crate) fn key_shared_target(event: &KeySharedEvent) -> RepairTarget {
    RepairTarget {
        key_event_id: event.key_event_id,
        frontier_hash: event.frontier_hash,
        recipient_event_id: event.recipient_event_id,
        unwrap_key_event_id: event.unwrap_key_event_id,
    }
}

#[allow(dead_code)]
pub(crate) fn key_request_target(event: &KeyRequestEvent) -> RepairTarget {
    RepairTarget {
        key_event_id: event.key_event_id,
        frontier_hash: event.frontier_hash,
        recipient_event_id: event.recipient_event_id,
        unwrap_key_event_id: event.unwrap_key_event_id,
    }
}

pub(crate) fn slotted_frontier_refs(
    refs: &[EventId],
) -> KeyRepairResult<[[u8; 32]; MAX_REMOVAL_FRONTIER_REFS]> {
    let sorted_refs = canonicalize_frontier_refs(refs).map_err(|reason| {
        Box::<dyn std::error::Error + Send + Sync>::from(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            reason,
        ))
    })?;
    if sorted_refs.len() > MAX_REMOVAL_FRONTIER_REFS {
        return Err(format!(
            "frontier count {} exceeds max {}",
            sorted_refs.len(),
            MAX_REMOVAL_FRONTIER_REFS
        )
        .into());
    }
    let mut slots = [[0u8; 32]; MAX_REMOVAL_FRONTIER_REFS];
    for (slot, event_id) in slots.iter_mut().zip(sorted_refs.iter()) {
        *slot = *event_id;
    }
    Ok(slots)
}

pub(crate) fn current_local_logical_frontier(
    conn: &Connection,
    recorded_by: &str,
) -> KeyRepairResult<RotationFrontier> {
    let frontier_refs = current_removal_frontier_for_peer(conn, recorded_by)?;
    Ok(RotationFrontier {
        frontier_hash: frontier_hash_from_refs(&frontier_refs),
        frontier_refs,
    })
}

pub(crate) fn has_key_rotation_for_frontier(
    conn: &Connection,
    recorded_by: &str,
    key_event_id: &EventId,
    frontier: &RotationFrontier,
) -> KeyRepairResult<bool> {
    let key_event_id_b64 = event_id_to_base64(key_event_id);
    let slots = slotted_frontier_refs(&frontier.frontier_refs)?;
    Ok(conn.query_row(
        "SELECT EXISTS(
             SELECT 1
             FROM key_rotations
             WHERE recorded_by = ?1
               AND key_event_id = ?2
               AND frontier_hash = ?3
               AND frontier_count = ?4
               AND frontier_ref_1 = ?5
               AND frontier_ref_2 = ?6
               AND frontier_ref_3 = ?7
               AND frontier_ref_4 = ?8
         )",
        rusqlite::params![
            recorded_by,
            &key_event_id_b64,
            event_id_to_base64(&frontier.frontier_hash),
            frontier.frontier_refs.len() as i64,
            event_id_to_base64(&slots[0]),
            event_id_to_base64(&slots[1]),
            event_id_to_base64(&slots[2]),
            event_id_to_base64(&slots[3]),
        ],
        |row| row.get(0),
    )?)
}

fn emit_key_repair_round(
    db_path: &str,
    policy: KeyResponsePolicy,
) -> KeyRepairResult<(KeyRepairEmitStats, KeyRepairEmitStats)> {
    let mut request_stats = KeyRepairEmitStats::default();
    let mut response_stats = KeyRepairEmitStats::default();
    accumulate_request_stats(&mut request_stats, db_path)?;
    accumulate_response_stats(&mut response_stats, db_path, policy)?;
    Ok((request_stats, response_stats))
}

fn accumulate_request_stats(stats: &mut KeyRepairEmitStats, db_path: &str) -> KeyRepairResult<()> {
    let conn = open_connection(db_path)?;
    crate::db::schema::create_tables(&conn)?;
    let tenants = discover_local_tenants(&conn)?;
    drop(conn);
    for tenant in tenants {
        stats.scanned_peers = stats.scanned_peers.saturating_add(1);
        stats.emitted_requests = stats
            .emitted_requests
            .saturating_add(emit_key_requests_for_peer(db_path, &tenant.peer_id)?);
    }
    Ok(())
}

fn accumulate_response_stats(
    stats: &mut KeyRepairEmitStats,
    db_path: &str,
    policy: KeyResponsePolicy,
) -> KeyRepairResult<()> {
    let conn = open_connection(db_path)?;
    crate::db::schema::create_tables(&conn)?;
    let tenants = discover_local_tenants(&conn)?;
    drop(conn);
    for tenant in tenants {
        stats.scanned_peers = stats.scanned_peers.saturating_add(1);
        stats.emitted_responses =
            stats
                .emitted_responses
                .saturating_add(emit_key_shared_responses_for_peer(
                    db_path,
                    &tenant.peer_id,
                    policy,
                )?);
    }
    Ok(())
}

fn emit_key_requests_for_peer(db_path: &str, recorded_by: &str) -> KeyRepairResult<usize> {
    let conn = open_connection(db_path)?;
    crate::db::schema::create_tables(&conn)?;
    let blocked = blocked_encrypted_events(&conn, recorded_by)?;
    if blocked.is_empty() {
        return Ok(0);
    }
    let authoring = load_local_authoring_context(&conn, recorded_by)?;
    let (recipient_event_id, unwrap_key_event_id) =
        local_repair_recipient_material(&conn, recorded_by)?;
    let mut emitted = 0usize;

    for (blocked_event_id, key_event_id, created_at_ms) in blocked {
        let Some(rotation) = local_rotation_frontier(&conn, recorded_by, &key_event_id)? else {
            continue;
        };
        let target_id = delivery_target_id(
            &key_event_id,
            &rotation.frontier_hash,
            &recipient_event_id,
            &unwrap_key_event_id,
        );
        let request = ParsedEvent::KeyRequest(KeyRequestEvent {
            created_at_ms,
            blocked_event_id,
            key_event_id,
            frontier_hash: rotation.frontier_hash,
            delivery_target_id: target_id,
            recipient_event_id,
            unwrap_key_event_id,
        });
        let event_id =
            signed_event_id(&request, &authoring.signer_event_id, &authoring.signing_key)?;
        let event_id_b64 = event_id_to_base64(&event_id);
        let existed_before: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM events WHERE event_id = ?1)",
            rusqlite::params![&event_id_b64],
            |row| row.get(0),
        )?;
        let _ = create_signed_event_synchronous(
            &conn,
            recorded_by,
            &authoring.signer_event_id,
            &request,
            &authoring.signing_key,
        )?;
        if !existed_before {
            emitted = emitted.saturating_add(1);
        }
    }

    Ok(emitted)
}

fn emit_key_shared_responses_for_peer(
    db_path: &str,
    recorded_by: &str,
    policy: KeyResponsePolicy,
) -> KeyRepairResult<usize> {
    let conn = open_connection(db_path)?;
    crate::db::schema::create_tables(&conn)?;
    let authoring = load_local_authoring_context(&conn, recorded_by)?;
    let known_responses = known_key_shared_summaries(&conn, recorded_by)?;
    let repaired_key_ids = repaired_key_ids_for_local_recipient(&conn, recorded_by)?;
    let mut best_rank_by_target = BTreeMap::<RepairTarget, ([u8; 32], EventId, EventId)>::new();
    for response in known_responses {
        let rank = response_rank(response.target, response.signer_event_id);
        best_rank_by_target
            .entry(response.target)
            .and_modify(|best| {
                if (rank, response.signer_event_id, response.event_id) < (best.0, best.1, best.2) {
                    *best = (rank, response.signer_event_id, response.event_id);
                }
            })
            .or_insert((rank, response.signer_event_id, response.event_id));
    }

    let requests = known_key_requests(&conn, recorded_by)?;
    let mut emitted = 0usize;
    for request in requests {
        if !has_local_key_material(&conn, recorded_by, &request.target.key_event_id)? {
            continue;
        }
        if !is_authorized_repair_target(&conn, recorded_by, &request.target)? {
            continue;
        }
        if repaired_key_ids.contains(&request.target.key_event_id) {
            continue;
        }

        let local_rank = response_rank(request.target, authoring.signer_event_id);
        if policy == KeyResponsePolicy::BestObservedOnly {
            if let Some((best_rank, best_signer, best_event_id)) =
                best_rank_by_target.get(&request.target)
            {
                let local_event_id = signed_event_id(
                    &build_key_shared_response(&conn, recorded_by, &authoring, request)?,
                    &authoring.signer_event_id,
                    &authoring.signing_key,
                )?;
                if (*best_rank, *best_signer, *best_event_id)
                    < (local_rank, authoring.signer_event_id, local_event_id)
                {
                    continue;
                }
            }
        }

        let response = build_key_shared_response(&conn, recorded_by, &authoring, request)?;
        let event_id = signed_event_id(
            &response,
            &authoring.signer_event_id,
            &authoring.signing_key,
        )?;
        let event_id_b64 = event_id_to_base64(&event_id);
        let existed_before: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM events WHERE event_id = ?1)",
            rusqlite::params![&event_id_b64],
            |row| row.get(0),
        )?;
        let _ = create_signed_event_synchronous(
            &conn,
            recorded_by,
            &authoring.signer_event_id,
            &response,
            &authoring.signing_key,
        )?;
        if !existed_before {
            emitted = emitted.saturating_add(1);
        }
    }

    Ok(emitted)
}

fn repaired_key_ids_for_local_recipient(
    conn: &Connection,
    recorded_by: &str,
) -> KeyRepairResult<BTreeSet<EventId>> {
    let Ok((recipient_event_id, _)) = local_repair_recipient_material(conn, recorded_by) else {
        return Ok(BTreeSet::new());
    };
    let recipient_event_id_b64 = event_id_to_base64(&recipient_event_id);
    let mut stmt = conn.prepare(
        "SELECT DISTINCT key_event_id
         FROM key_shared
         WHERE recorded_by = ?1
           AND recipient_event_id = ?2",
    )?;
    let rows = stmt.query_map(
        rusqlite::params![recorded_by, &recipient_event_id_b64],
        |row| crate::db::sql_types::get_text(row, 0),
    )?;
    let mut out = BTreeSet::new();
    for row in rows {
        let key_event_id_b64 = row?;
        if let Some(key_event_id) = event_id_from_base64(&key_event_id_b64) {
            out.insert(key_event_id);
        }
    }
    Ok(out)
}

fn blocked_encrypted_events(
    conn: &Connection,
    recorded_by: &str,
) -> KeyRepairResult<Vec<(EventId, EventId, u64)>> {
    let mut stmt = conn.prepare(
        "SELECT be.event_id, e.blob, e.created_at
         FROM blocked_events be
         JOIN events e ON e.event_id = be.event_id
         WHERE be.peer_id = ?1
           AND e.event_type IN ('signed', 'encrypted')
         ORDER BY e.created_at ASC, e.event_id ASC",
    )?;
    let rows = stmt.query_map(rusqlite::params![recorded_by], |row| {
        Ok((
            crate::db::sql_types::get_text(row, 0)?,
            crate::db::sql_types::get_blob(row, 1)?,
            row.get::<_, i64>(2)?,
        ))
    })?;

    let mut out = Vec::new();
    for row in rows {
        let (event_id_b64, blob, created_at_ms) = row?;
        let Some(blocked_event_id) = event_id_from_base64(&event_id_b64) else {
            continue;
        };
        let Ok(ParsedEvent::Encrypted(enc)) = parse_semantic_event(&blob) else {
            continue;
        };
        out.push((blocked_event_id, enc.key_event_id, created_at_ms as u64));
    }
    Ok(out)
}

fn local_repair_recipient_material(
    conn: &Connection,
    recorded_by: &str,
) -> KeyRepairResult<(EventId, EventId)> {
    let invite_event_id_b64: String = conn.query_row(
        "SELECT invite_event_id
         FROM invites_accepted
         WHERE recorded_by = ?1
         ORDER BY created_at ASC, event_id ASC
         LIMIT 1",
        rusqlite::params![recorded_by],
        |row| crate::db::sql_types::get_text(row, 0),
    )?;
    let invite_secret_event_id_b64: String = conn.query_row(
        "SELECT event_id
         FROM invite_secrets
         WHERE recorded_by = ?1
           AND invite_event_id = ?2
         ORDER BY created_at ASC, event_id ASC
         LIMIT 1",
        rusqlite::params![recorded_by, &invite_event_id_b64],
        |row| crate::db::sql_types::get_text(row, 0),
    )?;
    let recipient_event_id =
        event_id_from_base64(&invite_event_id_b64).ok_or("invalid invite_event_id base64")?;
    let unwrap_key_event_id = event_id_from_base64(&invite_secret_event_id_b64)
        .ok_or("invalid invite_secret.event_id base64")?;
    Ok((recipient_event_id, unwrap_key_event_id))
}

fn known_key_requests(conn: &Connection, recorded_by: &str) -> KeyRepairResult<Vec<RequestRow>> {
    let mut stmt = conn.prepare(
        "SELECT kr.key_event_id, kr.recipient_event_id, kr.unwrap_key_event_id
                , kr.frontier_hash, e.created_at
         FROM key_requests kr
         JOIN events e ON e.event_id = kr.event_id
         WHERE kr.recorded_by = ?1
         ORDER BY kr.rowid ASC",
    )?;
    let rows = stmt.query_map(rusqlite::params![recorded_by], |row| {
        Ok((
            crate::db::sql_types::get_text(row, 0)?,
            crate::db::sql_types::get_text(row, 1)?,
            crate::db::sql_types::get_text(row, 2)?,
            crate::db::sql_types::get_text(row, 3)?,
            row.get::<_, i64>(4)?,
        ))
    })?;
    let mut out = Vec::new();
    for row in rows {
        let (key_b64, recipient_b64, unwrap_b64, frontier_b64, created_at_ms) = row?;
        let Some(key_event_id) = event_id_from_base64(&key_b64) else {
            continue;
        };
        let Some(recipient_event_id) = event_id_from_base64(&recipient_b64) else {
            continue;
        };
        let Some(unwrap_key_event_id) = event_id_from_base64(&unwrap_b64) else {
            continue;
        };
        let Some(frontier_hash) = event_id_from_base64(&frontier_b64) else {
            continue;
        };
        out.push(RequestRow {
            created_at_ms: created_at_ms as u64,
            target: RepairTarget {
                key_event_id,
                frontier_hash,
                recipient_event_id,
                unwrap_key_event_id,
            },
        });
    }
    Ok(out)
}

fn known_key_shared_summaries(
    conn: &Connection,
    recorded_by: &str,
) -> KeyRepairResult<Vec<KeySharedSummary>> {
    let mut stmt = conn.prepare(
        "SELECT e.event_id, e.blob
         FROM recorded_events re
         JOIN events e ON e.event_id = re.event_id
         WHERE re.peer_id = ?1
         ORDER BY re.id ASC",
    )?;
    let rows = stmt.query_map(rusqlite::params![recorded_by], |row| {
        Ok((
            crate::db::sql_types::get_text(row, 0)?,
            crate::db::sql_types::get_blob(row, 1)?,
        ))
    })?;
    let mut out = Vec::new();
    for row in rows {
        let (event_id_b64, blob) = row?;
        let Some(event_id) = event_id_from_base64(&event_id_b64) else {
            continue;
        };
        let Ok(ParsedEvent::KeyShared(ks)) = parse_semantic_event(&blob) else {
            continue;
        };
        let Some(signer_event_id) = crate::event_modules::signed::outer_signer_event_id(&blob)
        else {
            continue;
        };
        out.push(KeySharedSummary {
            event_id,
            target: RepairTarget {
                key_event_id: ks.key_event_id,
                frontier_hash: ks.frontier_hash,
                recipient_event_id: ks.recipient_event_id,
                unwrap_key_event_id: ks.unwrap_key_event_id,
            },
            signer_event_id,
        });
    }
    Ok(out)
}

fn parse_semantic_event(blob: &[u8]) -> Result<ParsedEvent, crate::event_modules::EventError> {
    let parsed = events::parse_event(blob)?;
    unwrap_signed(parsed)
}

fn unwrap_signed(parsed: ParsedEvent) -> Result<ParsedEvent, crate::event_modules::EventError> {
    match parsed {
        ParsedEvent::Signed(signed) => unwrap_signed(events::parse_event(&signed.payload)?),
        other => Ok(other),
    }
}

fn has_local_key_material(
    conn: &Connection,
    recorded_by: &str,
    key_event_id: &EventId,
) -> KeyRepairResult<bool> {
    let key_event_id_b64 = event_id_to_base64(key_event_id);
    Ok(conn.query_row(
        "SELECT EXISTS(
             SELECT 1 FROM key_secrets
             WHERE recorded_by = ?1 AND event_id = ?2
         )",
        rusqlite::params![recorded_by, &key_event_id_b64],
        |row| row.get(0),
    )?)
}

fn build_key_shared_response(
    conn: &Connection,
    recorded_by: &str,
    authoring: &crate::event_modules::workspace::LocalAuthoringContext,
    request: RequestRow,
) -> KeyRepairResult<ParsedEvent> {
    let rotation = local_rotation_frontier(conn, recorded_by, &request.target.key_event_id)?
        .ok_or("missing local key rotation for key_shared response")?;
    let frontier_slots = slotted_frontier_refs(&rotation.frontier_refs)?;
    let key_event_id_b64 = event_id_to_base64(&request.target.key_event_id);
    let key_bytes: Vec<u8> = conn.query_row(
        "SELECT key_bytes
         FROM key_secrets
         WHERE recorded_by = ?1 AND event_id = ?2
         LIMIT 1",
        rusqlite::params![recorded_by, &key_event_id_b64],
        |row| crate::db::sql_types::get_blob(row, 0),
    )?;
    if key_bytes.len() != 32 {
        return Err("corrupt key_bytes in key_secrets".into());
    }
    let mut plaintext_key = [0u8; 32];
    plaintext_key.copy_from_slice(&key_bytes);

    let recipient_key = request_recipient_verifying_key(conn, &request.target.recipient_event_id)?;
    let wrapped_key =
        wrap_key_for_recipient(&authoring.signing_key, &recipient_key, &plaintext_key);

    let target_id = delivery_target_id(
        &request.target.key_event_id,
        &request.target.frontier_hash,
        &request.target.recipient_event_id,
        &request.target.unwrap_key_event_id,
    );

    Ok(ParsedEvent::KeyShared(KeySharedEvent {
        created_at_ms: request.created_at_ms,
        key_event_id: request.target.key_event_id,
        frontier_count: rotation.frontier_refs.len() as u8,
        frontier_ref_1: frontier_slots[0],
        frontier_ref_2: frontier_slots[1],
        frontier_ref_3: frontier_slots[2],
        frontier_ref_4: frontier_slots[3],
        frontier_hash: request.target.frontier_hash,
        delivery_target_id: target_id,
        recipient_event_id: request.target.recipient_event_id,
        unwrap_key_event_id: request.target.unwrap_key_event_id,
        wrapped_key,
    }))
}

fn request_recipient_verifying_key(
    conn: &Connection,
    recipient_event_id: &EventId,
) -> KeyRepairResult<VerifyingKey> {
    let recipient_event_id_b64 = event_id_to_base64(recipient_event_id);
    let blob: Vec<u8> = conn.query_row(
        "SELECT blob FROM events WHERE event_id = ?1",
        rusqlite::params![&recipient_event_id_b64],
        |row| crate::db::sql_types::get_blob(row, 0),
    )?;
    let parsed = parse_semantic_event(&blob)?;
    let public_key = match parsed {
        ParsedEvent::UserInvite(evt) => evt.public_key,
        ParsedEvent::DeviceInvite(evt) => evt.public_key,
        _ => return Err("recipient_event_id is not an invite event".into()),
    };
    Ok(VerifyingKey::from_bytes(&public_key)?)
}

fn signed_event_id(
    event: &ParsedEvent,
    signer_event_id: &EventId,
    signing_key: &ed25519_dalek::SigningKey,
) -> KeyRepairResult<EventId> {
    let blob =
        crate::projection::create::encode_signed_wrapper_blob(event, signer_event_id, signing_key)?;
    Ok(crate::crypto::hash_event(&blob))
}

fn local_rotation_frontier(
    conn: &Connection,
    recorded_by: &str,
    key_event_id: &EventId,
) -> KeyRepairResult<Option<RotationFrontier>> {
    let frontier = current_local_logical_frontier(conn, recorded_by)?;
    if has_key_rotation_for_frontier(conn, recorded_by, key_event_id, &frontier)? {
        Ok(Some(frontier))
    } else {
        Ok(None)
    }
}

fn is_authorized_repair_target(
    conn: &Connection,
    recorded_by: &str,
    target: &RepairTarget,
) -> KeyRepairResult<bool> {
    let Some(rotation) = local_rotation_frontier(conn, recorded_by, &target.key_event_id)? else {
        return Ok(false);
    };
    if rotation.frontier_hash != target.frontier_hash {
        return Ok(false);
    }
    let Some(removed) =
        removed_member_refs_for_frontier(conn, recorded_by, &rotation.frontier_refs)?
    else {
        return Ok(false);
    };
    Ok(!removed.contains(&target.recipient_event_id))
}

fn removed_member_refs_for_frontier(
    conn: &Connection,
    recorded_by: &str,
    frontier_refs: &[EventId],
) -> KeyRepairResult<Option<BTreeSet<EventId>>> {
    let mut removed = BTreeSet::new();
    let mut stack = frontier_refs.to_vec();
    let mut visited = BTreeSet::new();

    while let Some(removal_event_id) = stack.pop() {
        if !visited.insert(removal_event_id) {
            continue;
        }
        let Some((removed_member_ref, parents)) =
            removal_row(conn, recorded_by, &removal_event_id)?
        else {
            return Ok(None);
        };
        removed.insert(removed_member_ref);
        stack.extend(parents);
    }

    Ok(Some(removed))
}

fn removal_row(
    conn: &Connection,
    recorded_by: &str,
    removal_event_id: &EventId,
) -> KeyRepairResult<Option<(EventId, Vec<EventId>)>> {
    let removal_event_id_b64 = event_id_to_base64(removal_event_id);
    let row: Option<(String, i64, String, String, String, String)> = conn
        .query_row(
            "SELECT removed_member_ref, parent_count, parent_1, parent_2, parent_3, parent_4
             FROM removals
             WHERE recorded_by = ?1 AND event_id = ?2
             LIMIT 1",
            rusqlite::params![recorded_by, &removal_event_id_b64],
            |row| {
                Ok((
                    crate::db::sql_types::get_text(row, 0)?,
                    row.get::<_, i64>(1)?,
                    crate::db::sql_types::get_text(row, 2)?,
                    crate::db::sql_types::get_text(row, 3)?,
                    crate::db::sql_types::get_text(row, 4)?,
                    crate::db::sql_types::get_text(row, 5)?,
                ))
            },
        )
        .optional()?;
    let Some((removed_member_ref_b64, parent_count, parent_1, parent_2, parent_3, parent_4)) = row
    else {
        return Ok(None);
    };
    let removed_member_ref = event_id_from_base64(&removed_member_ref_b64)
        .ok_or("invalid removal removed_member_ref")?;
    let parents = frontier_refs_from_slots(
        parent_count as u8,
        &[
            decode_frontier_slot(&parent_1)?,
            decode_frontier_slot(&parent_2)?,
            decode_frontier_slot(&parent_3)?,
            decode_frontier_slot(&parent_4)?,
        ],
    )?;
    Ok(Some((removed_member_ref, parents)))
}

fn decode_frontier_slot(value: &str) -> KeyRepairResult<EventId> {
    event_id_from_base64(value)
        .ok_or_else(|| format!("invalid frontier slot event_id `{value}`").into())
}
