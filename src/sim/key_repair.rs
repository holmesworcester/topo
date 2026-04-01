use std::collections::BTreeMap;
use std::collections::BTreeSet;

use ed25519_dalek::VerifyingKey;
use rusqlite::Connection;
use rusqlite::OptionalExtension;
use serde::Serialize;

use crate::crypto::{event_id_from_base64, event_id_to_base64, EventId};
use crate::db::open_connection;
use crate::event_modules::key_request::{
    delivery_target_id, deterministic_key_request_created_at_ms, KeyRequestEvent,
};
use crate::event_modules::key_rotation::KeyRotationEvent;
use crate::event_modules::key_secret::{
    deterministic_key_secret_event, deterministic_key_secret_event_id,
};
use crate::event_modules::key_shared::KeySharedEvent;
use crate::event_modules::removal::{
    canonicalize_frontier_refs, frontier_hash_from_refs, frontier_refs_from_slots, RemovalEvent,
    MAX_REMOVAL_FRONTIER_REFS,
};
use crate::event_modules::workspace::load_local_authoring_context;
use crate::event_modules::{self as events, ParsedEvent};
use crate::projection::create::{
    create_encrypted_event_synchronous, create_event_synchronous, create_signed_event_synchronous,
};
use crate::projection::encrypted::wrap_key_for_recipient;
use crate::state::db::transport_creds::discover_local_tenants;

type SimResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

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
    blocked_event_id: EventId,
    target: RepairTarget,
}

#[derive(Clone, Copy, Debug)]
struct KeySharedSummary {
    event_id: EventId,
    target: RepairTarget,
    signer_event_id: EventId,
}

#[derive(Clone, Debug)]
struct RotationFrontier {
    frontier_hash: EventId,
    frontier_refs: Vec<EventId>,
}

pub fn seed_deterministic_key_secret(
    db_path: &str,
    recorded_by: &str,
    key_bytes: [u8; 32],
) -> SimResult<EventId> {
    let conn = open_connection(db_path)?;
    crate::db::schema::create_tables(&conn)?;
    let event = deterministic_key_secret_event(key_bytes);
    let expected = deterministic_key_secret_event_id(&key_bytes);
    let created = create_event_synchronous(&conn, recorded_by, &event)?;
    if created != expected {
        return Err("deterministic key_secret event_id mismatch".into());
    }
    Ok(created)
}

pub fn create_encrypted_message_with_key(
    db_path: &str,
    recorded_by: &str,
    key_event_id: &EventId,
    content: &str,
) -> SimResult<EventId> {
    let conn = open_connection(db_path)?;
    crate::db::schema::create_tables(&conn)?;
    ensure_key_rotation_exists(&conn, recorded_by, key_event_id)?;
    let authoring = load_local_authoring_context(&conn, recorded_by)?;
    let inner = ParsedEvent::Message(crate::event_modules::MessageEvent {
        created_at_ms: crate::state::db::queue::current_timestamp_ms_u64(),
        workspace_id: authoring.workspace_id,
        author_id: authoring.author_id,
        content: content.to_string(),
    });
    Ok(create_encrypted_event_synchronous(
        &conn,
        recorded_by,
        key_event_id,
        &inner,
        Some((&authoring.signer_event_id, &authoring.signing_key)),
    )?)
}

pub fn create_removal(
    db_path: &str,
    recorded_by: &str,
    removed_member_ref: &EventId,
    parent_refs: &[EventId],
) -> SimResult<EventId> {
    if parent_refs.len() > MAX_REMOVAL_FRONTIER_REFS {
        return Err(format!(
            "removal parent count {} exceeds max {}",
            parent_refs.len(),
            MAX_REMOVAL_FRONTIER_REFS
        )
        .into());
    }
    let conn = open_connection(db_path)?;
    crate::db::schema::create_tables(&conn)?;
    let authoring = load_local_authoring_context(&conn, recorded_by)?;
    let slots = slotted_frontier_refs(parent_refs)?;
    let event = ParsedEvent::Removal(RemovalEvent {
        created_at_ms: crate::state::db::queue::current_timestamp_ms_u64(),
        removed_member_ref: *removed_member_ref,
        parent_count: parent_refs.len() as u8,
        parent_1: slots[0],
        parent_2: slots[1],
        parent_3: slots[2],
        parent_4: slots[3],
        frontier_hash: frontier_hash_from_refs(parent_refs),
        removed_by: authoring.signer_event_id,
    });
    Ok(create_signed_event_synchronous(
        &conn,
        recorded_by,
        &authoring.signer_event_id,
        &event,
        &authoring.signing_key,
    )?)
}

pub fn create_key_rotation(
    db_path: &str,
    recorded_by: &str,
    key_event_id: &EventId,
    frontier_refs: &[EventId],
) -> SimResult<EventId> {
    if frontier_refs.len() > MAX_REMOVAL_FRONTIER_REFS {
        return Err(format!(
            "key rotation frontier count {} exceeds max {}",
            frontier_refs.len(),
            MAX_REMOVAL_FRONTIER_REFS
        )
        .into());
    }
    let conn = open_connection(db_path)?;
    crate::db::schema::create_tables(&conn)?;
    let authoring = load_local_authoring_context(&conn, recorded_by)?;
    let slots = slotted_frontier_refs(frontier_refs)?;
    let event = ParsedEvent::KeyRotation(KeyRotationEvent {
        created_at_ms: crate::state::db::queue::current_timestamp_ms_u64(),
        key_event_id: *key_event_id,
        frontier_count: frontier_refs.len() as u8,
        frontier_ref_1: slots[0],
        frontier_ref_2: slots[1],
        frontier_ref_3: slots[2],
        frontier_ref_4: slots[3],
        frontier_hash: frontier_hash_from_refs(frontier_refs),
        rotated_by: authoring.signer_event_id,
    });
    Ok(create_signed_event_synchronous(
        &conn,
        recorded_by,
        &authoring.signer_event_id,
        &event,
        &authoring.signing_key,
    )?)
}

pub fn emit_key_requests_for_dbs(db_paths: &[String]) -> SimResult<KeyRepairEmitStats> {
    let mut stats = KeyRepairEmitStats::default();
    for db_path in db_paths {
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
    }
    Ok(stats)
}

pub fn emit_key_requests_for_peers(peers: &[(String, String)]) -> SimResult<KeyRepairEmitStats> {
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
) -> SimResult<KeyRepairEmitStats> {
    let mut stats = KeyRepairEmitStats::default();
    for db_path in db_paths {
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
    }
    Ok(stats)
}

pub fn emit_key_shared_responses_for_peers(
    peers: &[(String, String)],
    policy: KeyResponsePolicy,
) -> SimResult<KeyRepairEmitStats> {
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

fn emit_key_requests_for_peer(db_path: &str, recorded_by: &str) -> SimResult<usize> {
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

    for (blocked_event_id, key_event_id) in blocked {
        let Some(rotation) = local_rotation_frontier(&conn, recorded_by, &key_event_id)? else {
            continue;
        };
        let created_at_ms = deterministic_key_request_created_at_ms(
            &blocked_event_id,
            &key_event_id,
            &rotation.frontier_hash,
            &recipient_event_id,
            &unwrap_key_event_id,
            &authoring.signer_event_id,
        );
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
) -> SimResult<usize> {
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
) -> SimResult<BTreeSet<EventId>> {
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
        |row| row.get::<_, String>(0),
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
) -> SimResult<Vec<(EventId, EventId)>> {
    let mut stmt = conn.prepare(
        "SELECT be.event_id, e.blob
         FROM blocked_events be
         JOIN events e ON e.event_id = be.event_id
         WHERE be.peer_id = ?1
           AND e.event_type IN ('signed', 'encrypted')
         ORDER BY e.created_at ASC, e.event_id ASC",
    )?;
    let rows = stmt.query_map(rusqlite::params![recorded_by], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?))
    })?;

    let mut out = Vec::new();
    for row in rows {
        let (event_id_b64, blob) = row?;
        let Some(blocked_event_id) = event_id_from_base64(&event_id_b64) else {
            continue;
        };
        let Ok(ParsedEvent::Encrypted(enc)) = parse_semantic_event(&blob) else {
            continue;
        };
        out.push((blocked_event_id, enc.key_event_id));
    }
    Ok(out)
}

fn local_repair_recipient_material(
    conn: &Connection,
    recorded_by: &str,
) -> SimResult<(EventId, EventId)> {
    let invite_event_id_b64: String = conn.query_row(
        "SELECT invite_event_id
         FROM invites_accepted
         WHERE recorded_by = ?1
         ORDER BY created_at ASC, event_id ASC
         LIMIT 1",
        rusqlite::params![recorded_by],
        |row| row.get(0),
    )?;
    let invite_secret_event_id_b64: String = conn.query_row(
        "SELECT event_id
         FROM invite_secrets
         WHERE recorded_by = ?1
           AND invite_event_id = ?2
         ORDER BY created_at ASC, event_id ASC
         LIMIT 1",
        rusqlite::params![recorded_by, &invite_event_id_b64],
        |row| row.get(0),
    )?;
    let recipient_event_id =
        event_id_from_base64(&invite_event_id_b64).ok_or("invalid invite_event_id base64")?;
    let unwrap_key_event_id = event_id_from_base64(&invite_secret_event_id_b64)
        .ok_or("invalid invite_secret.event_id base64")?;
    Ok((recipient_event_id, unwrap_key_event_id))
}

fn known_key_requests(conn: &Connection, recorded_by: &str) -> SimResult<Vec<RequestRow>> {
    let mut stmt = conn.prepare(
        "SELECT blocked_event_id, key_event_id, recipient_event_id, unwrap_key_event_id
                , frontier_hash
         FROM key_requests
         WHERE recorded_by = ?1
         ORDER BY rowid ASC",
    )?;
    let rows = stmt.query_map(rusqlite::params![recorded_by], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, String>(4)?,
        ))
    })?;
    let mut out = Vec::new();
    for row in rows {
        let (blocked_b64, key_b64, recipient_b64, unwrap_b64, frontier_b64) = row?;
        let Some(blocked_event_id) = event_id_from_base64(&blocked_b64) else {
            continue;
        };
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
            blocked_event_id,
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
) -> SimResult<Vec<KeySharedSummary>> {
    let mut stmt = conn.prepare(
        "SELECT e.event_id, e.blob
         FROM recorded_events re
         JOIN events e ON e.event_id = re.event_id
         WHERE re.peer_id = ?1
         ORDER BY re.id ASC",
    )?;
    let rows = stmt.query_map(rusqlite::params![recorded_by], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?))
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
) -> SimResult<bool> {
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
) -> SimResult<ParsedEvent> {
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
        |row| row.get(0),
    )?;
    if key_bytes.len() != 32 {
        return Err("corrupt key_bytes in key_secrets".into());
    }
    let mut plaintext_key = [0u8; 32];
    plaintext_key.copy_from_slice(&key_bytes);

    let recipient_key = request_recipient_verifying_key(conn, &request.target.recipient_event_id)?;
    let wrapped_key =
        wrap_key_for_recipient(&authoring.signing_key, &recipient_key, &plaintext_key);

    let created_at_ms = deterministic_response_created_at_ms(
        &request.blocked_event_id,
        &request.target.key_event_id,
        &request.target.frontier_hash,
        &request.target.recipient_event_id,
        &request.target.unwrap_key_event_id,
        &authoring.signer_event_id,
    );
    let target_id = delivery_target_id(
        &request.target.key_event_id,
        &request.target.frontier_hash,
        &request.target.recipient_event_id,
        &request.target.unwrap_key_event_id,
    );

    Ok(ParsedEvent::KeyShared(KeySharedEvent {
        created_at_ms,
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
) -> SimResult<VerifyingKey> {
    let recipient_event_id_b64 = event_id_to_base64(recipient_event_id);
    let blob: Vec<u8> = conn.query_row(
        "SELECT blob FROM events WHERE event_id = ?1",
        rusqlite::params![&recipient_event_id_b64],
        |row| row.get(0),
    )?;
    let parsed = parse_semantic_event(&blob)?;
    let public_key = match parsed {
        ParsedEvent::UserInvite(evt) => evt.public_key,
        ParsedEvent::DeviceInvite(evt) => evt.public_key,
        _ => return Err("recipient_event_id is not an invite event".into()),
    };
    Ok(VerifyingKey::from_bytes(&public_key)?)
}

fn deterministic_response_created_at_ms(
    blocked_event_id: &[u8; 32],
    key_event_id: &[u8; 32],
    frontier_hash: &[u8; 32],
    recipient_event_id: &[u8; 32],
    unwrap_key_event_id: &[u8; 32],
    signed_by: &[u8; 32],
) -> u64 {
    use blake2::digest::consts::U8;
    use blake2::{Blake2b, Digest};

    let mut hasher = Blake2b::<U8>::new();
    hasher.update(b"poc7-key-response-created-at-v1");
    hasher.update(blocked_event_id);
    hasher.update(key_event_id);
    hasher.update(frontier_hash);
    hasher.update(recipient_event_id);
    hasher.update(unwrap_key_event_id);
    hasher.update(signed_by);
    let digest = hasher.finalize();
    let mut out = [0u8; 8];
    out.copy_from_slice(&digest[..8]);
    u64::from_le_bytes(out)
}

fn signed_event_id(
    event: &ParsedEvent,
    signer_event_id: &EventId,
    signing_key: &ed25519_dalek::SigningKey,
) -> SimResult<EventId> {
    let blob =
        crate::projection::create::encode_signed_wrapper_blob(event, signer_event_id, signing_key)?;
    Ok(crate::crypto::hash_event(&blob))
}

pub(crate) fn response_rank(target: RepairTarget, signer_event_id: EventId) -> [u8; 32] {
    use blake2::digest::consts::U32;
    use blake2::{Blake2b, Digest};

    let mut hasher = Blake2b::<U32>::new();
    hasher.update(b"poc7-key-response-rank-v1");
    hasher.update(target.key_event_id);
    hasher.update(target.frontier_hash);
    hasher.update(target.recipient_event_id);
    hasher.update(target.unwrap_key_event_id);
    hasher.update(signer_event_id);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest[..32]);
    out
}

fn slotted_frontier_refs(refs: &[EventId]) -> SimResult<[[u8; 32]; MAX_REMOVAL_FRONTIER_REFS]> {
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

fn ensure_key_rotation_exists(
    conn: &Connection,
    recorded_by: &str,
    key_event_id: &EventId,
) -> SimResult<()> {
    if local_rotation_frontier(conn, recorded_by, key_event_id)?.is_some() {
        return Ok(());
    }
    let authoring = load_local_authoring_context(conn, recorded_by)?;
    let event = ParsedEvent::KeyRotation(KeyRotationEvent {
        created_at_ms: crate::state::db::queue::current_timestamp_ms_u64(),
        key_event_id: *key_event_id,
        frontier_count: 0,
        frontier_ref_1: [0u8; 32],
        frontier_ref_2: [0u8; 32],
        frontier_ref_3: [0u8; 32],
        frontier_ref_4: [0u8; 32],
        frontier_hash: frontier_hash_from_refs(&[]),
        rotated_by: authoring.signer_event_id,
    });
    let _ = create_signed_event_synchronous(
        conn,
        recorded_by,
        &authoring.signer_event_id,
        &event,
        &authoring.signing_key,
    )?;
    Ok(())
}

fn local_rotation_frontier(
    conn: &Connection,
    recorded_by: &str,
    key_event_id: &EventId,
) -> SimResult<Option<RotationFrontier>> {
    let key_event_id_b64 = event_id_to_base64(key_event_id);
    let row: Option<(String, u8, String, String, String, String)> = conn
        .query_row(
            "SELECT frontier_hash, frontier_count, frontier_ref_1, frontier_ref_2, frontier_ref_3, frontier_ref_4
             FROM key_rotations
             WHERE recorded_by = ?1
               AND key_event_id = ?2
             ORDER BY rowid DESC
             LIMIT 1",
            rusqlite::params![recorded_by, &key_event_id_b64],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                ))
            },
        )
        .optional()?;
    let Some((frontier_hash_b64, frontier_count, ref1_b64, ref2_b64, ref3_b64, ref4_b64)) = row
    else {
        return Ok(None);
    };
    let Some(frontier_hash) = event_id_from_base64(&frontier_hash_b64) else {
        return Ok(None);
    };
    let Some(ref1) = event_id_from_base64(&ref1_b64) else {
        return Ok(None);
    };
    let Some(ref2) = event_id_from_base64(&ref2_b64) else {
        return Ok(None);
    };
    let Some(ref3) = event_id_from_base64(&ref3_b64) else {
        return Ok(None);
    };
    let Some(ref4) = event_id_from_base64(&ref4_b64) else {
        return Ok(None);
    };
    let frontier_refs = frontier_refs_from_slots(frontier_count, &[ref1, ref2, ref3, ref4])
        .map_err(|reason| format!("invalid key rotation frontier slots: {reason}"))?;
    Ok(Some(RotationFrontier {
        frontier_hash,
        frontier_refs,
    }))
}

fn is_authorized_repair_target(
    conn: &Connection,
    recorded_by: &str,
    target: &RepairTarget,
) -> SimResult<bool> {
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
) -> SimResult<Option<BTreeSet<EventId>>> {
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
) -> SimResult<Option<(EventId, Vec<EventId>)>> {
    let removal_event_id_b64 = event_id_to_base64(removal_event_id);
    let row: Option<(String, u8, String, String, String, String)> = conn
        .query_row(
            "SELECT removed_member_ref, parent_count, parent_1, parent_2, parent_3, parent_4
             FROM removals
             WHERE recorded_by = ?1
               AND event_id = ?2
             LIMIT 1",
            rusqlite::params![recorded_by, &removal_event_id_b64],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                ))
            },
        )
        .optional()?;
    let Some((
        removed_member_b64,
        parent_count,
        parent1_b64,
        parent2_b64,
        parent3_b64,
        parent4_b64,
    )) = row
    else {
        return Ok(None);
    };
    let Some(removed_member_ref) = event_id_from_base64(&removed_member_b64) else {
        return Ok(None);
    };
    let Some(parent1) = event_id_from_base64(&parent1_b64) else {
        return Ok(None);
    };
    let Some(parent2) = event_id_from_base64(&parent2_b64) else {
        return Ok(None);
    };
    let Some(parent3) = event_id_from_base64(&parent3_b64) else {
        return Ok(None);
    };
    let Some(parent4) = event_id_from_base64(&parent4_b64) else {
        return Ok(None);
    };
    let parents = frontier_refs_from_slots(parent_count, &[parent1, parent2, parent3, parent4])
        .map_err(|reason| format!("invalid removal parent slots: {reason}"))?;
    Ok(Some((removed_member_ref, parents)))
}

pub(crate) fn key_shared_target(event: &KeySharedEvent) -> RepairTarget {
    RepairTarget {
        key_event_id: event.key_event_id,
        frontier_hash: event.frontier_hash,
        recipient_event_id: event.recipient_event_id,
        unwrap_key_event_id: event.unwrap_key_event_id,
    }
}

pub(crate) fn key_request_target(event: &KeyRequestEvent) -> RepairTarget {
    RepairTarget {
        key_event_id: event.key_event_id,
        frontier_hash: event.frontier_hash,
        recipient_event_id: event.recipient_event_id,
        unwrap_key_event_id: event.unwrap_key_event_id,
    }
}
