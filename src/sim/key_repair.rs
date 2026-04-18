use rusqlite::Connection;

use crate::crypto::EventId;
use crate::db::open_connection;
use crate::event_modules::key_rotation::KeyRotationEvent;
use crate::event_modules::key_secret::{
    deterministic_key_secret_event, deterministic_key_secret_event_id,
};
use crate::event_modules::removal::{
    frontier_hash_from_refs, RemovalEvent, MAX_REMOVAL_FRONTIER_REFS,
};
use crate::event_modules::workspace::load_local_authoring_context;
use crate::event_modules::ParsedEvent;
use crate::projection::create::{
    create_encrypted_event, create_event, create_signed_event,
};
pub(crate) use crate::runtime::key_repair::{
    current_local_logical_frontier, has_key_rotation_for_frontier, key_shared_target,
    response_rank, slotted_frontier_refs, RepairTarget,
};
pub use crate::runtime::key_repair::{
    emit_key_requests_for_dbs, emit_key_requests_for_peers, emit_key_shared_responses_for_dbs,
    emit_key_shared_responses_for_peers, KeyRepairEmitStats, KeyResponsePolicy,
};

type SimResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

pub fn seed_deterministic_key_secret(
    db_path: &str,
    recorded_by: &str,
    key_bytes: [u8; 32],
) -> SimResult<EventId> {
    let conn = open_connection(db_path)?;
    crate::db::schema::create_tables(&conn)?;
    let event = deterministic_key_secret_event(key_bytes);
    let expected = deterministic_key_secret_event_id(&key_bytes);
    let created = create_event(&conn, recorded_by, &event)?;
    if created != expected {
        return Err("deterministic key_secret event_id mismatch".into());
    }
    ensure_key_rotation_exists(&conn, recorded_by, &created)?;
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
    Ok(create_encrypted_event(
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
    Ok(create_signed_event(
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
    Ok(create_signed_event(
        &conn,
        recorded_by,
        &authoring.signer_event_id,
        &event,
        &authoring.signing_key,
    )?)
}

fn ensure_key_rotation_exists(
    conn: &Connection,
    recorded_by: &str,
    key_event_id: &EventId,
) -> SimResult<()> {
    let frontier = current_local_logical_frontier(conn, recorded_by)?;
    if has_key_rotation_for_frontier(conn, recorded_by, key_event_id, &frontier)? {
        return Ok(());
    }
    let authoring = load_local_authoring_context(conn, recorded_by)?;
    let slots = slotted_frontier_refs(&frontier.frontier_refs)?;
    let event = ParsedEvent::KeyRotation(KeyRotationEvent {
        created_at_ms: crate::state::db::queue::current_timestamp_ms_u64(),
        key_event_id: *key_event_id,
        frontier_count: frontier.frontier_refs.len() as u8,
        frontier_ref_1: slots[0],
        frontier_ref_2: slots[1],
        frontier_ref_3: slots[2],
        frontier_ref_4: slots[3],
        frontier_hash: frontier.frontier_hash,
        rotated_by: authoring.signer_event_id,
    });
    let _ = create_signed_event(
        conn,
        recorded_by,
        &authoring.signer_event_id,
        &event,
        &authoring.signing_key,
    )?;
    Ok(())
}
