use std::collections::{BTreeMap, BTreeSet};

use rand::RngCore;
use rusqlite::Connection;

use crate::crypto::{event_id_from_base64, EventId};
use crate::db::open_connection;
use crate::event_modules::removal::{
    frontier_hash_from_refs, RemovalEvent, MAX_REMOVAL_FRONTIER_REFS,
};
use crate::event_modules::workspace::identity_ops::create_key_rotation_event_with_selected_recipients_at;
use crate::event_modules::workspace::load_local_authoring_context;
use crate::event_modules::ParsedEvent;
use crate::projection::create::{create_encrypted_event, create_signed_event};
pub(crate) use crate::runtime::key_repair::{
    key_shared_target, response_rank, slotted_frontier_refs, RepairTarget,
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
    let local_recipient_event_id = crate::event_modules::peer_shared::load_local_peer_signer_required(
        &conn,
        recorded_by,
    )?
    .0;
    seed_key_rotation_for_recipients(db_path, recorded_by, &[local_recipient_event_id], key_bytes)
}

pub fn seed_key_rotation_for_recipients(
    db_path: &str,
    recorded_by: &str,
    recipient_event_ids: &[EventId],
    key_bytes: [u8; 32],
) -> SimResult<EventId> {
    let conn = open_connection(db_path)?;
    crate::db::schema::create_tables(&conn)?;
    let recipient_keys = load_recipient_keys(&conn, recorded_by, recipient_event_ids)?;
    if recipient_keys.is_empty() {
        return Err("seed_key_rotation_for_recipients requires at least one real recipient".into());
    }
    create_key_rotation_event_with_selected_recipients_at(
        &conn,
        recorded_by,
        &[],
        key_bytes,
        &recipient_keys,
        crate::state::db::queue::current_timestamp_ms_u64(),
    )
}

pub fn create_encrypted_message_with_key(
    db_path: &str,
    recorded_by: &str,
    key_event_id: &EventId,
    content: &str,
) -> SimResult<EventId> {
    let conn = open_connection(db_path)?;
    crate::db::schema::create_tables(&conn)?;
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
        // TODO(phase B): resolve admin-authority event for signer's user.
        admin_authority_event_id: [0u8; 32],
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
    let recipient_keys = prior_rotation_recipient_keys(&conn, recorded_by, key_event_id)?;
    if recipient_keys.is_empty() {
        return Err("create_key_rotation requires an existing rotation recipient set".into());
    }
    let mut rng = rand::thread_rng();
    let mut rotated_key_bytes = [0u8; 32];
    rng.fill_bytes(&mut rotated_key_bytes);
    create_key_rotation_event_with_selected_recipients_at(
        &conn,
        recorded_by,
        frontier_refs,
        rotated_key_bytes,
        &recipient_keys,
        crate::state::db::queue::current_timestamp_ms_u64(),
    )
}

fn load_recipient_keys(
    conn: &Connection,
    recorded_by: &str,
    recipient_event_ids: &[EventId],
) -> SimResult<Vec<(EventId, [u8; 32])>> {
    let wanted = recipient_event_ids.iter().copied().collect::<BTreeSet<_>>();
    let mut stmt = conn.prepare(
        "SELECT event_id, public_key
         FROM peers_shared
         WHERE recorded_by = ?1",
    )?;
    let rows = stmt.query_map(rusqlite::params![recorded_by], |row| {
        Ok((
            crate::db::sql_types::get_text(row, 0)?,
            crate::db::sql_types::get_blob(row, 1)?,
        ))
    })?;
    let mut found = BTreeMap::new();
    for row in rows {
        let (event_id_b64, public_key_blob) = row?;
        let Some(event_id) = event_id_from_base64(&event_id_b64) else {
            continue;
        };
        if !wanted.contains(&event_id) {
            continue;
        }
        let mut public_key = [0u8; 32];
        if public_key_blob.len() != 32 {
            continue;
        }
        public_key.copy_from_slice(&public_key_blob);
        found.insert(event_id, public_key);
    }
    Ok(recipient_event_ids
        .iter()
        .filter_map(|event_id| found.get(event_id).copied().map(|public_key| (*event_id, public_key)))
        .collect())
}

fn prior_rotation_recipient_keys(
    conn: &Connection,
    recorded_by: &str,
    key_event_id: &EventId,
) -> SimResult<Vec<(EventId, [u8; 32])>> {
    let known_recipient_keys = {
        let mut stmt = conn.prepare(
            "SELECT event_id, public_key
             FROM peers_shared
             WHERE recorded_by = ?1",
        )?;
        let rows = stmt.query_map(rusqlite::params![recorded_by], |row| {
            Ok((
                crate::db::sql_types::get_text(row, 0)?,
                crate::db::sql_types::get_blob(row, 1)?,
            ))
        })?;
        let mut out = BTreeMap::new();
        for row in rows {
            let (event_id_b64, public_key_blob) = row?;
            let Some(event_id) = event_id_from_base64(&event_id_b64) else {
                continue;
            };
            if public_key_blob.len() != 32 {
                continue;
            }
            let mut public_key = [0u8; 32];
            public_key.copy_from_slice(&public_key_blob);
            out.insert(event_id, public_key);
        }
        out
    };

    let event_id_b64 = crate::crypto::event_id_to_base64(key_event_id);
    let blob: Vec<u8> = conn.query_row(
        "SELECT blob FROM events WHERE event_id = ?1",
        rusqlite::params![&event_id_b64],
        |row| crate::db::sql_types::get_blob(row, 0),
    )?;
    let parsed = unwrap_signed(crate::event_modules::parse_event(&blob)?)?;
    let ParsedEvent::KeyRotation(rotation) = parsed else {
        return Err("prior key event is not a key_rotation".into());
    };
    let mut out = Vec::new();
    let mut seen = BTreeSet::new();
    for recipient_event_id in rotation.recipient_slots {
        if let Some(public_key) = known_recipient_keys.get(&recipient_event_id) {
            if seen.insert(recipient_event_id) {
                out.push((recipient_event_id, *public_key));
            }
        }
    }
    Ok(out)
}

fn unwrap_signed(parsed: ParsedEvent) -> SimResult<ParsedEvent> {
    match parsed {
        ParsedEvent::Signed(signed) => {
            let inner = crate::event_modules::parse_event(&signed.payload)?;
            unwrap_signed(inner)
        }
        other => Ok(other),
    }
}
