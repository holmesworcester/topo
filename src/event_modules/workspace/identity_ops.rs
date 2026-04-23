//! Identity primitives and helpers.
//!
//! This module owns reusable crypto/data helpers for identity operations.
//! Workflow orchestration (event creation sequences, invite flows) is owned
//! by `event_modules::workspace::commands`.

use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::RngCore;
use rusqlite::{Connection, OptionalExtension};

use crate::crypto::{
    encrypt_bundle_for_recipient, event_id_from_base64, event_id_to_base64, EventId,
};
use crate::event_modules::key_history::{
    encode_key_history_plaintext, KeyHistoryEntry, KeyHistoryEvent, KEY_HISTORY_CAP,
    NO_KEY_HISTORY_EVENT_ID,
};
use crate::event_modules::key_rotation::{KeyRotationEvent, KEY_ROTATION_CAP};
use crate::event_modules::removal::{
    canonicalize_frontier_refs, frontier_hash_from_refs, frontier_refs_from_slots,
    MAX_REMOVAL_FRONTIER_REFS,
};
use crate::event_modules::*;
use crate::projection::create::{
    create_event, create_signed_event, event_id_or_blocked,
    store_signed_event_then_project,
};
use crate::projection::encrypted::wrap_key_for_recipient;
use crate::state::db::queue::current_timestamp_ms_u64;
use crate::transport::{extract_spki_fingerprint, generate_self_signed_cert_from_signing_key};

pub const INVITE_HISTORY_KEY_CAP: usize = KEY_HISTORY_CAP;
pub const INVITE_ACTIVE_TTL_MS: i64 = 30 * 24 * 60 * 60 * 1000;

#[derive(Debug, Clone)]
struct InviteShareTarget {
    invite_event_id: EventId,
    public_key: [u8; 32],
    unwrap_key_event_id: EventId,
    created_at_ms: i64,
}

#[derive(Debug, Clone)]
struct KeyRotationSummary {
    key_event_id: EventId,
    frontier_refs: Vec<EventId>,
}

#[derive(Debug, Clone)]
struct RotationRecipient {
    recipient_event_id: EventId,
    public_key: [u8; 32],
}

pub(crate) struct RotateContentKeyResult {
    pub key_event_id: EventId,
    pub rotation_event_id: EventId,
    pub proactive_share_count: usize,
}

/// Ensure a local `tenant` event exists for this tenant and return its event id.
/// `tenant` is the local root for local-only identity events.
pub(crate) fn ensure_local_tenant_event(
    conn: &Connection,
    recorded_by: &str,
    peer_key: &SigningKey,
) -> Result<EventId, Box<dyn std::error::Error + Send + Sync>> {
    ensure_local_tenant_event_at(conn, recorded_by, peer_key, current_timestamp_ms_u64())
}

pub(crate) fn ensure_local_tenant_event_at(
    conn: &Connection,
    recorded_by: &str,
    peer_key: &SigningKey,
    created_at_ms: u64,
) -> Result<EventId, Box<dyn std::error::Error + Send + Sync>> {
    let existing: Option<String> = conn
        .query_row(
            "SELECT event_id
             FROM tenants
             WHERE recorded_by = ?1
             ORDER BY created_at ASC, event_id ASC
             LIMIT 1",
            rusqlite::params![recorded_by],
            |row| row.get(0),
        )
        .ok();
    let tenant_event_id = if let Some(eid_b64) = existing {
        event_id_from_base64(&eid_b64).ok_or("invalid tenants.event_id base64")?
    } else {
        let tenant_evt = ParsedEvent::Tenant(TenantEvent {
            created_at_ms,
            public_key: peer_key.verifying_key().to_bytes(),
        });
        event_id_or_blocked(create_event(conn, recorded_by, &tenant_evt))?
    };

    Ok(tenant_event_id)
}

fn create_deterministic_key_secret_event(
    conn: &Connection,
    recorded_by: &str,
    key_bytes: [u8; 32],
) -> Result<EventId, Box<dyn std::error::Error + Send + Sync>> {
    let expected = crate::event_modules::key_secret::deterministic_key_secret_event_id(&key_bytes);
    let sk_evt = crate::event_modules::key_secret::deterministic_key_secret_event(key_bytes);
    let created = create_event(conn, recorded_by, &sk_evt)?;
    if created != expected {
        return Err("key_secret event_id mismatch for deterministic key material".into());
    }
    Ok(created)
}

fn parse_event_id_b64(
    value: &str,
    what: &str,
) -> Result<EventId, Box<dyn std::error::Error + Send + Sync>> {
    event_id_from_base64(value).ok_or_else(|| format!("invalid {what} base64: {value}").into())
}

fn parse_blob_event_id(
    value: Vec<u8>,
    what: &str,
) -> Result<EventId, Box<dyn std::error::Error + Send + Sync>> {
    if value.len() != 32 {
        return Err(format!("{what} blob must be 32 bytes, got {}", value.len()).into());
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&value);
    Ok(out)
}

fn slotted_frontier_refs(
    frontier_refs: &[EventId],
) -> Result<[[u8; 32]; MAX_REMOVAL_FRONTIER_REFS], Box<dyn std::error::Error + Send + Sync>> {
    if frontier_refs.len() > MAX_REMOVAL_FRONTIER_REFS {
        return Err(format!(
            "frontier ref count {} exceeds max {}",
            frontier_refs.len(),
            MAX_REMOVAL_FRONTIER_REFS
        )
        .into());
    }
    let sorted_refs = canonicalize_frontier_refs(frontier_refs)?;
    let mut slots = [[0u8; 32]; MAX_REMOVAL_FRONTIER_REFS];
    for (slot, event_id) in slots.iter_mut().zip(sorted_refs.iter()) {
        *slot = *event_id;
    }
    Ok(slots)
}

fn recent_key_rotations_for_peer(
    conn: &Connection,
    recorded_by: &str,
    limit: usize,
) -> Result<Vec<KeyRotationSummary>, Box<dyn std::error::Error + Send + Sync>> {
    let mut stmt = conn.prepare(
        "SELECT kr.key_event_id,
                kr.frontier_count,
                kr.frontier_ref_1,
                kr.frontier_ref_2,
                kr.frontier_ref_3,
                kr.frontier_ref_4,
                e.created_at
         FROM key_rotations kr
         JOIN key_secrets ks
           ON ks.recorded_by = kr.recorded_by
          AND ks.event_id = kr.key_event_id
         JOIN events e
           ON e.event_id = kr.event_id
         WHERE kr.recorded_by = ?1
         ORDER BY e.created_at DESC, kr.event_id DESC
         LIMIT ?2",
    )?;
    let rows = stmt.query_map(rusqlite::params![recorded_by, limit as i64], |row| {
        Ok((
            crate::db::sql_types::get_text(row, 0)?,
            row.get::<_, u8>(1)?,
            crate::db::sql_types::get_text(row, 2)?,
            crate::db::sql_types::get_text(row, 3)?,
            crate::db::sql_types::get_text(row, 4)?,
            crate::db::sql_types::get_text(row, 5)?,
            row.get::<_, i64>(6)?,
        ))
    })?;

    let mut out = Vec::new();
    for row in rows {
        let (key_b64, frontier_count, ref1_b64, ref2_b64, ref3_b64, ref4_b64, _created_at_ms) =
            row?;
        let key_event_id = parse_event_id_b64(&key_b64, "key_rotation.key_event_id")?;
        let ref1 = parse_event_id_b64(&ref1_b64, "key_rotation.frontier_ref_1")?;
        let ref2 = parse_event_id_b64(&ref2_b64, "key_rotation.frontier_ref_2")?;
        let ref3 = parse_event_id_b64(&ref3_b64, "key_rotation.frontier_ref_3")?;
        let ref4 = parse_event_id_b64(&ref4_b64, "key_rotation.frontier_ref_4")?;
        let frontier_refs = frontier_refs_from_slots(frontier_count, &[ref1, ref2, ref3, ref4])
            .map_err(|reason| format!("invalid key_rotation frontier refs: {reason}"))?;
        out.push(KeyRotationSummary {
            key_event_id,
            frontier_refs,
        });
    }
    Ok(out)
}

pub(crate) fn current_removal_frontier_for_peer(
    conn: &Connection,
    recorded_by: &str,
) -> Result<Vec<EventId>, Box<dyn std::error::Error + Send + Sync>> {
    let mut stmt = conn.prepare(
        "SELECT r.event_id
         FROM removals r
         WHERE r.recorded_by = ?1
           AND NOT EXISTS (
               SELECT 1
               FROM removals child
               WHERE child.recorded_by = r.recorded_by
                 AND (
                     child.parent_1 = r.event_id
                     OR child.parent_2 = r.event_id
                     OR child.parent_3 = r.event_id
                     OR child.parent_4 = r.event_id
                 )
           )
         ORDER BY r.event_id ASC",
    )?;
    let rows = stmt.query_map(rusqlite::params![recorded_by], |row| {
        crate::db::sql_types::get_text(row, 0)
    })?;
    let mut out = Vec::new();
    for row in rows {
        out.push(parse_event_id_b64(&row?, "removals.event_id frontier tip")?);
    }
    if out.len() > MAX_REMOVAL_FRONTIER_REFS {
        return Err(format!(
            "current removal frontier has {} refs, exceeds max {}",
            out.len(),
            MAX_REMOVAL_FRONTIER_REFS
        )
        .into());
    }
    Ok(out)
}

fn decode_frontier_slot_text(
    value: &str,
) -> Result<EventId, Box<dyn std::error::Error + Send + Sync>> {
    event_id_from_base64(value)
        .ok_or_else(|| format!("invalid frontier slot event_id `{value}`").into())
}

fn removal_row(
    conn: &Connection,
    recorded_by: &str,
    removal_event_id: &EventId,
) -> Result<Option<(EventId, Vec<EventId>)>, Box<dyn std::error::Error + Send + Sync>> {
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
            decode_frontier_slot_text(&parent_1)?,
            decode_frontier_slot_text(&parent_2)?,
            decode_frontier_slot_text(&parent_3)?,
            decode_frontier_slot_text(&parent_4)?,
        ],
    )?;
    Ok(Some((removed_member_ref, parents)))
}

fn removed_member_refs_for_frontier(
    conn: &Connection,
    recorded_by: &str,
    frontier_refs: &[EventId],
) -> Result<std::collections::BTreeSet<EventId>, Box<dyn std::error::Error + Send + Sync>> {
    let mut removed = std::collections::BTreeSet::new();
    let mut stack = frontier_refs.to_vec();
    let mut visited = std::collections::BTreeSet::new();

    while let Some(removal_event_id) = stack.pop() {
        if !visited.insert(removal_event_id) {
            continue;
        }
        let Some((removed_member_ref, parents)) = removal_row(conn, recorded_by, &removal_event_id)?
        else {
            continue;
        };
        removed.insert(removed_member_ref);
        stack.extend(parents);
    }

    Ok(removed)
}

pub(crate) fn peer_shared_removal_refs(
    conn: &Connection,
    peer_shared_event_id: &EventId,
    user_event_id: Option<EventId>,
) -> Result<Option<std::collections::BTreeSet<EventId>>, Box<dyn std::error::Error + Send + Sync>>
{
    let peer_shared_event_id_b64 = event_id_to_base64(peer_shared_event_id);
    let peer_shared_blob: Option<Vec<u8>> = conn
        .query_row(
            "SELECT blob
             FROM events
             WHERE event_id = ?1
             LIMIT 1",
            rusqlite::params![&peer_shared_event_id_b64],
            |row| crate::db::sql_types::get_blob(row, 0),
        )
        .optional()?;
    let Some(peer_shared_blob) = peer_shared_blob else {
        return Ok(None);
    };
    let Some(device_invite_event_id) =
        crate::event_modules::signed::outer_signer_event_id(&peer_shared_blob)
    else {
        return Ok(None);
    };
    let device_invite_event_id_b64 = event_id_to_base64(&device_invite_event_id);
    let device_invite_blob: Option<Vec<u8>> = conn
        .query_row(
            "SELECT blob
             FROM events
             WHERE event_id = ?1
             LIMIT 1",
            rusqlite::params![&device_invite_event_id_b64],
            |row| crate::db::sql_types::get_blob(row, 0),
        )
        .optional()?;
    let Some(device_invite_blob) = device_invite_blob else {
        return Ok(None);
    };
    let device_invite = match parse_event(&device_invite_blob)? {
        ParsedEvent::DeviceInvite(device_invite) => device_invite,
        ParsedEvent::Signed(signed) => match parse_event(&signed.payload)? {
            ParsedEvent::DeviceInvite(device_invite) => device_invite,
            _ => return Ok(None),
        },
        _ => return Ok(None),
    };

    let mut refs = std::collections::BTreeSet::new();
    refs.insert(*peer_shared_event_id);
    if let Some(user_event_id) = user_event_id {
        refs.insert(user_event_id);
        let user_event_id_b64 = event_id_to_base64(&user_event_id);
        let user_blob: Option<Vec<u8>> = conn
            .query_row(
                "SELECT blob
                 FROM events
                 WHERE event_id = ?1
                 LIMIT 1",
                rusqlite::params![&user_event_id_b64],
                |row| crate::db::sql_types::get_blob(row, 0),
            )
            .optional()?;
        if let Some(user_blob) = user_blob {
            if let Some(user_invite_event_id) =
                crate::event_modules::signed::outer_signer_event_id(&user_blob)
            {
                refs.insert(user_invite_event_id);
            }
        }
    }
    refs.insert(device_invite_event_id);
    refs.insert(device_invite.authority_event_id);
    Ok(Some(refs))
}

fn active_rotation_recipients_for_frontier(
    conn: &Connection,
    recorded_by: &str,
    frontier_refs: &[EventId],
) -> Result<Vec<RotationRecipient>, Box<dyn std::error::Error + Send + Sync>> {
    let removed = removed_member_refs_for_frontier(conn, recorded_by, frontier_refs)?;
    let mut stmt = conn.prepare(
        "SELECT event_id, user_event_id, public_key
         FROM peers_shared
         WHERE recorded_by = ?1
         ORDER BY event_id ASC",
    )?;
    let rows = stmt.query_map(rusqlite::params![recorded_by], |row| {
        Ok((
            crate::db::sql_types::get_text(row, 0)?,
            crate::db::sql_types::get_text(row, 1)?,
            crate::db::sql_types::get_blob(row, 2)?,
        ))
    })?;

    let mut recipients = Vec::new();
    for row in rows {
        let (event_id_b64, user_event_id_b64, public_key_blob) = row?;
        let recipient_event_id = parse_event_id_b64(&event_id_b64, "peers_shared.event_id")?;
        let user_event_id = if user_event_id_b64.is_empty() {
            None
        } else {
            Some(parse_event_id_b64(
                &user_event_id_b64,
                "peers_shared.user_event_id",
            )?)
        };
        let Some(removal_refs) =
            peer_shared_removal_refs(conn, &recipient_event_id, user_event_id)?
        else {
            continue;
        };
        if removal_refs.iter().any(|removed_ref| removed.contains(removed_ref)) {
            continue;
        }
        let public_key = parse_blob_event_id(public_key_blob, "peers_shared.public_key")?;
        recipients.push(RotationRecipient {
            recipient_event_id,
            public_key,
        });
    }

    // Delivery-layer: include every locally-projected invite as an
    // additional recipient slot. The invite's Ed25519 public_key is
    // the wrap target; on unwrap, the joiner matches one of their
    // locally-stored `invite_secrets` private keys. This is the
    // mechanism by which a joiner can decrypt messages encrypted
    // under a K_bundle rotated AFTER the invite was created: every
    // rotation broadcasts the new K_bundle to each still-active
    // invite pubkey, so any peer holding the invite privkey (whether
    // they've accepted yet or not) can unwrap.
    //
    // We deliberately do NOT filter out invites that have already
    // been consumed (accepted → peer_shared materialized). Rationale:
    // the accepted peer_shared is included in its own slot above, so
    // the redundant invite slot is harmless; and detecting
    // "consumed" robustly would require walking invite → user →
    // peer_shared lineage, which is more complex than the slot-
    // budget cost of carrying the redundant invite slot. 8192-slot
    // cap is orders of magnitude above realistic invite counts.
    //
    // Removed invites are skipped: if the invite's authority
    // (workspace / user) has been removed via the current frontier,
    // the invite no longer grants decryption capability on future
    // bundles. In practice invite authorities are peers_shared or
    // workspace itself; the `removed` set already captures those.
    let mut user_invite_stmt = conn.prepare(
        "SELECT event_id, public_key
         FROM user_invites
         WHERE recorded_by = ?1
         ORDER BY event_id ASC",
    )?;
    let user_invite_rows = user_invite_stmt.query_map(rusqlite::params![recorded_by], |row| {
        Ok((
            crate::db::sql_types::get_text(row, 0)?,
            crate::db::sql_types::get_blob(row, 1)?,
        ))
    })?;
    for row in user_invite_rows {
        let (event_id_b64, public_key_blob) = row?;
        let recipient_event_id = parse_event_id_b64(&event_id_b64, "user_invites.event_id")?;
        let public_key = parse_blob_event_id(public_key_blob, "user_invites.public_key")?;
        recipients.push(RotationRecipient {
            recipient_event_id,
            public_key,
        });
    }

    let mut device_invite_stmt = conn.prepare(
        "SELECT event_id, public_key
         FROM device_invites
         WHERE recorded_by = ?1
         ORDER BY event_id ASC",
    )?;
    let device_invite_rows =
        device_invite_stmt.query_map(rusqlite::params![recorded_by], |row| {
            Ok((
                crate::db::sql_types::get_text(row, 0)?,
                crate::db::sql_types::get_blob(row, 1)?,
            ))
        })?;
    for row in device_invite_rows {
        let (event_id_b64, public_key_blob) = row?;
        let recipient_event_id = parse_event_id_b64(&event_id_b64, "device_invites.event_id")?;
        let public_key = parse_blob_event_id(public_key_blob, "device_invites.public_key")?;
        recipients.push(RotationRecipient {
            recipient_event_id,
            public_key,
        });
    }

    recipients.sort_by_key(|recipient| recipient.recipient_event_id);
    Ok(recipients)
}

fn latest_materialized_key_for_peer(
    conn: &Connection,
    recorded_by: &str,
) -> Result<Option<EventId>, Box<dyn std::error::Error + Send + Sync>> {
    // Only consider rows whose `key_secrets` entry is a K_bundle
    // (has a matching `key_rotations` row). Per-message K_m rows
    // live in `key_secrets` too — keyed by `message_key.event_id` —
    // but they're not valid inputs for creating a new K_bundle:
    // reusing a K_m as a K_bundle would produce duplicate key
    // material across two different cryptographic roles and defeat
    // strong FS's "K_bundle shredded on deletion" invariant on the
    // originating message's rotation.
    let existing: Option<String> = conn
        .query_row(
            "SELECT ks.event_id
             FROM key_secrets ks
             JOIN key_rotations kr
               ON kr.recorded_by = ks.recorded_by
              AND kr.event_id = ks.event_id
             JOIN events e
               ON e.event_id = ks.event_id
             WHERE ks.recorded_by = ?1
             ORDER BY e.created_at DESC, ks.event_id DESC
             LIMIT 1",
            rusqlite::params![recorded_by],
            |row| row.get(0),
        )
        .ok();
    existing
        .map(|eid_b64| parse_event_id_b64(&eid_b64, "key_secrets.event_id"))
        .transpose()
}

fn latest_content_key_for_frontier(
    conn: &Connection,
    recorded_by: &str,
    frontier_refs: &[EventId],
) -> Result<Option<EventId>, Box<dyn std::error::Error + Send + Sync>> {
    let slots = slotted_frontier_refs(frontier_refs)?;
    let frontier_hash = frontier_hash_from_refs(frontier_refs);
    let existing: Option<String> = conn
        .query_row(
            "SELECT kr.event_id
             FROM key_rotations kr
             JOIN key_secrets ks
               ON ks.recorded_by = kr.recorded_by
              AND ks.event_id = kr.event_id
             JOIN events e
               ON e.event_id = kr.event_id
             WHERE kr.recorded_by = ?1
               AND kr.frontier_hash = ?2
               AND kr.frontier_count = ?3
               AND kr.frontier_ref_1 = ?4
               AND kr.frontier_ref_2 = ?5
               AND kr.frontier_ref_3 = ?6
               AND kr.frontier_ref_4 = ?7
             ORDER BY e.created_at DESC, kr.event_id DESC
             LIMIT 1",
            rusqlite::params![
                recorded_by,
                event_id_to_base64(&frontier_hash),
                frontier_refs.len() as i64,
                event_id_to_base64(&slots[0]),
                event_id_to_base64(&slots[1]),
                event_id_to_base64(&slots[2]),
                event_id_to_base64(&slots[3]),
            ],
            |row| crate::db::sql_types::get_text(row, 0),
        )
        .optional()?;
    existing
        .map(|eid_b64| parse_event_id_b64(&eid_b64, "key_rotations.event_id"))
        .transpose()
}

fn recent_key_history_entries_for_peer(
    conn: &Connection,
    recorded_by: &str,
    limit: usize,
) -> Result<Vec<KeyHistoryEntry>, Box<dyn std::error::Error + Send + Sync>> {
    let mut stmt = conn.prepare(
        "SELECT kr.event_id, ks.key_bytes
         FROM key_rotations kr
         JOIN key_secrets ks
           ON ks.recorded_by = kr.recorded_by
          AND ks.event_id = kr.event_id
         JOIN events e
           ON e.event_id = kr.event_id
         WHERE kr.recorded_by = ?1
         ORDER BY e.created_at DESC, kr.event_id DESC
         LIMIT ?2",
    )?;
    let rows = stmt.query_map(rusqlite::params![recorded_by, limit as i64], |row| {
        Ok((
            crate::db::sql_types::get_text(row, 0)?,
            crate::db::sql_types::get_blob(row, 1)?,
        ))
    })?;
    let mut out = Vec::new();
    for row in rows {
        let (event_id_b64, key_bytes_blob) = row?;
        let key_event_id = parse_event_id_b64(&event_id_b64, "key_rotations.event_id")?;
        let key_bytes = parse_blob_event_id(key_bytes_blob, "key_secrets.key_bytes")?;
        out.push(KeyHistoryEntry {
            key_event_id,
            key_bytes,
        });
    }
    Ok(out)
}

fn create_key_history_event_for_public_key(
    conn: &Connection,
    recorded_by: &str,
    signer_key: &SigningKey,
    signer_event_id: &EventId,
    recipient_public_key: &[u8; 32],
    created_at_ms: u64,
    history_cap: usize,
) -> Result<EventId, Box<dyn std::error::Error + Send + Sync>> {
    let recipient_vk = VerifyingKey::from_bytes(recipient_public_key)
        .map_err(|err| format!("invalid invite public key: {err}"))?;
    let plaintext = encode_key_history_plaintext(&recent_key_history_entries_for_peer(
        conn,
        recorded_by,
        history_cap,
    )?)?;
    let (nonce, ciphertext, auth_tag) = encrypt_bundle_for_recipient(
        signer_key,
        &recipient_vk,
        &plaintext,
    )
    .map_err(|err| -> Box<dyn std::error::Error + Send + Sync> { err.to_string().into() })?;
    let event = ParsedEvent::KeyHistory(KeyHistoryEvent {
        created_at_ms,
        recipient_public_key: *recipient_public_key,
        nonce,
        ciphertext,
        auth_tag,
    });
    Ok(create_signed_event(
        conn,
        recorded_by,
        signer_event_id,
        &event,
        signer_key,
    )?)
}

fn existing_rotation_for_frontier(
    conn: &Connection,
    recorded_by: &str,
    frontier_refs: &[EventId],
) -> Result<Option<EventId>, Box<dyn std::error::Error + Send + Sync>> {
    let slots = slotted_frontier_refs(frontier_refs)?;
    let frontier_hash = frontier_hash_from_refs(frontier_refs);
    // Strong-FS (delete-triggered bundle purge): a KeyRotation row
    // may outlive its `key_secrets` plaintext row (the latter gets
    // shredded on first-delete-in-bundle). Only consider a rotation
    // "existing" if its plaintext is still materialized locally —
    // otherwise the caller should rotate to a fresh K_bundle. This
    // mirrors the INNER JOIN in `latest_content_key_for_frontier`.
    conn
        .query_row(
            "SELECT kr.event_id
             FROM key_rotations kr
             JOIN key_secrets ks
               ON ks.recorded_by = kr.recorded_by
              AND ks.event_id = kr.event_id
             WHERE kr.recorded_by = ?1
               AND kr.frontier_hash = ?2
               AND kr.frontier_count = ?3
               AND kr.frontier_ref_1 = ?4
               AND kr.frontier_ref_2 = ?5
               AND kr.frontier_ref_3 = ?6
               AND kr.frontier_ref_4 = ?7
             ORDER BY kr.rowid DESC
             LIMIT 1",
            rusqlite::params![
                recorded_by,
                event_id_to_base64(&frontier_hash),
                frontier_refs.len() as i64,
                event_id_to_base64(&slots[0]),
                event_id_to_base64(&slots[1]),
                event_id_to_base64(&slots[2]),
                event_id_to_base64(&slots[3]),
            ],
            |row| crate::db::sql_types::get_text(row, 0),
        )
        .optional()?
        .map(|existing| parse_event_id_b64(&existing, "key_rotations.event_id"))
        .transpose()
}

pub(crate) fn create_key_rotation_event_with_selected_recipients_at(
    conn: &Connection,
    recorded_by: &str,
    frontier_refs: &[EventId],
    key_bytes: [u8; 32],
    recipient_keys: &[(EventId, [u8; 32])],
    created_at_ms: u64,
) -> Result<EventId, Box<dyn std::error::Error + Send + Sync>> {
    let authoring =
        crate::event_modules::workspace::load_local_authoring_context(conn, recorded_by)?;
    if recipient_keys.len() > KEY_ROTATION_CAP {
        return Err(format!(
            "workspace recipient count {} exceeds key rotation cap {}",
            recipient_keys.len(),
            KEY_ROTATION_CAP
        )
        .into());
    }
    let slots = slotted_frontier_refs(frontier_refs)?;
    let frontier_hash = frontier_hash_from_refs(frontier_refs);
    let mut rng = rand::thread_rng();
    let mut recipient_slots = Vec::with_capacity(KEY_ROTATION_CAP);
    let mut wrapped_keys = Vec::with_capacity(KEY_ROTATION_CAP);

    for (recipient_event_id, public_key) in recipient_keys {
        let recipient_vk = VerifyingKey::from_bytes(public_key)
            .map_err(|err| format!("invalid peer_shared public key: {err}"))?;
        recipient_slots.push(*recipient_event_id);
        wrapped_keys.push(wrap_key_for_recipient(
            &authoring.signing_key,
            &recipient_vk,
            &key_bytes,
        ));
    }
    while recipient_slots.len() < KEY_ROTATION_CAP {
        let chaff_key = SigningKey::generate(&mut rng);
        let mut chaff_recipient_id = [0u8; 32];
        rng.fill_bytes(&mut chaff_recipient_id);
        if recipient_slots.iter().any(|existing| *existing == chaff_recipient_id) {
            continue;
        }
        let mut dummy_key = [0u8; 32];
        rng.fill_bytes(&mut dummy_key);
        recipient_slots.push(chaff_recipient_id);
        wrapped_keys.push(wrap_key_for_recipient(
            &authoring.signing_key,
            &chaff_key.verifying_key(),
            &dummy_key,
        ));
    }
    let event = ParsedEvent::KeyRotation(KeyRotationEvent {
        created_at_ms,
        frontier_count: frontier_refs.len() as u8,
        frontier_ref_1: slots[0],
        frontier_ref_2: slots[1],
        frontier_ref_3: slots[2],
        frontier_ref_4: slots[3],
        frontier_hash,
        rotated_by: authoring.signer_event_id,
        recipient_slots,
        wrapped_keys,
    });

    Ok(create_signed_event(
        conn,
        recorded_by,
        &authoring.signer_event_id,
        &event,
        &authoring.signing_key,
    )?)
}

fn create_key_rotation_event_with_key_bytes_at(
    conn: &Connection,
    recorded_by: &str,
    frontier_refs: &[EventId],
    key_bytes: [u8; 32],
    created_at_ms: u64,
) -> Result<EventId, Box<dyn std::error::Error + Send + Sync>> {
    let recipients = active_rotation_recipients_for_frontier(conn, recorded_by, frontier_refs)?;
    let recipient_keys = recipients
        .iter()
        .map(|recipient| (recipient.recipient_event_id, recipient.public_key))
        .collect::<Vec<_>>();
    create_key_rotation_event_with_selected_recipients_at(
        conn,
        recorded_by,
        frontier_refs,
        key_bytes,
        &recipient_keys,
        created_at_ms,
    )
}

fn load_key_secret_bytes(
    conn: &Connection,
    recorded_by: &str,
    key_event_id: &EventId,
) -> Result<[u8; 32], Box<dyn std::error::Error + Send + Sync>> {
    let key_event_b64 = event_id_to_base64(key_event_id);
    let key_bytes: Vec<u8> = conn.query_row(
        "SELECT key_bytes
         FROM key_secrets
         WHERE recorded_by = ?1
           AND event_id = ?2
         LIMIT 1",
        rusqlite::params![recorded_by, &key_event_b64],
        |row| row.get(0),
    )?;
    if key_bytes.len() != 32 {
        return Err("corrupt key_bytes in key_secrets".into());
    }
    let mut plaintext_key = [0u8; 32];
    plaintext_key.copy_from_slice(&key_bytes);
    Ok(plaintext_key)
}

fn key_shared_exists_for_delivery_target(
    conn: &Connection,
    recorded_by: &str,
    key_event_id: &EventId,
    frontier_hash: &EventId,
    delivery_target: &EventId,
    recipient_event_id: &EventId,
) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
    let exists: bool = conn.query_row(
        "SELECT EXISTS(
             SELECT 1
             FROM key_shared
             WHERE recorded_by = ?1
               AND key_event_id = ?2
               AND frontier_hash = ?3
               AND delivery_target_id = ?4
               AND recipient_event_id = ?5
         )",
        rusqlite::params![
            recorded_by,
            event_id_to_base64(key_event_id),
            event_id_to_base64(frontier_hash),
            event_id_to_base64(delivery_target),
            event_id_to_base64(recipient_event_id),
        ],
        |row| row.get(0),
    )?;
    Ok(exists)
}

fn emit_key_shared_for_invite_target(
    conn: &Connection,
    recorded_by: &str,
    sender_peer_shared_key: &SigningKey,
    sender_peer_shared_event_id: &EventId,
    key_event_id: &EventId,
    frontier_refs: &[EventId],
    recipient_event_id: &EventId,
    unwrap_key_event_id: &EventId,
    recipient_public_key: &[u8; 32],
) -> Result<Option<EventId>, Box<dyn std::error::Error + Send + Sync>> {
    let plaintext_key = load_key_secret_bytes(conn, recorded_by, key_event_id)?;
    let recipient_vk = VerifyingKey::from_bytes(recipient_public_key)
        .map_err(|err| format!("invalid invite public key: {err}"))?;
    let frontier_hash = frontier_hash_from_refs(frontier_refs);
    let delivery_target = crate::event_modules::key_request::delivery_target_id(
        key_event_id,
        &frontier_hash,
        recipient_event_id,
        unwrap_key_event_id,
    );
    if key_shared_exists_for_delivery_target(
        conn,
        recorded_by,
        key_event_id,
        &frontier_hash,
        &delivery_target,
        recipient_event_id,
    )? {
        return Ok(None);
    }

    let wrapped = wrap_key_for_recipient(sender_peer_shared_key, &recipient_vk, &plaintext_key);
    let slots = slotted_frontier_refs(frontier_refs)?;
    let event = ParsedEvent::KeyShared(KeySharedEvent {
        created_at_ms: current_timestamp_ms_u64(),
        key_event_id: *key_event_id,
        frontier_count: frontier_refs.len() as u8,
        frontier_ref_1: slots[0],
        frontier_ref_2: slots[1],
        frontier_ref_3: slots[2],
        frontier_ref_4: slots[3],
        frontier_hash,
        delivery_target_id: delivery_target,
        recipient_event_id: *recipient_event_id,
        unwrap_key_event_id: *unwrap_key_event_id,
        wrapped_key: wrapped,
    });
    let created = event_id_or_blocked(create_signed_event(
        conn,
        recorded_by,
        sender_peer_shared_event_id,
        &event,
        sender_peer_shared_key,
    ))?;
    Ok(Some(created))
}

fn collect_active_invite_targets_from_table(
    conn: &Connection,
    recorded_by: &str,
    table: &str,
    cutoff_ms: i64,
) -> Result<Vec<InviteShareTarget>, Box<dyn std::error::Error + Send + Sync>> {
    let sql = format!(
        "SELECT inv.event_id, inv.public_key, sec.event_id, e.created_at
         FROM {table} inv
         JOIN invite_secrets sec
           ON sec.recorded_by = inv.recorded_by
          AND sec.invite_event_id = inv.event_id
         JOIN events e
           ON e.event_id = inv.event_id
         WHERE inv.recorded_by = ?1
           AND e.created_at >= ?2
         ORDER BY e.created_at DESC, inv.event_id DESC"
    );
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map(rusqlite::params![recorded_by, cutoff_ms], |row| {
        Ok((
            crate::db::sql_types::get_text(row, 0)?,
            crate::db::sql_types::get_blob(row, 1)?,
            crate::db::sql_types::get_text(row, 2)?,
            row.get::<_, i64>(3)?,
        ))
    })?;
    let mut out = Vec::new();
    for row in rows {
        let (invite_b64, public_key_blob, unwrap_b64, created_at_ms) = row?;
        out.push(InviteShareTarget {
            invite_event_id: parse_event_id_b64(&invite_b64, "invite.event_id")?,
            public_key: parse_blob_event_id(public_key_blob, "invite.public_key")?,
            unwrap_key_event_id: parse_event_id_b64(&unwrap_b64, "invite_secret.event_id")?,
            created_at_ms,
        });
    }
    Ok(out)
}

fn active_invite_targets_with_local_secrets(
    conn: &Connection,
    recorded_by: &str,
    now_ms: i64,
) -> Result<Vec<InviteShareTarget>, Box<dyn std::error::Error + Send + Sync>> {
    let cutoff_ms = now_ms.saturating_sub(INVITE_ACTIVE_TTL_MS);
    let mut out =
        collect_active_invite_targets_from_table(conn, recorded_by, "user_invites", cutoff_ms)?;
    out.extend(collect_active_invite_targets_from_table(
        conn,
        recorded_by,
        "device_invites",
        cutoff_ms,
    )?);
    out.sort_by(|left, right| {
        right.created_at_ms.cmp(&left.created_at_ms).then_with(|| {
            event_id_to_base64(&right.invite_event_id)
                .cmp(&event_id_to_base64(&left.invite_event_id))
        })
    });
    Ok(out)
}

fn emit_recent_key_history_for_invite(
    conn: &Connection,
    recorded_by: &str,
    sender_peer_shared_key: &SigningKey,
    sender_peer_shared_event_id: &EventId,
    invite_event_id: &EventId,
    invite_public_key: &[u8; 32],
    unwrap_key_event_id: &EventId,
    history_cap: usize,
) -> Result<usize, Box<dyn std::error::Error + Send + Sync>> {
    let mut emitted = 0usize;
    for rotation in recent_key_rotations_for_peer(conn, recorded_by, history_cap)? {
        if emit_key_shared_for_invite_target(
            conn,
            recorded_by,
            sender_peer_shared_key,
            sender_peer_shared_event_id,
            &rotation.key_event_id,
            &rotation.frontier_refs,
            invite_event_id,
            unwrap_key_event_id,
            invite_public_key,
        )?
        .is_some()
        {
            emitted = emitted.saturating_add(1);
        }
    }
    Ok(emitted)
}

pub(crate) fn emit_proactive_key_shares_for_active_invites(
    conn: &Connection,
    recorded_by: &str,
    sender_peer_shared_key: &SigningKey,
    sender_peer_shared_event_id: &EventId,
    key_event_id: &EventId,
    frontier_refs: &[EventId],
) -> Result<usize, Box<dyn std::error::Error + Send + Sync>> {
    let mut emitted = 0usize;
    for target in active_invite_targets_with_local_secrets(
        conn,
        recorded_by,
        current_timestamp_ms_u64() as i64,
    )? {
        if emit_key_shared_for_invite_target(
            conn,
            recorded_by,
            sender_peer_shared_key,
            sender_peer_shared_event_id,
            key_event_id,
            frontier_refs,
            &target.invite_event_id,
            &target.unwrap_key_event_id,
            &target.public_key,
        )?
        .is_some()
        {
            emitted = emitted.saturating_add(1);
        }
    }
    Ok(emitted)
}

pub(crate) fn rotate_content_key_for_peer(
    conn: &Connection,
    recorded_by: &str,
) -> Result<RotateContentKeyResult, Box<dyn std::error::Error + Send + Sync>> {
    rotate_content_key_for_peer_at(conn, recorded_by, current_timestamp_ms_u64())
}

pub(crate) fn rotate_content_key_for_peer_at(
    conn: &Connection,
    recorded_by: &str,
    created_at_ms: u64,
) -> Result<RotateContentKeyResult, Box<dyn std::error::Error + Send + Sync>> {
    let frontier_refs = current_removal_frontier_for_peer(conn, recorded_by)?;
    let mut rng = rand::thread_rng();
    let mut content_key_bytes = [0u8; 32];
    rng.fill_bytes(&mut content_key_bytes);

    let rotation_event_id = create_key_rotation_event_with_key_bytes_at(
        conn,
        recorded_by,
        &frontier_refs,
        content_key_bytes,
        created_at_ms,
    )?;

    Ok(RotateContentKeyResult {
        key_event_id: rotation_event_id,
        rotation_event_id,
        proactive_share_count: 0,
    })
}

// ---------------------------------------------------------------------------
// Data types (shared across modules)
// ---------------------------------------------------------------------------

/// Result of accepting a user invite.
pub struct JoinChain {
    pub user_event_id: EventId,
    pub user_key: SigningKey,
    pub device_invite_event_id: EventId,
    pub device_invite_key: SigningKey,
    pub endpoint_shared_event_id: EventId,
    pub peer_shared_event_id: EventId,
    pub peer_shared_key: SigningKey,
    pub invite_accepted_event_id: EventId,
    pub content_key_event_id: Option<EventId>,
}

/// Result of accepting a device link invite.
pub struct LinkChain {
    pub endpoint_shared_event_id: EventId,
    pub peer_shared_event_id: EventId,
    pub peer_shared_key: SigningKey,
    pub invite_accepted_event_id: EventId,
}

/// Data needed to transfer an invite between tenants.
#[derive(Clone)]
pub struct InviteData {
    pub invite_event_id: EventId,
    pub invite_key: SigningKey,
    pub workspace_id: EventId,
    pub invite_type: InviteType,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InviteType {
    User,
    DeviceLink { user_event_id: EventId },
}

/// Bootstrap context for invite creation. When provided, bootstrap_context
/// is written between event storage and projection so the projector can
/// emit trust commands.
pub struct InviteBootstrapContext<'a> {
    pub bootstrap_addrs: &'a [String],
    pub bootstrap_spki: &'a [u8; 32],
    pub relay_url: Option<&'a str>,
}

/// Derive the expected bootstrap transport SPKI fingerprint for an invitee from
/// invite signing key material.
pub(crate) fn expected_invite_bootstrap_spki_from_invite_key(
    invite_key: &SigningKey,
) -> Result<[u8; 32], Box<dyn std::error::Error + Send + Sync>> {
    let (cert_der, _) = generate_self_signed_cert_from_signing_key(invite_key)?;
    extract_spki_fingerprint(cert_der.as_ref())
}

// ---------------------------------------------------------------------------
// Reusable primitive helpers (pub(crate) for event-module command use)
// ---------------------------------------------------------------------------

/// Ensure the local tenant has at least one content key materialized.
/// Returns the canonical key_event_id to use in key-wrap and encrypted deps.
pub(crate) fn ensure_content_key_for_peer(
    conn: &Connection,
    recorded_by: &str,
) -> Result<EventId, Box<dyn std::error::Error + Send + Sync>> {
    ensure_content_key_for_peer_at(conn, recorded_by, current_timestamp_ms_u64())
}

pub(crate) fn ensure_content_key_for_peer_at(
    conn: &Connection,
    recorded_by: &str,
    created_at_ms: u64,
) -> Result<EventId, Box<dyn std::error::Error + Send + Sync>> {
    let frontier_refs = current_removal_frontier_for_peer(conn, recorded_by)?;
    if let Some(existing) = latest_content_key_for_frontier(conn, recorded_by, &frontier_refs)? {
        return Ok(existing);
    }
    if frontier_refs.is_empty() {
        if let Some(existing) = latest_materialized_key_for_peer(conn, recorded_by)? {
            if let Some(existing_rotation) = existing_rotation_for_frontier(conn, recorded_by, &[])? {
                return Ok(existing_rotation);
            }
            let key_bytes = load_key_secret_bytes(conn, recorded_by, &existing)?;
            return create_key_rotation_event_with_key_bytes_at(
                conn,
                recorded_by,
                &[],
                key_bytes,
                created_at_ms,
            );
        }
    }
    rotate_content_key_for_peer_at(conn, recorded_by, created_at_ms)
        .map(|result| result.key_event_id)
}

/// Emit the most recent capped key history for an invite target.
/// The invite's deterministic invite_secret is stored locally first, then
/// recent frontier-bound `key_shared` deliveries are emitted as separate events.
pub(crate) fn wrap_content_key_for_invite(
    conn: &Connection,
    recorded_by: &str,
    sender_peer_shared_key: &SigningKey,
    sender_peer_shared_event_id: &EventId,
    invite_key: &SigningKey,
    invite_event_id: &EventId,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let _ = ensure_content_key_for_peer(conn, recorded_by)?;
    let invite_secret_event_id =
        store_invite_secret(conn, recorded_by, invite_event_id, invite_key)?;
    let _ = emit_recent_key_history_for_invite(
        conn,
        recorded_by,
        sender_peer_shared_key,
        sender_peer_shared_event_id,
        invite_event_id,
        &invite_key.verifying_key().to_bytes(),
        &invite_secret_event_id,
        INVITE_HISTORY_KEY_CAP,
    )?;
    Ok(())
}

/// Persist local invite private key material as deterministic invite_secret.
/// Returns the deterministic invite_secret event id.
pub(crate) fn store_invite_secret(
    conn: &Connection,
    recorded_by: &str,
    invite_event_id: &EventId,
    invite_key: &SigningKey,
) -> Result<EventId, Box<dyn std::error::Error + Send + Sync>> {
    let private_key = invite_key.to_bytes();
    let expected = crate::event_modules::invite_secret::deterministic_invite_secret_event_id(
        invite_event_id,
        &private_key,
    );
    let evt = crate::event_modules::invite_secret::deterministic_invite_secret_event(
        *invite_event_id,
        private_key,
    );
    let created = event_id_or_blocked(create_event(conn, recorded_by, &evt))?;
    if created != expected {
        return Err("invite_secret event_id mismatch for deterministic key material".into());
    }
    Ok(created)
}

fn create_invite_event_with_optional_bootstrap_context(
    conn: &Connection,
    recorded_by: &str,
    signer_event_id: &EventId,
    event: &ParsedEvent,
    signer: &SigningKey,
    workspace_id: &EventId,
    bootstrap_ctx: Option<&InviteBootstrapContext<'_>>,
) -> Result<EventId, Box<dyn std::error::Error + Send + Sync>> {
    if let Some(ctx) = bootstrap_ctx {
        Ok(store_signed_event_then_project(
            conn,
            recorded_by,
            signer_event_id,
            event,
            signer,
            |conn, event_id| {
                let eid_b64 = event_id_to_base64(event_id);
                let ws_b64 = event_id_to_base64(workspace_id);
                for addr in ctx.bootstrap_addrs {
                    crate::db::transport_trust::append_bootstrap_context(
                        conn,
                        recorded_by,
                        &eid_b64,
                        &ws_b64,
                        addr,
                        ctx.bootstrap_spki,
                    )?;
                }
                if ctx.bootstrap_addrs.is_empty() {
                    crate::db::transport_trust::append_bootstrap_context(
                        conn,
                        recorded_by,
                        &eid_b64,
                        &ws_b64,
                        ctx.relay_url.unwrap_or(""),
                        ctx.bootstrap_spki,
                    )?;
                }
                Ok(())
            },
        )?)
    } else {
        Ok(create_signed_event(
            conn,
            recorded_by,
            signer_event_id,
            event,
            signer,
        )?)
    }
}

/// Create an ongoing user invite signed by an admin peer_shared signer.
pub(crate) fn create_user_invite_events_as_admin(
    conn: &Connection,
    recorded_by: &str,
    admin_peer_shared_key: &SigningKey,
    admin_peer_shared_event_id: &EventId,
    admin_event_id: &EventId,
    workspace_id: &EventId,
    bootstrap_ctx: Option<&InviteBootstrapContext<'_>>,
) -> Result<InviteData, Box<dyn std::error::Error + Send + Sync>> {
    create_user_invite_events_with_signer(
        conn,
        recorded_by,
        admin_peer_shared_key,
        admin_peer_shared_event_id,
        admin_event_id,
        workspace_id,
        Some(admin_peer_shared_key),
        Some(admin_peer_shared_event_id),
        bootstrap_ctx,
    )
}

fn create_user_invite_events_with_signer(
    conn: &Connection,
    recorded_by: &str,
    signer_key: &SigningKey,
    signer_event_id: &EventId,
    authority_event_id: &EventId,
    workspace_id: &EventId,
    _sender_peer_shared_key: Option<&SigningKey>,
    sender_peer_shared_event_id: Option<&EventId>,
    bootstrap_ctx: Option<&InviteBootstrapContext<'_>>,
) -> Result<InviteData, Box<dyn std::error::Error + Send + Sync>> {
    let mut rng = rand::thread_rng();
    let invite_key = SigningKey::generate(&mut rng);
    let invite_pub = invite_key.verifying_key().to_bytes();
    let key_history_event_id = if sender_peer_shared_event_id.is_some() {
        let _ = ensure_content_key_for_peer(conn, recorded_by)?;
        create_key_history_event_for_public_key(
            conn,
            recorded_by,
            signer_key,
            signer_event_id,
            &invite_pub,
            current_timestamp_ms_u64(),
            INVITE_HISTORY_KEY_CAP,
        )?
    } else {
        NO_KEY_HISTORY_EVENT_ID
    };

    let evt = ParsedEvent::UserInvite(UserInviteEvent {
        created_at_ms: current_timestamp_ms_u64(),
        public_key: invite_pub,
        workspace_id: *workspace_id,
        authority_event_id: *authority_event_id,
        key_history_event_id,
    });

    let invite_event_id = create_invite_event_with_optional_bootstrap_context(
        conn,
        recorded_by,
        signer_event_id,
        &evt,
        signer_key,
        workspace_id,
        bootstrap_ctx,
    )?;

    let _ = store_invite_secret(conn, recorded_by, &invite_event_id, &invite_key)?;

    Ok(InviteData {
        invite_event_id,
        invite_key,
        workspace_id: *workspace_id,
        invite_type: InviteType::User,
    })
}

/// Create an ongoing device-link invite signed by a peer_shared signer for the
/// signer's own user.
pub(crate) fn create_device_link_invite_events_for_user(
    conn: &Connection,
    recorded_by: &str,
    peer_shared_key: &SigningKey,
    peer_shared_event_id: &EventId,
    user_event_id: &EventId,
    workspace_id: &EventId,
    bootstrap_ctx: Option<&InviteBootstrapContext<'_>>,
) -> Result<InviteData, Box<dyn std::error::Error + Send + Sync>> {
    create_device_link_invite_events_with_signer(
        conn,
        recorded_by,
        peer_shared_key,
        peer_shared_event_id,
        user_event_id,
        user_event_id,
        workspace_id,
        bootstrap_ctx,
    )
}

fn create_device_link_invite_events_with_signer(
    conn: &Connection,
    recorded_by: &str,
    signer_key: &SigningKey,
    signer_event_id: &EventId,
    authority_event_id: &EventId,
    user_event_id: &EventId,
    workspace_id: &EventId,
    bootstrap_ctx: Option<&InviteBootstrapContext<'_>>,
) -> Result<InviteData, Box<dyn std::error::Error + Send + Sync>> {
    let mut rng = rand::thread_rng();
    let device_invite_key = SigningKey::generate(&mut rng);
    let device_invite_pub = device_invite_key.verifying_key().to_bytes();
    let _ = ensure_content_key_for_peer(conn, recorded_by)?;
    let key_history_event_id = create_key_history_event_for_public_key(
        conn,
        recorded_by,
        signer_key,
        signer_event_id,
        &device_invite_pub,
        current_timestamp_ms_u64(),
        INVITE_HISTORY_KEY_CAP,
    )?;

    let evt = ParsedEvent::DeviceInvite(DeviceInviteEvent {
        created_at_ms: current_timestamp_ms_u64(),
        public_key: device_invite_pub,
        authority_event_id: *authority_event_id,
        key_history_event_id,
    });

    let invite_event_id = create_invite_event_with_optional_bootstrap_context(
        conn,
        recorded_by,
        signer_event_id,
        &evt,
        signer_key,
        workspace_id,
        bootstrap_ctx,
    )?;

    let _ = store_invite_secret(conn, recorded_by, &invite_event_id, &device_invite_key)?;

    Ok(InviteData {
        invite_event_id,
        invite_key: device_invite_key,
        workspace_id: *workspace_id,
        invite_type: InviteType::DeviceLink {
            user_event_id: *user_event_id,
        },
    })
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------
