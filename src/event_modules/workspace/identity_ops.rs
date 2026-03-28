//! Identity primitives and helpers.
//!
//! This module owns reusable crypto/data helpers for identity operations.
//! Workflow orchestration (event creation sequences, invite flows) is owned
//! by `event_modules::workspace::commands`.

use ed25519_dalek::{SigningKey, VerifyingKey};
use rusqlite::{Connection, OptionalExtension};

use crate::crypto::{event_id_from_base64, event_id_to_base64, EventId};
use crate::event_modules::key_rotation::KeyRotationEvent;
use crate::event_modules::removal::{
    canonicalize_frontier_refs, frontier_hash_from_refs, frontier_refs_from_slots,
    MAX_REMOVAL_FRONTIER_REFS,
};
use crate::event_modules::*;
use crate::projection::create::{
    create_event_synchronous, create_signed_event_synchronous, event_id_or_blocked,
    store_signed_event_then_project,
};
use crate::projection::encrypted::wrap_key_for_recipient;
use crate::state::db::queue::current_timestamp_ms_u64;
use crate::transport::{extract_spki_fingerprint, generate_self_signed_cert_from_signing_key};

pub const INVITE_HISTORY_KEY_CAP: usize = 100;
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
            created_at_ms: current_timestamp_ms_u64(),
            public_key: peer_key.verifying_key().to_bytes(),
        });
        event_id_or_blocked(create_event_synchronous(conn, recorded_by, &tenant_evt))?
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
    let created = create_event_synchronous(conn, recorded_by, &sk_evt)?;
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
            row.get::<_, String>(0)?,
            row.get::<_, u8>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, String>(4)?,
            row.get::<_, String>(5)?,
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

fn current_removal_frontier_for_peer(
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
        row.get::<_, String>(0)
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

fn latest_materialized_key_for_peer(
    conn: &Connection,
    recorded_by: &str,
) -> Result<Option<EventId>, Box<dyn std::error::Error + Send + Sync>> {
    let existing: Option<String> = conn
        .query_row(
            "SELECT ks.event_id
             FROM key_secrets ks
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
            "SELECT kr.key_event_id
             FROM key_rotations kr
             JOIN key_secrets ks
               ON ks.recorded_by = kr.recorded_by
              AND ks.event_id = kr.key_event_id
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
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    existing
        .map(|eid_b64| parse_event_id_b64(&eid_b64, "key_rotations.key_event_id"))
        .transpose()
}

fn ensure_rotation_for_key_frontier(
    conn: &Connection,
    recorded_by: &str,
    key_event_id: &EventId,
    frontier_refs: &[EventId],
) -> Result<EventId, Box<dyn std::error::Error + Send + Sync>> {
    let key_event_id_b64 = event_id_to_base64(key_event_id);
    let slots = slotted_frontier_refs(frontier_refs)?;
    let frontier_hash = frontier_hash_from_refs(frontier_refs);
    if let Some(existing) = conn
        .query_row(
            "SELECT event_id
             FROM key_rotations
             WHERE recorded_by = ?1
               AND key_event_id = ?2
               AND frontier_hash = ?3
               AND frontier_count = ?4
               AND frontier_ref_1 = ?5
               AND frontier_ref_2 = ?6
               AND frontier_ref_3 = ?7
               AND frontier_ref_4 = ?8
             ORDER BY rowid DESC
             LIMIT 1",
            rusqlite::params![
                recorded_by,
                &key_event_id_b64,
                event_id_to_base64(&frontier_hash),
                frontier_refs.len() as i64,
                event_id_to_base64(&slots[0]),
                event_id_to_base64(&slots[1]),
                event_id_to_base64(&slots[2]),
                event_id_to_base64(&slots[3]),
            ],
            |row| row.get::<_, String>(0),
        )
        .ok()
    {
        return parse_event_id_b64(&existing, "key_rotations.event_id");
    }

    let authoring =
        crate::event_modules::workspace::load_local_authoring_context(conn, recorded_by)?;
    let event = ParsedEvent::KeyRotation(KeyRotationEvent {
        created_at_ms: current_timestamp_ms_u64(),
        key_event_id: *key_event_id,
        frontier_count: frontier_refs.len() as u8,
        frontier_ref_1: slots[0],
        frontier_ref_2: slots[1],
        frontier_ref_3: slots[2],
        frontier_ref_4: slots[3],
        frontier_hash,
        rotated_by: authoring.signer_event_id,
        signed_by: authoring.signer_event_id,
        signer_type: 5,
        signature: [0u8; 64],
    });

    Ok(create_signed_event_synchronous(
        conn,
        recorded_by,
        &event,
        &authoring.signing_key,
    )?)
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
        signed_by: *sender_peer_shared_event_id,
        signer_type: 5,
        signature: [0u8; 64],
    });
    let created = event_id_or_blocked(create_signed_event_synchronous(
        conn,
        recorded_by,
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
            row.get::<_, String>(0)?,
            row.get::<_, Vec<u8>>(1)?,
            row.get::<_, String>(2)?,
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
    let frontier_refs = current_removal_frontier_for_peer(conn, recorded_by)?;
    let mut rng = rand::thread_rng();
    let mut content_key_bytes = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rng, &mut content_key_bytes);

    let key_event_id = create_deterministic_key_secret_event(conn, recorded_by, content_key_bytes)?;
    let rotation_event_id =
        ensure_rotation_for_key_frontier(conn, recorded_by, &key_event_id, &frontier_refs)?;
    let authoring =
        crate::event_modules::workspace::load_local_authoring_context(conn, recorded_by)?;
    let proactive_share_count = emit_proactive_key_shares_for_active_invites(
        conn,
        recorded_by,
        &authoring.signing_key,
        &authoring.signer_event_id,
        &key_event_id,
        &frontier_refs,
    )?;

    Ok(RotateContentKeyResult {
        key_event_id,
        rotation_event_id,
        proactive_share_count,
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
    pub peer_shared_event_id: EventId,
    pub peer_shared_key: SigningKey,
    pub invite_accepted_event_id: EventId,
    pub content_key_event_id: Option<EventId>,
}

/// Result of accepting a device link invite.
pub struct LinkChain {
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
    let frontier_refs = current_removal_frontier_for_peer(conn, recorded_by)?;
    if let Some(existing) = latest_content_key_for_frontier(conn, recorded_by, &frontier_refs)? {
        return Ok(existing);
    }
    if frontier_refs.is_empty() {
        if let Some(existing) = latest_materialized_key_for_peer(conn, recorded_by)? {
            let _ = ensure_rotation_for_key_frontier(conn, recorded_by, &existing, &[])?;
            return Ok(existing);
        }
    }
    create_content_key(conn, recorded_by)
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
    let created = event_id_or_blocked(create_event_synchronous(conn, recorded_by, &evt))?;
    if created != expected {
        return Err("invite_secret event_id mismatch for deterministic key material".into());
    }
    Ok(created)
}

fn create_invite_event_with_optional_bootstrap_context(
    conn: &Connection,
    recorded_by: &str,
    event: &ParsedEvent,
    signer: &SigningKey,
    workspace_id: &EventId,
    bootstrap_ctx: Option<&InviteBootstrapContext<'_>>,
) -> Result<EventId, Box<dyn std::error::Error + Send + Sync>> {
    if let Some(ctx) = bootstrap_ctx {
        Ok(store_signed_event_then_project(
            conn,
            recorded_by,
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
                Ok(())
            },
        )?)
    } else {
        Ok(create_signed_event_synchronous(
            conn,
            recorded_by,
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
        5,
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
    signer_type: u8,
    workspace_id: &EventId,
    sender_peer_shared_key: Option<&SigningKey>,
    sender_peer_shared_event_id: Option<&EventId>,
    bootstrap_ctx: Option<&InviteBootstrapContext<'_>>,
) -> Result<InviteData, Box<dyn std::error::Error + Send + Sync>> {
    let mut rng = rand::thread_rng();
    let invite_key = SigningKey::generate(&mut rng);
    let invite_pub = invite_key.verifying_key().to_bytes();

    let evt = ParsedEvent::UserInvite(UserInviteEvent {
        created_at_ms: current_timestamp_ms_u64(),
        public_key: invite_pub,
        workspace_id: *workspace_id,
        authority_event_id: *authority_event_id,
        signed_by: *signer_event_id,
        signer_type,
        signature: [0u8; 64],
    });

    let invite_event_id = create_invite_event_with_optional_bootstrap_context(
        conn,
        recorded_by,
        &evt,
        signer_key,
        workspace_id,
        bootstrap_ctx,
    )?;

    if let (Some(ps_key), Some(ps_eid)) = (sender_peer_shared_key, sender_peer_shared_event_id) {
        wrap_content_key_for_invite(
            conn,
            recorded_by,
            ps_key,
            ps_eid,
            &invite_key,
            &invite_event_id,
        )?;
    }

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
        5,
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
    signer_type: u8,
    user_event_id: &EventId,
    workspace_id: &EventId,
    bootstrap_ctx: Option<&InviteBootstrapContext<'_>>,
) -> Result<InviteData, Box<dyn std::error::Error + Send + Sync>> {
    let mut rng = rand::thread_rng();
    let device_invite_key = SigningKey::generate(&mut rng);
    let device_invite_pub = device_invite_key.verifying_key().to_bytes();

    let evt = ParsedEvent::DeviceInvite(DeviceInviteEvent {
        created_at_ms: current_timestamp_ms_u64(),
        public_key: device_invite_pub,
        authority_event_id: *authority_event_id,
        signed_by: *signer_event_id,
        signer_type,
        signature: [0u8; 64],
    });

    let invite_event_id = create_invite_event_with_optional_bootstrap_context(
        conn,
        recorded_by,
        &evt,
        signer_key,
        workspace_id,
        bootstrap_ctx,
    )?;

    // Linked devices need the same workspace content key as user invitees so
    // they can decrypt preexisting encrypted content immediately after replay.
    wrap_content_key_for_invite(
        conn,
        recorded_by,
        signer_key,
        signer_event_id,
        &device_invite_key,
        &invite_event_id,
    )?;

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

/// Generate a random 32-byte content secret key and create a local Secret event.
fn create_content_key(
    conn: &Connection,
    recorded_by: &str,
) -> Result<EventId, Box<dyn std::error::Error + Send + Sync>> {
    Ok(rotate_content_key_for_peer(conn, recorded_by)?.key_event_id)
}
