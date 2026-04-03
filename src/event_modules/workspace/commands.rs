//! Workspace lifecycle commands.
//!
//! These commands own the event-domain logic for workspace membership operations:
//! - Creating a new workspace (full identity chain bootstrap)
//! - Joining a workspace as a new user (invite acceptance)
//! - Adding a new device to an existing workspace (device-link acceptance)
//! - Creating user invites and device-link invites
//!
//! Service.rs calls these for event-domain work; transport/sync orchestration
//! stays in service.

use ed25519_dalek::SigningKey;
use rusqlite::{Connection, OptionalExtension};

use super::identity_ops::{self as ops, InviteBootstrapContext, JoinChain, LinkChain};
use std::collections::HashSet;

use crate::crypto::EventId;
use crate::crypto::{event_id_from_base64, event_id_to_base64};
use crate::db::store::insert_recorded_event_checked;
use crate::event_modules::{
    peer_secret::PeerSecretEvent, AdminEvent, DeviceInviteEvent, InviteAcceptedEvent, ParsedEvent,
    PeerSharedEvent, UserEvent, UserInviteEvent, WorkspaceEvent,
};
use crate::projection::apply::project_one;
use crate::projection::create::{
    create_event_staged, create_event_synchronous, create_signed_event_synchronous,
    event_id_or_blocked, project_event,
};
use crate::state::db::queue::current_timestamp_ms_u64;
use crate::state::live_hints::{self, LiveHintEvent};
use crate::transport::ensure_daemon_identity;

fn index_endpoint_shared_for_workspace(
    db: &Connection,
    recorded_by: &str,
    workspace_id: &EventId,
    endpoint_shared_event_id: &EventId,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let endpoint_shared_event_id_b64 = event_id_to_base64(endpoint_shared_event_id);
    let workspace_id_b64 = event_id_to_base64(workspace_id);
    let created_at_ms: i64 = db.query_row(
        "SELECT created_at
         FROM events
         WHERE event_id = ?1
           AND event_type = 'endpoint_shared'
           AND share_scope = 'shared'
         LIMIT 1",
        rusqlite::params![&endpoint_shared_event_id_b64],
        |row| row.get(0),
    )?;
    crate::db::store::insert_shared_event_index_entry_if_shared(
        db,
        crate::event_modules::ShareScope::Shared,
        created_at_ms,
        endpoint_shared_event_id,
        &workspace_id_b64,
    )?;
    crate::state::shared_workspace_fanout::fanout_shared_event_immediate(
        db,
        recorded_by,
        &workspace_id_b64,
        endpoint_shared_event_id,
    )?;
    crate::state::live_hints::publish_from_connection(
        db,
        &[LiveHintEvent {
            tenant_id: recorded_by.to_string(),
            event_id: *endpoint_shared_event_id,
            source_peer_id: None,
        }],
    );
    Ok(())
}

/// In a shared DB, sibling tenants can already have the workspace's shared
/// event history in `events`/`shared_event_index` even though this tenant has not yet
/// projected it into its own `valid_events` scope. Replay those shared events
/// locally so same-workspace joins converge without waiting for a redundant
/// network fetch that negentropy will not request.
///
/// Only events already projected as valid by at least one existing workspace
/// sibling are replayed. This keeps seed replay aligned with same-DB fanout
/// behavior without needing a redundant network fetch.
fn replay_existing_workspace_shared_events_for_tenant(
    db: &Connection,
    recorded_by: &str,
    workspace_id: &EventId,
) -> Result<usize, Box<dyn std::error::Error + Send + Sync>> {
    let workspace_id_b64 = event_id_to_base64(workspace_id);

    // Source 1: Events validated by at least one existing workspace sibling.
    let mut ve_stmt = db.prepare(
        "SELECT DISTINCT ve.event_id
         FROM valid_events ve
         JOIN invites_accepted ia
           ON ia.recorded_by = ve.peer_id AND ia.workspace_id = ?1
         JOIN events e
           ON e.event_id = ve.event_id AND e.share_scope = 'shared'
         WHERE ve.peer_id <> ?2
         ORDER BY e.created_at ASC, ve.event_id ASC",
    )?;
    let mut seen: HashSet<EventId> = HashSet::new();
    let mut event_ids: Vec<EventId> = Vec::new();
    for row in ve_stmt.query_map(rusqlite::params![&workspace_id_b64, recorded_by], |row| {
        row.get::<_, String>(0)
    })? {
        if let Some(eid) = row.ok().and_then(|b64| event_id_from_base64(&b64)) {
            if seen.insert(eid) {
                event_ids.push(eid);
            }
        }
    }

    // Source 2: Canonical shared blobs in shared_event_index that siblings haven't
    // projected yet (e.g. blocked on key_secret). These are needed because
    // the new tenant's projector may succeed where siblings are still
    // waiting (e.g. key_secret materializes via cascade during this replay).
    let mut ni_stmt = db.prepare(
        "SELECT ni.id
         FROM shared_event_index ni
         WHERE ni.workspace_id = ?1
         ORDER BY ni.ts ASC, ni.id ASC",
    )?;
    for row in ni_stmt.query_map(rusqlite::params![&workspace_id_b64], |row| {
        row.get::<_, Vec<u8>>(0)
    })? {
        let blob = match row {
            Ok(b) => b,
            Err(_) => continue,
        };
        if blob.len() != 32 {
            continue;
        }
        let mut eid = [0u8; 32];
        eid.copy_from_slice(&blob);
        if seen.contains(&eid) {
            continue;
        }
        let eid_b64 = event_id_to_base64(&eid);
        let event_type: Option<String> = db
            .query_row(
                "SELECT event_type
                 FROM events
                 WHERE event_id = ?1
                 LIMIT 1",
                rusqlite::params![&eid_b64],
                |row| row.get(0),
            )
            .ok();
        let has_eligible_recorder = if event_type.as_deref() == Some("endpoint_shared") {
            true
        } else {
            db.query_row(
                "SELECT EXISTS (
                    SELECT 1 FROM recorded_events re
                    JOIN invites_accepted ia
                      ON ia.recorded_by = re.peer_id AND ia.workspace_id = ?1
                    WHERE re.event_id = ?2
                      AND re.peer_id <> ?3
                )",
                rusqlite::params![&workspace_id_b64, &eid_b64, recorded_by],
                |row| row.get(0),
            )
            .unwrap_or(false)
        };
        if has_eligible_recorder {
            seen.insert(eid);
            event_ids.push(eid);
        }
    }

    let pq = crate::state::db::project_queue::ProjectQueue::new(db);
    let recorded_at = current_timestamp_ms_u64() as i64;
    let publish_after_commit = db.is_autocommit();
    let mut live_hints = Vec::new();
    let replay_targets: Vec<(EventId, String)> = event_ids
        .iter()
        .map(|event_id| {
            let event_id_b64 = event_id_to_base64(event_id);
            let endpoint_id = db
                .query_row(
                    "SELECT endpoint_id
                     FROM endpoints_shared
                     WHERE event_id = ?1
                     LIMIT 1",
                    rusqlite::params![&event_id_b64],
                    |row| row.get::<_, String>(0),
                )
                .optional()?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>((
                *event_id,
                endpoint_id.unwrap_or_else(|| recorded_by.to_string()),
            ))
        })
        .collect::<Result<Vec<_>, _>>()?;

    // Phase 1: Durably record and enqueue ALL events before projecting any.
    // Wrapped in a savepoint so a crash mid-loop cannot leave partial
    // recorded_events without matching project_queue entries.
    // Uses SAVEPOINT (not BEGIN) to nest safely inside caller transactions.
    db.execute_batch("SAVEPOINT replay_seed")?;
    for (event_id, replay_recorded_by) in &replay_targets {
        if insert_recorded_event_checked(
            db,
            replay_recorded_by,
            event_id,
            recorded_at,
            "same_workspace_seed",
        )? {
            if replay_recorded_by == recorded_by {
                live_hints.push(LiveHintEvent {
                    tenant_id: recorded_by.to_string(),
                    event_id: *event_id,
                    source_peer_id: None,
                });
            }
        }
        let event_id_b64 = event_id_to_base64(event_id);
        let _ = pq.enqueue(replay_recorded_by, &event_id_b64);
    }
    db.execute_batch("RELEASE replay_seed")?;
    if publish_after_commit {
        live_hints::publish_from_connection(db, &live_hints);
    }

    // Phase 2: Project inline and clean up queue entries.
    // Blocked events (e.g. encrypted events whose key_secret hasn't been
    // replayed yet) are tracked by the blocked_events/cascade system, so
    // mark_done is safe — cascade will retry when the dependency arrives.
    // Rejected events are left in the queue for startup drain retry to
    // handle transient failures that may resolve with more context.
    let mut replayed = 0usize;
    for (event_id, replay_recorded_by) in &replay_targets {
        let decision = project_one(db, replay_recorded_by, event_id)
            .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e.to_string().into() })?;
        let event_id_b64 = event_id_to_base64(event_id);
        match decision {
            crate::projection::decision::ProjectionDecision::Valid
            | crate::projection::decision::ProjectionDecision::AlreadyProcessed
            | crate::projection::decision::ProjectionDecision::Block { .. } => {
                let _ = pq.mark_done(replay_recorded_by, &event_id_b64);
                replayed += 1;
            }
            crate::projection::decision::ProjectionDecision::Reject { .. } => {
                // Leave in project_queue for startup drain retry.
            }
        }
    }

    Ok(replayed)
}

/// Emit a peer_secret event for the given signer identity.
/// The event is projected into `peer_secrets` via the projector.
fn emit_peer_secret(
    db: &Connection,
    recorded_by: &str,
    signer_event_id: &EventId,
    signing_key: &SigningKey,
) -> Result<EventId, Box<dyn std::error::Error + Send + Sync>> {
    emit_peer_secret_at(
        db,
        recorded_by,
        signer_event_id,
        signing_key,
        current_timestamp_ms_u64(),
    )
}

fn emit_peer_secret_at(
    db: &Connection,
    recorded_by: &str,
    signer_event_id: &EventId,
    signing_key: &SigningKey,
    created_at_ms: u64,
) -> Result<EventId, Box<dyn std::error::Error + Send + Sync>> {
    let evt = ParsedEvent::PeerSecret(PeerSecretEvent {
        created_at_ms,
        signer_event_id: *signer_event_id,
        private_key_bytes: signing_key.to_bytes(),
    });
    event_id_or_blocked(create_event_synchronous(db, recorded_by, &evt))
        .map_err(|e| format!("emit peer_secret failed: {}", e).into())
}

// ─── Result types ───

/// Result of creating a new workspace (full identity chain bootstrap).
pub struct CreateWorkspaceResult {
    pub workspace_id: EventId,
    pub endpoint_shared_event_id: EventId,
    pub peer_shared_event_id: EventId,
    pub peer_shared_key: SigningKey,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct CreateWorkspaceOptions {
    pub message_count: usize,
    pub network_age_ms: Option<u64>,
    pub end_at_ms: Option<u64>,
}

impl CreateWorkspaceOptions {
    fn resolved_network_age_ms(self) -> Option<u64> {
        match self.network_age_ms.filter(|age| *age > 0) {
            Some(age) => Some(age),
            None if self.message_count > 0 => {
                Some(crate::event_modules::message::commands::DEFAULT_GENERATE_HISTORY_SPAN_MS)
            }
            None => None,
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct TimestampCursor {
    next_ms: u64,
    end_ms: u64,
}

impl TimestampCursor {
    fn new(start_ms: u64, end_ms: u64) -> Self {
        let end_ms = end_ms.max(start_ms);
        Self {
            next_ms: start_ms,
            end_ms,
        }
    }

    fn take(&mut self) -> u64 {
        let ts = self.next_ms;
        self.next_ms = self.next_ms.saturating_add(1).min(self.end_ms);
        ts
    }

    fn peek(&self) -> u64 {
        self.next_ms.min(self.end_ms)
    }
}

fn next_created_at(cursor: &mut Option<TimestampCursor>) -> u64 {
    cursor
        .as_mut()
        .map(|timestamps| timestamps.take())
        .unwrap_or_else(current_timestamp_ms_u64)
}

/// Create a new workspace with a full identity chain.
///
/// Creates: Workspace → InviteAccepted (workspace binding) → UserInvite →
/// User → Admin → DeviceInvite → PeerShared + local signer secret +
/// content key material.
///
/// Returns the peer_shared event ID and signing key needed for transport
/// identity derivation.
///
/// Idempotent: if a local peer signer already exists, returns it without
/// creating new events.
pub fn create_workspace(
    db: &Connection,
    recorded_by: &str,
    workspace_name: &str,
    username: &str,
    device_name: &str,
) -> Result<CreateWorkspaceResult, Box<dyn std::error::Error + Send + Sync>> {
    create_workspace_with_options(
        db,
        recorded_by,
        workspace_name,
        username,
        device_name,
        CreateWorkspaceOptions::default(),
    )
}

pub fn create_workspace_with_options(
    db: &Connection,
    recorded_by: &str,
    workspace_name: &str,
    username: &str,
    device_name: &str,
    options: CreateWorkspaceOptions,
) -> Result<CreateWorkspaceResult, Box<dyn std::error::Error + Send + Sync>> {
    // Idempotent check: direct callers can reuse an explicit tenant scope by
    // passing its recorded_by. User-facing create-workspace paths pass an
    // unbound bootstrap alias so they always mint a new tenant.
    if let Some((eid, signing_key)) = load_local_peer_signer(db, recorded_by)? {
        let endpoint_shared_event_id =
            crate::event_modules::endpoint_shared::load_local_endpoint_shared(db)?
                .ok_or("endpoint_shared missing after local signer reuse")?
                .event_id;
        let endpoint_shared_event_id =
            crate::crypto::event_id_from_base64(&endpoint_shared_event_id)
                .ok_or("invalid endpoint_shared event_id")?;
        let workspace_id = db
            .query_row(
                "SELECT workspace_id
                 FROM invites_accepted
                 WHERE recorded_by = ?1
                 ORDER BY created_at ASC, event_id ASC
                 LIMIT 1",
                rusqlite::params![recorded_by],
                |row| row.get::<_, String>(0),
            )
            .ok()
            .and_then(|b64| crate::crypto::event_id_from_base64(&b64))
            .unwrap_or([0u8; 32]);
        return Ok(CreateWorkspaceResult {
            workspace_id,
            endpoint_shared_event_id,
            peer_shared_event_id: eid,
            peer_shared_key: signing_key,
        });
    }

    // Validate text field lengths upfront, before any events are created,
    // to prevent partial workspace creation if encoding would fail later.
    use super::super::layout::common::NAME_BYTES;
    if workspace_name.as_bytes().len() > NAME_BYTES {
        return Err(format!(
            "workspace name too long: {} bytes, max {}",
            workspace_name.as_bytes().len(),
            NAME_BYTES
        )
        .into());
    }
    if username.as_bytes().len() > NAME_BYTES {
        return Err(format!(
            "username too long: {} bytes, max {}",
            username.as_bytes().len(),
            NAME_BYTES
        )
        .into());
    }
    if device_name.as_bytes().len() > NAME_BYTES {
        return Err(format!(
            "device name too long: {} bytes, max {}",
            device_name.as_bytes().len(),
            NAME_BYTES
        )
        .into());
    }

    create_workspace_inner(db, workspace_name, username, device_name, options)
}

fn create_workspace_inner(
    db: &Connection,
    workspace_name: &str,
    username: &str,
    device_name: &str,
    options: CreateWorkspaceOptions,
) -> Result<CreateWorkspaceResult, Box<dyn std::error::Error + Send + Sync>> {
    let mut rng = rand::thread_rng();
    let end_at_ms = options.end_at_ms.unwrap_or_else(current_timestamp_ms_u64);
    let mut timestamps = options
        .resolved_network_age_ms()
        .map(|age| TimestampCursor::new(end_at_ms.saturating_sub(age), end_at_ms));
    let _ = ensure_daemon_identity(db)?;
    let endpoint_shared_event_id =
        crate::event_modules::endpoint_shared::load_local_endpoint_shared(db)?
            .ok_or("endpoint_shared missing after ensure_daemon_identity")?
            .event_id;
    let endpoint_shared_event_id = crate::crypto::event_id_from_base64(&endpoint_shared_event_id)
        .ok_or("invalid endpoint_shared event_id")?;

    // Pre-derive peer_id from PeerShared key so all events are written under
    // the correct recorded_by from the start (no finalize_identity needed).
    // Pure crypto derivation — transport cert is installed via projection when
    // the PeerShared PeerSecret is emitted in step 7.
    let peer_shared_key = SigningKey::generate(&mut rng);
    let derived_peer_id = hex::encode(crate::crypto::spki_fingerprint_from_ed25519_pubkey(
        &peer_shared_key.verifying_key().to_bytes(),
    ));

    // 1. Pre-compute workspace event_id for the local self-accept flow.
    let workspace_key = SigningKey::generate(&mut rng);
    let ws = ParsedEvent::Workspace(WorkspaceEvent {
        created_at_ms: next_created_at(&mut timestamps),
        public_key: workspace_key.verifying_key().to_bytes(),
        name: workspace_name.to_string(),
    });
    let ws_blob = crate::event_modules::encode_event(&ws)
        .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e.to_string().into() })?;
    let ws_eid = crate::crypto::hash_event(&ws_blob);

    // 2. Workspace event (staged — guard may block until invite_accepted projects)
    let ws_eid2 = create_event_staged(db, &derived_peer_id, &ws)?;
    assert_eq!(ws_eid, ws_eid2, "pre-computed workspace event_id mismatch");

    // 3. Ensure tenant root chain exists: tenant root, peer depends on tenant.
    let tenant_event_id = ops::ensure_local_tenant_event_at(
        db,
        &derived_peer_id,
        &peer_shared_key,
        next_created_at(&mut timestamps),
    )?;

    // 4. InviteAccepted (local event — becomes authoritative workspace binding).
    let ia = ParsedEvent::InviteAccepted(InviteAcceptedEvent {
        created_at_ms: next_created_at(&mut timestamps),
        tenant_event_id,
        invite_event_id: ws_eid,
        workspace_id: ws_eid,
    });
    let _ia_eid = create_event_synchronous(db, &derived_peer_id, &ia)?;
    project_event(db, &derived_peer_id, &ws_eid)
        .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e.to_string().into() })?;

    // 5. UserInvite (signed by workspace_key)
    let invite_key = SigningKey::generate(&mut rng);
    let uib = ParsedEvent::UserInvite(UserInviteEvent {
        created_at_ms: next_created_at(&mut timestamps),
        public_key: invite_key.verifying_key().to_bytes(),
        workspace_id: ws_eid,
        authority_event_id: ws_eid,
        signed_by: ws_eid,
        signer_type: 1,
        signature: [0u8; 64],
    });
    let uib_eid = create_signed_event_synchronous(db, &derived_peer_id, &uib, &workspace_key)?;

    // 7. User (signed by invite_key)
    let user_key = SigningKey::generate(&mut rng);
    let ub = ParsedEvent::User(UserEvent {
        created_at_ms: next_created_at(&mut timestamps),
        public_key: user_key.verifying_key().to_bytes(),
        username: username.to_string(),
        signed_by: uib_eid,
        signer_type: 2,
        signature: [0u8; 64],
    });
    let ub_eid = create_signed_event_synchronous(db, &derived_peer_id, &ub, &invite_key)?;

    // 8. Admin (bootstrap grant for creator user; signed by workspace_key)
    let admin_evt = ParsedEvent::Admin(AdminEvent {
        created_at_ms: next_created_at(&mut timestamps),
        public_key: user_key.verifying_key().to_bytes(),
        user_event_id: ub_eid,
        signed_by: ws_eid,
        signer_type: 1,
        signature: [0u8; 64],
    });
    let _admin_eid =
        create_signed_event_synchronous(db, &derived_peer_id, &admin_evt, &workspace_key)?;

    // 9. DeviceInvite (signed by user_key)
    let device_invite_key = SigningKey::generate(&mut rng);
    let dif = ParsedEvent::DeviceInvite(DeviceInviteEvent {
        created_at_ms: next_created_at(&mut timestamps),
        public_key: device_invite_key.verifying_key().to_bytes(),
        authority_event_id: ub_eid,
        signed_by: ub_eid,
        signer_type: 4,
        signature: [0u8; 64],
    });
    let dif_eid = create_signed_event_synchronous(db, &derived_peer_id, &dif, &user_key)?;

    // 10. PeerShared (signed by device_invite_key; key pre-generated above)
    let psf = ParsedEvent::PeerShared(PeerSharedEvent {
        created_at_ms: next_created_at(&mut timestamps),
        public_key: peer_shared_key.verifying_key().to_bytes(),
        user_event_id: ub_eid,
        endpoint_shared_event_id,
        device_name: device_name.to_string(),
        signed_by: dif_eid,
        signer_type: 3,
        signature: [0u8; 64],
    });
    let psf_eid = create_signed_event_synchronous(db, &derived_peer_id, &psf, &device_invite_key)?;
    index_endpoint_shared_for_workspace(db, &derived_peer_id, &ws_eid, &endpoint_shared_event_id)?;

    // 11. Emit peer_secret for peer_shared signer key only.
    // Transport identity is already installed, so all writes use derived_peer_id.
    emit_peer_secret_at(
        db,
        &derived_peer_id,
        &psf_eid,
        &peer_shared_key,
        next_created_at(&mut timestamps),
    )?;

    // 12. Seed deterministic local content-key material.
    let _ = ops::ensure_content_key_for_peer_at(
        db,
        &derived_peer_id,
        next_created_at(&mut timestamps),
    )?;

    if options.message_count > 0 {
        let start_at_ms = timestamps
            .as_ref()
            .map(TimestampCursor::peek)
            .unwrap_or(end_at_ms);
        let _ = crate::event_modules::message::commands::generate_messages_for_recorded_by_between(
            db,
            &derived_peer_id,
            options.message_count,
            start_at_ms,
            end_at_ms,
        )?;
    }

    Ok(CreateWorkspaceResult {
        workspace_id: ws_eid,
        endpoint_shared_event_id,
        peer_shared_event_id: psf_eid,
        peer_shared_key,
    })
}

// ─── 2. Join workspace as new user ───

/// Join a workspace by accepting a user invite.
///
/// Creates: InviteAccepted → User → DeviceInvite → PeerShared +
/// unwraps bootstrap content key.
///
/// Returns the JoinChain with keys/ids needed by service for transport setup.
/// Signer secrets are NOT emitted here — call `persist_join_peer_secret`
/// after push-back sync completes.
pub fn join_workspace_as_new_user(
    db: &Connection,
    recorded_by: &str,
    invite_key: &SigningKey,
    invite_event_id: &EventId,
    workspace_id: EventId,
    username: &str,
    device_name: &str,
    peer_shared_key: SigningKey,
) -> Result<JoinChain, Box<dyn std::error::Error + Send + Sync>> {
    // Validate text field lengths upfront to prevent partial creation.
    use super::super::layout::common::NAME_BYTES;
    if username.as_bytes().len() > NAME_BYTES {
        return Err(format!(
            "username too long: {} bytes, max {}",
            username.as_bytes().len(),
            NAME_BYTES
        )
        .into());
    }
    if device_name.as_bytes().len() > NAME_BYTES {
        return Err(format!(
            "device name too long: {} bytes, max {}",
            device_name.as_bytes().len(),
            NAME_BYTES
        )
        .into());
    }

    join_workspace_inner(
        db,
        recorded_by,
        invite_key,
        invite_event_id,
        workspace_id,
        username,
        device_name,
        peer_shared_key,
    )
}

fn join_workspace_inner(
    db: &Connection,
    recorded_by: &str,
    invite_key: &SigningKey,
    invite_event_id: &EventId,
    workspace_id: EventId,
    username: &str,
    device_name: &str,
    peer_shared_key: SigningKey,
) -> Result<JoinChain, Box<dyn std::error::Error + Send + Sync>> {
    let mut rng = rand::thread_rng();
    let _ = ensure_daemon_identity(db)?;
    let endpoint_shared_event_id =
        crate::event_modules::endpoint_shared::load_local_endpoint_shared(db)?
            .ok_or("endpoint_shared missing after ensure_daemon_identity")?
            .event_id;
    let endpoint_shared_event_id = crate::crypto::event_id_from_base64(&endpoint_shared_event_id)
        .ok_or("invalid endpoint_shared event_id")?;
    let tenant_event_id = ops::ensure_local_tenant_event(db, recorded_by, &peer_shared_key)?;

    // Persist deterministic invite_secret material. This is the key event
    // that key_shared depends on for unwrap projection.
    let _ = ops::store_invite_secret(db, recorded_by, invite_event_id, invite_key)?;

    // 1. InviteAccepted (local event) — binds accepted workspace, triggers guard cascade
    let ia_evt = ParsedEvent::InviteAccepted(InviteAcceptedEvent {
        created_at_ms: current_timestamp_ms_u64(),
        tenant_event_id,
        invite_event_id: *invite_event_id,
        workspace_id,
    });
    let invite_accepted_event_id = create_event_synchronous(db, recorded_by, &ia_evt)?;

    let _ = replay_existing_workspace_shared_events_for_tenant(db, recorded_by, &workspace_id)?;

    // 2. User (signed by invite_key) — may block if invite event not yet synced.
    // Tolerates Blocked: the event is stored and will project via cascade when
    // the invite event arrives.
    let user_key = SigningKey::generate(&mut rng);
    let ub_evt = ParsedEvent::User(UserEvent {
        created_at_ms: current_timestamp_ms_u64(),
        public_key: user_key.verifying_key().to_bytes(),
        username: username.to_string(),
        signed_by: *invite_event_id,
        signer_type: 2,
        signature: [0u8; 64],
    });
    let user_event_id = event_id_or_blocked(create_signed_event_synchronous(
        db,
        recorded_by,
        &ub_evt,
        invite_key,
    ))?;

    // 3. DeviceInvite (signed by user_key) — may block if User is blocked.
    let device_invite_key = SigningKey::generate(&mut rng);
    let dif_evt = ParsedEvent::DeviceInvite(DeviceInviteEvent {
        created_at_ms: current_timestamp_ms_u64(),
        public_key: device_invite_key.verifying_key().to_bytes(),
        authority_event_id: user_event_id,
        signed_by: user_event_id,
        signer_type: 4,
        signature: [0u8; 64],
    });
    let device_invite_event_id = event_id_or_blocked(create_signed_event_synchronous(
        db,
        recorded_by,
        &dif_evt,
        &user_key,
    ))?;

    // 4. PeerShared (signed by device_invite_key) — may block.
    let psf_evt = ParsedEvent::PeerShared(PeerSharedEvent {
        created_at_ms: current_timestamp_ms_u64(),
        public_key: peer_shared_key.verifying_key().to_bytes(),
        user_event_id,
        endpoint_shared_event_id,
        device_name: device_name.to_string(),
        signed_by: device_invite_event_id,
        signer_type: 3,
        signature: [0u8; 64],
    });
    let peer_shared_event_id = event_id_or_blocked(create_signed_event_synchronous(
        db,
        recorded_by,
        &psf_evt,
        &device_invite_key,
    ))?;
    index_endpoint_shared_for_workspace(db, recorded_by, &workspace_id, &endpoint_shared_event_id)?;

    // 5. Key unwrap is dep-driven via:
    //    key_shared --deps on invite_secret--> deterministic secret emit.
    //    No inline unwrap here.
    let content_key_event_id = None;

    Ok(JoinChain {
        user_event_id,
        user_key,
        device_invite_event_id,
        device_invite_key,
        endpoint_shared_event_id,
        peer_shared_event_id,
        peer_shared_key,
        invite_accepted_event_id,
        content_key_event_id,
    })
}

/// Persist signer secrets for a join.
///
/// The peer_shared PeerSecret triggers MaterializeTransportIdentity
/// on projection, which installs the PeerShared-derived transport identity.
/// Events may block if the identity chain hasn't completed yet; they will
/// project via cascade when prerequisites arrive.
///
/// With pre-derive, `recorded_by` is already the final PeerShared-derived
/// identity, so no scoping or load_transport_peer_id is needed.
pub fn persist_join_peer_secret(
    db: &Connection,
    recorded_by: &str,
    join: &JoinChain,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    emit_peer_secret(
        db,
        recorded_by,
        &join.peer_shared_event_id,
        &join.peer_shared_key,
    )?;
    Ok(())
}

// ─── 3. Add new device ───

/// Add a new device to an existing workspace by accepting a device link invite.
///
/// Creates: InviteAccepted → PeerShared.
///
/// Returns the LinkChain with keys/ids needed by service for transport setup.
/// Signer secrets are NOT emitted here — call `persist_link_peer_secret`
/// separately.
pub fn add_device_to_workspace(
    db: &Connection,
    recorded_by: &str,
    device_invite_key: &SigningKey,
    device_invite_event_id: &EventId,
    workspace_id: EventId,
    user_event_id: EventId,
    device_name: &str,
    peer_shared_key: SigningKey,
) -> Result<LinkChain, Box<dyn std::error::Error + Send + Sync>> {
    let _ = ensure_daemon_identity(db)?;
    let endpoint_shared_event_id =
        crate::event_modules::endpoint_shared::load_local_endpoint_shared(db)?
            .ok_or("endpoint_shared missing after ensure_daemon_identity")?
            .event_id;
    let endpoint_shared_event_id = crate::crypto::event_id_from_base64(&endpoint_shared_event_id)
        .ok_or("invalid endpoint_shared event_id")?;
    let tenant_event_id = ops::ensure_local_tenant_event(db, recorded_by, &peer_shared_key)?;

    // Persist deterministic invite_secret material so invite_accepted projection
    // can install bootstrap transport identity through the normal command path.
    let _ = ops::store_invite_secret(db, recorded_by, device_invite_event_id, device_invite_key)?;

    // 1. InviteAccepted (local event) — binds accepted workspace, triggers guard cascade
    let ia_evt = ParsedEvent::InviteAccepted(InviteAcceptedEvent {
        created_at_ms: current_timestamp_ms_u64(),
        tenant_event_id,
        invite_event_id: *device_invite_event_id,
        workspace_id,
    });
    let invite_accepted_event_id = create_event_synchronous(db, recorded_by, &ia_evt)?;

    let _ = replay_existing_workspace_shared_events_for_tenant(db, recorded_by, &workspace_id)?;

    // 2. PeerShared (signed by device_invite_key) — may block if device invite
    // event not yet synced. Tolerates Blocked: the event is stored and will project
    // via cascade when prerequisites arrive.
    let psf_evt = ParsedEvent::PeerShared(PeerSharedEvent {
        created_at_ms: current_timestamp_ms_u64(),
        public_key: peer_shared_key.verifying_key().to_bytes(),
        user_event_id,
        endpoint_shared_event_id,
        device_name: device_name.to_string(),
        signed_by: *device_invite_event_id,
        signer_type: 3,
        signature: [0u8; 64],
    });
    let peer_shared_event_id = event_id_or_blocked(create_signed_event_synchronous(
        db,
        recorded_by,
        &psf_evt,
        device_invite_key,
    ))?;
    index_endpoint_shared_for_workspace(db, recorded_by, &workspace_id, &endpoint_shared_event_id)?;

    Ok(LinkChain {
        endpoint_shared_event_id,
        peer_shared_event_id,
        peer_shared_key,
        invite_accepted_event_id,
    })
}

/// Persist signer secrets for a device link.
///
/// Events may block if the identity chain hasn't completed yet.
pub fn persist_link_peer_secret(
    db: &Connection,
    recorded_by: &str,
    link: &LinkChain,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    emit_peer_secret(
        db,
        recorded_by,
        &link.peer_shared_event_id,
        &link.peer_shared_key,
    )?;
    Ok(())
}

// ─── 4. Create user invite ───

/// Result of creating a user or device-link invite.
pub struct InviteResult {
    pub invite_link: String,
    pub invite_event_id: EventId,
}

/// Create a user invite for the workspace.
///
/// Event-domain logic: ensures content key material → creates invite event chain
/// (UserInvite + optional wrapped content key) → formats invite link.
pub fn create_user_invite(
    db: &Connection,
    recorded_by: &str,
    admin_peer_shared_key: &SigningKey,
    admin_peer_shared_event_id: &EventId,
    admin_event_id: &EventId,
    workspace_id: &EventId,
    bootstrap_addrs: &[super::invite_link::BootstrapAddress],
    bootstrap_spki: &[u8; 32],
    relay_url: Option<&str>,
) -> Result<InviteResult, Box<dyn std::error::Error + Send + Sync>> {
    let _ = ops::ensure_content_key_for_peer(db, recorded_by)?;

    let addr_strings: Vec<String> = bootstrap_addrs
        .iter()
        .map(|a| a.to_bootstrap_addr_string())
        .collect();
    let ctx = InviteBootstrapContext {
        bootstrap_addrs: &addr_strings,
        bootstrap_spki,
    };
    let invite = ops::create_user_invite_events_as_admin(
        db,
        recorded_by,
        admin_peer_shared_key,
        admin_peer_shared_event_id,
        admin_event_id,
        workspace_id,
        Some(&ctx),
    )?;

    let invite_link = super::invite_link::create_invite_link_with_relay(
        &invite,
        bootstrap_addrs,
        bootstrap_spki,
        relay_url,
    )?;

    Ok(InviteResult {
        invite_link,
        invite_event_id: invite.invite_event_id,
    })
}

// ─── 5. Create device-link invite ───

/// Create a device-link invite for an existing user.
///
/// Event-domain logic: creates device invite event (DeviceInvite) →
/// formats invite link.
pub fn create_device_link_invite(
    db: &Connection,
    recorded_by: &str,
    peer_shared_key: &SigningKey,
    peer_shared_event_id: &EventId,
    user_event_id: &EventId,
    workspace_id: &EventId,
    bootstrap_addrs: &[super::invite_link::BootstrapAddress],
    bootstrap_spki: &[u8; 32],
    relay_url: Option<&str>,
) -> Result<InviteResult, Box<dyn std::error::Error + Send + Sync>> {
    let addr_strings: Vec<String> = bootstrap_addrs
        .iter()
        .map(|a| a.to_bootstrap_addr_string())
        .collect();
    let ctx = InviteBootstrapContext {
        bootstrap_addrs: &addr_strings,
        bootstrap_spki,
    };
    let invite = ops::create_device_link_invite_events_for_user(
        db,
        recorded_by,
        peer_shared_key,
        peer_shared_event_id,
        user_event_id,
        workspace_id,
        Some(&ctx),
    )?;

    let invite_link = super::invite_link::create_invite_link_with_relay(
        &invite,
        bootstrap_addrs,
        bootstrap_spki,
        relay_url,
    )?;

    Ok(InviteResult {
        invite_link,
        invite_event_id: invite.invite_event_id,
    })
}

// ─── 6. Test-only helpers ───

/// Create a user invite without bootstrap context.
/// Returns InviteData directly without formatting an invite link.
/// Used by test fixtures and scenarios that handle bootstrap separately.
pub fn create_user_invite_raw(
    db: &Connection,
    recorded_by: &str,
    admin_peer_shared_key: &SigningKey,
    admin_peer_shared_event_id: &EventId,
    admin_event_id: &EventId,
    workspace_id: &EventId,
) -> Result<super::identity_ops::InviteData, Box<dyn std::error::Error + Send + Sync>> {
    ops::create_user_invite_events_as_admin(
        db,
        recorded_by,
        admin_peer_shared_key,
        admin_peer_shared_event_id,
        admin_event_id,
        workspace_id,
        None,
    )
}

/// Create a device-link invite without bootstrap context.
/// Returns InviteData directly without formatting an invite link.
/// Used by test fixtures and scenarios that handle bootstrap separately.
pub fn create_device_link_invite_raw(
    db: &Connection,
    recorded_by: &str,
    peer_shared_key: &SigningKey,
    peer_shared_event_id: &EventId,
    user_event_id: &EventId,
    workspace_id: &EventId,
) -> Result<super::identity_ops::InviteData, Box<dyn std::error::Error + Send + Sync>> {
    ops::create_device_link_invite_events_for_user(
        db,
        recorded_by,
        peer_shared_key,
        peer_shared_event_id,
        user_event_id,
        workspace_id,
        None,
    )
}

// ─── Private helpers ───

pub(super) fn load_local_peer_signer(
    db: &Connection,
    recorded_by: &str,
) -> Result<Option<(EventId, SigningKey)>, Box<dyn std::error::Error + Send + Sync>> {
    crate::event_modules::peer_shared::load_local_peer_signer(db, recorded_by)
}

// ─── Response types ───

pub use super::commands_api::{
    accept_device_link, accept_invite, create_device_link_for_peer, create_invite_for_db,
    create_invite_for_peer, create_invite_with_spki, create_workspace_for_db,
    create_workspace_for_db_with_seed, rotate_key_for_db, rotate_key_for_peer,
    AcceptDeviceLinkResponse, AcceptInviteResponse, CreateInviteResponse, CreateWorkspaceResponse,
    RotateKeyResponse,
};

#[cfg(test)]
mod tests;
