use rusqlite::Connection;
use std::time::{SystemTime, UNIX_EPOCH};

use super::apply::project_one;
use super::decision::ProjectionDecision;
use crate::crypto::{event_id_to_base64, hash_event, EventId};
use crate::db::store::{
    insert_event, insert_recorded_event, insert_recorded_event_checked,
    insert_shared_event_index_entry_if_shared, lookup_workspace_id,
};
use crate::event_modules::encrypted::NO_OWNER_EVENT_ID;
use crate::event_modules::{self as events, registry, ParsedEvent, TransportPrivacy};
use crate::event_modules::{EncryptedEvent, SignedEvent};
use crate::projection::encrypted::encrypt_event_blob;
use crate::projection::signer::sign_event_bytes;
use crate::state::shared_workspace_fanout::{
    fanout_stored_shared_event_immediate, fanout_stored_shared_event_inline,
};
use ed25519_dalek::SigningKey;

#[derive(Debug)]
pub enum CreateEventError {
    EncodeError(String),
    DbError(String),
    Blocked {
        event_id: EventId,
        missing: Vec<[u8; 32]>,
    },
    Rejected {
        event_id: EventId,
        reason: String,
    },
}

impl std::fmt::Display for CreateEventError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CreateEventError::EncodeError(e) => write!(f, "encode error: {}", e),
            CreateEventError::DbError(e) => write!(f, "db error: {}", e),
            CreateEventError::Blocked { event_id, missing } => {
                write!(
                    f,
                    "event {} blocked on {} deps",
                    event_id_to_base64(event_id),
                    missing.len()
                )
            }
            CreateEventError::Rejected { event_id, reason } => {
                write!(
                    f,
                    "event {} rejected: {}",
                    event_id_to_base64(event_id),
                    reason
                )
            }
        }
    }
}

impl std::error::Error for CreateEventError {}

impl From<rusqlite::Error> for CreateEventError {
    fn from(value: rusqlite::Error) -> Self {
        CreateEventError::DbError(value.to_string())
    }
}

#[derive(Debug)]
enum CreateAttemptOutcome {
    Success(EventId),
    Blocked {
        event_id: EventId,
        missing: Vec<[u8; 32]>,
    },
    Rejected {
        event_id: EventId,
        reason: String,
    },
}

impl CreateAttemptOutcome {
    fn into_result(self) -> Result<EventId, CreateEventError> {
        match self {
            Self::Success(event_id) => Ok(event_id),
            Self::Blocked { event_id, missing } => {
                Err(CreateEventError::Blocked { event_id, missing })
            }
            Self::Rejected { event_id, reason } => {
                Err(CreateEventError::Rejected { event_id, reason })
            }
        }
    }
}

/// Extract event_id from Ok or Blocked (event is stored in both cases).
/// Returns Err only for true failures (encode, db, rejected).
///
/// Used by accept flows where chain events may block on prereqs that arrive
/// later via sync. The events are stored and will project when deps are met.
pub fn event_id_or_blocked(
    result: Result<EventId, CreateEventError>,
) -> Result<EventId, CreateEventError> {
    match result {
        Ok(eid) => Ok(eid),
        Err(CreateEventError::Blocked { event_id, .. }) => Ok(event_id),
        Err(e) => Err(e),
    }
}

#[derive(Debug)]
struct StoredBlob {
    event_id: EventId,
}

#[derive(Debug)]
struct StoredProjectionOutcome {
    outcome: CreateAttemptOutcome,
}

/// Shared helper: hash blob, write to events/shared_event_index/recorded_events (no projection).
/// Returns a `StoredBlob` with the stored event_id.
/// Callers must invoke `project_stored_event` to trigger projection.
fn store_blob_only(
    conn: &Connection,
    recorded_by: &str,
    blob: &[u8],
    meta: &events::EventTypeMeta,
    created_at_ms: i64,
) -> Result<StoredBlob, CreateEventError> {
    let event_id = hash_event(blob);

    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64;

    insert_event(
        conn,
        &event_id,
        meta.type_name,
        blob,
        meta.share_scope,
        created_at_ms,
        now_ms,
    )
    .map_err(|e| CreateEventError::DbError(e.to_string()))?;

    let ws_id_for_neg = if meta.type_name == "workspace" {
        Some(crate::crypto::event_id_to_base64(&event_id))
    } else {
        lookup_workspace_id(conn, recorded_by)
    };

    if let Some(ref ws_id) = ws_id_for_neg {
        insert_shared_event_index_entry_if_shared(
            conn,
            meta.share_scope,
            created_at_ms,
            &event_id,
            ws_id,
            blob,
        )
        .map_err(|e| CreateEventError::DbError(e.to_string()))?;
    } else if meta.share_scope == crate::event_modules::registry::ShareScope::Shared
        && meta.type_name != "endpoint_shared"
    {
        tracing::warn!(
            "no accepted workspace binding for {}, shared event {} missing from shared_event_index",
            recorded_by,
            crate::crypto::event_id_to_base64(&event_id)
        );
    }

    insert_recorded_event(conn, recorded_by, &event_id, now_ms, "local_create")
        .map_err(|e| CreateEventError::DbError(e.to_string()))?;

    Ok(StoredBlob { event_id })
}

/// Project a stored event and return the committed projection outcome with live hints.
fn project_stored_event_outcome(
    conn: &Connection,
    recorded_by: &str,
    event_id: &EventId,
) -> Result<StoredProjectionOutcome, CreateEventError> {
    let decision = project_one(conn, recorded_by, event_id)
        .map_err(|e| CreateEventError::DbError(e.to_string()))?;

    match decision {
        ProjectionDecision::Valid | ProjectionDecision::AlreadyProcessed => {
            fanout_stored_shared_event_inline(conn, recorded_by, event_id)
                .map_err(|e| CreateEventError::DbError(e.to_string()))?;
            Ok(StoredProjectionOutcome {
                outcome: CreateAttemptOutcome::Success(*event_id),
            })
        }
        ProjectionDecision::BlockOnMissingDeps { missing } => Ok(StoredProjectionOutcome {
            outcome: CreateAttemptOutcome::Blocked {
                event_id: *event_id,
                missing,
            },
        }),
        ProjectionDecision::Reject { reason } => Ok(StoredProjectionOutcome {
            outcome: CreateAttemptOutcome::Rejected {
                event_id: *event_id,
                reason,
            },
        }),
    }
}

fn project_event_outcome(
    conn: &Connection,
    recorded_by: &str,
    event_id: &EventId,
) -> Result<CreateAttemptOutcome, CreateEventError> {
    let projected = if conn.is_autocommit() {
        crate::state::db::queue::with_immediate_tx_result(conn, || {
            project_stored_event_outcome(conn, recorded_by, event_id)
        })?
    } else {
        project_stored_event_outcome(conn, recorded_by, event_id)?
    };
    Ok(projected.outcome)
}

fn store_blob_then_project_with<F>(
    conn: &Connection,
    recorded_by: &str,
    blob: &[u8],
    meta: &events::EventTypeMeta,
    created_at_ms: i64,
    post_store: F,
) -> Result<EventId, CreateEventError>
where
    F: FnOnce(&Connection, &EventId) -> Result<(), CreateEventError>,
{
    let mut post_store = Some(post_store);
    let outcome = crate::state::db::queue::with_immediate_tx_result(
        conn,
        || -> Result<StoredProjectionOutcome, CreateEventError> {
            let stored = store_blob_only(conn, recorded_by, blob, meta, created_at_ms)?;
            let post_store = post_store
                .take()
                .expect("store_blob_then_project_with closure invoked more than once");
            post_store(conn, &stored.event_id)?;
            let projected = project_stored_event_outcome(conn, recorded_by, &stored.event_id)?;
            Ok(StoredProjectionOutcome {
                outcome: projected.outcome,
            })
        },
    )?;
    outcome.outcome.into_result()
}

/// Shared helper: hash blob, write to events/shared_event_index/recorded_events, project via project_one.
fn store_blob_and_project(
    conn: &Connection,
    recorded_by: &str,
    blob: &[u8],
    meta: &events::EventTypeMeta,
    created_at_ms: i64,
) -> Result<EventId, CreateEventError> {
    store_blob_then_project_with(conn, recorded_by, blob, meta, created_at_ms, |_, _| Ok(()))
}

/// Create a new event: encode, hash, write to events/shared_event_index/recorded_events,
/// then project via `project_one`. Returns the event_id on success.
pub fn create_event(
    conn: &Connection,
    recorded_by: &str,
    event: &ParsedEvent,
) -> Result<EventId, CreateEventError> {
    let blob =
        events::encode_event(event).map_err(|e| CreateEventError::EncodeError(e.to_string()))?;

    let type_code = event.event_type_code();
    let reg = registry();
    let meta = reg
        .lookup(type_code)
        .ok_or_else(|| CreateEventError::EncodeError(format!("unknown type code {}", type_code)))?;

    let created_at_ms = event.created_at_ms() as i64;
    store_blob_and_project(conn, recorded_by, &blob, meta, created_at_ms)
}

pub(crate) fn encode_signed_wrapper_blob(
    inner_event: &ParsedEvent,
    signer_event_id: &EventId,
    signing_key: &SigningKey,
) -> Result<Vec<u8>, CreateEventError> {
    if matches!(inner_event, ParsedEvent::Signed(_)) {
        return Err(CreateEventError::EncodeError(
            "nested Signed envelopes are not allowed".to_string(),
        ));
    }

    let payload = events::encode_event(inner_event)
        .map_err(|e| CreateEventError::EncodeError(e.to_string()))?;
    let mut signed_blob = events::encode_event(&ParsedEvent::Signed(SignedEvent {
        signer_event_id: *signer_event_id,
        inner_type_code: inner_event.event_type_code(),
        inner_created_at_ms: inner_event.created_at_ms(),
        payload,
        signature: [0u8; 64],
    }))
    .map_err(|e| CreateEventError::EncodeError(e.to_string()))?;
    let sig = sign_event_bytes(signing_key, &signed_blob[..signed_blob.len() - 64]);
    let sig_offset = signed_blob.len() - 64;
    signed_blob[sig_offset..].copy_from_slice(&sig);
    Ok(signed_blob)
}

/// Create a signed event by wrapping the inner event in a Signed envelope,
/// signing the canonical wrapper bytes, then storing and projecting the outer blob.
pub fn create_signed_event(
    conn: &Connection,
    recorded_by: &str,
    signer_event_id: &EventId,
    event: &ParsedEvent,
    signing_key: &ed25519_dalek::SigningKey,
) -> Result<EventId, CreateEventError> {
    let blob = encode_signed_wrapper_blob(event, signer_event_id, signing_key)?;

    let type_code = events::EVENT_TYPE_SIGNED;
    let reg = registry();
    let meta = reg
        .lookup(type_code)
        .ok_or_else(|| CreateEventError::EncodeError(format!("unknown type code {}", type_code)))?;

    let created_at_ms = event.created_at_ms() as i64;
    store_blob_and_project(conn, recorded_by, &blob, meta, created_at_ms)
}

/// Store a signed event without projecting. Returns the event_id.
/// The caller must call `project_event` after writing any required context.
/// Used when projection depends on context that must be written after
/// the event_id is known (e.g., bootstrap_context for invite trust).
pub fn store_signed_event_only(
    conn: &Connection,
    recorded_by: &str,
    signer_event_id: &EventId,
    event: &ParsedEvent,
    signing_key: &ed25519_dalek::SigningKey,
) -> Result<EventId, CreateEventError> {
    let blob = encode_signed_wrapper_blob(event, signer_event_id, signing_key)?;

    let type_code = events::EVENT_TYPE_SIGNED;
    let reg = registry();
    let meta = reg
        .lookup(type_code)
        .ok_or_else(|| CreateEventError::EncodeError(format!("unknown type code {}", type_code)))?;

    let created_at_ms = event.created_at_ms() as i64;
    let stored = if conn.is_autocommit() {
        crate::state::db::queue::with_immediate_tx_result(conn, || {
            store_blob_only(conn, recorded_by, &blob, meta, created_at_ms)
        })?
    } else {
        store_blob_only(conn, recorded_by, &blob, meta, created_at_ms)?
    };
    Ok(stored.event_id)
}

/// Rare explicit two-phase create path:
/// 1. store the signed event so the event_id is known,
/// 2. write any event-id-dependent context,
/// 3. project in the same transaction and return only after the outcome commits.
///
/// Use this instead of open-coding a local create transaction when projection
/// depends on context derived from the stored event id.
pub fn store_signed_event_then_project<F>(
    conn: &Connection,
    recorded_by: &str,
    signer_event_id: &EventId,
    event: &ParsedEvent,
    signing_key: &ed25519_dalek::SigningKey,
    post_store: F,
) -> Result<EventId, CreateEventError>
where
    F: FnOnce(&Connection, &EventId) -> Result<(), CreateEventError>,
{
    let blob = encode_signed_wrapper_blob(event, signer_event_id, signing_key)?;

    let type_code = events::EVENT_TYPE_SIGNED;
    let reg = registry();
    let meta = reg
        .lookup(type_code)
        .ok_or_else(|| CreateEventError::EncodeError(format!("unknown type code {}", type_code)))?;

    let created_at_ms = event.created_at_ms() as i64;
    store_blob_then_project_with(conn, recorded_by, &blob, meta, created_at_ms, post_store)
}

/// Store an unsigned event without projecting. Returns the event_id.
/// The caller must call `project_event` after writing any required context.
pub fn store_event_only(
    conn: &Connection,
    recorded_by: &str,
    event: &ParsedEvent,
) -> Result<EventId, CreateEventError> {
    let blob =
        events::encode_event(event).map_err(|e| CreateEventError::EncodeError(e.to_string()))?;

    let type_code = event.event_type_code();
    let reg = registry();
    let meta = reg
        .lookup(type_code)
        .ok_or_else(|| CreateEventError::EncodeError(format!("unknown type code {}", type_code)))?;

    let created_at_ms = event.created_at_ms() as i64;
    let stored = if conn.is_autocommit() {
        crate::state::db::queue::with_immediate_tx_result(conn, || {
            store_blob_only(conn, recorded_by, &blob, meta, created_at_ms)
        })?
    } else {
        store_blob_only(conn, recorded_by, &blob, meta, created_at_ms)?
    };
    Ok(stored.event_id)
}

/// Project a previously-stored event. Returns event_id on Valid/AlreadyProcessed,
/// or CreateEventError on Block/Reject.
pub fn project_event(
    conn: &Connection,
    recorded_by: &str,
    event_id: &EventId,
) -> Result<EventId, CreateEventError> {
    project_event_outcome(conn, recorded_by, event_id)?.into_result()
}

/// Create an encrypted event: encode inner event, optionally sign it,
/// resolve encryption key from key_secrets, encrypt, build EncryptedEvent
/// wrapper, then store and project.
///
/// If signer info is provided, the encrypted wrapper is itself wrapped in an
/// outer Signed envelope, producing Signed(Encrypted(inner)).
pub fn create_encrypted_event(
    conn: &Connection,
    recorded_by: &str,
    key_event_id: &EventId,
    inner_event: &ParsedEvent,
    signer: Option<(&EventId, &SigningKey)>,
) -> Result<EventId, CreateEventError> {
    create_encrypted_event_with_owner(
        conn,
        recorded_by,
        key_event_id,
        None,
        inner_event,
        signer,
    )
}

/// Create an encrypted event with optional outer owner linkage for convergent
/// dependent deletion. `owner_event_id` is carried in wrapper metadata and may
/// be zero/absent for root content or delete intents.
pub fn create_encrypted_event_with_owner(
    conn: &Connection,
    recorded_by: &str,
    key_event_id: &EventId,
    owner_event_id: Option<&EventId>,
    inner_event: &ParsedEvent,
    signer: Option<(&EventId, &SigningKey)>,
) -> Result<EventId, CreateEventError> {
    let inner_meta = events::registry()
        .lookup(inner_event.event_type_code())
        .ok_or_else(|| CreateEventError::EncodeError("unknown event type".to_string()))?;
    if !inner_meta.encryptable {
        return Err(CreateEventError::EncodeError(format!(
            "{} events cannot be encrypted",
            inner_meta.type_name
        )));
    }
    if inner_meta.transport_privacy() == TransportPrivacy::PlaintextOnly {
        return Err(CreateEventError::EncodeError(format!(
            "{} events may not be carried inside encrypted wrappers",
            inner_meta.type_name
        )));
    }

    // 1. Encode inner event
    let inner_blob = events::encode_event(inner_event)
        .map_err(|e| CreateEventError::EncodeError(e.to_string()))?;

    // 2. Resolve encryption key from key_secrets table
    let key_b64 = event_id_to_base64(key_event_id);
    let key_bytes: Vec<u8> = conn
        .query_row(
            "SELECT key_bytes FROM key_secrets WHERE recorded_by = ?1 AND event_id = ?2",
            rusqlite::params![recorded_by, &key_b64],
            |row| crate::db::sql_types::get_blob(row, 0),
        )
        .map_err(|e| CreateEventError::DbError(format!("key lookup: {}", e)))?;

    if key_bytes.len() != 32 {
        return Err(CreateEventError::EncodeError(format!(
            "secret key wrong length: {}",
            key_bytes.len()
        )));
    }
    let mut key_arr = [0u8; 32];
    key_arr.copy_from_slice(&key_bytes);

    // 3. Encrypt
    let (nonce, ciphertext, auth_tag) = encrypt_event_blob(&key_arr, &inner_blob)
        .map_err(|e| CreateEventError::EncodeError(e.to_string()))?;

    // 4. Build EncryptedEvent wrapper
    let wrapper = ParsedEvent::Encrypted(EncryptedEvent {
        // Preserve the inner event's logical timestamp on the wrapper so
        // recency-based discovery/sync policies can prioritize encrypted
        // content by the user-visible event time without decrypting first.
        created_at_ms: inner_event.created_at_ms(),
        key_event_id: *key_event_id,
        owner_event_id: owner_event_id.copied().unwrap_or(NO_OWNER_EVENT_ID),
        inner_type_code: inner_event.event_type_code(),
        nonce,
        ciphertext,
        auth_tag,
    });

    // 5. Store either the plaintext encrypted wrapper or Signed(Encrypted(inner)).
    match signer {
        Some((signer_event_id, signing_key)) => create_signed_event(
            conn,
            recorded_by,
            signer_event_id,
            &wrapper,
            signing_key,
        ),
        None => create_event(conn, recorded_by, &wrapper),
    }
}

/// Staged encrypted create: persist and enqueue an encrypted event even if its
/// inner event is Blocked. Returns the outer wrapper event_id on both Valid and
/// Blocked outcomes.
pub fn create_encrypted_event_staged(
    conn: &Connection,
    recorded_by: &str,
    key_event_id: &EventId,
    inner_event: &ParsedEvent,
    signer: Option<(&EventId, &SigningKey)>,
) -> Result<EventId, CreateEventError> {
    event_id_or_blocked(create_encrypted_event(
        conn,
        recorded_by,
        key_event_id,
        inner_event,
        signer,
    ))
}

/// Staged create: persist and enqueue an event even if it is Blocked.
/// Returns the event_id on both Valid and Blocked outcomes.
/// Use this only for pre-accepted-binding events in bootstrap flows where blocking
/// is expected and will resolve via guard cascade after invite_accepted projects.
pub fn create_event_staged(
    conn: &Connection,
    recorded_by: &str,
    event: &ParsedEvent,
) -> Result<EventId, CreateEventError> {
    event_id_or_blocked(create_event(conn, recorded_by, event))
}

/// Staged signed create: persist and enqueue a signed event even if it is Blocked.
/// Returns the event_id on both Valid and Blocked outcomes.
/// Use this only for pre-accepted-binding events in bootstrap flows where blocking
/// is expected and will resolve via guard cascade after invite_accepted projects.
pub fn create_signed_event_staged(
    conn: &Connection,
    recorded_by: &str,
    signer_event_id: &EventId,
    event: &ParsedEvent,
    signing_key: &ed25519_dalek::SigningKey,
) -> Result<EventId, CreateEventError> {
    event_id_or_blocked(create_signed_event(
        conn,
        recorded_by,
        signer_event_id,
        event,
        signing_key,
    ))
}

struct EmitOutcome {
    event_id: EventId,
}

/// Emit a deterministic event: compute blob, hash to event_id, check if already
/// exists, if not: store in events/shared_event_index/recorded_events and project via project_one.
/// Returns the event_id regardless of whether it was newly created or already existed.
///
/// This follows the emitted-event rule: "emit canonical event X only (to events +
/// normal queue flow), let X project through X's own projector."
pub fn emit_deterministic_event(
    conn: &Connection,
    recorded_by: &str,
    event: &ParsedEvent,
) -> Result<EventId, Box<dyn std::error::Error>> {
    let blob = events::encode_event(event).map_err(|e| format!("encode error: {}", e))?;
    emit_deterministic_blob(conn, recorded_by, &blob)
}

/// Emit a deterministic canonical blob through the normal event pipeline.
pub fn emit_deterministic_blob(
    conn: &Connection,
    recorded_by: &str,
    blob: &[u8],
) -> Result<EventId, Box<dyn std::error::Error>> {
    let emitted = if conn.is_autocommit() {
        crate::state::db::queue::with_immediate_tx_result(conn, || {
            emit_deterministic_blob_in_tx(conn, recorded_by, blob)
        })?
    } else {
        emit_deterministic_blob_in_tx(conn, recorded_by, blob)?
    };
    Ok(emitted.event_id)
}

fn emit_deterministic_blob_in_tx(
    conn: &Connection,
    recorded_by: &str,
    blob: &[u8],
) -> Result<EmitOutcome, Box<dyn std::error::Error>> {
    if blob.is_empty() {
        return Err("deterministic blob cannot be empty".into());
    }
    let event_id = hash_event(blob);
    let event_id_b64 = event_id_to_base64(&event_id);

    let type_code = blob[0];
    let meta = registry()
        .lookup(type_code)
        .ok_or_else(|| format!("unknown type code {}", type_code))?;

    let created_at_ms = events::extract_created_at_ms(blob)
        .ok_or("deterministic blob too short to contain created_at_ms")?
        as i64;
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64;

    let exists: bool = conn.query_row(
        "SELECT COUNT(*) > 0 FROM events WHERE event_id = ?1",
        rusqlite::params![&event_id_b64],
        |row| row.get(0),
    )?;

    if !exists {
        insert_event(
            conn,
            &event_id,
            meta.type_name,
            blob,
            meta.share_scope,
            created_at_ms,
            now_ms,
        )?;
        let ws_id_for_neg = if meta.type_name == "workspace" {
            Some(crate::crypto::event_id_to_base64(&event_id))
        } else {
            lookup_workspace_id(conn, recorded_by)
        };
        if let Some(ws_id) = ws_id_for_neg {
            insert_shared_event_index_entry_if_shared(
                conn,
                meta.share_scope,
                created_at_ms,
                &event_id,
                &ws_id,
                blob,
            )?;
        } else if meta.share_scope == crate::event_modules::registry::ShareScope::Shared
            && meta.type_name != "endpoint_shared"
        {
            tracing::warn!(
                "no accepted workspace binding for {}, shared event {} missing from shared_event_index",
                recorded_by,
                crate::crypto::event_id_to_base64(&event_id)
            );
        }
    }

    let _ = insert_recorded_event_checked(conn, recorded_by, &event_id, now_ms, "emitted")?;

    match project_one(conn, recorded_by, &event_id) {
        Ok(ProjectionDecision::Valid | ProjectionDecision::AlreadyProcessed) => {
            fanout_stored_shared_event_immediate(conn, recorded_by, &event_id)
                .map_err(|e| format!("same-workspace fanout failed: {}", e))?;
        }
        Ok(_) => {}
        Err(e) => {
            tracing::warn!(
                "emit_deterministic_blob projection error for {}: {}",
                event_id_b64,
                e
            );
        }
    }

    Ok(EmitOutcome { event_id })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{open_in_memory, schema::create_tables};
    use crate::event_modules::{
        DeviceInviteEvent, InviteAcceptedEvent, MessageEvent, PeerSharedEvent, ReactionEvent,
        TenantEvent, UserEvent, UserInviteEvent, WorkspaceEvent,
    };
    use crate::testutil::SharedDbNode;
    use ed25519_dalek::SigningKey;

    fn now_ms() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64
    }

    fn setup() -> Connection {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();
        conn
    }

    fn origin_recovery_counts(
        conn: &Connection,
        recorded_by: &str,
        event_id: &EventId,
    ) -> (i64, i64) {
        let event_id_b64 = event_id_to_base64(event_id);
        let project_queue_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM project_queue WHERE peer_id = ?1 AND event_id = ?2",
                rusqlite::params![recorded_by, &event_id_b64],
                |row| row.get(0),
            )
            .unwrap();
        let pending_fanout_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM pending_shared_fanouts
                 WHERE origin_peer_id = ?1 AND event_id = ?2",
                rusqlite::params![recorded_by, event_id.as_slice()],
                |row| row.get(0),
            )
            .unwrap();
        (project_queue_count, pending_fanout_count)
    }

    fn setup_workspace_event(conn: &Connection, recorded_by: &str) -> EventId {
        let ws = ParsedEvent::Workspace(WorkspaceEvent {
            created_at_ms: now_ms(),
            public_key: [0xAA; 32],
            name: "test-workspace".to_string(),
        });
        create_event_staged(conn, recorded_by, &ws).unwrap()
    }

    /// Create a minimal identity chain for the given tenant.
    /// Returns (peer_shared_event_id, peer_shared_signing_key).
    fn make_identity_chain(conn: &Connection, recorded_by: &str) -> (EventId, SigningKey, EventId) {
        let mut rng = rand::thread_rng();

        let peer_key = SigningKey::generate(&mut rng);
        let tenant_evt = ParsedEvent::Tenant(TenantEvent {
            created_at_ms: now_ms(),
            public_key: peer_key.verifying_key().to_bytes(),
        });
        let tenant_eid = create_event(conn, recorded_by, &tenant_evt).unwrap();

        let workspace_key = SigningKey::generate(&mut rng);
        let workspace_pub = workspace_key.verifying_key().to_bytes();
        let net_event = ParsedEvent::Workspace(WorkspaceEvent {
            created_at_ms: now_ms(),
            public_key: workspace_pub,
            name: "test-workspace".to_string(),
        });
        // Workspace may block (needs accepted-workspace binding). Use staged API.
        let net_eid = create_event_staged(conn, recorded_by, &net_event).unwrap();

        let ia_event = ParsedEvent::InviteAccepted(InviteAcceptedEvent {
            created_at_ms: now_ms(),
            tenant_event_id: tenant_eid,
            invite_event_id: net_eid,
            workspace_id: net_eid,
        });
        let _ia_eid = create_event(conn, recorded_by, &ia_event).unwrap();

        // Re-project workspace now that accepted-workspace binding exists
        project_one(conn, recorded_by, &net_eid).unwrap();

        let invite_key = SigningKey::generate(&mut rng);
        let uib = ParsedEvent::UserInvite(UserInviteEvent {
            created_at_ms: now_ms(),
            public_key: invite_key.verifying_key().to_bytes(),
            workspace_id: net_eid,
            authority_event_id: net_eid,
        });
        let uib_eid =
            create_signed_event(conn, recorded_by, &net_eid, &uib, &workspace_key)
                .unwrap();

        let user_key = SigningKey::generate(&mut rng);
        let ub = ParsedEvent::User(UserEvent {
            created_at_ms: now_ms(),
            public_key: user_key.verifying_key().to_bytes(),
            username: "test-user".to_string(),
        });
        let ub_eid =
            create_signed_event(conn, recorded_by, &uib_eid, &ub, &invite_key).unwrap();

        let device_invite_key = SigningKey::generate(&mut rng);
        let dif = ParsedEvent::DeviceInvite(DeviceInviteEvent {
            created_at_ms: now_ms(),
            public_key: device_invite_key.verifying_key().to_bytes(),
            authority_event_id: ub_eid,
        });
        let dif_eid =
            create_signed_event(conn, recorded_by, &ub_eid, &dif, &user_key).unwrap();

        let endpoint_key = SigningKey::generate(&mut rng);
        let endpoint_event =
            crate::event_modules::endpoint_shared::deterministic_endpoint_shared_event(
                endpoint_key.to_bytes(),
            );
        let endpoint_id = hex::encode(endpoint_key.verifying_key().to_bytes());
        let endpoint_shared_event_id =
            create_event(conn, &endpoint_id, &endpoint_event).unwrap();

        let peer_shared_key = SigningKey::generate(&mut rng);
        let psf = ParsedEvent::PeerShared(PeerSharedEvent {
            created_at_ms: now_ms(),
            public_key: peer_shared_key.verifying_key().to_bytes(),
            user_event_id: ub_eid,
            endpoint_shared_event_id,
            device_name: "test-device".to_string(),
        });
        let psf_eid =
            create_signed_event(conn, recorded_by, &dif_eid, &psf, &device_invite_key)
                .unwrap();
        conn.execute(
            "INSERT INTO peer_secrets
             (recorded_by, event_id, signer_event_id, private_key, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![
                recorded_by,
                format!("test-peer-secret-{}", event_id_to_base64(&psf_eid)),
                event_id_to_base64(&psf_eid),
                peer_shared_key.to_bytes().to_vec(),
                now_ms() as i64,
            ],
        )
        .unwrap();

        (psf_eid, peer_shared_key, ub_eid)
    }

    #[test]
    fn test_create_message_synchronous() {
        let conn = setup();
        let recorded_by = "peer1";
        let net_eid = setup_workspace_event(&conn, recorded_by);

        let (signer_eid, signing_key, user_event_id) = make_identity_chain(&conn, recorded_by);
        let key_event_id =
            crate::event_modules::workspace::identity_ops::ensure_content_key_for_peer(
                &conn,
                recorded_by,
            )
            .unwrap();

        let msg = ParsedEvent::Message(MessageEvent {
            created_at_ms: now_ms(),
            workspace_id: net_eid,
            author_id: user_event_id,
            content: "hello".to_string(),
        });

        let eid = create_encrypted_event(
            &conn,
            recorded_by,
            &key_event_id,
            &msg,
            Some((&signer_eid, &signing_key)),
        )
        .unwrap();
        let eid_b64 = event_id_to_base64(&eid);

        // events table
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM events WHERE event_id = ?1",
                rusqlite::params![&eid_b64],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 1);

        // messages table
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM messages WHERE message_id = ?1 AND recorded_by = ?2",
                rusqlite::params![&eid_b64, recorded_by],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 1);

        // valid_events
        let valid: bool = conn
            .query_row(
                "SELECT COUNT(*) > 0 FROM valid_events WHERE peer_id = ?1 AND event_id = ?2",
                rusqlite::params![recorded_by, &eid_b64],
                |row| row.get(0),
            )
            .unwrap();
        assert!(valid);
    }

    #[test]
    fn test_create_reaction_chain() {
        let conn = setup();
        let recorded_by = "peer1";
        let net_eid = setup_workspace_event(&conn, recorded_by);

        let (signer_eid, signing_key, user_event_id) = make_identity_chain(&conn, recorded_by);
        let key_event_id =
            crate::event_modules::workspace::identity_ops::ensure_content_key_for_peer(
                &conn,
                recorded_by,
            )
            .unwrap();

        let msg = ParsedEvent::Message(MessageEvent {
            created_at_ms: now_ms(),
            workspace_id: net_eid,
            author_id: user_event_id,
            content: "target".to_string(),
        });
        let msg_eid = create_encrypted_event(
            &conn,
            recorded_by,
            &key_event_id,
            &msg,
            Some((&signer_eid, &signing_key)),
        )
        .unwrap();

        let rxn = ParsedEvent::Reaction(ReactionEvent {
            created_at_ms: now_ms(),
            target_event_id: msg_eid,
            author_id: user_event_id,
            emoji: "\u{1f44d}".to_string(),
        });
        let rxn_eid = create_encrypted_event(
            &conn,
            recorded_by,
            &key_event_id,
            &rxn,
            Some((&signer_eid, &signing_key)),
        )
        .unwrap();

        // Both valid
        let msg_b64 = event_id_to_base64(&msg_eid);
        let rxn_b64 = event_id_to_base64(&rxn_eid);
        for b64 in [&msg_b64, &rxn_b64] {
            let valid: bool = conn
                .query_row(
                    "SELECT COUNT(*) > 0 FROM valid_events WHERE peer_id = ?1 AND event_id = ?2",
                    rusqlite::params![recorded_by, b64],
                    |row| row.get(0),
                )
                .unwrap();
            assert!(valid);
        }
    }

    #[test]
    fn test_create_reaction_before_target() {
        let conn = setup();
        let recorded_by = "peer1";

        let (signer_eid, signing_key, user_event_id) = make_identity_chain(&conn, recorded_by);
        let key_event_id =
            crate::event_modules::workspace::identity_ops::ensure_content_key_for_peer(
                &conn,
                recorded_by,
            )
            .unwrap();

        let fake_target = [99u8; 32];
        let rxn = ParsedEvent::Reaction(ReactionEvent {
            created_at_ms: now_ms(),
            target_event_id: fake_target,
            author_id: user_event_id,
            emoji: "\u{1f44d}".to_string(),
        });

        // Event is stored but blocked — returns Blocked error with event_id
        let err = create_encrypted_event(
            &conn,
            recorded_by,
            &key_event_id,
            &rxn,
            Some((&signer_eid, &signing_key)),
        )
        .unwrap_err();
        let (eid, missing) = match err {
            CreateEventError::Blocked { event_id, missing } => (event_id, missing),
            other => panic!("expected Blocked, got: {}", other),
        };
        assert_eq!(missing.len(), 1);
        assert_eq!(missing[0], fake_target);
        let eid_b64 = event_id_to_base64(&eid);

        // Should be in events table but NOT in valid_events
        let in_events: bool = conn
            .query_row(
                "SELECT COUNT(*) > 0 FROM events WHERE event_id = ?1",
                rusqlite::params![&eid_b64],
                |row| row.get(0),
            )
            .unwrap();
        assert!(in_events);

        let in_valid: bool = conn
            .query_row(
                "SELECT COUNT(*) > 0 FROM valid_events WHERE peer_id = ?1 AND event_id = ?2",
                rusqlite::params![recorded_by, &eid_b64],
                |row| row.get(0),
            )
            .unwrap();
        assert!(!in_valid);

        // Should be in blocked_event_deps
        let blocked: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM blocked_event_deps WHERE peer_id = ?1 AND event_id = ?2",
                rusqlite::params![recorded_by, &eid_b64],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(blocked, 1);
    }

    #[test]
    fn test_create_signed_event_rejects_plaintext_content() {
        let conn = setup();
        let recorded_by = "peer1";

        let (signer_eid, signing_key, user_event_id) = make_identity_chain(&conn, recorded_by);

        // Create signed message with PeerShared signer
        let msg = ParsedEvent::Message(MessageEvent {
            created_at_ms: now_ms(),
            workspace_id: [1u8; 32],
            author_id: user_event_id,
            content: "signed content".to_string(),
        });

        let err =
            create_signed_event(&conn, recorded_by, &signer_eid, &msg, &signing_key)
                .expect_err("plaintext content should be rejected");
        match err {
            CreateEventError::Rejected { reason, .. } => {
                assert!(reason.contains("must be carried inside encrypted wrappers"));
            }
            other => panic!("expected plaintext rejection, got {other:?}"),
        }
    }

    #[test]
    fn test_create_encrypted_event_returns_blocked_error() {
        // Verify strict API: create_signed_event returns Err(Blocked) for
        // events with missing dependencies.
        let conn = setup();
        let recorded_by = "peer1";

        let (signer_eid, signing_key, user_event_id) = make_identity_chain(&conn, recorded_by);
        let key_event_id =
            crate::event_modules::workspace::identity_ops::ensure_content_key_for_peer(
                &conn,
                recorded_by,
            )
            .unwrap();

        // Reaction targeting a non-existent event → blocked on missing dep
        let fake_target = [0xDD; 32];
        let rxn = ParsedEvent::Reaction(ReactionEvent {
            created_at_ms: now_ms(),
            target_event_id: fake_target,
            author_id: user_event_id,
            emoji: "x".to_string(),
        });
        let result = create_encrypted_event(
            &conn,
            recorded_by,
            &key_event_id,
            &rxn,
            Some((&signer_eid, &signing_key)),
        );
        match result {
            Err(CreateEventError::Blocked { event_id, missing }) => {
                assert_eq!(missing.len(), 1);
                assert_eq!(missing[0], fake_target);
                // Event is stored even though blocked
                let eid_b64 = event_id_to_base64(&event_id);
                let in_events: bool = conn
                    .query_row(
                        "SELECT COUNT(*) > 0 FROM events WHERE event_id = ?1",
                        rusqlite::params![&eid_b64],
                        |row| row.get(0),
                    )
                    .unwrap();
                assert!(in_events, "event should be stored even when blocked");
            }
            Ok(_) => panic!("expected Blocked error, got Ok"),
            Err(e) => panic!("expected Blocked error, got: {}", e),
        }
    }

    #[test]
    fn test_create_signed_event_staged_returns_ok_on_blocked() {
        // Verify staged API: create_signed_event_staged returns Ok(event_id)
        // even when event is blocked.
        let conn = setup();
        let recorded_by = "peer1";

        let (signer_eid, signing_key, user_event_id) = make_identity_chain(&conn, recorded_by);
        let key_event_id =
            crate::event_modules::workspace::identity_ops::ensure_content_key_for_peer(
                &conn,
                recorded_by,
            )
            .unwrap();

        let fake_target = [0xEE; 32];
        let rxn = ParsedEvent::Reaction(ReactionEvent {
            created_at_ms: now_ms(),
            target_event_id: fake_target,
            author_id: user_event_id,
            emoji: "y".to_string(),
        });
        let eid = create_encrypted_event_staged(
            &conn,
            recorded_by,
            &key_event_id,
            &rxn,
            Some((&signer_eid, &signing_key)),
        )
        .expect("staged API should return Ok even for blocked events");

        let eid_b64 = event_id_to_base64(&eid);
        let in_events: bool = conn
            .query_row(
                "SELECT COUNT(*) > 0 FROM events WHERE event_id = ?1",
                rusqlite::params![&eid_b64],
                |row| row.get(0),
            )
            .unwrap();
        assert!(in_events, "event should be stored");

        // Should NOT be in valid_events (blocked)
        let in_valid: bool = conn
            .query_row(
                "SELECT COUNT(*) > 0 FROM valid_events WHERE peer_id = ?1 AND event_id = ?2",
                rusqlite::params![recorded_by, &eid_b64],
                |row| row.get(0),
            )
            .unwrap();
        assert!(!in_valid, "blocked event should not be in valid_events");
    }

    /// PLAN §6.4 contract: `create_event` returns Ok only for Valid events.
    /// A message with all deps satisfied must return Ok(event_id) and be in valid_events.
    #[test]
    fn test_create_event_sync_contract_valid_only() {
        let conn = setup();
        let recorded_by = "peer1";
        let net_eid = setup_workspace_event(&conn, recorded_by);
        let (signer_eid, signing_key, user_event_id) = make_identity_chain(&conn, recorded_by);
        let key_event_id =
            crate::event_modules::workspace::identity_ops::ensure_content_key_for_peer(
                &conn,
                recorded_by,
            )
            .unwrap();

        let msg = ParsedEvent::Message(MessageEvent {
            created_at_ms: now_ms(),
            workspace_id: net_eid,
            author_id: user_event_id,
            content: "contract-valid".to_string(),
        });
        let result = create_encrypted_event(
            &conn,
            recorded_by,
            &key_event_id,
            &msg,
            Some((&signer_eid, &signing_key)),
        );
        assert!(
            result.is_ok(),
            "PLAN §6.4: valid event must return Ok, got: {:?}",
            result
        );

        let eid = result.unwrap();
        let eid_b64 = event_id_to_base64(&eid);
        let in_valid: bool = conn
            .query_row(
                "SELECT COUNT(*) > 0 FROM valid_events WHERE peer_id = ?1 AND event_id = ?2",
                rusqlite::params![recorded_by, &eid_b64],
                |row| row.get(0),
            )
            .unwrap();
        assert!(
            in_valid,
            "PLAN §6.4: Ok result implies event is in valid_events"
        );
    }

    /// PLAN §6.4 contract: `create_event` returns Err(Blocked) with event_id
    /// and missing deps when a dependency is unresolved.
    #[test]
    fn test_create_event_sync_contract_blocked_returns_err_with_event_id() {
        let conn = setup();
        let recorded_by = "peer1";
        let (signer_eid, signing_key, user_event_id) = make_identity_chain(&conn, recorded_by);
        let key_event_id =
            crate::event_modules::workspace::identity_ops::ensure_content_key_for_peer(
                &conn,
                recorded_by,
            )
            .unwrap();

        let fake_target = [0xCC; 32];
        let rxn = ParsedEvent::Reaction(ReactionEvent {
            created_at_ms: now_ms(),
            target_event_id: fake_target,
            author_id: user_event_id,
            emoji: "z".to_string(),
        });
        let result = create_encrypted_event(
            &conn,
            recorded_by,
            &key_event_id,
            &rxn,
            Some((&signer_eid, &signing_key)),
        );

        match result {
            Err(CreateEventError::Blocked { event_id, missing }) => {
                // Error must contain the event_id so callers can reference it
                let eid_b64 = event_id_to_base64(&event_id);
                let stored: bool = conn
                    .query_row(
                        "SELECT COUNT(*) > 0 FROM events WHERE event_id = ?1",
                        rusqlite::params![&eid_b64],
                        |row| row.get(0),
                    )
                    .unwrap();
                assert!(
                    stored,
                    "PLAN §6.4: blocked event_id must reference a stored event"
                );
                assert!(
                    !missing.is_empty(),
                    "PLAN §6.4: Blocked error must list missing deps"
                );
                assert_eq!(missing[0], fake_target);
            }
            Ok(_) => panic!("PLAN §6.4: blocked event must NOT return Ok"),
            Err(e) => panic!("expected Blocked, got: {}", e),
        }
    }

    #[test]
    fn test_valid_sync_create_leaves_no_origin_recovery_rows() {
        let conn = setup();
        let recorded_by = "peer1";
        let net_eid = setup_workspace_event(&conn, recorded_by);
        let (signer_eid, signing_key, user_event_id) = make_identity_chain(&conn, recorded_by);
        let key_event_id =
            crate::event_modules::workspace::identity_ops::ensure_content_key_for_peer(
                &conn,
                recorded_by,
            )
            .unwrap();

        let msg = ParsedEvent::Message(MessageEvent {
            created_at_ms: now_ms(),
            workspace_id: net_eid,
            author_id: user_event_id,
            content: "no origin recovery rows".to_string(),
        });

        let event_id = create_encrypted_event(
            &conn,
            recorded_by,
            &key_event_id,
            &msg,
            Some((&signer_eid, &signing_key)),
        )
        .unwrap();

        let (project_queue_count, pending_fanout_count) =
            origin_recovery_counts(&conn, recorded_by, &event_id);
        assert_eq!(
            project_queue_count, 0,
            "synchronous local create should not leave an origin project_queue row behind"
        );
        assert_eq!(
            pending_fanout_count, 0,
            "synchronous local create should not rely on pending shared fanout recovery rows"
        );
    }

    #[test]
    fn test_encrypted_wrapper_created_at_matches_inner_event_timestamp() {
        let conn = setup();
        let recorded_by = "peer1";
        let net_eid = setup_workspace_event(&conn, recorded_by);
        let (signer_eid, signing_key, user_event_id) = make_identity_chain(&conn, recorded_by);
        let key_event_id =
            crate::event_modules::workspace::identity_ops::ensure_content_key_for_peer(
                &conn,
                recorded_by,
            )
            .unwrap();
        let inner_created_at_ms = 1_700_000_000_123u64;
        let msg = ParsedEvent::Message(MessageEvent {
            created_at_ms: inner_created_at_ms,
            workspace_id: net_eid,
            author_id: user_event_id,
            content: "timestamp preserved".to_string(),
        });

        let event_id = create_encrypted_event(
            &conn,
            recorded_by,
            &key_event_id,
            &msg,
            Some((&signer_eid, &signing_key)),
        )
        .unwrap();
        let wrapper_blob: Vec<u8> = conn
            .query_row(
                "SELECT blob FROM events WHERE event_id = ?1",
                rusqlite::params![event_id_to_base64(&event_id)],
                |row| crate::db::sql_types::get_blob(row, 0),
            )
            .unwrap();
        let wrapper = crate::event_modules::parse_event(&wrapper_blob).unwrap();

        assert_eq!(wrapper.created_at_ms(), inner_created_at_ms);
    }

    #[test]
    fn test_blocked_sync_create_commits_block_state_without_origin_recovery_rows() {
        let conn = setup();
        let recorded_by = "peer1";
        let (signer_eid, signing_key, user_event_id) = make_identity_chain(&conn, recorded_by);
        let key_event_id =
            crate::event_modules::workspace::identity_ops::ensure_content_key_for_peer(
                &conn,
                recorded_by,
            )
            .unwrap();

        let fake_target = [0xEF; 32];
        let rxn = ParsedEvent::Reaction(ReactionEvent {
            created_at_ms: now_ms(),
            target_event_id: fake_target,
            author_id: user_event_id,
            emoji: "!".to_string(),
        });

        let event_id = match create_encrypted_event(
            &conn,
            recorded_by,
            &key_event_id,
            &rxn,
            Some((&signer_eid, &signing_key)),
        ) {
            Err(CreateEventError::Blocked { event_id, missing }) => {
                assert_eq!(missing, vec![fake_target]);
                event_id
            }
            other => panic!("expected blocked result, got {other:?}"),
        };

        let blocked_header: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM blocked_events WHERE peer_id = ?1 AND event_id = ?2",
                rusqlite::params![recorded_by, event_id_to_base64(&event_id)],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            blocked_header, 1,
            "blocked row must be durable before return"
        );

        let (project_queue_count, pending_fanout_count) =
            origin_recovery_counts(&conn, recorded_by, &event_id);
        assert_eq!(
            project_queue_count, 0,
            "blocked synchronous create should use blocked state, not origin project_queue recovery"
        );
        assert_eq!(
            pending_fanout_count, 0,
            "blocked synchronous create should not leave pending shared fanout recovery rows"
        );
    }

    #[test]
    fn test_local_shared_create_fanout_is_same_workspace_only() {
        let mut node = SharedDbNode::new(2);
        node.add_tenant_in_workspace("same-ws", 0);

        let origin = &node.tenants[0];
        let other_workspace = &node.tenants[1];
        let sibling = &node.tenants[2];

        let message_id = origin.create_message("local fanout marker");
        let message_b64 = event_id_to_base64(&message_id);
        let db = crate::db::open_connection(&node.db_path).unwrap();

        let sibling_count: i64 = db
            .query_row(
                "SELECT COUNT(*) FROM messages WHERE recorded_by = ?1 AND message_id = ?2",
                rusqlite::params![&sibling.identity, &message_b64],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            sibling_count, 1,
            "same-workspace sibling should project message"
        );

        let other_count: i64 = db
            .query_row(
                "SELECT COUNT(*) FROM messages WHERE recorded_by = ?1 AND message_id = ?2",
                rusqlite::params![&other_workspace.identity, &message_b64],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            other_count, 0,
            "different-workspace tenant must not receive same-workspace fanout"
        );
    }
}
