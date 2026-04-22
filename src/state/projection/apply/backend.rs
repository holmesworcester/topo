use crate::crypto::EventId;
use crate::db::queue::current_timestamp_ms;
use crate::db::store::lookup_workspace_id;
use crate::db::timeline::EventTimeline;
use crate::event_modules::ParsedEvent;
use crate::projection::projector::{EmitCommand, WriteOp};
use crate::projection::decision_context::ProjectionQueries;
use crate::projection::signer::{resolve_signer_key, SignerResolution};
use rusqlite::{Connection, OptionalExtension};

use super::stages::record_rejection;
use super::write_exec::{execute_emit_commands, execute_write_ops};

fn is_zero_event_id(event_id: &EventId) -> bool {
    event_id.iter().all(|byte| *byte == 0)
}

fn dedupe_dep_ids(mut dep_ids: Vec<EventId>) -> Vec<EventId> {
    dep_ids.retain(|dep_id| !is_zero_event_id(dep_id));
    dep_ids.sort_unstable();
    dep_ids.dedup();
    dep_ids
}

fn collect_wrapper_dep_ids(outer_event: &ParsedEvent) -> Vec<EventId> {
    match outer_event {
        ParsedEvent::Signed(signed) => {
            let mut dep_ids = vec![signed.signer_event_id];
            if let Ok(ParsedEvent::Encrypted(encrypted)) =
                crate::event_modules::parse_event(&signed.payload)
            {
                dep_ids.push(encrypted.key_event_id);
            }
            dep_ids
        }
        ParsedEvent::Encrypted(encrypted) => vec![encrypted.key_event_id],
        _ => Vec::new(),
    }
}

fn filter_syncable_shared_dep_ids(
    conn: &Connection,
    dep_ids: Vec<EventId>,
) -> ProjectionApplyResult<Vec<EventId>> {
    let dep_ids = dedupe_dep_ids(dep_ids);
    if dep_ids.is_empty() {
        return Ok(Vec::new());
    }

    let mut syncable = Vec::new();
    for dep_id in dep_ids {
        let dep_id_b64 = crate::crypto::event_id_to_base64(&dep_id);
        let is_shared: bool = conn
            .query_row(
                "SELECT EXISTS(
                     SELECT 1
                     FROM events
                     WHERE event_id = ?1
                       AND share_scope = 'shared'
                 )",
                rusqlite::params![dep_id_b64],
                |row| row.get(0),
            )
            .optional()?
            .unwrap_or(false);
        if is_shared {
            syncable.push(dep_id);
        }
    }
    Ok(syncable)
}

fn collect_associated_key_shared_dep_ids(
    conn: &Connection,
    recorded_by: &str,
    outer_event: &ParsedEvent,
) -> ProjectionApplyResult<Vec<EventId>> {
    let key_event_id = match outer_event {
        ParsedEvent::Encrypted(encrypted) => Some(encrypted.key_event_id),
        ParsedEvent::Signed(signed) => match crate::event_modules::parse_event(&signed.payload)? {
            ParsedEvent::Encrypted(encrypted) => Some(encrypted.key_event_id),
            _ => None,
        },
        _ => None,
    };
    let Some(key_event_id) = key_event_id else {
        return Ok(Vec::new());
    };

    let mut stmt = conn.prepare(
        "SELECT ks.event_id
         FROM key_shared ks
         JOIN events e ON e.event_id = ks.event_id
         WHERE ks.recorded_by = ?1
           AND ks.key_event_id = ?2
           AND e.share_scope = 'shared'
         ORDER BY e.created_at, ks.event_id",
    )?;
    let rows = stmt.query_map(
        rusqlite::params![
            recorded_by,
            crate::crypto::event_id_to_base64(&key_event_id)
        ],
        |row| crate::db::sql_types::get_text(row, 0),
    )?;
    let mut dep_ids = Vec::new();
    for row in rows {
        let event_id_b64 = row?;
        if let Some(dep_id) = crate::crypto::event_id_from_base64(&event_id_b64) {
            dep_ids.push(dep_id);
        }
    }
    Ok(dep_ids)
}

fn resolve_shared_event_workspace_id(
    conn: &Connection,
    recorded_by: &str,
    event_id: &EventId,
) -> ProjectionApplyResult<Option<String>> {
    let indexed_workspace_id = conn
        .query_row(
            "SELECT workspace_id
             FROM shared_event_index
             WHERE id = ?1
               AND workspace_id != ''
             ORDER BY workspace_id
             LIMIT 1",
            rusqlite::params![event_id.as_slice()],
            |row| crate::db::sql_types::get_text(row, 0),
        )
        .optional()?;
    if indexed_workspace_id.is_some() {
        return Ok(indexed_workspace_id);
    }
    Ok(lookup_workspace_id(conn, recorded_by))
}

fn resolve_blocked_event_workspace_id(
    conn: &Connection,
    recorded_by: &str,
    event_id_b64: &str,
) -> ProjectionApplyResult<Option<String>> {
    let is_shared: bool = conn
        .query_row(
            "SELECT EXISTS(
                 SELECT 1
                 FROM events
                 WHERE event_id = ?1
                   AND share_scope = 'shared'
             )",
            rusqlite::params![event_id_b64],
            |row| row.get(0),
        )
        .optional()?
        .unwrap_or(false);
    if !is_shared {
        return Ok(None);
    }
    let Some(event_id) = crate::crypto::event_id_from_base64(event_id_b64) else {
        return Ok(None);
    };
    resolve_shared_event_workspace_id(conn, recorded_by, &event_id)
}

fn load_blocked_event_workspace_id(
    conn: &Connection,
    recorded_by: &str,
    event_id_b64: &str,
) -> ProjectionApplyResult<Option<String>> {
    Ok(conn
        .query_row(
            "SELECT workspace_id
             FROM blocked_events
             WHERE peer_id = ?1
               AND event_id = ?2
               AND workspace_id IS NOT NULL
               AND workspace_id != ''",
            rusqlite::params![recorded_by, event_id_b64],
            |row| crate::db::sql_types::get_text(row, 0),
        )
        .optional()?)
}

fn persist_shared_dep_edges(
    conn: &Connection,
    recorded_by: &str,
    event_id_b64: &str,
    sub_event: &ParsedEvent,
) -> ProjectionApplyResult<()> {
    let Some(event_id) = crate::crypto::event_id_from_base64(event_id_b64) else {
        return Ok(());
    };
    let Some(workspace_id) = resolve_shared_event_workspace_id(conn, recorded_by, &event_id)?
    else {
        return Ok(());
    };
    let outer_blob: Option<Vec<u8>> = conn
        .query_row(
            "SELECT blob
            FROM events
            WHERE event_id = ?1
               AND share_scope = 'shared'",
            rusqlite::params![event_id_b64],
            |row| crate::db::sql_types::get_blob(row, 0),
        )
        .optional()?;
    let Some(outer_blob) = outer_blob else {
        return Ok(());
    };
    let outer_event = crate::event_modules::parse_event(&outer_blob)?;

    let mut dep_ids = collect_wrapper_dep_ids(&outer_event);
    dep_ids.extend(collect_associated_key_shared_dep_ids(
        conn,
        recorded_by,
        &outer_event,
    )?);
    dep_ids.extend(
        sub_event
            .dep_field_values()
            .into_iter()
            .map(|(_, dep_id)| dep_id),
    );
    let dep_ids = filter_syncable_shared_dep_ids(conn, dep_ids)?;
    crate::db::dep_index::replace_shared_event_deps(conn, &workspace_id, &event_id, &dep_ids)?;
    Ok(())
}

fn persist_blocked_shared_dep_edges(
    conn: &Connection,
    recorded_by: &str,
    event_id_b64: &str,
    missing: &[EventId],
) -> ProjectionApplyResult<()> {
    let Some(event_id) = crate::crypto::event_id_from_base64(event_id_b64) else {
        return Ok(());
    };
    let Some(workspace_id) = load_blocked_event_workspace_id(conn, recorded_by, event_id_b64)?
    else {
        return Ok(());
    };
    let is_shared: bool = conn
        .query_row(
            "SELECT EXISTS(
                 SELECT 1
                 FROM events
                 WHERE event_id = ?1
                   AND share_scope = 'shared'
             )",
            rusqlite::params![event_id_b64],
            |row| row.get(0),
        )
        .optional()?
        .unwrap_or(false);
    if !is_shared {
        return Ok(());
    }

    let dep_ids = dedupe_dep_ids(missing.to_vec());
    crate::db::dep_index::replace_shared_event_deps(conn, &workspace_id, &event_id, &dep_ids)?;
    Ok(())
}

fn suppress_matching_key_requests_for_key_shared(
    conn: &Connection,
    recorded_by: &str,
    sub_event: &ParsedEvent,
) -> ProjectionApplyResult<()> {
    let ParsedEvent::KeyShared(key_shared) = sub_event else {
        return Ok(());
    };
    let delivery_target_id_b64 = crate::crypto::event_id_to_base64(&key_shared.delivery_target_id);
    conn.execute(
        "UPDATE valid_events
         SET suppress_sharing = 1
         WHERE peer_id = ?1
           AND event_id IN (
               SELECT event_id
               FROM key_requests
               WHERE recorded_by = ?1
                 AND delivery_target_id = ?2
           )",
        rusqlite::params![recorded_by, delivery_target_id_b64],
    )?;
    Ok(())
}

pub(crate) type ProjectionApplyResult<T> = Result<T, Box<dyn std::error::Error>>;

/// Zero-sized capability token for executing `WriteOp`s.
///
/// Only the apply module can construct a `WriteCapability`. Any trait method
/// that mutates persistent projection-tracked state takes this as a
/// parameter, so no code outside apply can drive a mutation even if it
/// happens to hold a `&dyn ProjectionBackend` (e.g. via the sim).
///
/// This is the Rust-type-system analog of the CI write-site gate: the gate
/// scans source code for forbidden constructor patterns, this makes the
/// construction literally impossible outside apply.
///
/// There is deliberately NO public constructor.
#[derive(Debug)]
pub(crate) struct WriteCapability {
    _private: (),
}

impl WriteCapability {
    /// Mint a capability. Visibility is scoped to the apply subtree so only
    /// code physically located at `src/state/projection/apply/**` can call
    /// this. Every write path threads one of these tokens to the backend.
    pub(in crate::state::projection::apply) fn new() -> Self {
        Self { _private: () }
    }
}

pub(crate) trait ProjectionBackend: ProjectionQueries {
    fn already_processed(
        &self,
        recorded_by: &str,
        event_id_b64: &str,
    ) -> ProjectionApplyResult<bool>;

    fn load_blob(&self, event_id_b64: &str) -> ProjectionApplyResult<Option<Vec<u8>>>;

    fn record_rejection(
        &self,
        recorded_by: &str,
        event_id_b64: &str,
        reason: &str,
    ) -> ProjectionApplyResult<()>;

    fn record_block(
        &self,
        recorded_by: &str,
        event_id_b64: &str,
        missing: &[EventId],
    ) -> ProjectionApplyResult<()>;

    fn resolve_signer_key(
        &self,
        recorded_by: &str,
        signer_event_id: &[u8; 32],
    ) -> ProjectionApplyResult<SignerResolution>;

    /// Execute a batch of write ops transactionally. Requires a
    /// `WriteCapability` that only apply code can mint. Non-apply callers
    /// can still hold a `&dyn ProjectionBackend`, but they cannot construct
    /// the token — so they cannot call this method.
    fn execute_write_ops(
        &self,
        _cap: &WriteCapability,
        ops: &[WriteOp],
    ) -> ProjectionApplyResult<()>;

    /// Execute post-write emit commands. Also gated by `WriteCapability`
    /// because commands mutate projection-tracked state (e.g., hard-purge,
    /// index-fanout, retry-blocked-encrypted).
    fn execute_emit_commands(
        &self,
        _cap: &WriteCapability,
        recorded_by: &str,
        commands: &[EmitCommand],
    ) -> ProjectionApplyResult<()>;

    fn mark_guard_blocked(&self, event_id_b64: &str) -> ProjectionApplyResult<()>;

    fn finalize_valid_projection(
        &self,
        recorded_by: &str,
        event_id_b64: &str,
        sub_event: &ParsedEvent,
        suppress_sharing: bool,
    ) -> ProjectionApplyResult<()>;
}

impl ProjectionBackend for Connection {
    fn already_processed(
        &self,
        recorded_by: &str,
        event_id_b64: &str,
    ) -> ProjectionApplyResult<bool> {
        let already_valid: bool = self.query_row(
            "SELECT COUNT(*) > 0 FROM valid_events WHERE peer_id = ?1 AND event_id = ?2",
            rusqlite::params![recorded_by, event_id_b64],
            |row| row.get(0),
        )?;
        if already_valid {
            return Ok(true);
        }

        let already_rejected: bool = self.query_row(
            "SELECT COUNT(*) > 0 FROM rejected_events WHERE peer_id = ?1 AND event_id = ?2",
            rusqlite::params![recorded_by, event_id_b64],
            |row| row.get(0),
        )?;
        Ok(already_rejected)
    }

    fn load_blob(&self, event_id_b64: &str) -> ProjectionApplyResult<Option<Vec<u8>>> {
        let blob = self
            .query_row(
                "SELECT blob FROM events WHERE event_id = ?1",
                rusqlite::params![event_id_b64],
                |row| crate::db::sql_types::get_blob(row, 0),
            )
            .map(Some)
            .or_else(|err| match err {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                other => Err(other),
            })?;
        Ok(blob)
    }

    fn record_rejection(
        &self,
        recorded_by: &str,
        event_id_b64: &str,
        reason: &str,
    ) -> ProjectionApplyResult<()> {
        record_rejection(self, recorded_by, event_id_b64, reason);
        Ok(())
    }

    fn record_block(
        &self,
        recorded_by: &str,
        event_id_b64: &str,
        missing: &[EventId],
    ) -> ProjectionApplyResult<()> {
        let workspace_id = resolve_blocked_event_workspace_id(self, recorded_by, event_id_b64)?;
        super::stages::record_block_rows(
            self,
            recorded_by,
            event_id_b64,
            missing,
            workspace_id.as_deref(),
        )?;
        persist_blocked_shared_dep_edges(self, recorded_by, event_id_b64, missing)?;
        Ok(())
    }

    fn resolve_signer_key(
        &self,
        recorded_by: &str,
        signer_event_id: &[u8; 32],
    ) -> ProjectionApplyResult<SignerResolution> {
        resolve_signer_key(self, recorded_by, signer_event_id)
    }

    fn execute_write_ops(
        &self,
        _cap: &WriteCapability,
        ops: &[WriteOp],
    ) -> ProjectionApplyResult<()> {
        execute_write_ops(self, ops)
    }

    fn execute_emit_commands(
        &self,
        _cap: &WriteCapability,
        recorded_by: &str,
        commands: &[EmitCommand],
    ) -> ProjectionApplyResult<()> {
        execute_emit_commands(self, recorded_by, commands)
    }

    fn mark_guard_blocked(&self, event_id_b64: &str) -> ProjectionApplyResult<()> {
        let _ = EventTimeline::new(self).mark_blocked_b64(event_id_b64, current_timestamp_ms());
        Ok(())
    }

    fn finalize_valid_projection(
        &self,
        recorded_by: &str,
        event_id_b64: &str,
        sub_event: &ParsedEvent,
        suppress_sharing: bool,
    ) -> ProjectionApplyResult<()> {
        // Some projectors hard-purge the current event inside the same
        // transaction (for example, content arriving after a tombstone).
        // In that case projection succeeded but there is nothing left to
        // mark valid or deliver to subscriptions.
        let still_recorded: bool = self.query_row(
            "SELECT COUNT(*) > 0 FROM recorded_events WHERE peer_id = ?1 AND event_id = ?2",
            rusqlite::params![recorded_by, event_id_b64],
            |row| row.get(0),
        )?;
        if !still_recorded {
            return Ok(());
        }

        self.execute_batch("SAVEPOINT project_valid")?;
        let commit_result = (|| -> ProjectionApplyResult<()> {
            let semantic_type_code = i64::from(sub_event.event_type_code());
            self.execute(
                "INSERT OR IGNORE INTO valid_events
                 (peer_id, event_id, semantic_type_code, suppress_sharing)
                 VALUES (?1, ?2, ?3, ?4)",
                rusqlite::params![
                    recorded_by,
                    event_id_b64,
                    semantic_type_code,
                    if suppress_sharing { 1i64 } else { 0i64 }
                ],
            )?;
            self.execute(
                "UPDATE valid_events
                 SET semantic_type_code = ?3,
                     suppress_sharing = ?4
                 WHERE peer_id = ?1 AND event_id = ?2",
                rusqlite::params![
                    recorded_by,
                    event_id_b64,
                    semantic_type_code,
                    if suppress_sharing { 1i64 } else { 0i64 }
                ],
            )?;
            suppress_matching_key_requests_for_key_shared(self, recorded_by, sub_event)?;
            persist_shared_dep_edges(self, recorded_by, event_id_b64, sub_event)?;

            crate::state::subscriptions::on_projected_event(
                self,
                recorded_by,
                event_id_b64,
                sub_event,
            )
            .map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;

            let _ =
                EventTimeline::new(self).mark_projected_b64(event_id_b64, current_timestamp_ms());
            Ok(())
        })();

        match commit_result {
            Ok(()) => {
                self.execute_batch("RELEASE project_valid")?;
                Ok(())
            }
            Err(err) => {
                let _ = self.execute_batch("ROLLBACK TO project_valid");
                let _ = self.execute_batch("RELEASE project_valid");
                Err(err)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::collections::{BTreeSet, HashMap};

    use crate::crypto::{event_id_to_base64, hash_event};
    use crate::event_modules::encrypted::NO_OWNER_EVENT_ID;
    use crate::event_modules::file_slice::FILE_SLICE_WIRE_SIZE;
    use crate::event_modules::{
        encode_event, EncryptedEvent, ParsedEvent, TenantEvent, EVENT_TYPE_FILE_SLICE,
    };
    use crate::projection::apply::stages::apply_projection_with_backend;
    use crate::projection::projector::{EmitCommand, ProjectorDecisionContext, WriteOp};
    use crate::projection::decision::ProjectionDecision;
    use crate::projection::decision_context::{DepLoadResult, ProjectionQueryResult};

    use super::*;
    use crate::projection::apply::project_one::project_one_step_with_backend;

    struct FakeProjectionBackend {
        blobs: HashMap<String, Vec<u8>>,
        dep_result: RefCell<DepLoadResult>,
        rejections: RefCell<Vec<(String, String, String)>>,
        blocked_event_deps: RefCell<HashMap<String, BTreeSet<String>>>,
        blocked_events: RefCell<HashMap<String, i64>>,
        guard_blocked: RefCell<Vec<String>>,
        valid_marked: RefCell<Vec<String>>,
        write_batches: RefCell<usize>,
        emit_batches: RefCell<usize>,
        emitted_commands: RefCell<Vec<EmitCommand>>,
    }

    impl FakeProjectionBackend {
        fn with_blob(event_id_b64: String, blob: Vec<u8>) -> Self {
            Self::with_blob_and_dep_result(event_id_b64, blob, DepLoadResult::missing())
        }

        fn with_blob_and_dep_result(
            event_id_b64: String,
            blob: Vec<u8>,
            dep_result: DepLoadResult,
        ) -> Self {
            let mut blobs = HashMap::new();
            blobs.insert(event_id_b64, blob);
            Self {
                blobs,
                dep_result: RefCell::new(dep_result),
                rejections: RefCell::new(Vec::new()),
                blocked_event_deps: RefCell::new(HashMap::new()),
                blocked_events: RefCell::new(HashMap::new()),
                guard_blocked: RefCell::new(Vec::new()),
                valid_marked: RefCell::new(Vec::new()),
                write_batches: RefCell::new(0),
                emit_batches: RefCell::new(0),
                emitted_commands: RefCell::new(Vec::new()),
            }
        }
    }

    impl ProjectionBackend for FakeProjectionBackend {
        fn already_processed(
            &self,
            _recorded_by: &str,
            _event_id_b64: &str,
        ) -> ProjectionApplyResult<bool> {
            Ok(false)
        }

        fn load_blob(&self, event_id_b64: &str) -> ProjectionApplyResult<Option<Vec<u8>>> {
            Ok(self.blobs.get(event_id_b64).cloned())
        }

        fn record_rejection(
            &self,
            recorded_by: &str,
            event_id_b64: &str,
            reason: &str,
        ) -> ProjectionApplyResult<()> {
            self.rejections.borrow_mut().push((
                recorded_by.to_string(),
                event_id_b64.to_string(),
                reason.to_string(),
            ));
            Ok(())
        }

        fn record_block(
            &self,
            _recorded_by: &str,
            event_id_b64: &str,
            missing: &[EventId],
        ) -> ProjectionApplyResult<()> {
            let mut deduped = missing.to_vec();
            deduped.sort_unstable();
            deduped.dedup();
            let deps_remaining = {
                let mut blockers_by_event = self.blocked_event_deps.borrow_mut();
                let blockers = blockers_by_event
                    .entry(event_id_b64.to_string())
                    .or_default();
                for dep_id in &deduped {
                    blockers.insert(event_id_to_base64(dep_id));
                }
                blockers.len() as i64
            };
            self.blocked_events
                .borrow_mut()
                .insert(event_id_b64.to_string(), deps_remaining);
            Ok(())
        }

        fn resolve_signer_key(
            &self,
            _recorded_by: &str,
            _signer_event_id: &[u8; 32],
        ) -> ProjectionApplyResult<SignerResolution> {
            Ok(SignerResolution::NotFound)
        }

        fn execute_write_ops(
            &self,
            _cap: &WriteCapability,
            _ops: &[WriteOp],
        ) -> ProjectionApplyResult<()> {
            *self.write_batches.borrow_mut() += 1;
            Ok(())
        }

        fn execute_emit_commands(
            &self,
            _cap: &WriteCapability,
            _recorded_by: &str,
            commands: &[EmitCommand],
        ) -> ProjectionApplyResult<()> {
            *self.emit_batches.borrow_mut() += 1;
            self.emitted_commands
                .borrow_mut()
                .extend_from_slice(commands);
            Ok(())
        }

        fn mark_guard_blocked(&self, event_id_b64: &str) -> ProjectionApplyResult<()> {
            self.guard_blocked
                .borrow_mut()
                .push(event_id_b64.to_string());
            Ok(())
        }

        fn finalize_valid_projection(
            &self,
            _recorded_by: &str,
            event_id_b64: &str,
            _sub_event: &ParsedEvent,
            _suppress_sharing: bool,
        ) -> ProjectionApplyResult<()> {
            self.valid_marked
                .borrow_mut()
                .push(event_id_b64.to_string());
            Ok(())
        }
    }

    impl ProjectionQueries for FakeProjectionBackend {
        fn load_dep_result(
            &self,
            _recorded_by: &str,
            _parsed: &ParsedEvent,
            _field_name: &str,
            _dep_id: &EventId,
        ) -> ProjectionQueryResult<DepLoadResult> {
            Ok(self.dep_result.borrow().clone())
        }

        fn load_key_secret_bytes(
            &self,
            _recorded_by: &str,
            _key_event_id: &[u8; 32],
        ) -> ProjectionQueryResult<Option<[u8; 32]>> {
            Ok(None)
        }

        fn load_workspace_context(
            &self,
            _frame: &crate::projection::decision_context::ProjectionFrameContext,
            _recorded_by: &str,
            _event_id_b64: &str,
            _workspace: &crate::event_modules::WorkspaceEvent,
        ) -> crate::projection::decision_context::ProjectionQueryResult<ProjectorDecisionContext> {
            Ok(ProjectorDecisionContext::default())
        }

        fn load_admin_context(
            &self,
            _frame: &crate::projection::decision_context::ProjectionFrameContext,
            _recorded_by: &str,
            _event_id_b64: &str,
            _admin: &crate::event_modules::AdminEvent,
        ) -> crate::projection::decision_context::ProjectionQueryResult<ProjectorDecisionContext> {
            Ok(ProjectorDecisionContext::default())
        }

        fn load_peer_shared_context(
            &self,
            _frame: &crate::projection::decision_context::ProjectionFrameContext,
            _recorded_by: &str,
            _event_id_b64: &str,
            _peer_shared: &crate::event_modules::PeerSharedEvent,
        ) -> crate::projection::decision_context::ProjectionQueryResult<ProjectorDecisionContext> {
            Ok(ProjectorDecisionContext::default())
        }

        fn load_user_invite_context(
            &self,
            _frame: &crate::projection::decision_context::ProjectionFrameContext,
            _recorded_by: &str,
            _event_id_b64: &str,
            _user_invite: &crate::event_modules::UserInviteEvent,
        ) -> crate::projection::decision_context::ProjectionQueryResult<ProjectorDecisionContext> {
            Ok(ProjectorDecisionContext::default())
        }

        fn load_device_invite_context(
            &self,
            _frame: &crate::projection::decision_context::ProjectionFrameContext,
            _recorded_by: &str,
            _event_id_b64: &str,
            _device_invite: &crate::event_modules::DeviceInviteEvent,
        ) -> crate::projection::decision_context::ProjectionQueryResult<ProjectorDecisionContext> {
            Ok(ProjectorDecisionContext::default())
        }

        fn load_message_context(
            &self,
            _frame: &crate::projection::decision_context::ProjectionFrameContext,
            _recorded_by: &str,
            _event_id_b64: &str,
            _message: &crate::event_modules::MessageEvent,
        ) -> crate::projection::decision_context::ProjectionQueryResult<ProjectorDecisionContext> {
            Ok(ProjectorDecisionContext::default())
        }

        fn load_message_deletion_context(
            &self,
            _frame: &crate::projection::decision_context::ProjectionFrameContext,
            _recorded_by: &str,
            _event_id_b64: &str,
            _message_deletion: &crate::event_modules::MessageDeletionEvent,
        ) -> crate::projection::decision_context::ProjectionQueryResult<ProjectorDecisionContext> {
            Ok(ProjectorDecisionContext::default())
        }

        fn load_reaction_context(
            &self,
            _frame: &crate::projection::decision_context::ProjectionFrameContext,
            _recorded_by: &str,
            _event_id_b64: &str,
            _reaction: &crate::event_modules::ReactionEvent,
        ) -> crate::projection::decision_context::ProjectionQueryResult<ProjectorDecisionContext> {
            Ok(ProjectorDecisionContext::default())
        }

        fn load_file_context(
            &self,
            _frame: &crate::projection::decision_context::ProjectionFrameContext,
            _recorded_by: &str,
            _event_id_b64: &str,
            _file: &crate::event_modules::FileEvent,
        ) -> crate::projection::decision_context::ProjectionQueryResult<ProjectorDecisionContext> {
            Ok(ProjectorDecisionContext::default())
        }

        fn load_file_slice_context(
            &self,
            _frame: &crate::projection::decision_context::ProjectionFrameContext,
            _recorded_by: &str,
            _event_id_b64: &str,
            _file_slice: &crate::event_modules::FileSliceEvent,
        ) -> crate::projection::decision_context::ProjectionQueryResult<ProjectorDecisionContext> {
            Ok(ProjectorDecisionContext::default())
        }

        fn load_invite_accepted_context(
            &self,
            _frame: &crate::projection::decision_context::ProjectionFrameContext,
            _recorded_by: &str,
            _event_id_b64: &str,
            _invite_accepted: &crate::event_modules::InviteAcceptedEvent,
        ) -> crate::projection::decision_context::ProjectionQueryResult<ProjectorDecisionContext> {
            Ok(ProjectorDecisionContext::default())
        }

        fn load_key_request_context(
            &self,
            _frame: &crate::projection::decision_context::ProjectionFrameContext,
            _recorded_by: &str,
            _event_id_b64: &str,
            _key_request: &crate::event_modules::KeyRequestEvent,
        ) -> crate::projection::decision_context::ProjectionQueryResult<ProjectorDecisionContext> {
            Ok(ProjectorDecisionContext::default())
        }

        fn load_key_shared_context(
            &self,
            _frame: &crate::projection::decision_context::ProjectionFrameContext,
            _recorded_by: &str,
            _event_id_b64: &str,
            _key_shared: &crate::event_modules::KeySharedEvent,
        ) -> crate::projection::decision_context::ProjectionQueryResult<ProjectorDecisionContext> {
            Ok(ProjectorDecisionContext::default())
        }
    }

    #[test]
    fn sqlite_backend_exposes_registry_context_queries() {
        let conn = crate::db::open_in_memory().unwrap();
        crate::db::schema::create_tables(&conn).unwrap();
        let parsed = ParsedEvent::Tenant(TenantEvent {
            created_at_ms: 1,
            public_key: [7u8; 32],
        });
        let meta = crate::event_modules::registry()
            .lookup(crate::event_modules::EVENT_TYPE_TENANT)
            .unwrap();
        let ctx = (meta.context_loader)(
            &conn,
            &crate::projection::decision_context::ProjectionFrameContext::default(),
            "peer-a",
            "event-a",
            &parsed,
        )
        .unwrap();
        let crate::projection::decision_context::ContextLoadResult::Ready(ctx) = ctx else {
            panic!("expected ready context");
        };
        assert!(ctx.accepted_workspace_id.is_none());
        assert!(ctx.signer_user_mismatch_reason.is_none());
        assert!(ctx.deletion_intents.is_empty());
    }

    #[test]
    fn fake_backend_can_supply_tenant_blob() {
        let parsed = ParsedEvent::Tenant(TenantEvent {
            created_at_ms: 1,
            public_key: [9u8; 32],
        });
        let blob = encode_event(&parsed).unwrap();
        let event_id = hash_event(&blob);
        let event_id_b64 = event_id_to_base64(&event_id);
        let backend = FakeProjectionBackend::with_blob(event_id_b64.clone(), blob.clone());
        assert_eq!(backend.load_blob(&event_id_b64).unwrap(), Some(blob));
    }

    fn make_encrypted_wrapper_with_key_dep(key_event_id: [u8; 32]) -> (ParsedEvent, Vec<u8>) {
        let parsed = ParsedEvent::Encrypted(EncryptedEvent {
            created_at_ms: 7,
            key_event_id,
            owner_event_id: NO_OWNER_EVENT_ID,
            inner_type_code: EVENT_TYPE_FILE_SLICE,
            nonce: [0xAA; 12],
            ciphertext: vec![0xBB; FILE_SLICE_WIRE_SIZE],
            auth_tag: [0xCC; 16],
        });
        let blob = encode_event(&parsed).unwrap();
        (parsed, blob)
    }

    #[test]
    fn project_one_step_can_run_against_generic_backend_for_valid_event() {
        let parsed = ParsedEvent::Tenant(TenantEvent {
            created_at_ms: 5,
            public_key: [3u8; 32],
        });
        let blob = encode_event(&parsed).unwrap();
        let event_id = hash_event(&blob);
        let event_id_b64 = event_id_to_base64(&event_id);
        let backend = FakeProjectionBackend::with_blob(event_id_b64.clone(), blob);

        let (decision, parsed_out) =
            project_one_step_with_backend(&backend, "peer-a", &event_id).unwrap();

        assert!(matches!(decision, ProjectionDecision::Valid));
        assert_eq!(parsed_out, Some(parsed));
        assert_eq!(backend.valid_marked.borrow().as_slice(), &[event_id_b64]);
        assert_eq!(*backend.write_batches.borrow(), 1);
        assert_eq!(*backend.emit_batches.borrow(), 1);
    }

    #[test]
    fn project_one_step_can_reject_missing_blob_against_generic_backend() {
        let event_id = [11u8; 32];
        let event_id_b64 = event_id_to_base64(&event_id);
        let backend = FakeProjectionBackend::with_blob("other".to_string(), vec![1, 2, 3]);

        let (decision, parsed_out) =
            project_one_step_with_backend(&backend, "peer-a", &event_id).unwrap();

        match decision {
            ProjectionDecision::Reject { reason } => {
                assert!(
                    reason.contains("not found in events table"),
                    "reason: {reason}"
                );
            }
            other => panic!("expected reject, got {:?}", other),
        }
        assert!(parsed_out.is_none());
        assert_eq!(backend.rejections.borrow().len(), 1);
        assert_eq!(backend.rejections.borrow()[0].1, event_id_b64);
    }

    #[test]
    fn project_one_step_records_block_without_projection_side_effects_when_context_load_blocks() {
        let key_event_id = [0x51; 32];
        let (parsed, blob) = make_encrypted_wrapper_with_key_dep(key_event_id);
        let event_id = hash_event(&blob);
        let event_id_b64 = event_id_to_base64(&event_id);
        let backend = FakeProjectionBackend::with_blob_and_dep_result(
            event_id_b64.clone(),
            blob,
            DepLoadResult::missing(),
        );

        let (decision, parsed_out) =
            project_one_step_with_backend(&backend, "peer-a", &event_id).unwrap();

        assert_eq!(
            decision,
            ProjectionDecision::BlockOnMissingDeps {
                missing: vec![key_event_id]
            }
        );
        assert_eq!(parsed_out, Some(parsed));
        assert_eq!(
            backend
                .blocked_event_deps
                .borrow()
                .get(&event_id_b64)
                .cloned()
                .unwrap_or_default(),
            BTreeSet::from([event_id_to_base64(&key_event_id)])
        );
        assert_eq!(
            backend.blocked_events.borrow().get(&event_id_b64).copied(),
            Some(1)
        );
        assert_eq!(backend.guard_blocked.borrow().as_slice(), &[event_id_b64]);
        assert!(backend.rejections.borrow().is_empty());
        assert!(backend.valid_marked.borrow().is_empty());
        assert_eq!(*backend.write_batches.borrow(), 0);
        assert_eq!(*backend.emit_batches.borrow(), 0);
        assert!(backend.emitted_commands.borrow().is_empty());
    }

    #[test]
    fn project_one_step_records_rejection_without_projection_side_effects_when_context_load_rejects(
    ) {
        let key_event_id = [0x61; 32];
        let (parsed, blob) = make_encrypted_wrapper_with_key_dep(key_event_id);
        let event_id = hash_event(&blob);
        let event_id_b64 = event_id_to_base64(&event_id);
        let backend = FakeProjectionBackend::with_blob_and_dep_result(
            event_id_b64.clone(),
            blob,
            DepLoadResult::Reject {
                reason: "dependency rejected".to_string(),
            },
        );

        let (decision, parsed_out) =
            project_one_step_with_backend(&backend, "peer-a", &event_id).unwrap();

        assert_eq!(
            decision,
            ProjectionDecision::Reject {
                reason: "dependency rejected".to_string()
            }
        );
        assert_eq!(parsed_out, Some(parsed));
        assert_eq!(backend.rejections.borrow().len(), 1);
        assert_eq!(
            backend.rejections.borrow()[0],
            (
                "peer-a".to_string(),
                event_id_b64.clone(),
                "dependency rejected".to_string()
            )
        );
        assert!(backend.blocked_event_deps.borrow().is_empty());
        assert!(backend.guard_blocked.borrow().is_empty());
        assert!(backend.valid_marked.borrow().is_empty());
        assert_eq!(*backend.write_batches.borrow(), 0);
        assert_eq!(*backend.emit_batches.borrow(), 0);
        assert!(backend.emitted_commands.borrow().is_empty());
    }

    #[test]
    fn apply_projection_emits_hard_purge_without_write_ops_when_context_load_purges() {
        let key_event_id = [0x71; 32];
        let (parsed, blob) = make_encrypted_wrapper_with_key_dep(key_event_id);
        let event_id = hash_event(&blob);
        let event_id_b64 = event_id_to_base64(&event_id);
        let backend = FakeProjectionBackend::with_blob_and_dep_result(
            event_id_b64.clone(),
            blob.clone(),
            DepLoadResult::purge("deleted-message"),
        );

        let (decision, inner, suppress_sharing) =
            apply_projection_with_backend(&backend, "peer-a", &event_id_b64, &blob, &parsed)
                .unwrap();

        assert_eq!(decision, ProjectionDecision::Valid);
        assert!(inner.is_none());
        assert!(!suppress_sharing);
        assert_eq!(*backend.write_batches.borrow(), 0);
        assert_eq!(*backend.emit_batches.borrow(), 1);
        assert_eq!(
            backend.emitted_commands.borrow().as_slice(),
            &[EmitCommand::HardPurgeMessageGraph {
                message_event_id: "deleted-message".to_string()
            }]
        );
        assert!(backend.blocked_event_deps.borrow().is_empty());
        assert!(backend.guard_blocked.borrow().is_empty());
        assert!(backend.rejections.borrow().is_empty());
        assert!(backend.valid_marked.borrow().is_empty());
    }
}
