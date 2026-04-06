use crate::crypto::{decrypt_event_blob, event_id_from_base64, event_id_to_base64, EventId};
use crate::db::queue::current_timestamp_ms;
use crate::db::store::lookup_workspace_id;
use crate::db::timeline::EventTimeline;
use crate::event_modules::ParsedEvent;
use crate::projection::contract::{EmitCommand, WriteOp};
use crate::projection::decision::ProjectionDecision;
use crate::projection::encrypted::project_encrypted;
use crate::projection::queries::ProjectionQueries;
use crate::projection::signer::{resolve_signer_key, SignerResolution};
use rusqlite::{Connection, OptionalExtension};
use std::collections::{BTreeSet, HashSet, VecDeque};

use super::stages::{check_dep_types, check_deps_and_block, record_rejection};
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

fn direct_claim_seed_ids(outer_event: &ParsedEvent, sub_event: &ParsedEvent) -> Vec<EventId> {
    let mut dep_ids = sub_event
        .dep_field_values()
        .into_iter()
        .map(|(_, dep_id)| dep_id)
        .collect::<Vec<_>>();
    if let ParsedEvent::Encrypted(encrypted) = outer_event {
        dep_ids.push(encrypted.key_event_id);
    }
    dedupe_dep_ids(dep_ids)
}

fn load_locally_valid_shared_dep_ids(
    conn: &Connection,
    recorded_by: &str,
    event_id: &EventId,
) -> ProjectionApplyResult<Vec<EventId>> {
    let event_id_b64 = event_id_to_base64(event_id);
    let outer_blob: Option<Vec<u8>> = conn
        .query_row(
            "SELECT e.blob
             FROM events e
             JOIN valid_events v
               ON v.event_id = e.event_id
              AND v.peer_id = ?1
             WHERE e.event_id = ?2
               AND e.share_scope = 'shared'
             LIMIT 1",
            rusqlite::params![recorded_by, event_id_b64],
            |row| row.get(0),
        )
        .optional()?;
    let Some(outer_blob) = outer_blob else {
        return Ok(Vec::new());
    };

    let outer_event = crate::event_modules::parse_event(&outer_blob)?;
    let dep_ids = match outer_event {
        ParsedEvent::Encrypted(encrypted) => {
            let mut dep_ids = vec![encrypted.key_event_id];
            let key_bytes: Option<Vec<u8>> = conn
                .query_row(
                    "SELECT key_bytes
                     FROM key_secrets
                     WHERE recorded_by = ?1
                       AND event_id = ?2
                     LIMIT 1",
                    rusqlite::params![recorded_by, event_id_to_base64(&encrypted.key_event_id)],
                    |row| row.get(0),
                )
                .optional()?;
            if let Some(key_bytes) = key_bytes {
                if key_bytes.len() == 32 {
                    let mut key_arr = [0u8; 32];
                    key_arr.copy_from_slice(&key_bytes);
                    if let Ok(plaintext) = decrypt_event_blob(
                        &key_arr,
                        &encrypted.nonce,
                        &encrypted.ciphertext,
                        &encrypted.auth_tag,
                    ) {
                        if let Ok(inner_event) = crate::event_modules::parse_event(&plaintext) {
                            dep_ids.extend(
                                inner_event
                                    .dep_field_values()
                                    .into_iter()
                                    .map(|(_, dep_id)| dep_id),
                            );
                        }
                    }
                }
            }
            dep_ids
        }
        event => event
            .dep_field_values()
            .into_iter()
            .map(|(_, dep_id)| dep_id)
            .collect::<Vec<_>>(),
    };

    Ok(dedupe_dep_ids(dep_ids))
}

fn list_local_key_shared_event_ids_for_key(
    conn: &Connection,
    recorded_by: &str,
    key_event_id: &EventId,
) -> ProjectionApplyResult<Vec<EventId>> {
    let mut stmt = conn.prepare(
        "SELECT event_id
         FROM key_shared
         WHERE recorded_by = ?1
           AND key_event_id = ?2
         ORDER BY event_id",
    )?;
    let rows = stmt.query_map(
        rusqlite::params![recorded_by, event_id_to_base64(key_event_id)],
        |row| row.get::<_, String>(0),
    )?;

    let mut event_ids = Vec::new();
    for row in rows {
        let event_id_b64 = row?;
        if let Some(event_id) = event_id_from_base64(&event_id_b64) {
            event_ids.push(event_id);
        }
    }
    Ok(event_ids)
}

fn hard_claim_exists(
    conn: &Connection,
    workspace_id: &str,
    shard_start_ms: i64,
    event_id: &EventId,
) -> ProjectionApplyResult<bool> {
    let exists = conn.query_row(
        "SELECT EXISTS(
             SELECT 1
             FROM dep_claims
             WHERE workspace_id = ?1
               AND shard_start_ms = ?2
               AND event_id = ?3
               AND strength >= 2
         )",
        rusqlite::params![workspace_id, shard_start_ms, event_id_to_base64(event_id)],
        |row| row.get(0),
    )?;
    Ok(exists)
}

fn expand_hard_claim_closure_for_shard(
    conn: &Connection,
    recorded_by: &str,
    workspace_id: &str,
    shard_start_ms: i64,
    seed_ids: &[EventId],
    updated_at_ms: i64,
) -> ProjectionApplyResult<()> {
    let mut queue = VecDeque::from(dedupe_dep_ids(seed_ids.to_vec()));
    let mut seen = HashSet::<EventId>::new();

    while let Some(event_id) = queue.pop_front() {
        if !seen.insert(event_id) {
            continue;
        }

        let already_hard = hard_claim_exists(conn, workspace_id, shard_start_ms, &event_id)?;
        crate::db::dep_claims::upsert_hard_claims(
            conn,
            workspace_id,
            shard_start_ms,
            &[event_id],
            updated_at_ms,
        )?;
        if already_hard {
            continue;
        }

        for claimed_event_id in
            list_local_key_shared_event_ids_for_key(conn, recorded_by, &event_id)?
        {
            queue.push_back(claimed_event_id);
        }
        for dep_id in load_locally_valid_shared_dep_ids(conn, recorded_by, &event_id)? {
            queue.push_back(dep_id);
        }
    }

    Ok(())
}

fn persist_shared_dep_claims(
    conn: &Connection,
    recorded_by: &str,
    event_id_b64: &str,
    sub_event: &ParsedEvent,
) -> ProjectionApplyResult<()> {
    let outer_blob: Option<Vec<u8>> = conn
        .query_row(
            "SELECT blob
             FROM events
             WHERE event_id = ?1
               AND share_scope = 'shared'",
            rusqlite::params![event_id_b64],
            |row| row.get(0),
        )
        .optional()?;
    let Some(outer_blob) = outer_blob else {
        return Ok(());
    };

    let Some(workspace_id) = lookup_workspace_id(conn, recorded_by) else {
        return Ok(());
    };
    let Some(event_id) = event_id_from_base64(event_id_b64) else {
        return Err(format!("invalid projected event id: {event_id_b64}").into());
    };

    let outer_event = crate::event_modules::parse_event(&outer_blob)?;
    let dep_ids = direct_claim_seed_ids(&outer_event, sub_event);

    let mut shard_starts = BTreeSet::new();
    shard_starts.insert(crate::db::dep_claims::utc_week_start_ms(
        sub_event.created_at_ms() as i64,
    ));
    for shard_start_ms in
        crate::db::dep_claims::list_hard_claim_shards_for_event(conn, &workspace_id, &event_id)?
    {
        shard_starts.insert(shard_start_ms);
    }
    let mut key_claim_shards = BTreeSet::new();
    if let ParsedEvent::KeyShared(key_shared) = &outer_event {
        for shard_start_ms in crate::db::dep_claims::list_hard_claim_shards_for_event(
            conn,
            &workspace_id,
            &key_shared.key_event_id,
        )? {
            key_claim_shards.insert(shard_start_ms);
            shard_starts.insert(shard_start_ms);
        }
    }
    if dep_ids.is_empty() && key_claim_shards.is_empty() {
        return Ok(());
    }

    let now_ms = current_timestamp_ms();
    for shard_start_ms in shard_starts {
        let mut seed_ids = dep_ids.clone();
        if key_claim_shards.contains(&shard_start_ms) {
            seed_ids.push(event_id);
        }
        let seed_ids = dedupe_dep_ids(seed_ids);
        if seed_ids.is_empty() {
            continue;
        }
        expand_hard_claim_closure_for_shard(
            conn,
            recorded_by,
            &workspace_id,
            shard_start_ms,
            &seed_ids,
            now_ms,
        )?;
    }
    Ok(())
}

pub(crate) type ProjectionApplyResult<T> = Result<T, Box<dyn std::error::Error>>;

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

    fn check_deps_and_block(
        &self,
        recorded_by: &str,
        event_id_b64: &str,
        parsed: &ParsedEvent,
        deps: &[(&str, EventId)],
    ) -> ProjectionApplyResult<Option<ProjectionDecision>>;

    fn check_dep_types(
        &self,
        recorded_by: &str,
        parsed: &ParsedEvent,
        deps: &[(&str, EventId)],
        type_codes: &[&[u8]],
    ) -> ProjectionApplyResult<Option<String>>;

    fn resolve_signer_key(
        &self,
        recorded_by: &str,
        signer_type: u8,
        signer_event_id: &[u8; 32],
    ) -> ProjectionApplyResult<SignerResolution>;

    fn project_encrypted(
        &self,
        recorded_by: &str,
        event_id_b64: &str,
        encrypted: &crate::event_modules::EncryptedEvent,
    ) -> ProjectionApplyResult<(ProjectionDecision, Option<ParsedEvent>)>;

    fn execute_write_ops(&self, ops: &[WriteOp]) -> ProjectionApplyResult<()>;

    fn execute_emit_commands(
        &self,
        recorded_by: &str,
        commands: &[EmitCommand],
    ) -> ProjectionApplyResult<()>;

    fn mark_guard_blocked(&self, event_id_b64: &str) -> ProjectionApplyResult<()>;

    fn finalize_valid_projection(
        &self,
        recorded_by: &str,
        event_id_b64: &str,
        sub_event: &ParsedEvent,
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
                |row| row.get(0),
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
        super::stages::record_block_rows(self, recorded_by, event_id_b64, missing)?;
        Ok(())
    }

    fn check_deps_and_block(
        &self,
        recorded_by: &str,
        event_id_b64: &str,
        parsed: &ParsedEvent,
        deps: &[(&str, EventId)],
    ) -> ProjectionApplyResult<Option<ProjectionDecision>> {
        check_deps_and_block(self, recorded_by, event_id_b64, parsed, deps)
    }

    fn check_dep_types(
        &self,
        recorded_by: &str,
        parsed: &ParsedEvent,
        deps: &[(&str, EventId)],
        type_codes: &[&[u8]],
    ) -> ProjectionApplyResult<Option<String>> {
        check_dep_types(self, recorded_by, parsed, deps, type_codes)
    }

    fn resolve_signer_key(
        &self,
        recorded_by: &str,
        signer_type: u8,
        signer_event_id: &[u8; 32],
    ) -> ProjectionApplyResult<SignerResolution> {
        resolve_signer_key(self, recorded_by, signer_type, signer_event_id)
    }

    fn project_encrypted(
        &self,
        recorded_by: &str,
        event_id_b64: &str,
        encrypted: &crate::event_modules::EncryptedEvent,
    ) -> ProjectionApplyResult<(ProjectionDecision, Option<ParsedEvent>)> {
        project_encrypted(self, recorded_by, event_id_b64, encrypted)
    }

    fn execute_write_ops(&self, ops: &[WriteOp]) -> ProjectionApplyResult<()> {
        execute_write_ops(self, ops)
    }

    fn execute_emit_commands(
        &self,
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
                "INSERT OR IGNORE INTO valid_events (peer_id, event_id, semantic_type_code)
                 VALUES (?1, ?2, ?3)",
                rusqlite::params![recorded_by, event_id_b64, semantic_type_code],
            )?;

            crate::state::subscriptions::on_projected_event(
                self,
                recorded_by,
                event_id_b64,
                sub_event,
            )
            .map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;
            persist_shared_dep_claims(self, recorded_by, event_id_b64, sub_event)?;

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
    use crate::event_modules::{encode_event, ParsedEvent, TenantEvent};
    use crate::projection::contract::{ContextSnapshot, EmitCommand, WriteOp};
    use crate::projection::decision::ProjectionDecision;

    use super::*;
    use crate::projection::apply::project_one::project_one_step_with_backend;

    struct FakeProjectionBackend {
        blobs: HashMap<String, Vec<u8>>,
        rejections: RefCell<Vec<(String, String, String)>>,
        blocked_event_deps: RefCell<HashMap<String, BTreeSet<String>>>,
        blocked_events: RefCell<HashMap<String, i64>>,
        guard_blocked: RefCell<Vec<String>>,
        valid_marked: RefCell<Vec<String>>,
        write_batches: RefCell<usize>,
        emit_batches: RefCell<usize>,
    }

    impl FakeProjectionBackend {
        fn with_blob(event_id_b64: String, blob: Vec<u8>) -> Self {
            let mut blobs = HashMap::new();
            blobs.insert(event_id_b64, blob);
            Self {
                blobs,
                rejections: RefCell::new(Vec::new()),
                blocked_event_deps: RefCell::new(HashMap::new()),
                blocked_events: RefCell::new(HashMap::new()),
                guard_blocked: RefCell::new(Vec::new()),
                valid_marked: RefCell::new(Vec::new()),
                write_batches: RefCell::new(0),
                emit_batches: RefCell::new(0),
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

        fn check_deps_and_block(
            &self,
            _recorded_by: &str,
            _event_id_b64: &str,
            _parsed: &ParsedEvent,
            _deps: &[(&str, EventId)],
        ) -> ProjectionApplyResult<Option<ProjectionDecision>> {
            Ok(None)
        }

        fn check_dep_types(
            &self,
            _recorded_by: &str,
            _parsed: &ParsedEvent,
            _deps: &[(&str, EventId)],
            _type_codes: &[&[u8]],
        ) -> ProjectionApplyResult<Option<String>> {
            Ok(None)
        }

        fn resolve_signer_key(
            &self,
            _recorded_by: &str,
            _signer_type: u8,
            _signer_event_id: &[u8; 32],
        ) -> ProjectionApplyResult<SignerResolution> {
            Ok(SignerResolution::NotFound)
        }

        fn project_encrypted(
            &self,
            _recorded_by: &str,
            _event_id_b64: &str,
            _encrypted: &crate::event_modules::EncryptedEvent,
        ) -> ProjectionApplyResult<(ProjectionDecision, Option<ParsedEvent>)> {
            Err("fake backend does not support encrypted projection".into())
        }

        fn execute_write_ops(&self, _ops: &[WriteOp]) -> ProjectionApplyResult<()> {
            *self.write_batches.borrow_mut() += 1;
            Ok(())
        }

        fn execute_emit_commands(
            &self,
            _recorded_by: &str,
            _commands: &[EmitCommand],
        ) -> ProjectionApplyResult<()> {
            *self.emit_batches.borrow_mut() += 1;
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
        ) -> ProjectionApplyResult<()> {
            self.valid_marked
                .borrow_mut()
                .push(event_id_b64.to_string());
            Ok(())
        }
    }

    impl ProjectionQueries for FakeProjectionBackend {
        fn load_workspace_context(
            &self,
            _recorded_by: &str,
            _event_id_b64: &str,
            _workspace: &crate::event_modules::WorkspaceEvent,
        ) -> crate::projection::queries::ProjectionQueryResult<ContextSnapshot> {
            Ok(ContextSnapshot::default())
        }

        fn load_admin_context(
            &self,
            _recorded_by: &str,
            _event_id_b64: &str,
            _admin: &crate::event_modules::AdminEvent,
        ) -> crate::projection::queries::ProjectionQueryResult<ContextSnapshot> {
            Ok(ContextSnapshot::default())
        }

        fn load_peer_shared_context(
            &self,
            _recorded_by: &str,
            _event_id_b64: &str,
            _peer_shared: &crate::event_modules::PeerSharedEvent,
        ) -> crate::projection::queries::ProjectionQueryResult<ContextSnapshot> {
            Ok(ContextSnapshot::default())
        }

        fn load_user_invite_context(
            &self,
            _recorded_by: &str,
            _event_id_b64: &str,
            _user_invite: &crate::event_modules::UserInviteEvent,
        ) -> crate::projection::queries::ProjectionQueryResult<ContextSnapshot> {
            Ok(ContextSnapshot::default())
        }

        fn load_device_invite_context(
            &self,
            _recorded_by: &str,
            _event_id_b64: &str,
            _device_invite: &crate::event_modules::DeviceInviteEvent,
        ) -> crate::projection::queries::ProjectionQueryResult<ContextSnapshot> {
            Ok(ContextSnapshot::default())
        }

        fn load_message_context(
            &self,
            _recorded_by: &str,
            _event_id_b64: &str,
            _message: &crate::event_modules::MessageEvent,
        ) -> crate::projection::queries::ProjectionQueryResult<ContextSnapshot> {
            Ok(ContextSnapshot::default())
        }

        fn load_message_deletion_context(
            &self,
            _recorded_by: &str,
            _event_id_b64: &str,
            _message_deletion: &crate::event_modules::MessageDeletionEvent,
        ) -> crate::projection::queries::ProjectionQueryResult<ContextSnapshot> {
            Ok(ContextSnapshot::default())
        }

        fn load_reaction_context(
            &self,
            _recorded_by: &str,
            _event_id_b64: &str,
            _reaction: &crate::event_modules::ReactionEvent,
        ) -> crate::projection::queries::ProjectionQueryResult<ContextSnapshot> {
            Ok(ContextSnapshot::default())
        }

        fn load_file_context(
            &self,
            _recorded_by: &str,
            _event_id_b64: &str,
            _file: &crate::event_modules::FileEvent,
        ) -> crate::projection::queries::ProjectionQueryResult<ContextSnapshot> {
            Ok(ContextSnapshot::default())
        }

        fn load_file_slice_context(
            &self,
            _recorded_by: &str,
            _event_id_b64: &str,
            _file_slice: &crate::event_modules::FileSliceEvent,
        ) -> crate::projection::queries::ProjectionQueryResult<ContextSnapshot> {
            Ok(ContextSnapshot::default())
        }

        fn load_invite_accepted_context(
            &self,
            _recorded_by: &str,
            _event_id_b64: &str,
            _invite_accepted: &crate::event_modules::InviteAcceptedEvent,
        ) -> crate::projection::queries::ProjectionQueryResult<ContextSnapshot> {
            Ok(ContextSnapshot::default())
        }

        fn load_key_shared_context(
            &self,
            _recorded_by: &str,
            _event_id_b64: &str,
            _key_shared: &crate::event_modules::KeySharedEvent,
        ) -> crate::projection::queries::ProjectionQueryResult<ContextSnapshot> {
            Ok(ContextSnapshot::default())
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
        let ctx = (meta.context_loader)(&conn, "peer-a", "event-a", &parsed).unwrap();
        let crate::projection::queries::ContextLoadResult::Ready(ctx) = ctx else {
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
}
