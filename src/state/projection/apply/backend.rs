use crate::crypto::EventId;
use crate::db::queue::current_timestamp_ms;
use crate::db::timeline::EventTimeline;
use crate::event_modules::{EventTypeMeta, ParsedEvent};
use crate::projection::contract::{ContextSnapshot, EmitCommand, WriteOp};
use crate::projection::decision::ProjectionDecision;
use crate::projection::encrypted::project_encrypted;
use crate::projection::queries::SqliteProjectionQueries;
use crate::projection::signer::{resolve_signer_key, SignerResolution};
use rusqlite::Connection;

use super::stages::{check_dep_types, check_deps_and_block, record_rejection};
use super::write_exec::{execute_emit_commands, execute_write_ops};

pub(crate) type ProjectionApplyResult<T> = Result<T, Box<dyn std::error::Error>>;

pub(crate) trait ProjectionBackend {
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

    fn load_context(
        &self,
        meta: &'static EventTypeMeta,
        recorded_by: &str,
        event_id_b64: &str,
        parsed: &ParsedEvent,
    ) -> ProjectionApplyResult<ContextSnapshot>;

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

pub(crate) struct SqliteProjectionBackend<'a> {
    conn: &'a Connection,
}

impl<'a> SqliteProjectionBackend<'a> {
    pub(crate) fn new(conn: &'a Connection) -> Self {
        Self { conn }
    }
}

impl ProjectionBackend for SqliteProjectionBackend<'_> {
    fn already_processed(
        &self,
        recorded_by: &str,
        event_id_b64: &str,
    ) -> ProjectionApplyResult<bool> {
        let already_valid: bool = self.conn.query_row(
            "SELECT COUNT(*) > 0 FROM valid_events WHERE peer_id = ?1 AND event_id = ?2",
            rusqlite::params![recorded_by, event_id_b64],
            |row| row.get(0),
        )?;
        if already_valid {
            return Ok(true);
        }

        let already_rejected: bool = self.conn.query_row(
            "SELECT COUNT(*) > 0 FROM rejected_events WHERE peer_id = ?1 AND event_id = ?2",
            rusqlite::params![recorded_by, event_id_b64],
            |row| row.get(0),
        )?;
        Ok(already_rejected)
    }

    fn load_blob(&self, event_id_b64: &str) -> ProjectionApplyResult<Option<Vec<u8>>> {
        let blob = self
            .conn
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
        record_rejection(self.conn, recorded_by, event_id_b64, reason);
        Ok(())
    }

    fn check_deps_and_block(
        &self,
        recorded_by: &str,
        event_id_b64: &str,
        parsed: &ParsedEvent,
        deps: &[(&str, EventId)],
    ) -> ProjectionApplyResult<Option<ProjectionDecision>> {
        check_deps_and_block(self.conn, recorded_by, event_id_b64, parsed, deps)
    }

    fn check_dep_types(
        &self,
        recorded_by: &str,
        parsed: &ParsedEvent,
        deps: &[(&str, EventId)],
        type_codes: &[&[u8]],
    ) -> ProjectionApplyResult<Option<String>> {
        check_dep_types(self.conn, recorded_by, parsed, deps, type_codes)
    }

    fn resolve_signer_key(
        &self,
        recorded_by: &str,
        signer_type: u8,
        signer_event_id: &[u8; 32],
    ) -> ProjectionApplyResult<SignerResolution> {
        resolve_signer_key(self.conn, recorded_by, signer_type, signer_event_id)
    }

    fn project_encrypted(
        &self,
        recorded_by: &str,
        event_id_b64: &str,
        encrypted: &crate::event_modules::EncryptedEvent,
    ) -> ProjectionApplyResult<(ProjectionDecision, Option<ParsedEvent>)> {
        project_encrypted(self.conn, recorded_by, event_id_b64, encrypted)
    }

    fn load_context(
        &self,
        meta: &'static EventTypeMeta,
        recorded_by: &str,
        event_id_b64: &str,
        parsed: &ParsedEvent,
    ) -> ProjectionApplyResult<ContextSnapshot> {
        let queries = SqliteProjectionQueries::new(self.conn);
        (meta.context_loader)(&queries, recorded_by, event_id_b64, parsed)
    }

    fn execute_write_ops(&self, ops: &[WriteOp]) -> ProjectionApplyResult<()> {
        execute_write_ops(self.conn, ops)
    }

    fn execute_emit_commands(
        &self,
        recorded_by: &str,
        commands: &[EmitCommand],
    ) -> ProjectionApplyResult<()> {
        execute_emit_commands(self.conn, recorded_by, commands)
    }

    fn mark_guard_blocked(&self, event_id_b64: &str) -> ProjectionApplyResult<()> {
        let _ =
            EventTimeline::new(self.conn).mark_blocked_b64(event_id_b64, current_timestamp_ms());
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
        let still_recorded: bool = self.conn.query_row(
            "SELECT COUNT(*) > 0 FROM recorded_events WHERE peer_id = ?1 AND event_id = ?2",
            rusqlite::params![recorded_by, event_id_b64],
            |row| row.get(0),
        )?;
        if !still_recorded {
            return Ok(());
        }

        self.conn.execute_batch("SAVEPOINT project_valid")?;
        let commit_result = (|| -> ProjectionApplyResult<()> {
            let semantic_type_code = i64::from(sub_event.event_type_code());
            self.conn.execute(
                "INSERT OR IGNORE INTO valid_events (peer_id, event_id, semantic_type_code)
                 VALUES (?1, ?2, ?3)",
                rusqlite::params![recorded_by, event_id_b64, semantic_type_code],
            )?;

            crate::state::subscriptions::on_projected_event(
                self.conn,
                recorded_by,
                event_id_b64,
                sub_event,
            )
            .map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;

            let _ = EventTimeline::new(self.conn)
                .mark_projected_b64(event_id_b64, current_timestamp_ms());
            Ok(())
        })();

        match commit_result {
            Ok(()) => {
                self.conn.execute_batch("RELEASE project_valid")?;
                Ok(())
            }
            Err(err) => {
                let _ = self.conn.execute_batch("ROLLBACK TO project_valid");
                let _ = self.conn.execute_batch("RELEASE project_valid");
                Err(err)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::collections::HashMap;

    use crate::crypto::{event_id_to_base64, hash_event};
    use crate::event_modules::{encode_event, ParsedEvent, TenantEvent};
    use crate::projection::contract::{ContextSnapshot, EmitCommand, WriteOp};
    use crate::projection::decision::ProjectionDecision;

    use super::*;
    use crate::projection::apply::project_one::project_one_step_with_backend;

    struct FakeProjectionBackend {
        blobs: HashMap<String, Vec<u8>>,
        rejections: RefCell<Vec<(String, String, String)>>,
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

        fn load_context(
            &self,
            _meta: &'static EventTypeMeta,
            _recorded_by: &str,
            _event_id_b64: &str,
            _parsed: &ParsedEvent,
        ) -> ProjectionApplyResult<ContextSnapshot> {
            Ok(ContextSnapshot::default())
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

    #[test]
    fn sqlite_backend_loads_empty_context_via_registry_loader() {
        let conn = crate::db::open_in_memory().unwrap();
        crate::db::schema::create_tables(&conn).unwrap();
        let backend = SqliteProjectionBackend::new(&conn);
        let parsed = ParsedEvent::Tenant(TenantEvent {
            created_at_ms: 1,
            public_key: [7u8; 32],
        });
        let meta = crate::event_modules::registry()
            .lookup(crate::event_modules::EVENT_TYPE_TENANT)
            .unwrap();
        let ctx = backend
            .load_context(meta, "peer-a", "event-a", &parsed)
            .unwrap();
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
