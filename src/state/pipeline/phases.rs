use std::collections::{HashMap, HashSet};

use rusqlite::Connection;

use crate::contracts::event_pipeline_contract::IngestItem;
use crate::crypto::{event_id_to_base64, EventId};
use crate::db::queue::current_timestamp_ms;
use crate::db::store::lookup_workspace_id;
use crate::db::timeline::EventTimeline;
use crate::event_modules::{self as events, registry::EventRegistry, EventTypeMeta, ShareScope};
use crate::state::shared_workspace_fanout::SharedEventFanout;

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(super) struct PersistPhaseOutput {
    pub persisted_event_ids: Vec<EventId>,
    pub tenants_seen: HashSet<String>,
    pub shared_event_fanouts: Vec<SharedEventFanout>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PersistEventKind {
    Workspace,
    EndpointShared,
    Other,
}

use topo_verus_proofs::state::pipeline::persist_validation::{
    decide_persist_validation_plan, normalize_persist_validation, PersistValidationDecisionContext,
    PersistValidationPlan, PersistValidationRawRows,
};

#[derive(Debug, Clone, PartialEq, Eq)]
struct PersistEventRawRows {
    share_scope: ShareScope,
    event_kind: PersistEventKind,
    is_file_slice: bool,
    workspace_binding: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PersistEventDecisionContext {
    share_scope: ShareScope,
    event_kind: PersistEventKind,
    is_file_slice: bool,
    workspace_binding: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum PersistWorkspaceTarget {
    Skip,
    MissingBinding,
    EventId,
    WorkspaceBinding(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PersistEventPlan {
    shared_index_workspace: PersistWorkspaceTarget,
    priority_lane: i64,
    fanout_workspace: PersistWorkspaceTarget,
}

#[inline]
fn load_persist_validation_raw_rows(
    blob: &[u8],
    reg: &'static EventRegistry,
) -> (PersistValidationRawRows, Option<&'static EventTypeMeta>) {
    let Some(created_at_ms) = events::extract_created_at_ms(blob) else {
        return (PersistValidationRawRows::MissingCreatedAt, None);
    };
    let Some(type_code) = events::extract_event_type(blob) else {
        return (PersistValidationRawRows::MissingTypeCode, None);
    };
    let meta = reg.lookup(type_code);
    let raw_rows = match meta {
        Some(_) => PersistValidationRawRows::KnownType { created_at_ms },
        None => PersistValidationRawRows::UnknownType { type_code },
    };
    (raw_rows, meta)
}

fn persist_event_kind(type_name: &str) -> PersistEventKind {
    match type_name {
        "workspace" => PersistEventKind::Workspace,
        "endpoint_shared" => PersistEventKind::EndpointShared,
        _ => PersistEventKind::Other,
    }
}

fn normalize_persist_event(raw_rows: PersistEventRawRows) -> PersistEventDecisionContext {
    PersistEventDecisionContext {
        share_scope: raw_rows.share_scope,
        event_kind: raw_rows.event_kind,
        is_file_slice: raw_rows.is_file_slice,
        workspace_binding: raw_rows.workspace_binding,
    }
}

fn decide_persist_event_plan(context: &PersistEventDecisionContext) -> PersistEventPlan {
    // The tag-level persist dispatch (which workspace-target variant and which
    // priority lane) is verified in verus-proofs; the runtime rehydrates the
    // concrete `workspace_binding: Option<String>` into `WorkspaceBinding(String)`
    // when the verified core selects that branch.
    use topo_verus_proofs::state::pipeline::phases::{
        decide_persist_event_plan_core, PersistEventDecisionContextCore, ShareScopeCore,
        WorkspaceTargetCore,
    };
    let type_name_is_workspace = matches!(context.event_kind, PersistEventKind::Workspace);
    let type_name_is_endpoint_shared =
        matches!(context.event_kind, PersistEventKind::EndpointShared);
    let core_plan = decide_persist_event_plan_core(&PersistEventDecisionContextCore {
        share_scope: match context.share_scope {
            ShareScope::Shared => ShareScopeCore::Shared,
            ShareScope::Local => ShareScopeCore::Secret,
        },
        type_name_is_endpoint_shared,
        type_name_is_workspace,
        is_file_slice: context.is_file_slice,
        has_workspace_binding: context.workspace_binding.is_some(),
    });

    let workspace_target = match core_plan.shared_index_workspace {
        WorkspaceTargetCore::Skip => PersistWorkspaceTarget::Skip,
        WorkspaceTargetCore::MissingBinding => PersistWorkspaceTarget::MissingBinding,
        WorkspaceTargetCore::EventId => PersistWorkspaceTarget::EventId,
        WorkspaceTargetCore::WorkspaceBinding => match &context.workspace_binding {
            Some(workspace_id) => PersistWorkspaceTarget::WorkspaceBinding(workspace_id.clone()),
            None => unreachable!(
                "verified core returned WorkspaceBinding but runtime has no workspace_binding"
            ),
        },
    };

    PersistEventPlan {
        shared_index_workspace: workspace_target.clone(),
        priority_lane: core_plan.priority_lane as i64,
        fanout_workspace: workspace_target,
    }
}

fn resolve_persist_workspace_target(
    target: &PersistWorkspaceTarget,
    event_id_b64: &str,
) -> Option<String> {
    match target {
        PersistWorkspaceTarget::Skip | PersistWorkspaceTarget::MissingBinding => None,
        PersistWorkspaceTarget::EventId => Some(event_id_b64.to_string()),
        PersistWorkspaceTarget::WorkspaceBinding(workspace_id) => Some(workspace_id.clone()),
    }
}

fn ingest_recorded_by_for_blob(recorded_by: &str, blob: &[u8]) -> String {
    match crate::event_modules::parse_event(blob) {
        Ok(crate::event_modules::ParsedEvent::EndpointShared(event)) => {
            crate::event_modules::endpoint_shared::endpoint_id_from_public_key_bytes(
                &event.public_key,
            )
        }
        _ => recorded_by.to_string(),
    }
}

pub(super) fn run_persist_phase(
    db: &Connection,
    batch: &[IngestItem],
    reg: &'static EventRegistry,
    workspace_cache: &mut HashMap<String, String>,
    shared_event_index_stmt: &mut rusqlite::Statement<'_>,
    recorded_stmt: &mut rusqlite::Statement<'_>,
    events_stmt: &mut rusqlite::Statement<'_>,
    enqueue_stmt: &mut rusqlite::Statement<'_>,
) -> PersistPhaseOutput {
    let timeline = EventTimeline::new(db);
    let mut persist_output = PersistPhaseOutput {
        persisted_event_ids: Vec::with_capacity(batch.len()),
        tenants_seen: HashSet::new(),
        shared_event_fanouts: Vec::new(),
    };

    for (event_id, blob, recorded_by, source_tag, received_at_ms, first_stored_at_ms) in batch {
        let effective_recorded_by = ingest_recorded_by_for_blob(recorded_by, blob);
        let event_id_b64 = event_id_to_base64(event_id);
        let _ = timeline.mark_received_and_stored_b64(
            &event_id_b64,
            *received_at_ms,
            *first_stored_at_ms,
        );

        let (validation_raw_rows, maybe_meta) = load_persist_validation_raw_rows(blob, reg);
        let validation_plan =
            decide_persist_validation_plan(&normalize_persist_validation(validation_raw_rows));
        let PersistValidationPlan::Continue { created_at_ms } = validation_plan else {
            continue;
        };
        let Some(meta) = maybe_meta else {
            debug_assert!(false, "known validation plan without registry metadata");
            continue;
        };

        let event_kind = persist_event_kind(meta.type_name);
        let is_file_slice =
            events::outer_semantic_type_code(blob) == Some(events::EVENT_TYPE_FILE_SLICE);
        let workspace_binding = if meta.share_scope == ShareScope::Shared
            && matches!(event_kind, PersistEventKind::Other)
        {
            if let Some(cached) = workspace_cache.get(&effective_recorded_by) {
                Some(cached.clone())
            } else if let Some(ws) = lookup_workspace_id(db, &effective_recorded_by) {
                workspace_cache.insert(effective_recorded_by.clone(), ws.clone());
                Some(ws)
            } else {
                None
            }
        } else {
            None
        };
        let persist_plan =
            decide_persist_event_plan(&normalize_persist_event(PersistEventRawRows {
                share_scope: meta.share_scope,
                event_kind,
                is_file_slice,
                workspace_binding,
            }));

        // Only insert into shared_event_index when the pure persist
        // plan selects a workspace target.
        match &persist_plan.shared_index_workspace {
            PersistWorkspaceTarget::Skip => {}
            PersistWorkspaceTarget::MissingBinding => {
                tracing::warn!(
                    "no accepted workspace binding for {}, skipping shared_event_index for {}",
                    effective_recorded_by,
                    event_id_b64
                );
            }
            PersistWorkspaceTarget::EventId | PersistWorkspaceTarget::WorkspaceBinding(_) => {
                let ws_id = resolve_persist_workspace_target(
                    &persist_plan.shared_index_workspace,
                    &event_id_b64,
                )
                .expect("workspace target selected");
                if let Err(e) = shared_event_index_stmt.execute(rusqlite::params![
                    &ws_id,
                    created_at_ms as i64,
                    event_id.as_slice()
                ]) {
                    // Non-fatal: shared_event_index is a reconciliation cache;
                    // event will be re-added on next sync session.
                    tracing::warn!(
                        "shared_event_index insert error for {}: {}",
                        event_id_b64,
                        e
                    );
                }
            }
        }

        if let Err(e) = events_stmt.execute(rusqlite::params![
            &event_id_b64,
            meta.type_name,
            blob.as_slice(),
            meta.share_scope.as_str(),
            created_at_ms as i64,
            current_timestamp_ms()
        ]) {
            tracing::warn!("events insert error for {}: {}", event_id_b64, e);
            continue;
        }

        let recorded_at = current_timestamp_ms();
        let recorded_inserted = match recorded_stmt.execute(rusqlite::params![
            &effective_recorded_by,
            &event_id_b64,
            recorded_at,
            source_tag
        ]) {
            Ok(rows) => rows > 0,
            Err(e) => {
                tracing::warn!("recorded_events insert error for {}: {}", event_id_b64, e);
                continue;
            }
        };
        if recorded_inserted {
            let semantic_type_code = events::outer_semantic_type_code(blob).map(i64::from);
            if let Err(e) = crate::db::observability::insert_event_ingest_observation(
                db,
                &effective_recorded_by,
                &event_id_b64,
                source_tag,
                semantic_type_code,
                *received_at_ms,
                *first_stored_at_ms,
                recorded_at,
            ) {
                tracing::warn!(
                    "event_ingest_observations insert error for {}: {}",
                    event_id_b64,
                    e
                );
            }
        }
        // Enqueue for durable projection (atomicity boundary 1)
        if let Err(e) = enqueue_stmt.execute(rusqlite::params![
            &effective_recorded_by,
            &event_id_b64,
            current_timestamp_ms(),
            persist_plan.priority_lane,
            created_at_ms as i64
        ]) {
            tracing::warn!("project_queue enqueue error for {}: {}", event_id_b64, e);
        }

        persist_output
            .tenants_seen
            .insert(effective_recorded_by.clone());
        persist_output.persisted_event_ids.push(*event_id);
        if let Some(workspace_id) =
            resolve_persist_workspace_target(&persist_plan.fanout_workspace, &event_id_b64)
        {
            persist_output.shared_event_fanouts.push(SharedEventFanout {
                origin_peer_id: effective_recorded_by.clone(),
                workspace_id,
                event_id: *event_id,
            });
        }
    }

    // Persist fanout entries durably inside this transaction so they
    // survive a crash between COMMIT and post-commit effects.
    if !persist_output.shared_event_fanouts.is_empty() {
        if let Err(e) = crate::state::shared_workspace_fanout::persist_pending_fanouts(
            db,
            &persist_output.shared_event_fanouts,
        ) {
            tracing::warn!("persist_pending_fanouts error: {}", e);
        }
    }

    persist_output
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;
    use crate::crypto::{event_id_to_base64, hash_event};
    use crate::db::{
        open_in_memory,
        schema::create_tables,
        store::{SQL_INSERT_EVENT, SQL_INSERT_RECORDED_EVENT, SQL_INSERT_SHARED_EVENT_INDEX_ENTRY},
    };
    use crate::event_modules::{
        self, EncryptedEvent, MessageEvent, ParsedEvent, EVENT_TYPE_FILE_SLICE,
    };

    fn run_persist_phase_for_test(
        db: &rusqlite::Connection,
        batch: &[IngestItem],
        workspace_cache: &mut HashMap<String, String>,
    ) -> PersistPhaseOutput {
        let mut shared_event_index_stmt = db.prepare(SQL_INSERT_SHARED_EVENT_INDEX_ENTRY).unwrap();
        let mut recorded_stmt = db.prepare(SQL_INSERT_RECORDED_EVENT).unwrap();
        let mut events_stmt = db.prepare(SQL_INSERT_EVENT).unwrap();
        let mut enqueue_stmt = db
            .prepare(
                "INSERT OR IGNORE INTO project_queue
                 (peer_id, event_id, available_at, priority_lane, priority_ts)
                 SELECT ?1, ?2, ?3, ?4, ?5
                 WHERE NOT EXISTS (SELECT 1 FROM valid_events WHERE peer_id=?1 AND event_id=?2)
                 AND NOT EXISTS (SELECT 1 FROM rejected_events WHERE peer_id=?1 AND event_id=?2)
                 AND NOT EXISTS (SELECT 1 FROM blocked_event_deps WHERE peer_id=?1 AND event_id=?2)",
            )
            .unwrap();

        run_persist_phase(
            db,
            batch,
            event_modules::registry(),
            workspace_cache,
            &mut shared_event_index_stmt,
            &mut recorded_stmt,
            &mut events_stmt,
            &mut enqueue_stmt,
        )
    }

    #[test]
    fn persist_validation_rejects_missing_created_at() {
        let context = normalize_persist_validation(PersistValidationRawRows::MissingCreatedAt);

        assert_eq!(
            decide_persist_validation_plan(&context),
            PersistValidationPlan::Skip
        );
    }

    #[test]
    fn persist_validation_rejects_unknown_type() {
        let blob = {
            let mut blob = vec![0xff];
            blob.extend_from_slice(&123u64.to_le_bytes());
            blob
        };
        let (raw_rows, meta) = load_persist_validation_raw_rows(&blob, event_modules::registry());

        assert_eq!(
            raw_rows,
            PersistValidationRawRows::UnknownType { type_code: 0xff }
        );
        assert!(meta.is_none());
        assert_eq!(
            decide_persist_validation_plan(&normalize_persist_validation(raw_rows)),
            PersistValidationPlan::Skip
        );
    }

    #[test]
    fn run_persist_phase_skips_unknown_type() {
        let db = open_in_memory().unwrap();
        create_tables(&db).unwrap();

        let mut workspace_cache = HashMap::new();
        let blob = {
            let mut blob = vec![0xff];
            blob.extend_from_slice(&123u64.to_le_bytes());
            blob
        };
        let event_id = hash_event(&blob);
        let event_id_b64 = event_id_to_base64(&event_id);
        let batch = vec![(
            event_id,
            blob,
            "peer-alpha".to_string(),
            "sync".to_string(),
            0,
            0,
        )];

        let output = run_persist_phase_for_test(&db, &batch, &mut workspace_cache);

        assert!(output.persisted_event_ids.is_empty());
        let event_count: i64 = db
            .query_row(
                "SELECT COUNT(*) FROM events WHERE event_id = ?1",
                rusqlite::params![event_id_b64],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(event_count, 0);
    }

    #[test]
    fn persist_event_plan_excludes_endpoint_shared_even_with_workspace_binding() {
        let context = normalize_persist_event(PersistEventRawRows {
            share_scope: ShareScope::Shared,
            event_kind: PersistEventKind::EndpointShared,
            is_file_slice: false,
            workspace_binding: Some(event_id_to_base64(&[7u8; 32])),
        });

        assert_eq!(
            decide_persist_event_plan(&context),
            PersistEventPlan {
                shared_index_workspace: PersistWorkspaceTarget::Skip,
                priority_lane: 1,
                fanout_workspace: PersistWorkspaceTarget::Skip,
            }
        );
    }

    #[test]
    fn persist_event_plan_self_references_workspace_event() {
        let context = normalize_persist_event(PersistEventRawRows {
            share_scope: ShareScope::Shared,
            event_kind: PersistEventKind::Workspace,
            is_file_slice: false,
            workspace_binding: Some(event_id_to_base64(&[7u8; 32])),
        });

        assert_eq!(
            decide_persist_event_plan(&context),
            PersistEventPlan {
                shared_index_workspace: PersistWorkspaceTarget::EventId,
                priority_lane: 1,
                fanout_workspace: PersistWorkspaceTarget::EventId,
            }
        );
    }

    #[test]
    fn persist_event_plan_missing_workspace_binding_suppresses_index_and_fanout() {
        let context = normalize_persist_event(PersistEventRawRows {
            share_scope: ShareScope::Shared,
            event_kind: PersistEventKind::Other,
            is_file_slice: false,
            workspace_binding: None,
        });

        let plan = decide_persist_event_plan(&context);
        assert_eq!(
            plan,
            PersistEventPlan {
                shared_index_workspace: PersistWorkspaceTarget::MissingBinding,
                priority_lane: 1,
                fanout_workspace: PersistWorkspaceTarget::MissingBinding,
            }
        );
        assert_eq!(
            resolve_persist_workspace_target(&plan.shared_index_workspace, "event-a"),
            None
        );
        assert_eq!(
            resolve_persist_workspace_target(&plan.fanout_workspace, "event-a"),
            None
        );
    }

    #[test]
    fn run_persist_phase_indexes_and_fanouts_shared_message_with_cached_workspace_binding() {
        let db = open_in_memory().unwrap();
        create_tables(&db).unwrap();

        let workspace_id = event_id_to_base64(&[9u8; 32]);
        let blob = event_modules::encode_event(&ParsedEvent::Message(MessageEvent {
            created_at_ms: 777,
            workspace_id: [3u8; 32],
            author_id: [4u8; 32],
            content: "cached workspace binding".to_string(),
        }))
        .unwrap();
        let event_id = hash_event(&blob);
        let event_id_b64 = event_id_to_base64(&event_id);
        let mut workspace_cache = HashMap::from([("peer-alpha".to_string(), workspace_id.clone())]);
        let batch = vec![(
            event_id,
            blob,
            "peer-alpha".to_string(),
            "sync".to_string(),
            0,
            0,
        )];

        let output = run_persist_phase_for_test(&db, &batch, &mut workspace_cache);

        assert_eq!(output.persisted_event_ids, vec![event_id]);
        assert_eq!(output.shared_event_fanouts.len(), 1);
        assert_eq!(output.shared_event_fanouts[0].origin_peer_id, "peer-alpha");
        assert_eq!(output.shared_event_fanouts[0].workspace_id, workspace_id);
        assert!(output.tenants_seen.contains("peer-alpha"));

        let indexed_workspace_id: String = db
            .query_row(
                "SELECT workspace_id FROM shared_event_index WHERE id = ?1",
                rusqlite::params![event_id.as_slice()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            indexed_workspace_id,
            output.shared_event_fanouts[0].workspace_id
        );

        let pending_count: i64 = db
            .query_row(
                "SELECT COUNT(*)
                 FROM pending_shared_fanouts
                 WHERE origin_peer_id = ?1 AND workspace_id = ?2 AND event_id = ?3",
                rusqlite::params![
                    "peer-alpha",
                    &output.shared_event_fanouts[0].workspace_id,
                    event_id.as_slice()
                ],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(pending_count, 1);

        let queue_count: i64 = db
            .query_row(
                "SELECT COUNT(*) FROM project_queue WHERE peer_id = ?1 AND event_id = ?2",
                rusqlite::params!["peer-alpha", &event_id_b64],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(queue_count, 1);
    }

    #[test]
    fn run_persist_phase_suppresses_shared_index_and_fanout_without_workspace_binding_for_shared_message(
    ) {
        let db = open_in_memory().unwrap();
        create_tables(&db).unwrap();

        let blob = event_modules::encode_event(&ParsedEvent::Message(MessageEvent {
            created_at_ms: 888,
            workspace_id: [5u8; 32],
            author_id: [6u8; 32],
            content: "missing workspace binding".to_string(),
        }))
        .unwrap();
        let event_id = hash_event(&blob);
        let event_id_b64 = event_id_to_base64(&event_id);
        let mut workspace_cache = HashMap::new();
        let batch = vec![(
            event_id,
            blob,
            "peer-alpha".to_string(),
            "sync".to_string(),
            0,
            0,
        )];

        let output = run_persist_phase_for_test(&db, &batch, &mut workspace_cache);

        assert_eq!(output.persisted_event_ids, vec![event_id]);
        assert!(output.shared_event_fanouts.is_empty());
        assert!(output.tenants_seen.contains("peer-alpha"));

        let shared_index_count: i64 = db
            .query_row(
                "SELECT COUNT(*) FROM shared_event_index WHERE id = ?1",
                rusqlite::params![event_id.as_slice()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(shared_index_count, 0);

        let pending_count: i64 = db
            .query_row(
                "SELECT COUNT(*)
                 FROM pending_shared_fanouts
                 WHERE origin_peer_id = ?1 AND event_id = ?2",
                rusqlite::params!["peer-alpha", event_id.as_slice()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(pending_count, 0);

        let queue_count: i64 = db
            .query_row(
                "SELECT COUNT(*) FROM project_queue WHERE peer_id = ?1 AND event_id = ?2",
                rusqlite::params!["peer-alpha", &event_id_b64],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(queue_count, 1);
    }

    #[test]
    fn run_persist_phase_enqueues_encrypted_file_slice_as_bulk() {
        let db = open_in_memory().unwrap();
        create_tables(&db).unwrap();

        let mut workspace_cache = HashMap::new();
        let blob = event_modules::encode_event(&ParsedEvent::Encrypted(EncryptedEvent {
            created_at_ms: 123,
            key_event_id: [7u8; 32],
            owner_event_id: event_modules::encrypted::NO_OWNER_EVENT_ID,
            inner_type_code: EVENT_TYPE_FILE_SLICE,
            nonce: [8u8; 12],
            ciphertext: vec![0u8; event_modules::file_slice::FILE_SLICE_WIRE_SIZE],
            auth_tag: [9u8; 16],
        }))
        .unwrap();
        let event_id = hash_event(&blob);
        let batch = vec![(
            event_id,
            blob,
            "peer-alpha".to_string(),
            "sync".to_string(),
            0,
            0,
        )];

        let output = run_persist_phase_for_test(&db, &batch, &mut workspace_cache);

        assert_eq!(output.persisted_event_ids, vec![event_id]);
        let priority_lane: i64 = db
            .query_row(
                "SELECT priority_lane
                 FROM project_queue
                 WHERE peer_id = ?1 AND event_id = ?2",
                rusqlite::params!["peer-alpha", event_id_to_base64(&event_id)],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(priority_lane, 2);
    }

    #[test]
    fn run_persist_phase_does_not_index_endpoint_shared_even_with_cached_workspace() {
        let db = open_in_memory().unwrap();
        create_tables(&db).unwrap();

        let parsed =
            event_modules::endpoint_shared::deterministic_endpoint_shared_event([0x55u8; 32]);
        let endpoint_id = match &parsed {
            ParsedEvent::EndpointShared(event) => {
                event_modules::endpoint_shared::endpoint_id_from_public_key_bytes(&event.public_key)
            }
            _ => unreachable!("deterministic endpoint helper returns endpoint_shared"),
        };
        let blob = event_modules::encode_event(&parsed).unwrap();
        let event_id = hash_event(&blob);
        let mut workspace_cache =
            HashMap::from([(endpoint_id.clone(), event_id_to_base64(&[9u8; 32]))]);
        let batch = vec![(event_id, blob, endpoint_id, "sync".to_string(), 0, 0)];

        let output = run_persist_phase_for_test(&db, &batch, &mut workspace_cache);

        let shared_index_count: i64 = db
            .query_row(
                "SELECT COUNT(*) FROM shared_event_index WHERE id = ?1",
                rusqlite::params![event_id.as_slice()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(shared_index_count, 0);
        assert!(output.shared_event_fanouts.is_empty());
    }

    #[test]
    fn run_persist_phase_indexes_workspace_event_by_own_event_id() {
        let db = open_in_memory().unwrap();
        create_tables(&db).unwrap();

        let blob =
            event_modules::encode_event(&ParsedEvent::Workspace(event_modules::WorkspaceEvent {
                created_at_ms: 321,
                public_key: [4u8; 32],
                name: "plan-ws".to_string(),
            }))
            .unwrap();
        let event_id = hash_event(&blob);
        let event_id_b64 = event_id_to_base64(&event_id);
        let mut workspace_cache =
            HashMap::from([("peer-alpha".to_string(), event_id_to_base64(&[9u8; 32]))]);
        let batch = vec![(
            event_id,
            blob,
            "peer-alpha".to_string(),
            "sync".to_string(),
            0,
            0,
        )];

        let output = run_persist_phase_for_test(&db, &batch, &mut workspace_cache);

        let indexed_workspace_id: String = db
            .query_row(
                "SELECT workspace_id FROM shared_event_index WHERE id = ?1",
                rusqlite::params![event_id.as_slice()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(indexed_workspace_id, event_id_b64);
        assert_eq!(output.shared_event_fanouts.len(), 1);
        assert_eq!(output.shared_event_fanouts[0].workspace_id, event_id_b64);
    }
}
