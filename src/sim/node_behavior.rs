use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};

use rusqlite::types::ValueRef;
use serde::Serialize;

use crate::contracts::event_pipeline_contract::IngestItem;
use crate::crypto::{event_id_from_base64, event_id_to_base64, hash_event, EventId};
use crate::event_modules::{self as events, parse_event, ParsedEvent};
use crate::projection::apply::{
    project_one::project_one_step_with_backend, ProjectionApplyResult, ProjectionBackend,
};
use crate::projection::projector::{
    CurrentSignerInfo, DeletionIntentInfo, EmitCommand, FileDescriptorInfo,
    ProjectorDecisionContext, SqlVal, WriteOp,
};
use crate::projection::decision::ProjectionDecision;
use crate::projection::decision_context::{
    admin_authority_plan_to_mismatch_reason, build_workspace_projector_decision_context,
    content_authority_plan_to_signer_user_mismatch_reason, decide_admin_authority_plan,
    decide_content_authority_plan, decide_deletion_signer_plan, decide_peer_shared_authority_plan,
    deletion_signer_plan_to_context_fields, normalize_admin_authority, normalize_content_authority,
    normalize_deletion_signer, normalize_peer_shared_authority, normalize_workspace_acceptance,
    peer_shared_authority_plan_to_mismatch_reason, AdminAuthorityRawRows, ContentAuthorityRawRows,
    DeletionSignerRawRows, DepLoadResult, PeerSharedAuthorityRawRows, ProjectionFrameContext,
    ProjectionQueries, ProjectionQueryResult, SemanticTypeRawRows, WorkspaceAcceptedRawRows,
    WorkspaceDecisionContext,
};
use crate::projection::signer::{ResolvedSigner, SignerResolution};
use crate::sim::query_snapshot::ImportedPeerState;

const SUMMARY_TABLES: &[&str] = &[
    "admins",
    "blocked_event_deps",
    "blocked_events",
    "bootstrap_context",
    "deleted_messages",
    "deletion_intents",
    "device_invites",
    "files",
    "file_slices",
    "invite_bootstrap_trust",
    "invite_secrets",
    "invites_accepted",
    "key_requests",
    "key_rotations",
    "key_secrets",
    "key_shared",
    "messages",
    "peer_secrets",
    "peers_shared",
    "pending_invite_bootstrap_trust",
    "reactions",
    "removals",
    "rejected_events",
    "shared_event_index",
    "tenants",
    "user_invites",
    "users",
    "valid_events",
    "workspaces",
];

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(tag = "kind", content = "value")]
pub enum BehaviorValue {
    Text(String),
    Int(i64),
    Blob(Vec<u8>),
}

impl From<&SqlVal> for BehaviorValue {
    fn from(value: &SqlVal) -> Self {
        match value {
            SqlVal::Text(v) => Self::Text(v.clone()),
            SqlVal::Int(v) => Self::Int(*v),
            SqlVal::Blob(v) => Self::Blob(v.clone()),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct BehaviorRow {
    pub values: BTreeMap<String, BehaviorValue>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct NodeBehaviorSummary {
    pub recorded_by: String,
    pub tables: BTreeMap<String, Vec<BehaviorRow>>,
}

#[derive(Clone, Debug, Default)]
struct StoredEvent {
    blob: Vec<u8>,
}

#[derive(Clone, Debug, Default)]
struct StoredRecordedEvent {
    source: String,
}

#[derive(Clone, Debug, Default)]
struct ValidEventState {
    semantic_type_code: Option<i64>,
    suppress_sharing: bool,
}

#[derive(Clone, Debug, Default)]
struct NodeBehaviorData {
    recorded_by: String,
    local_transport_peer_id: Option<String>,
    local_transport_source: Option<String>,
    events: BTreeMap<String, StoredEvent>,
    recorded_events: BTreeMap<String, StoredRecordedEvent>,
    valid_events: BTreeMap<String, ValidEventState>,
    rejected_events: BTreeMap<String, String>,
    blocked_events: BTreeMap<String, i64>,
    blocked_event_deps: BTreeMap<String, BTreeSet<String>>,
    tables: BTreeMap<String, Vec<BehaviorRow>>,
}

#[derive(Clone, Debug, Default)]
pub struct EventProjectionFilter {
    blocked_type_codes: BTreeSet<u8>,
}

impl EventProjectionFilter {
    pub fn with_blocked_type_codes<I>(type_codes: I) -> Self
    where
        I: IntoIterator<Item = u8>,
    {
        Self {
            blocked_type_codes: type_codes.into_iter().collect(),
        }
    }

    fn blocks(&self, type_code: u8) -> bool {
        self.blocked_type_codes.contains(&type_code)
    }

    fn blocks_parsed(&self, parsed: &ParsedEvent) -> bool {
        if self.blocks(parsed.event_type_code()) {
            return true;
        }
        match parsed {
            ParsedEvent::Signed(signed) => {
                self.blocks(signed.inner_type_code)
                    || events::parse_event(&signed.payload)
                        .map(|inner| self.blocks_parsed(&inner))
                        .unwrap_or(false)
            }
            ParsedEvent::Encrypted(enc) => self.blocks(enc.inner_type_code),
            _ => false,
        }
    }
}

pub struct NodeBehaviorEngine {
    filter: EventProjectionFilter,
    state: RefCell<NodeBehaviorData>,
}

impl NodeBehaviorEngine {
    pub fn with_filter(recorded_by: &str, filter: EventProjectionFilter) -> Self {
        Self {
            filter,
            state: RefCell::new(NodeBehaviorData {
                recorded_by: recorded_by.to_string(),
                ..NodeBehaviorData::default()
            }),
        }
    }

    pub fn ingest_imported(
        imported: &ImportedPeerState,
        filter: EventProjectionFilter,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let engine = Self::with_filter(&imported.recorded_by, filter);
        {
            let mut state = engine.state.borrow_mut();
            state.local_transport_peer_id = imported.local_transport_peer_id.clone();
            state.local_transport_source = imported.local_transport_source.clone();
            for row in &imported.bootstrap_context_rows {
                let mut values = BTreeMap::new();
                values.insert(
                    "recorded_by".to_string(),
                    BehaviorValue::Text(imported.recorded_by.clone()),
                );
                values.insert(
                    "invite_event_id".to_string(),
                    BehaviorValue::Text(row.invite_event_id.clone()),
                );
                values.insert(
                    "workspace_id".to_string(),
                    BehaviorValue::Text(row.workspace_id.clone()),
                );
                values.insert(
                    "bootstrap_addr".to_string(),
                    BehaviorValue::Text(row.bootstrap_addr.clone()),
                );
                values.insert(
                    "bootstrap_spki_fingerprint".to_string(),
                    BehaviorValue::Blob(row.bootstrap_spki_fingerprint.clone()),
                );
                values.insert(
                    "observed_at".to_string(),
                    BehaviorValue::Int(row.observed_at),
                );
                let behavior_row = BehaviorRow { values };
                let rows = state
                    .tables
                    .entry("bootstrap_context".to_string())
                    .or_default();
                if !rows.contains(&behavior_row) {
                    rows.push(behavior_row);
                    rows.sort();
                }
            }
            for row in &imported.endpoint_shared_rows {
                let mut values = BTreeMap::new();
                values.insert(
                    "recorded_by".to_string(),
                    BehaviorValue::Text(row.recorded_by.clone()),
                );
                values.insert(
                    "event_id".to_string(),
                    BehaviorValue::Text(row.event_id.clone()),
                );
                values.insert(
                    "endpoint_id".to_string(),
                    BehaviorValue::Text(row.endpoint_id.clone()),
                );
                values.insert(
                    "public_key".to_string(),
                    BehaviorValue::Blob(row.public_key.clone()),
                );
                values.insert("created_at".to_string(), BehaviorValue::Int(row.created_at));
                let behavior_row = BehaviorRow { values };
                let rows = state
                    .tables
                    .entry("endpoints_shared".to_string())
                    .or_default();
                if !rows.contains(&behavior_row) {
                    rows.push(behavior_row);
                    rows.sort();
                }
            }
        }
        let mut pending_projection = Vec::<(i64, EventId)>::new();
        for ambient in &imported.ambient_shared_events {
            let event_id =
                event_id_from_base64(&ambient.event_id).ok_or("invalid ambient shared event id")?;
            engine.store_recorded_item(&event_id, &ambient.blob, &ambient.source)?;
            pending_projection.push((ambient.created_at_ms, event_id));
        }
        for known in &imported.known_events {
            let event_id =
                event_id_from_base64(&known.event_id).ok_or("invalid imported event id")?;
            engine.store_recorded_item(&event_id, &known.blob, &known.source)?;
            pending_projection.push((known.created_at_ms, event_id));
        }
        pending_projection.sort_by(|left, right| {
            (left.0, event_id_to_base64(&left.1)).cmp(&(right.0, event_id_to_base64(&right.1)))
        });
        for (_created_at_ms, event_id) in pending_projection {
            let blob = engine
                .load_blob(&event_id_to_base64(&event_id))?
                .ok_or("stored imported event missing blob")?;
            let parsed = events::parse_event(&blob)?;
            if !engine.filter.blocks_parsed(&parsed) {
                let _ = engine.project_parsed_event(&event_id, &parsed)?;
            }
        }
        engine.replay_shared_events()?;
        Ok(engine)
    }

    pub fn seed_imported(
        imported: &ImportedPeerState,
        filter: EventProjectionFilter,
        summary: &NodeBehaviorSummary,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let engine = Self::with_filter(&imported.recorded_by, filter);
        {
            let mut state = engine.state.borrow_mut();
            state.local_transport_peer_id = imported.local_transport_peer_id.clone();
            state.local_transport_source = imported.local_transport_source.clone();
            for ambient in &imported.ambient_shared_events {
                state
                    .events
                    .entry(ambient.event_id.clone())
                    .or_insert_with(|| StoredEvent {
                        blob: ambient.blob.clone(),
                    });
            }
            for known in &imported.known_events {
                state
                    .events
                    .entry(known.event_id.clone())
                    .or_insert_with(|| StoredEvent {
                        blob: known.blob.clone(),
                    });
                state
                    .recorded_events
                    .entry(known.event_id.clone())
                    .or_insert_with(|| StoredRecordedEvent {
                        source: known.source.clone(),
                    });
            }
            seed_state_from_summary(&mut state, summary)?;
        }
        Ok(engine)
    }

    pub fn ingest_item(&self, item: IngestItem) -> Result<(), Box<dyn std::error::Error>> {
        let (event_id, blob, _recorded_by, source, _created_at_ms, _inserted_at_ms) = item;
        self.store_recorded_item(&event_id, &blob, &source)?;

        let parsed = events::parse_event(&blob)?;
        if !self.filter.blocks_parsed(&parsed) {
            self.project_and_cascade(&event_id)?;
        }
        Ok(())
    }

    pub fn summary(&self) -> NodeBehaviorSummary {
        let state = self.state.borrow();
        let mut tables = BTreeMap::new();
        for table in SUMMARY_TABLES {
            let rows = match *table {
                "valid_events" => state
                    .valid_events
                    .iter()
                    .map(|(event_id, valid)| {
                        let mut values = BTreeMap::new();
                        values.insert(
                            "peer_id".to_string(),
                            BehaviorValue::Text(state.recorded_by.clone()),
                        );
                        values.insert(
                            "event_id".to_string(),
                            BehaviorValue::Text(event_id.clone()),
                        );
                        if let Some(code) = valid.semantic_type_code {
                            values
                                .insert("semantic_type_code".to_string(), BehaviorValue::Int(code));
                        }
                        values.insert(
                            "suppress_sharing".to_string(),
                            BehaviorValue::Int(i64::from(valid.suppress_sharing)),
                        );
                        BehaviorRow { values }
                    })
                    .collect(),
                "rejected_events" => state
                    .rejected_events
                    .iter()
                    .map(|(event_id, reason)| {
                        let mut values = BTreeMap::new();
                        values.insert(
                            "peer_id".to_string(),
                            BehaviorValue::Text(state.recorded_by.clone()),
                        );
                        values.insert(
                            "event_id".to_string(),
                            BehaviorValue::Text(event_id.clone()),
                        );
                        values.insert("reason".to_string(), BehaviorValue::Text(reason.clone()));
                        BehaviorRow { values }
                    })
                    .collect(),
                "blocked_events" => state
                    .blocked_events
                    .iter()
                    .map(|(event_id, deps_remaining)| {
                        let mut values = BTreeMap::new();
                        values.insert(
                            "peer_id".to_string(),
                            BehaviorValue::Text(state.recorded_by.clone()),
                        );
                        values.insert(
                            "event_id".to_string(),
                            BehaviorValue::Text(event_id.clone()),
                        );
                        values.insert(
                            "deps_remaining".to_string(),
                            BehaviorValue::Int(*deps_remaining),
                        );
                        BehaviorRow { values }
                    })
                    .collect(),
                "blocked_event_deps" => {
                    let mut rows = Vec::new();
                    for (event_id, blockers) in &state.blocked_event_deps {
                        for blocker in blockers {
                            let mut values = BTreeMap::new();
                            values.insert(
                                "peer_id".to_string(),
                                BehaviorValue::Text(state.recorded_by.clone()),
                            );
                            values.insert(
                                "event_id".to_string(),
                                BehaviorValue::Text(event_id.clone()),
                            );
                            values.insert(
                                "blocker_event_id".to_string(),
                                BehaviorValue::Text(blocker.clone()),
                            );
                            rows.push(BehaviorRow { values });
                        }
                    }
                    rows
                }
                other => state.tables.get(other).cloned().unwrap_or_default(),
            };
            if !rows.is_empty() {
                tables.insert((*table).to_string(), sort_rows(rows));
            }
        }
        for (table, rows) in &state.tables {
            if tables.contains_key(table) || rows.is_empty() {
                continue;
            }
            tables.insert(table.clone(), sort_rows(rows.clone()));
        }
        NodeBehaviorSummary {
            recorded_by: state.recorded_by.clone(),
            tables,
        }
    }

    pub fn recorded_by(&self) -> String {
        self.state.borrow().recorded_by.clone()
    }

    pub fn transport_peer_id(&self) -> String {
        let state = self.state.borrow();
        state
            .local_transport_peer_id
            .clone()
            .unwrap_or_else(|| state.recorded_by.clone())
    }

    pub fn recorded_event_ids(&self) -> BTreeSet<String> {
        self.state
            .borrow()
            .recorded_events
            .keys()
            .cloned()
            .collect()
    }

    pub fn shared_recorded_events(
        &self,
    ) -> Result<Vec<(String, String, i64, Vec<u8>)>, Box<dyn std::error::Error>> {
        let state = self.state.borrow();
        let mut out = Vec::new();
        for event_id in state.recorded_events.keys() {
            let Some(event) = state.events.get(event_id) else {
                continue;
            };
            let parsed = events::parse_event(&event.blob)?;
            let semantic = semantic_event_owned(&parsed);
            let Some(meta) = events::registry().lookup(semantic.event_type_code()) else {
                continue;
            };
            if meta.share_scope != events::ShareScope::Shared {
                continue;
            }
            out.push((
                event_id.clone(),
                meta.type_name.to_string(),
                events::extract_created_at_ms(&event.blob).unwrap_or(0) as i64,
                event.blob.clone(),
            ));
        }
        out.sort_by(|left, right| (left.2, &left.0).cmp(&(right.2, &right.0)));
        Ok(out)
    }

    pub fn transferable_shared_event(
        &self,
        event_id: &str,
    ) -> Result<Option<(String, String, i64, Vec<u8>)>, Box<dyn std::error::Error>> {
        let state = self.state.borrow();
        let Some(event) = state.events.get(event_id) else {
            return Ok(None);
        };
        let parsed = events::parse_event(&event.blob)?;
        let semantic = semantic_event_owned(&parsed);
        let Some(meta) = events::registry().lookup(semantic.event_type_code()) else {
            return Ok(None);
        };
        if meta.share_scope != events::ShareScope::Shared {
            return Ok(None);
        }
        Ok(Some((
            event_id.to_string(),
            meta.type_name.to_string(),
            events::extract_created_at_ms(&event.blob).unwrap_or(0) as i64,
            event.blob.clone(),
        )))
    }

    pub fn apply_transferred_batch(
        &self,
        source_tag: &str,
        blobs: Vec<Vec<u8>>,
    ) -> Result<usize, Box<dyn std::error::Error>> {
        let mut pending_projection = Vec::new();
        let mut ingested = 0usize;
        for blob in blobs {
            let event_id = hash_event(&blob);
            self.store_recorded_item(&event_id, &blob, source_tag)?;
            pending_projection.push((event_id, blob));
            ingested = ingested.saturating_add(1);
        }
        for (event_id, blob) in pending_projection {
            let parsed = events::parse_event(&blob)?;
            if !self.filter.blocks_parsed(&parsed) {
                self.project_parsed_event(&event_id, &parsed)?;
            }
        }
        Ok(ingested)
    }

    fn store_recorded_item(
        &self,
        event_id: &EventId,
        blob: &[u8],
        source: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let event_id_b64 = event_id_to_base64(event_id);
        let parsed = events::parse_event(blob)?;
        let _meta = events::registry()
            .lookup(parsed.event_type_code())
            .ok_or("unknown event type")?;
        let mut state = self.state.borrow_mut();
        state
            .events
            .entry(event_id_b64.clone())
            .or_insert_with(|| StoredEvent {
                blob: blob.to_vec(),
            });
        state
            .recorded_events
            .entry(event_id_b64)
            .or_insert_with(|| StoredRecordedEvent {
                source: source.to_string(),
            });
        Ok(())
    }

    fn project_and_cascade(
        &self,
        event_id: &EventId,
    ) -> Result<ProjectionDecision, Box<dyn std::error::Error>> {
        let recorded_by = self.state.borrow().recorded_by.clone();
        let (decision, _) = project_one_step_with_backend(self, &recorded_by, event_id)?;
        if matches!(decision, ProjectionDecision::Valid) {
            self.cascade_unblocked(&recorded_by, &event_id_to_base64(event_id))?;
        }
        Ok(decision)
    }

    fn project_parsed_event(
        &self,
        event_id: &EventId,
        parsed: &ParsedEvent,
    ) -> Result<ProjectionDecision, Box<dyn std::error::Error>> {
        if let ParsedEvent::EndpointShared(endpoint_shared) = parsed {
            return self.project_endpoint_shared_global(event_id, endpoint_shared);
        }
        self.project_and_cascade(event_id)
    }

    fn project_endpoint_shared_global(
        &self,
        event_id: &EventId,
        endpoint_shared: &events::EndpointSharedEvent,
    ) -> Result<ProjectionDecision, Box<dyn std::error::Error>> {
        let endpoint_id = crate::event_modules::endpoint_shared::endpoint_id_from_public_key_bytes(
            &endpoint_shared.public_key,
        );
        let (decision, _) = project_one_step_with_backend(self, &endpoint_id, event_id)?;
        if matches!(decision, ProjectionDecision::Valid) {
            self.state.borrow_mut().valid_events.insert(
                event_id_to_base64(event_id),
                ValidEventState {
                    semantic_type_code: Some(i64::from(events::EVENT_TYPE_ENDPOINT_SHARED)),
                    suppress_sharing: false,
                },
            );
        }
        Ok(decision)
    }

    fn replay_shared_events(&self) -> Result<(), Box<dyn std::error::Error>> {
        let event_ids = {
            let state = self.state.borrow();
            let mut out = Vec::new();
            for (event_id_b64, event) in &state.events {
                let parsed = events::parse_event(&event.blob)?;
                if self.filter.blocks_parsed(&parsed) {
                    continue;
                }
                let semantic = semantic_event_owned(&parsed);
                let Some(meta) = events::registry().lookup(semantic.event_type_code()) else {
                    continue;
                };
                if meta.share_scope != events::ShareScope::Shared {
                    continue;
                }
                let created_at_ms = events::extract_created_at_ms(&event.blob).unwrap_or(0) as i64;
                out.push((created_at_ms, event_id_b64.clone()));
            }
            out.sort_by(|left, right| (left.0, &left.1).cmp(&(right.0, &right.1)));
            out.into_iter()
                .filter_map(|(_, event_id_b64)| event_id_from_base64(&event_id_b64))
                .collect::<Vec<_>>()
        };
        for event_id in event_ids {
            let blob = self
                .load_blob(&event_id_to_base64(&event_id))?
                .ok_or("stored replay event missing blob")?;
            let parsed = events::parse_event(&blob)?;
            if matches!(
                semantic_event_owned(&parsed),
                ParsedEvent::KeyHistory(_) | ParsedEvent::KeyRotation(_) | ParsedEvent::KeyShared(_)
            ) {
                self.state
                    .borrow_mut()
                    .valid_events
                    .remove(&event_id_to_base64(&event_id));
            }
            let _ = self.project_parsed_event(&event_id, &parsed)?;
        }
        Ok(())
    }

    fn cascade_unblocked(
        &self,
        recorded_by: &str,
        blocker_b64: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut worklist = vec![blocker_b64.to_string()];
        while let Some(blocker) = worklist.pop() {
            let candidates = {
                let state = self.state.borrow();
                state
                    .blocked_event_deps
                    .iter()
                    .filter_map(|(event_id, blockers)| {
                        blockers.contains(&blocker).then_some(event_id.clone())
                    })
                    .collect::<Vec<_>>()
            };

            for event_id_b64 in candidates {
                let ready = {
                    let mut state = self.state.borrow_mut();
                    let Some(blockers) = state.blocked_event_deps.get_mut(&event_id_b64) else {
                        continue;
                    };
                    blockers.remove(&blocker);
                    if blockers.is_empty() {
                        state.blocked_event_deps.remove(&event_id_b64);
                        state.blocked_events.remove(&event_id_b64);
                        true
                    } else {
                        let deps_remaining = blockers.len() as i64;
                        state
                            .blocked_events
                            .insert(event_id_b64.clone(), deps_remaining);
                        false
                    }
                };

                if !ready {
                    continue;
                }

                if let Some(event_id) = event_id_from_base64(&event_id_b64) {
                    let (decision, _) =
                        project_one_step_with_backend(self, recorded_by, &event_id)?;
                    if matches!(decision, ProjectionDecision::Valid) {
                        worklist.push(event_id_b64);
                    }
                }
            }
        }
        Ok(())
    }
}

fn semantic_event_owned(parsed: &ParsedEvent) -> ParsedEvent {
    match parsed {
        ParsedEvent::Signed(signed) => match events::parse_event(&signed.payload) {
            Ok(inner) => semantic_event_owned(&inner),
            Err(_) => parsed.clone(),
        },
        _ => parsed.clone(),
    }
}

fn seed_state_from_summary(
    state: &mut NodeBehaviorData,
    summary: &NodeBehaviorSummary,
) -> Result<(), Box<dyn std::error::Error>> {
    state.tables.clear();
    state.valid_events.clear();
    state.rejected_events.clear();
    state.blocked_events.clear();
    state.blocked_event_deps.clear();

    for (table, rows) in &summary.tables {
        match table.as_str() {
            "valid_events" => {
                for row in rows {
                    let Some(event_id) = row_text(row, "event_id") else {
                        continue;
                    };
                    state.valid_events.insert(
                        event_id.to_string(),
                        ValidEventState {
                            semantic_type_code: row_int(row, "semantic_type_code"),
                            suppress_sharing: row_int(row, "suppress_sharing")
                                .is_some_and(|value| value != 0),
                        },
                    );
                }
            }
            "rejected_events" => {
                for row in rows {
                    let (Some(event_id), Some(reason)) =
                        (row_text(row, "event_id"), row_text(row, "reason"))
                    else {
                        continue;
                    };
                    state
                        .rejected_events
                        .insert(event_id.to_string(), reason.to_string());
                }
            }
            "blocked_events" => {
                for row in rows {
                    let (Some(event_id), Some(deps_remaining)) =
                        (row_text(row, "event_id"), row_int(row, "deps_remaining"))
                    else {
                        continue;
                    };
                    state
                        .blocked_events
                        .insert(event_id.to_string(), deps_remaining);
                }
            }
            "blocked_event_deps" => {
                for row in rows {
                    let (Some(event_id), Some(blocker_event_id)) =
                        (row_text(row, "event_id"), row_text(row, "blocker_event_id"))
                    else {
                        continue;
                    };
                    state
                        .blocked_event_deps
                        .entry(event_id.to_string())
                        .or_default()
                        .insert(blocker_event_id.to_string());
                }
            }
            _ => {
                state.tables.insert(table.clone(), rows.clone());
            }
        }
    }

    Ok(())
}

fn row_text<'a>(row: &'a BehaviorRow, column: &str) -> Option<&'a str> {
    match row.values.get(column) {
        Some(BehaviorValue::Text(value)) => Some(value.as_str()),
        _ => None,
    }
}

fn row_int(row: &BehaviorRow, column: &str) -> Option<i64> {
    match row.values.get(column) {
        Some(BehaviorValue::Int(value)) => Some(*value),
        _ => None,
    }
}

fn row_blob<'a>(row: &'a BehaviorRow, column: &str) -> Option<&'a [u8]> {
    match row.values.get(column) {
        Some(BehaviorValue::Blob(value)) => Some(value.as_slice()),
        _ => None,
    }
}

fn table_rows_for_recorded<'a>(
    state: &'a NodeBehaviorData,
    table: &str,
    recorded_by: &str,
) -> Vec<&'a BehaviorRow> {
    state
        .tables
        .get(table)
        .into_iter()
        .flat_map(|rows| rows.iter())
        .filter(|row| {
            row_text(row, "recorded_by") == Some(recorded_by)
                || row_text(row, "peer_id") == Some(recorded_by)
        })
        .collect()
}

fn insert_or_ignore_key_matches(table: &str, left: &BehaviorRow, right: &BehaviorRow) -> bool {
    let key_columns: &[&str] = match table {
        "key_secrets" => &["recorded_by", "event_id"],
        _ => return left == right,
    };
    key_columns.iter().all(|column| {
        left.values.get(*column).zip(right.values.get(*column)).is_some_and(
            |(left_value, right_value)| left_value == right_value,
        )
    })
}

fn first_row_for_recorded<'a>(
    state: &'a NodeBehaviorData,
    table: &str,
    recorded_by: &str,
    column: &str,
    value: &str,
) -> Option<&'a BehaviorRow> {
    table_rows_for_recorded(state, table, recorded_by)
        .into_iter()
        .find(|row| row_text(row, column) == Some(value))
}

fn first_row_for_table<'a>(
    state: &'a NodeBehaviorData,
    table: &str,
    column: &str,
    value: &str,
) -> Option<&'a BehaviorRow> {
    state
        .tables
        .get(table)
        .into_iter()
        .flat_map(|rows| rows.iter())
        .find(|row| row_text(row, column) == Some(value))
}

fn rows_for_recorded_matching<'a>(
    state: &'a NodeBehaviorData,
    table: &str,
    recorded_by: &str,
    predicates: &[(&str, &str)],
) -> Vec<&'a BehaviorRow> {
    table_rows_for_recorded(state, table, recorded_by)
        .into_iter()
        .filter(|row| {
            predicates
                .iter()
                .all(|(column, value)| row_text(row, column) == Some(*value))
        })
        .collect()
}

fn has_valid_event(state: &NodeBehaviorData, recorded_by: &str, event_id_b64: &str) -> bool {
    state.recorded_by == recorded_by && state.valid_events.contains_key(event_id_b64)
}

fn valid_event_blob(
    state: &NodeBehaviorData,
    recorded_by: &str,
    event_id_b64: &str,
) -> Option<Vec<u8>> {
    has_valid_event(state, recorded_by, event_id_b64).then(|| {
        state
            .events
            .get(event_id_b64)
            .map(|event| event.blob.clone())
            .unwrap_or_default()
    })
}

fn recorded_source(
    state: &NodeBehaviorData,
    recorded_by: &str,
    event_id_b64: &str,
) -> Option<String> {
    (state.recorded_by == recorded_by)
        .then(|| {
            state
                .recorded_events
                .get(event_id_b64)
                .map(|recorded| recorded.source.clone())
        })
        .flatten()
}

fn bootstrap_decision_context(
    state: &NodeBehaviorData,
    recorded_by: &str,
    invite_event_id_b64: &str,
) -> Option<crate::projection::projector::BootstrapDecisionContext> {
    let mut rows = rows_for_recorded_matching(
        state,
        "bootstrap_context",
        recorded_by,
        &[("invite_event_id", invite_event_id_b64)],
    );
    if rows.is_empty() {
        return None;
    }
    rows.sort_by_key(|row| {
        (
            -row_int(row, "observed_at").unwrap_or(i64::MIN),
            row_text(row, "bootstrap_addr")
                .unwrap_or_default()
                .to_string(),
        )
    });
    let latest = rows[0];
    let workspace_id = row_text(latest, "workspace_id")?.to_string();
    let fingerprint = row_blob(latest, "bootstrap_spki_fingerprint")?;
    if fingerprint.len() != 32 {
        return None;
    }
    let mut bootstrap_spki_fingerprint = [0u8; 32];
    bootstrap_spki_fingerprint.copy_from_slice(fingerprint);
    let mut addrs = BTreeSet::new();
    for row in rows {
        if let Some(addr) = row_text(row, "bootstrap_addr") {
            addrs.insert(addr.to_string());
        }
    }
    Some(crate::projection::projector::BootstrapDecisionContext {
        workspace_id,
        bootstrap_addrs: addrs.into_iter().collect(),
        bootstrap_spki_fingerprint,
    })
}

fn signer_user_mismatch_reason_behavior(
    state: &NodeBehaviorData,
    frame: &ProjectionFrameContext,
    recorded_by: &str,
    author_id: &[u8; 32],
) -> Option<String> {
    let raw_rows = match frame.current_signer.as_ref() {
        None => ContentAuthorityRawRows::MissingCurrentSigner,
        Some(current_signer)
            if current_signer.semantic_type_code != events::EVENT_TYPE_PEER_SHARED =>
        {
            ContentAuthorityRawRows::UnsupportedSignerType {
                semantic_type_code: current_signer.semantic_type_code,
            }
        }
        Some(current_signer) => ContentAuthorityRawRows::PeerSharedSigner {
            signer_event_id: current_signer.event_id.clone(),
            signer_user_ids: table_rows_for_recorded(state, "peers_shared", recorded_by)
                .into_iter()
                .filter(|row| row_text(row, "event_id") == Some(current_signer.event_id.as_str()))
                .map(|row| row_text(row, "user_event_id").map(ToOwned::to_owned))
                .collect(),
            malformed: false,
        },
    };
    let context = normalize_content_authority(&raw_rows, &event_id_to_base64(author_id));
    content_authority_plan_to_signer_user_mismatch_reason(decide_content_authority_plan(&context))
}

fn deletion_signer_context_behavior(
    state: &NodeBehaviorData,
    frame: &ProjectionFrameContext,
    recorded_by: &str,
) -> (Option<String>, bool, Option<String>) {
    let raw_rows = match frame.current_signer.as_ref() {
        None => DeletionSignerRawRows::MissingCurrentSigner,
        Some(current_signer) if current_signer.semantic_type_code == events::EVENT_TYPE_ADMIN => {
            DeletionSignerRawRows::AdminSigner
        }
        Some(current_signer)
            if current_signer.semantic_type_code == events::EVENT_TYPE_PEER_SHARED =>
        {
            DeletionSignerRawRows::PeerSharedSigner {
                signer_event_id: current_signer.event_id.clone(),
                signer_user_ids: table_rows_for_recorded(state, "peers_shared", recorded_by)
                    .into_iter()
                    .filter(|row| {
                        row_text(row, "event_id") == Some(current_signer.event_id.as_str())
                    })
                    .map(|row| row_text(row, "user_event_id").map(ToOwned::to_owned))
                    .collect(),
                malformed: false,
            }
        }
        Some(current_signer) => DeletionSignerRawRows::UnsupportedSignerType {
            semantic_type_code: current_signer.semantic_type_code,
        },
    };
    let context = normalize_deletion_signer(&raw_rows);
    deletion_signer_plan_to_context_fields(decide_deletion_signer_plan(&context))
}

fn deleted_message_purges_dep_behavior(
    state: &NodeBehaviorData,
    recorded_by: &str,
    parsed: &ParsedEvent,
    field_name: &str,
    dep_b64: &str,
) -> Option<String> {
    let is_deleted_message_target = matches!(
        (parsed, field_name),
        (ParsedEvent::Reaction(_), "target_event_id")
            | (ParsedEvent::File(_), "message_id")
            | (ParsedEvent::Encrypted(_), "owner_event_id")
    );
    (is_deleted_message_target
        && first_row_for_recorded(
            state,
            "deleted_messages",
            recorded_by,
            "message_id",
            dep_b64,
        )
        .is_some())
    .then(|| dep_b64.to_string())
}

fn resolve_signer_key_behavior(
    state: &NodeBehaviorData,
    recorded_by: &str,
    signer_event_id: &[u8; 32],
) -> ProjectionApplyResult<SignerResolution> {
    if state.recorded_by != recorded_by {
        return Ok(SignerResolution::NotFound);
    }
    let event_id_b64 = event_id_to_base64(signer_event_id);
    if !state.valid_events.contains_key(&event_id_b64) {
        return Ok(SignerResolution::NotFound);
    }
    let Some(blob) = state.events.get(&event_id_b64).map(|event| &event.blob) else {
        return Ok(SignerResolution::NotFound);
    };
    if blob.len() < 41 {
        return Ok(SignerResolution::Invalid(format!(
            "signer blob too short: {} bytes",
            blob.len()
        )));
    }
    let parsed = events::parse_event(blob)?;
    let (semantic_type_code, public_key) = match parsed {
        ParsedEvent::Signed(signed) => match events::parse_event(&signed.payload)? {
            ParsedEvent::Workspace(event) => (events::EVENT_TYPE_WORKSPACE, event.public_key),
            ParsedEvent::UserInvite(event) => (events::EVENT_TYPE_USER_INVITE, event.public_key),
            ParsedEvent::DeviceInvite(event) => {
                (events::EVENT_TYPE_DEVICE_INVITE, event.public_key)
            }
            ParsedEvent::User(event) => (events::EVENT_TYPE_USER, event.public_key),
            ParsedEvent::Admin(event) => (events::EVENT_TYPE_ADMIN, event.public_key),
            ParsedEvent::PeerShared(event) => (events::EVENT_TYPE_PEER_SHARED, event.public_key),
            other => {
                return Ok(SignerResolution::Invalid(format!(
                    "signer event type_code={} is not a supported signer identity type",
                    other.event_type_code()
                )))
            }
        },
        ParsedEvent::Workspace(event) => (events::EVENT_TYPE_WORKSPACE, event.public_key),
        ParsedEvent::UserInvite(event) => (events::EVENT_TYPE_USER_INVITE, event.public_key),
        ParsedEvent::DeviceInvite(event) => (events::EVENT_TYPE_DEVICE_INVITE, event.public_key),
        ParsedEvent::User(event) => (events::EVENT_TYPE_USER, event.public_key),
        ParsedEvent::Admin(event) => (events::EVENT_TYPE_ADMIN, event.public_key),
        ParsedEvent::PeerShared(event) => (events::EVENT_TYPE_PEER_SHARED, event.public_key),
        other => {
            return Ok(SignerResolution::Invalid(format!(
                "signer event type_code={} is not a supported signer identity type",
                other.event_type_code()
            )))
        }
    };
    Ok(SignerResolution::Found(ResolvedSigner {
        info: CurrentSignerInfo {
            event_id: event_id_b64,
            semantic_type_code,
        },
        public_key,
    }))
}

impl ProjectionQueries for NodeBehaviorEngine {
    fn load_dep_result(
        &self,
        recorded_by: &str,
        parsed: &ParsedEvent,
        field_name: &str,
        dep_id: &EventId,
    ) -> ProjectionQueryResult<DepLoadResult> {
        let state = self.state.borrow();
        if state.recorded_by != recorded_by {
            return Ok(DepLoadResult::missing());
        }
        let dep_b64 = event_id_to_base64(dep_id);
        if state.valid_events.contains_key(&dep_b64) {
            let semantic_type_code = state
                .valid_events
                .get(&dep_b64)
                .and_then(|value| value.semantic_type_code);
            return Ok(DepLoadResult::ready_raw(semantic_type_code));
        }
        if state.tables.get("endpoints_shared").is_some_and(|rows| {
            rows.iter()
                .any(|row| row_text(row, "event_id") == Some(&dep_b64))
        }) {
            return Ok(DepLoadResult::Ready {
                semantic_type_rows: SemanticTypeRawRows::UniqueKnown {
                    semantic_type_code: Some(i64::from(
                        crate::event_modules::EVENT_TYPE_ENDPOINT_SHARED,
                    )),
                },
            });
        }
        if let Some(message_event_id) =
            deleted_message_purges_dep_behavior(&state, recorded_by, parsed, field_name, &dep_b64)
        {
            return Ok(DepLoadResult::purge(message_event_id));
        }
        Ok(DepLoadResult::missing())
    }

    fn load_key_secret_bytes(
        &self,
        recorded_by: &str,
        key_event_id: &[u8; 32],
    ) -> ProjectionQueryResult<Option<[u8; 32]>> {
        Ok(key_secret_bytes(
            &self.state.borrow(),
            recorded_by,
            key_event_id,
        ))
    }

    fn load_workspace_context(
        &self,
        frame: &ProjectionFrameContext,
        recorded_by: &str,
        event_id_b64: &str,
        workspace: &events::WorkspaceEvent,
    ) -> ProjectionQueryResult<ProjectorDecisionContext> {
        let context =
            self.load_workspace_decision_context(frame, recorded_by, event_id_b64, workspace)?;
        Ok(build_workspace_projector_decision_context(&context))
    }

    fn load_workspace_decision_context(
        &self,
        _frame: &ProjectionFrameContext,
        recorded_by: &str,
        _event_id_b64: &str,
        _workspace: &events::WorkspaceEvent,
    ) -> ProjectionQueryResult<WorkspaceDecisionContext> {
        let state = self.state.borrow();
        let mut workspace_ids = Vec::new();
        let mut malformed = false;
        for row in table_rows_for_recorded(&state, "invites_accepted", recorded_by) {
            match row_text(row, "workspace_id") {
                Some(workspace_id) => workspace_ids.push(workspace_id.to_string()),
                None => malformed = true,
            }
        }
        Ok(normalize_workspace_acceptance(&WorkspaceAcceptedRawRows {
            workspace_ids,
            malformed,
        }))
    }

    fn load_admin_context(
        &self,
        frame: &ProjectionFrameContext,
        recorded_by: &str,
        _event_id_b64: &str,
        admin: &events::AdminEvent,
    ) -> ProjectionQueryResult<ProjectorDecisionContext> {
        let state = self.state.borrow();
        let user_event_id_b64 = event_id_to_base64(&admin.user_event_id);
        let authority_event_id_b64 = event_id_to_base64(&admin.authority_event_id);
        let raw_rows = match frame.current_signer.as_ref() {
            None => AdminAuthorityRawRows::MissingCurrentSigner,
            Some(current_signer)
                if current_signer.semantic_type_code == events::EVENT_TYPE_WORKSPACE =>
            {
                AdminAuthorityRawRows::WorkspaceSigner {
                    authority_matches_signer: current_signer.event_id == authority_event_id_b64,
                    user_event_id: user_event_id_b64.clone(),
                    user_public_keys: table_rows_for_recorded(&state, "users", recorded_by)
                        .into_iter()
                        .filter(|row| row_text(row, "event_id") == Some(&user_event_id_b64))
                        .map(|row| row_blob(row, "public_key").map(ToOwned::to_owned))
                        .collect(),
                    malformed: false,
                }
            }
            Some(current_signer)
                if current_signer.semantic_type_code == events::EVENT_TYPE_PEER_SHARED =>
            {
                let signer_b64 = current_signer.event_id.clone();
                let authority_matches_signer =
                    table_rows_for_recorded(&state, "peers_shared", recorded_by)
                        .into_iter()
                        .find(|row| row_text(row, "event_id") == Some(&signer_b64))
                        .and_then(|row| row_text(row, "user_event_id").map(ToOwned::to_owned))
                        .is_some_and(|user_event_id| {
                            table_rows_for_recorded(&state, "users", recorded_by)
                                .into_iter()
                                .find(|row| row_text(row, "event_id") == Some(&user_event_id))
                                .and_then(|user_row| {
                                    row_blob(user_row, "public_key").map(|v| v.to_vec())
                                })
                                .is_some_and(|public_key| {
                                    table_rows_for_recorded(&state, "admins", recorded_by)
                                        .into_iter()
                                        .any(|row| {
                                            row_text(row, "event_id")
                                                == Some(&authority_event_id_b64)
                                                && row_blob(row, "public_key")
                                                    .is_some_and(|admin_key| admin_key == public_key)
                                        })
                                })
                        });
                AdminAuthorityRawRows::PeerSharedSigner {
                    authority_matches_signer,
                    user_event_id: user_event_id_b64.clone(),
                    user_public_keys: table_rows_for_recorded(&state, "users", recorded_by)
                        .into_iter()
                        .filter(|row| row_text(row, "event_id") == Some(&user_event_id_b64))
                        .map(|row| row_blob(row, "public_key").map(ToOwned::to_owned))
                        .collect(),
                    malformed: false,
                }
            }
            Some(current_signer) => AdminAuthorityRawRows::UnsupportedSignerType {
                semantic_type_code: current_signer.semantic_type_code,
            },
        };
        let context = normalize_admin_authority(&raw_rows, &admin.public_key);
        Ok(ProjectorDecisionContext {
            admin_user_key_mismatch_reason: admin_authority_plan_to_mismatch_reason(
                decide_admin_authority_plan(&context),
            ),
            ..ProjectorDecisionContext::default()
        })
    }

    fn load_peer_shared_context(
        &self,
        frame: &ProjectionFrameContext,
        recorded_by: &str,
        _event_id_b64: &str,
        peer_shared: &events::PeerSharedEvent,
    ) -> ProjectionQueryResult<ProjectorDecisionContext> {
        let state = self.state.borrow();
        let raw_rows = match frame.current_signer.as_ref() {
            None => PeerSharedAuthorityRawRows::MissingCurrentSigner,
            Some(current_signer)
                if current_signer.semantic_type_code != events::EVENT_TYPE_DEVICE_INVITE =>
            {
                PeerSharedAuthorityRawRows::UnsupportedSignerType {
                    semantic_type_code: current_signer.semantic_type_code,
                }
            }
            Some(current_signer) => {
                let signed_by_b64 = current_signer.event_id.clone();
                match valid_event_blob(&state, recorded_by, &signed_by_b64) {
                    None => PeerSharedAuthorityRawRows::MissingDeviceInviteBlob {
                        signer_event_id: signed_by_b64,
                    },
                    Some(blob) => match parse_event(&blob) {
                        Ok(ParsedEvent::DeviceInvite(device_invite)) => {
                            PeerSharedAuthorityRawRows::DeviceInviteSigner {
                                signer_event_id: signed_by_b64,
                                authorized_user_id: event_id_to_base64(
                                    &device_invite.authority_event_id,
                                ),
                            }
                        }
                        Ok(ParsedEvent::Signed(signed)) => match parse_event(&signed.payload) {
                            Ok(ParsedEvent::DeviceInvite(device_invite)) => {
                                PeerSharedAuthorityRawRows::DeviceInviteSigner {
                                    signer_event_id: signed_by_b64,
                                    authorized_user_id: event_id_to_base64(
                                        &device_invite.authority_event_id,
                                    ),
                                }
                            }
                            Ok(other) => PeerSharedAuthorityRawRows::MalformedDeviceInvite {
                                signer_event_id: signed_by_b64.clone(),
                                reason: format!(
                                    "peer_shared signer {} resolved to unexpected event type {}",
                                    signed_by_b64,
                                    other.event_type_code()
                                ),
                            },
                            Err(err) => PeerSharedAuthorityRawRows::MalformedDeviceInvite {
                                signer_event_id: signed_by_b64.clone(),
                                reason: format!(
                                    "failed to parse signed device_invite signer {}: {}",
                                    signed_by_b64, err
                                ),
                            },
                        },
                        Ok(other) => PeerSharedAuthorityRawRows::MalformedDeviceInvite {
                            signer_event_id: signed_by_b64.clone(),
                            reason: format!(
                                "peer_shared signer {} resolved to unexpected event type {}",
                                signed_by_b64,
                                other.event_type_code()
                            ),
                        },
                        Err(err) => PeerSharedAuthorityRawRows::MalformedDeviceInvite {
                            signer_event_id: signed_by_b64.clone(),
                            reason: format!(
                                "failed to parse device_invite signer {}: {}",
                                signed_by_b64, err
                            ),
                        },
                    },
                }
            }
        };
        let claimed_user_b64 = event_id_to_base64(&peer_shared.user_event_id);
        let authority_context = normalize_peer_shared_authority(&raw_rows, &claimed_user_b64);

        let endpoint_shared_event_id_b64 =
            event_id_to_base64(&peer_shared.endpoint_shared_event_id);
        let endpoint_shared_row = first_row_for_table(
            &state,
            "endpoints_shared",
            "event_id",
            &endpoint_shared_event_id_b64,
        );

        Ok(ProjectorDecisionContext {
            peer_shared_user_mismatch_reason: peer_shared_authority_plan_to_mismatch_reason(
                decide_peer_shared_authority_plan(&authority_context),
            ),
            peer_shared_endpoint_id: endpoint_shared_row
                .and_then(|row| row_text(row, "endpoint_id").map(ToOwned::to_owned)),
            peer_shared_endpoint_binding_reason: match endpoint_shared_row {
                Some(_) => None,
                None => Some(format!(
                    "no projected endpoint_shared row for {}",
                    endpoint_shared_event_id_b64
                )),
            },
            ..ProjectorDecisionContext::default()
        })
    }

    fn load_user_invite_context(
        &self,
        frame: &ProjectionFrameContext,
        recorded_by: &str,
        event_id_b64: &str,
        user_invite: &events::UserInviteEvent,
    ) -> ProjectionQueryResult<ProjectorDecisionContext> {
        let state = self.state.borrow();
        let mut ctx = ProjectorDecisionContext::default();
        ctx.is_local_create = recorded_source(&state, recorded_by, event_id_b64)
            .is_some_and(|source| source == "local" || source == "local_create");
        if frame
            .current_signer
            .as_ref()
            .is_some_and(|signer| signer.semantic_type_code == events::EVENT_TYPE_PEER_SHARED)
        {
            let signer_b64 = frame.current_signer.as_ref().unwrap().event_id.clone();
            let authority_b64 = event_id_to_base64(&user_invite.authority_event_id);
            let authority_matches_signer =
                table_rows_for_recorded(&state, "peers_shared", recorded_by)
                    .into_iter()
                    .find(|row| row_text(row, "event_id") == Some(&signer_b64))
                    .and_then(|row| row_text(row, "user_event_id").map(ToOwned::to_owned))
                    .is_some_and(|user_event_id| {
                        table_rows_for_recorded(&state, "users", recorded_by)
                            .into_iter()
                            .find(|row| row_text(row, "event_id") == Some(&user_event_id))
                            .and_then(|user_row| {
                                row_blob(user_row, "public_key").map(|v| v.to_vec())
                            })
                            .is_some_and(|public_key| {
                                table_rows_for_recorded(&state, "admins", recorded_by)
                                    .into_iter()
                                    .any(|row| {
                                        row_text(row, "event_id") == Some(&authority_b64)
                                            && row_blob(row, "public_key")
                                                .is_some_and(|admin_key| admin_key == public_key)
                                    })
                            })
                    });
            ctx.invite_authority_matches_signer = Some(authority_matches_signer);
        }
        ctx.bootstrap_context = bootstrap_decision_context(&state, recorded_by, event_id_b64);
        Ok(ctx)
    }

    fn load_device_invite_context(
        &self,
        frame: &ProjectionFrameContext,
        recorded_by: &str,
        event_id_b64: &str,
        device_invite: &events::DeviceInviteEvent,
    ) -> ProjectionQueryResult<ProjectorDecisionContext> {
        let state = self.state.borrow();
        let mut ctx = ProjectorDecisionContext::default();
        ctx.is_local_create = recorded_source(&state, recorded_by, event_id_b64)
            .is_some_and(|source| source == "local" || source == "local_create");
        if frame
            .current_signer
            .as_ref()
            .is_some_and(|signer| signer.semantic_type_code == events::EVENT_TYPE_PEER_SHARED)
        {
            let signer_b64 = frame.current_signer.as_ref().unwrap().event_id.clone();
            let authority_b64 = event_id_to_base64(&device_invite.authority_event_id);
            let authority_matches_signer = first_row_for_recorded(
                &state,
                "peers_shared",
                recorded_by,
                "event_id",
                &signer_b64,
            )
            .and_then(|row| row_text(row, "user_event_id"))
            .is_some_and(|user_event_id| user_event_id == authority_b64);
            ctx.invite_authority_matches_signer = Some(authority_matches_signer);
        }
        ctx.bootstrap_context = bootstrap_decision_context(&state, recorded_by, event_id_b64);
        Ok(ctx)
    }

    fn load_message_context(
        &self,
        frame: &ProjectionFrameContext,
        recorded_by: &str,
        event_id_b64: &str,
        message: &events::MessageEvent,
    ) -> ProjectionQueryResult<ProjectorDecisionContext> {
        let state = self.state.borrow();
        let signer_user_mismatch_reason =
            signer_user_mismatch_reason_behavior(&state, frame, recorded_by, &message.author_id);
        let mut deletion_intents = table_rows_for_recorded(&state, "deletion_intents", recorded_by)
            .into_iter()
            .filter(|row| row_text(row, "target_id") == Some(event_id_b64))
            .filter_map(|row| {
                Some(DeletionIntentInfo {
                    deletion_event_id: row_text(row, "deletion_event_id")?.to_string(),
                    author_id: row_text(row, "author_id")?.to_string(),
                    authorized_by_admin: row_int(row, "authorized_by_admin").unwrap_or(0) != 0,
                    created_at: row_int(row, "created_at")?,
                })
            })
            .collect::<Vec<_>>();
        deletion_intents
            .sort_by(|left, right| left.deletion_event_id.cmp(&right.deletion_event_id));
        Ok(ProjectorDecisionContext {
            signer_user_mismatch_reason,
            deletion_intents,
            ..ProjectorDecisionContext::default()
        })
    }

    fn load_message_deletion_context(
        &self,
        frame: &ProjectionFrameContext,
        recorded_by: &str,
        _event_id_b64: &str,
        message_deletion: &events::MessageDeletionEvent,
    ) -> ProjectionQueryResult<ProjectorDecisionContext> {
        let state = self.state.borrow();
        let mut ctx = ProjectorDecisionContext::default();
        let (deletion_signer_user_id, deletion_signer_is_admin, deletion_signer_reject_reason) =
            deletion_signer_context_behavior(&state, frame, recorded_by);
        ctx.deletion_signer_user_id = deletion_signer_user_id;
        ctx.deletion_signer_is_admin = deletion_signer_is_admin;
        ctx.deletion_signer_reject_reason = deletion_signer_reject_reason;

        let target_b64 = event_id_to_base64(&message_deletion.target_event_id);
        ctx.target_tombstone_author = first_row_for_recorded(
            &state,
            "deleted_messages",
            recorded_by,
            "message_id",
            &target_b64,
        )
        .and_then(|row| row_text(row, "author_id").map(ToOwned::to_owned));
        ctx.target_message_author =
            first_row_for_recorded(&state, "messages", recorded_by, "message_id", &target_b64)
                .and_then(|row| row_text(row, "author_id").map(ToOwned::to_owned));
        if ctx.target_message_author.is_none() && ctx.target_tombstone_author.is_none() {
            ctx.target_is_non_message = has_valid_event(&state, recorded_by, &target_b64);
        }
        Ok(ctx)
    }

    fn load_reaction_context(
        &self,
        frame: &ProjectionFrameContext,
        recorded_by: &str,
        _event_id_b64: &str,
        reaction: &events::ReactionEvent,
    ) -> ProjectionQueryResult<ProjectorDecisionContext> {
        let state = self.state.borrow();
        let signer_user_mismatch_reason =
            signer_user_mismatch_reason_behavior(&state, frame, recorded_by, &reaction.author_id);
        Ok(ProjectorDecisionContext {
            signer_user_mismatch_reason,
            ..ProjectorDecisionContext::default()
        })
    }

    fn load_file_context(
        &self,
        _frame: &ProjectionFrameContext,
        _recorded_by: &str,
        _event_id_b64: &str,
        _file: &events::FileEvent,
    ) -> ProjectionQueryResult<ProjectorDecisionContext> {
        Ok(ProjectorDecisionContext::default())
    }

    fn load_file_slice_context(
        &self,
        frame: &ProjectionFrameContext,
        recorded_by: &str,
        _event_id_b64: &str,
        file_slice: &events::FileSliceEvent,
    ) -> ProjectionQueryResult<ProjectorDecisionContext> {
        let state = self.state.borrow();
        let file_id_b64 = event_id_to_base64(&file_slice.file_id);
        let mut ctx = ProjectorDecisionContext::default();
        if let Some(owner_event_id_b64) = frame.current_owner_event_id.as_deref() {
            if first_row_for_recorded(
                &state,
                "deleted_messages",
                recorded_by,
                "message_id",
                owner_event_id_b64,
            )
            .is_some()
            {
                ctx.purge_message_event_id = Some(owner_event_id_b64.to_string());
            }
        }
        ctx.file_descriptors = table_rows_for_recorded(&state, "files", recorded_by)
            .into_iter()
            .filter(|row| row_text(row, "file_id") == Some(&file_id_b64))
            .filter_map(|row| {
                Some(FileDescriptorInfo {
                    event_id: row_text(row, "event_id")?.to_string(),
                    message_id: row_text(row, "message_id")?.to_string(),
                    signer_event_id: row_text(row, "signer_event_id")?.to_string(),
                    key_event_id: row_text(row, "key_event_id")?.to_string(),
                    root_hash: [0u8; 32],
                    blob_bytes: 0,
                    slice_bytes: 0,
                })
            })
            .collect();
        if ctx.purge_message_event_id.is_none() {
            for descriptor in &ctx.file_descriptors {
                if first_row_for_recorded(
                    &state,
                    "deleted_messages",
                    recorded_by,
                    "message_id",
                    &descriptor.message_id,
                )
                .is_some()
                {
                    ctx.purge_message_event_id = Some(descriptor.message_id.clone());
                    break;
                }
            }
        }
        ctx.file_descriptors
            .sort_by(|left, right| left.event_id.cmp(&right.event_id));
        ctx.existing_file_slice = table_rows_for_recorded(&state, "file_slices", recorded_by)
            .into_iter()
            .find(|row| {
                row_text(row, "file_id") == Some(&file_id_b64)
                    && row_int(row, "slice_number") == Some(file_slice.slice_number as i64)
            })
            .and_then(|row| {
                Some((
                    row_text(row, "event_id")?.to_string(),
                    row_text(row, "descriptor_event_id")?.to_string(),
                ))
            });
        Ok(ctx)
    }

    fn load_invite_accepted_context(
        &self,
        _frame: &ProjectionFrameContext,
        recorded_by: &str,
        _event_id_b64: &str,
        invite_accepted: &events::InviteAcceptedEvent,
    ) -> ProjectionQueryResult<ProjectorDecisionContext> {
        let state = self.state.borrow();
        let mut ctx = ProjectorDecisionContext::default();
        let invite_event_id_b64 = event_id_to_base64(&invite_accepted.invite_event_id);
        let workspace_id_b64 = event_id_to_base64(&invite_accepted.workspace_id);
        ctx.has_local_invite_secret =
            table_rows_for_recorded(&state, "invite_secrets", recorded_by)
                .into_iter()
                .any(|row| {
                    row_text(row, "invite_event_id") == Some(&invite_event_id_b64)
                        && row_blob(row, "private_key")
                            .is_some_and(|private_key| private_key.len() == 32)
                });
        ctx.peer_shared_transport_identity_active = state.local_transport_peer_id.as_deref()
            == Some(recorded_by)
            && state.local_transport_source.as_deref() == Some("peershared");
        if let Some(bc) = bootstrap_decision_context(&state, recorded_by, &invite_event_id_b64) {
            if bc.workspace_id != workspace_id_b64 {
                ctx.invite_accepted_link_workspace_mismatch_reason = Some(
                    "invite_accepted workspace_id does not match locally recorded invite-link workspace"
                        .to_string(),
                );
            }
            ctx.bootstrap_spki_already_peer_shared =
                table_rows_for_recorded(&state, "peers_shared", recorded_by)
                    .into_iter()
                    .any(|row| {
                        row_blob(row, "transport_fingerprint")
                            .is_some_and(|fingerprint| fingerprint == bc.bootstrap_spki_fingerprint)
                    });
            ctx.bootstrap_context = Some(bc);
        } else if invite_accepted.invite_event_id != invite_accepted.workspace_id {
            ctx.invite_accepted_link_workspace_mismatch_reason = Some(
                "invite_accepted missing locally recorded invite-link workspace binding"
                    .to_string(),
            );
        }
        Ok(ctx)
    }

    fn load_key_shared_context(
        &self,
        frame: &ProjectionFrameContext,
        recorded_by: &str,
        _event_id_b64: &str,
        key_shared: &events::KeySharedEvent,
    ) -> ProjectionQueryResult<ProjectorDecisionContext> {
        let state = self.state.borrow();
        let recipient_b64 = event_id_to_base64(&key_shared.recipient_event_id);
        let unwrap_key_b64 = event_id_to_base64(&key_shared.unwrap_key_event_id);
        let Some(private_key_bytes) =
            table_rows_for_recorded(&state, "invite_secrets", recorded_by)
                .into_iter()
                .find(|row| {
                    row_text(row, "event_id") == Some(&unwrap_key_b64)
                        && row_text(row, "invite_event_id") == Some(&recipient_b64)
                })
                .and_then(|row| row_blob(row, "private_key").map(|v| v.to_vec()))
        else {
            return Ok(ProjectorDecisionContext::default());
        };
        if private_key_bytes.len() != 32 {
            return Ok(ProjectorDecisionContext::default());
        }
        let mut key_arr = [0u8; 32];
        key_arr.copy_from_slice(&private_key_bytes);
        let local_signing_key = ed25519_dalek::SigningKey::from_bytes(&key_arr);
        let Some(current_signer) = frame.current_signer.as_ref() else {
            return Ok(ProjectorDecisionContext::default());
        };
        let Some(current_signer_event_id) =
            crate::crypto::event_id_from_base64(&current_signer.event_id)
        else {
            return Ok(ProjectorDecisionContext::default());
        };
        let sender_key =
            match resolve_signer_key_behavior(&state, recorded_by, &current_signer_event_id)? {
                SignerResolution::Found(key) => key,
                _ => return Ok(ProjectorDecisionContext::default()),
            };
        let sender_pub = match ed25519_dalek::VerifyingKey::from_bytes(&sender_key.public_key) {
            Ok(key) => key,
            Err(_) => return Ok(ProjectorDecisionContext::default()),
        };
        let plaintext_key = crate::projection::encrypted::unwrap_key_from_sender(
            &local_signing_key,
            &sender_pub,
            &key_shared.wrapped_key,
        );
        Ok(ProjectorDecisionContext {
            unwrapped_secret_material: Some(crate::projection::projector::UnwrappedSecretMaterial {
                key_bytes: plaintext_key,
            }),
            ..ProjectorDecisionContext::default()
        })
    }

    fn load_key_rotation_context(
        &self,
        frame: &ProjectionFrameContext,
        recorded_by: &str,
        _event_id_b64: &str,
        key_rotation: &events::KeyRotationEvent,
    ) -> ProjectionQueryResult<ProjectorDecisionContext> {
        let state = self.state.borrow();
        let Some((local_recipient_event_id_b64, private_key_bytes)) =
            table_rows_for_recorded(&state, "peer_secrets", recorded_by)
                .into_iter()
                .filter_map(|row| {
                    Some((
                        row_text(row, "signer_event_id")?.to_string(),
                        row_blob(row, "private_key")?.to_vec(),
                        row_int(row, "created_at").unwrap_or_default(),
                        row_text(row, "event_id").unwrap_or_default().to_string(),
                    ))
                })
                .max_by(|left, right| (left.2, &left.3).cmp(&(right.2, &right.3)))
                .map(|(signer_event_id, private_key, _, _)| (signer_event_id, private_key))
        else {
            return Ok(ProjectorDecisionContext::default());
        };
        let Some(local_recipient_event_id) = event_id_from_base64(&local_recipient_event_id_b64)
        else {
            return Ok(ProjectorDecisionContext::default());
        };
        let Some(slot_index) = key_rotation
            .recipient_slots
            .iter()
            .position(|slot| *slot == local_recipient_event_id)
        else {
            return Ok(ProjectorDecisionContext::default());
        };
        if private_key_bytes.len() != 32 {
            return Ok(ProjectorDecisionContext::default());
        }
        let mut key_arr = [0u8; 32];
        key_arr.copy_from_slice(&private_key_bytes);
        let local_signing_key = ed25519_dalek::SigningKey::from_bytes(&key_arr);
        let Some(current_signer) = frame.current_signer.as_ref() else {
            return Ok(ProjectorDecisionContext::default());
        };
        let Some(current_signer_event_id) =
            crate::crypto::event_id_from_base64(&current_signer.event_id)
        else {
            return Ok(ProjectorDecisionContext::default());
        };
        let sender_key =
            match resolve_signer_key_behavior(&state, recorded_by, &current_signer_event_id)? {
                SignerResolution::Found(key) => key,
                _ => return Ok(ProjectorDecisionContext::default()),
            };
        let sender_pub = match ed25519_dalek::VerifyingKey::from_bytes(&sender_key.public_key) {
            Ok(key) => key,
            Err(_) => return Ok(ProjectorDecisionContext::default()),
        };
        let plaintext_key = crate::projection::encrypted::unwrap_key_from_sender(
            &local_signing_key,
            &sender_pub,
            &key_rotation.wrapped_keys[slot_index],
        );
        Ok(ProjectorDecisionContext {
            unwrapped_secret_material: Some(crate::projection::projector::UnwrappedSecretMaterial {
                key_bytes: plaintext_key,
            }),
            ..ProjectorDecisionContext::default()
        })
    }

    fn load_key_history_context(
        &self,
        frame: &ProjectionFrameContext,
        recorded_by: &str,
        _event_id_b64: &str,
        key_history: &events::KeyHistoryEvent,
    ) -> ProjectionQueryResult<ProjectorDecisionContext> {
        let state = self.state.borrow();
        let Some(private_key_bytes) =
            table_rows_for_recorded(&state, "invite_secrets", recorded_by)
                .into_iter()
                .filter_map(|row| row_blob(row, "private_key").map(|v| v.to_vec()))
                .find(|private_key_bytes| {
                    if private_key_bytes.len() != 32 {
                        return false;
                    }
                    let mut key_arr = [0u8; 32];
                    key_arr.copy_from_slice(private_key_bytes);
                    ed25519_dalek::SigningKey::from_bytes(&key_arr)
                        .verifying_key()
                        .to_bytes()
                        == key_history.recipient_public_key
                })
        else {
            return Ok(ProjectorDecisionContext::default());
        };
        if private_key_bytes.len() != 32 {
            return Ok(ProjectorDecisionContext::default());
        }
        let mut key_arr = [0u8; 32];
        key_arr.copy_from_slice(&private_key_bytes);
        let local_signing_key = ed25519_dalek::SigningKey::from_bytes(&key_arr);
        let Some(current_signer) = frame.current_signer.as_ref() else {
            return Ok(ProjectorDecisionContext::default());
        };
        let Some(current_signer_event_id) =
            crate::crypto::event_id_from_base64(&current_signer.event_id)
        else {
            return Ok(ProjectorDecisionContext::default());
        };
        let sender_key =
            match resolve_signer_key_behavior(&state, recorded_by, &current_signer_event_id)? {
                SignerResolution::Found(key) => key,
                _ => return Ok(ProjectorDecisionContext::default()),
            };
        let sender_pub = match ed25519_dalek::VerifyingKey::from_bytes(&sender_key.public_key) {
            Ok(key) => key,
            Err(_) => return Ok(ProjectorDecisionContext::default()),
        };
        let plaintext = match crate::crypto::decrypt_bundle_from_sender(
            &local_signing_key,
            &sender_pub,
            &key_history.nonce,
            &key_history.ciphertext,
            &key_history.auth_tag,
        ) {
            Ok(plaintext) => plaintext,
            Err(_) => return Ok(ProjectorDecisionContext::default()),
        };
        let entries = match crate::event_modules::key_history::decode_key_history_plaintext(&plaintext)
        {
            Ok(entries) => entries,
            Err(_) => return Ok(ProjectorDecisionContext::default()),
        };

        Ok(ProjectorDecisionContext {
            unwrapped_key_history_material: entries
                .into_iter()
                .map(|entry| crate::projection::projector::HistoricalKeyMaterial {
                    key_event_id: entry.key_event_id,
                    key_bytes: entry.key_bytes,
                })
                .collect(),
            ..ProjectorDecisionContext::default()
        })
    }

    fn load_key_request_context(
        &self,
        _frame: &ProjectionFrameContext,
        recorded_by: &str,
        _event_id_b64: &str,
        key_request: &events::KeyRequestEvent,
    ) -> ProjectionQueryResult<ProjectorDecisionContext> {
        let state = self.state.borrow();
        let delivery_target_id = event_id_to_base64(&key_request.delivery_target_id);
        let key_request_suppress_sharing = first_row_for_recorded(
            &state,
            "key_shared",
            recorded_by,
            "delivery_target_id",
            &delivery_target_id,
        )
        .is_some();
        Ok(ProjectorDecisionContext {
            key_request_suppress_sharing,
            ..ProjectorDecisionContext::default()
        })
    }
}

impl ProjectionBackend for NodeBehaviorEngine {
    fn already_processed(
        &self,
        recorded_by: &str,
        event_id_b64: &str,
    ) -> ProjectionApplyResult<bool> {
        let state = self.state.borrow();
        Ok(state.recorded_by == recorded_by
            && (state.valid_events.contains_key(event_id_b64)
                || state.rejected_events.contains_key(event_id_b64)))
    }

    fn load_blob(&self, event_id_b64: &str) -> ProjectionApplyResult<Option<Vec<u8>>> {
        Ok(self
            .state
            .borrow()
            .events
            .get(event_id_b64)
            .map(|event| event.blob.clone()))
    }

    fn record_rejection(
        &self,
        _recorded_by: &str,
        event_id_b64: &str,
        reason: &str,
    ) -> ProjectionApplyResult<()> {
        self.state
            .borrow_mut()
            .rejected_events
            .entry(event_id_b64.to_string())
            .or_insert_with(|| reason.to_string());
        Ok(())
    }

    fn record_block(
        &self,
        recorded_by: &str,
        event_id_b64: &str,
        missing: &[EventId],
    ) -> ProjectionApplyResult<()> {
        if self.state.borrow().recorded_by != recorded_by {
            return Ok(());
        }

        let mut deduped = missing.to_vec();
        deduped.sort_unstable();
        deduped.dedup();
        let mut state = self.state.borrow_mut();
        let deps_remaining = {
            let blockers = state
                .blocked_event_deps
                .entry(event_id_b64.to_string())
                .or_default();
            for dep_id in &deduped {
                blockers.insert(event_id_to_base64(dep_id));
            }
            blockers.len() as i64
        };
        state
            .blocked_events
            .insert(event_id_b64.to_string(), deps_remaining);
        Ok(())
    }

    fn resolve_signer_key(
        &self,
        recorded_by: &str,
        signer_event_id: &[u8; 32],
    ) -> ProjectionApplyResult<SignerResolution> {
        resolve_signer_key_behavior(&self.state.borrow(), recorded_by, signer_event_id)
    }

    fn execute_write_ops(&self, ops: &[WriteOp]) -> ProjectionApplyResult<()> {
        let mut state = self.state.borrow_mut();
        for op in ops {
            match op {
                WriteOp::InsertOrIgnore {
                    table,
                    columns,
                    values,
                } => {
                    let mut row_values = BTreeMap::new();
                    for (column, value) in columns.iter().zip(values) {
                        row_values.insert((*column).to_string(), BehaviorValue::from(value));
                    }
                    let row = BehaviorRow { values: row_values };
                    let rows = state.tables.entry((*table).to_string()).or_default();
                    if !rows
                        .iter()
                        .any(|existing| insert_or_ignore_key_matches(table, existing, &row))
                    {
                        rows.push(row);
                        rows.sort();
                    }
                }
                WriteOp::Delete {
                    table,
                    where_clause,
                } => {
                    if let Some(rows) = state.tables.get_mut(*table) {
                        rows.retain(|row| {
                            !where_clause.iter().all(|(column, expected)| {
                                row.values
                                    .get(*column)
                                    .is_some_and(|value| value == &BehaviorValue::from(expected))
                            })
                        });
                    }
                }
                WriteOp::InsertKeySecretFromUnwrap(r) | WriteOp::InsertKeySecretLocal(r) => {
                    let table = crate::event_modules::key_shared::KEY_SECRETS_TABLE;
                    let columns = crate::event_modules::key_shared::KEY_SECRETS_COLUMNS;
                    let mut row_values = BTreeMap::new();
                    row_values.insert(columns[0].to_string(),
                        BehaviorValue::Text(r.event_id_b64.clone()));
                    row_values.insert(columns[1].to_string(),
                        BehaviorValue::Blob(r.key_bytes.to_vec()));
                    row_values.insert(columns[2].to_string(),
                        BehaviorValue::Int(r.created_at_ms));
                    row_values.insert(columns[3].to_string(),
                        BehaviorValue::Text(r.recorded_by.clone()));
                    let row = BehaviorRow { values: row_values };
                    let rows = state.tables.entry(table.to_string()).or_default();
                    // SQLite executes this as `INSERT OR IGNORE INTO key_secrets`
                    // which conflicts on the primary key (recorded_by, event_id).
                    // Match that semantics in the sim: reject a duplicate based on
                    // primary key, regardless of whether non-key columns differ.
                    let primary_key_exists = rows.iter().any(|existing| {
                        existing.values.get(columns[0])
                            == Some(&BehaviorValue::Text(r.event_id_b64.clone()))
                            && existing.values.get(columns[3])
                                == Some(&BehaviorValue::Text(r.recorded_by.clone()))
                    });
                    if !primary_key_exists {
                        rows.push(row);
                        rows.sort();
                    }
                }
            }
        }
        Ok(())
    }

    fn execute_emit_commands(
        &self,
        _recorded_by: &str,
        commands: &[EmitCommand],
    ) -> ProjectionApplyResult<()> {
        for command in commands {
            match command {
                EmitCommand::EmitDeterministicBlob { blob } => {
                    let event_id = hash_event(blob);
                    let event_id_b64 = event_id_to_base64(&event_id);
                    let parsed = events::parse_event(blob)?;
                    let _meta = events::registry()
                        .lookup(parsed.event_type_code())
                        .ok_or("unknown deterministic blob type")?;
                    {
                        let mut state = self.state.borrow_mut();
                        state
                            .events
                            .entry(event_id_b64.clone())
                            .or_insert_with(|| StoredEvent { blob: blob.clone() });
                        state
                            .recorded_events
                            .entry(event_id_b64)
                            .or_insert_with(|| StoredRecordedEvent {
                                source: "emit".to_string(),
                            });
                    }
                    if !self.filter.blocks_parsed(&parsed) {
                        let _ = self.project_parsed_event(&event_id, &parsed)?;
                    }
                }
                EmitCommand::RetryWorkspaceEvent { workspace_id } => {
                    if let Some(event_id) = event_id_from_base64(workspace_id) {
                        let _ = self.project_and_cascade(&event_id)?;
                    }
                }
                EmitCommand::RetryBlockedEncryptedByKey { key_event_id } => {
                    let blocked_candidates = {
                        let state = self.state.borrow();
                        state
                            .blocked_events
                            .keys()
                            .filter_map(|event_id_b64| {
                                let blob = state.events.get(event_id_b64)?.blob.clone();
                                let parsed = parse_semantic_event_for_retry(&blob).ok()?;
                                let ParsedEvent::Encrypted(enc) = parsed else {
                                    return None;
                                };
                                if event_id_to_base64(&enc.key_event_id) == *key_event_id {
                                    event_id_from_base64(event_id_b64)
                                } else {
                                    None
                                }
                            })
                            .collect::<Vec<_>>()
                    };
                    for event_id in blocked_candidates {
                        let _ = self.project_and_cascade(&event_id)?;
                    }
                }
                EmitCommand::IndexEndpointSharedForWorkspace {
                    workspace_id,
                    endpoint_shared_event_id,
                } => {
                    let Some(endpoint_event_id) = event_id_from_base64(endpoint_shared_event_id)
                    else {
                        continue;
                    };
                    let Some(blob) = self
                        .state
                        .borrow()
                        .events
                        .get(endpoint_shared_event_id)
                        .map(|event| event.blob.clone())
                    else {
                        continue;
                    };
                    let parsed = parse_event(&blob)?;
                    if !matches!(parsed, ParsedEvent::EndpointShared(_)) {
                        continue;
                    }
                    let Some(created_at_ms) = crate::event_modules::extract_created_at_ms(&blob)
                    else {
                        continue;
                    };
                    let mut row_values = BTreeMap::new();
                    row_values.insert(
                        "workspace_id".to_string(),
                        BehaviorValue::Text(workspace_id.clone()),
                    );
                    row_values.insert("ts".to_string(), BehaviorValue::Int(created_at_ms as i64));
                    row_values.insert(
                        "id".to_string(),
                        BehaviorValue::Blob(endpoint_event_id.to_vec()),
                    );
                    let row = BehaviorRow { values: row_values };
                    let mut state = self.state.borrow_mut();
                    let rows = state.tables.entry("shared_event_index".to_string()).or_default();
                    if !rows.contains(&row) {
                        rows.push(row);
                        rows.sort();
                    }
                }
                EmitCommand::MaterializeTransportIdentity { .. }
                | EmitCommand::HardPurgeMessageGraph { .. } => {}
            }
        }
        Ok(())
    }

    fn mark_guard_blocked(&self, _event_id_b64: &str) -> ProjectionApplyResult<()> {
        Ok(())
    }

    fn finalize_valid_projection(
        &self,
        recorded_by: &str,
        event_id_b64: &str,
        sub_event: &ParsedEvent,
        suppress_sharing: bool,
    ) -> ProjectionApplyResult<()> {
        if self.state.borrow().recorded_by != recorded_by {
            return Ok(());
        }
        self.state.borrow_mut().valid_events.insert(
            event_id_b64.to_string(),
            ValidEventState {
                semantic_type_code: Some(i64::from(match sub_event {
                    ParsedEvent::Encrypted(enc) => enc.inner_type_code,
                    _ => sub_event.event_type_code(),
                })),
                suppress_sharing,
            },
        );
        if let ParsedEvent::KeyShared(key_shared) = sub_event {
            let delivery_target_id = event_id_to_base64(&key_shared.delivery_target_id);
            let matching_request_ids = {
                let state = self.state.borrow();
                table_rows_for_recorded(&state, "key_requests", recorded_by)
                    .into_iter()
                    .filter(|row| {
                        row_text(row, "delivery_target_id") == Some(delivery_target_id.as_str())
                    })
                    .filter_map(|row| row_text(row, "event_id").map(ToOwned::to_owned))
                    .collect::<Vec<_>>()
            };
            let mut state = self.state.borrow_mut();
            for key_request_event_id in matching_request_ids {
                if let Some(valid) = state.valid_events.get_mut(&key_request_event_id) {
                    valid.suppress_sharing = true;
                }
            }
        }
        Ok(())
    }
}

fn key_secret_bytes(
    state: &NodeBehaviorData,
    recorded_by: &str,
    key_event_id: &[u8; 32],
) -> Option<[u8; 32]> {
    if state.recorded_by != recorded_by {
        return None;
    }
    let event_id_b64 = event_id_to_base64(key_event_id);
    let rows = state.tables.get("key_secrets")?;
    let row = rows.iter().find(|row| {
        row.values.get("recorded_by") == Some(&BehaviorValue::Text(recorded_by.to_string()))
            && row.values.get("event_id") == Some(&BehaviorValue::Text(event_id_b64.clone()))
    })?;
    let BehaviorValue::Blob(key_bytes) = row.values.get("key_bytes")? else {
        return None;
    };
    if key_bytes.len() != 32 {
        return None;
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(key_bytes);
    Some(out)
}

fn sort_rows(mut rows: Vec<BehaviorRow>) -> Vec<BehaviorRow> {
    rows.sort();
    rows
}

fn parse_semantic_event_for_retry(blob: &[u8]) -> Result<ParsedEvent, Box<dyn std::error::Error>> {
    let parsed = events::parse_event(blob)?;
    match parsed {
        ParsedEvent::Signed(signed) => parse_semantic_event_for_retry(&signed.payload),
        other => Ok(other),
    }
}

pub fn sqlite_behavior_summary(
    db_path: &str,
    recorded_by: &str,
) -> Result<NodeBehaviorSummary, Box<dyn std::error::Error>> {
    let conn = crate::db::open_connection(db_path)?;
    crate::db::schema::create_tables(&conn)?;
    let mut tables = BTreeMap::new();
    for table in SUMMARY_TABLES {
        let rows = sqlite_rows_for_peer(&conn, table, recorded_by)?;
        if !rows.is_empty() {
            tables.insert((*table).to_string(), rows);
        }
    }
    Ok(NodeBehaviorSummary {
        recorded_by: recorded_by.to_string(),
        tables,
    })
}

fn sqlite_rows_for_peer(
    conn: &rusqlite::Connection,
    table: &str,
    recorded_by: &str,
) -> Result<Vec<BehaviorRow>, Box<dyn std::error::Error>> {
    let mut pragma = conn.prepare(&format!("PRAGMA table_info({table})"))?;
    let columns = pragma
        .query_map([], |row| crate::db::sql_types::get_text(row, 1))?
        .collect::<Result<Vec<_>, _>>()?;
    if columns.is_empty() {
        return Ok(Vec::new());
    }

    let filter_column = if columns.iter().any(|column| column == "recorded_by") {
        Some("recorded_by")
    } else if columns.iter().any(|column| column == "peer_id") {
        Some("peer_id")
    } else {
        None
    };
    let sql = if let Some(filter_column) = filter_column {
        format!(
            "SELECT {} FROM {} WHERE {} = ?1 ORDER BY {}",
            columns.join(", "),
            table,
            filter_column,
            columns.join(", ")
        )
    } else {
        format!(
            "SELECT {} FROM {} ORDER BY {}",
            columns.join(", "),
            table,
            columns.join(", ")
        )
    };
    let mut stmt = conn.prepare(&sql)?;
    let rows = if filter_column.is_some() {
        stmt.query_map(rusqlite::params![recorded_by], |row| {
            Ok(row_to_behavior_row(row, &columns))
        })?
        .collect::<Result<Vec<_>, _>>()?
    } else {
        stmt.query_map([], |row| Ok(row_to_behavior_row(row, &columns)))?
            .collect::<Result<Vec<_>, _>>()?
    };
    Ok(sort_rows(rows))
}

fn row_to_behavior_row(row: &rusqlite::Row<'_>, columns: &[String]) -> BehaviorRow {
    let mut values = BTreeMap::new();
    for (idx, column) in columns.iter().enumerate() {
        let value = match row.get_ref(idx).expect("row value") {
            ValueRef::Null => continue,
            ValueRef::Integer(v) => BehaviorValue::Int(v),
            ValueRef::Real(v) => BehaviorValue::Text(v.to_string()),
            ValueRef::Text(v) => BehaviorValue::Text(String::from_utf8_lossy(v).into_owned()),
            ValueRef::Blob(v) => BehaviorValue::Blob(v.to_vec()),
        };
        values.insert(column.clone(), value);
    }
    BehaviorRow { values }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use tempfile::tempdir;

    use super::*;
    use crate::event_modules::workspace::commands::CreateInviteResponse;
    use crate::event_modules::EVENT_TYPE_ENCRYPTED;
    use crate::rpc::protocol::RpcMethod;
    use crate::sim::{import_peer_state, snapshot_replayed_peer_to_path, VirtualDaemon};

    fn projected_table(
        summary: &NodeBehaviorSummary,
        table: &str,
        drop_columns: &[&str],
    ) -> Vec<BehaviorRow> {
        let drop_columns = drop_columns.iter().copied().collect::<BTreeSet<_>>();
        let mut rows = summary.tables.get(table).cloned().unwrap_or_default();
        for row in &mut rows {
            row.values
                .retain(|column, _| !drop_columns.contains(column.as_str()));
        }
        rows.sort();
        rows
    }

    fn assert_projected_table_eq(
        actual: &NodeBehaviorSummary,
        expected: &NodeBehaviorSummary,
        table: &str,
        drop_columns: &[&str],
    ) {
        let drop_created_at_for_key_secrets = table == "key_secrets"
            && !drop_columns.iter().any(|column| *column == "created_at");
        let drop_columns = if drop_created_at_for_key_secrets {
            let mut columns = drop_columns.to_vec();
            columns.push("created_at");
            columns
        } else {
            drop_columns.to_vec()
        };
        assert_eq!(
            projected_table(actual, table, &drop_columns),
            projected_table(expected, table, &drop_columns),
            "table mismatch for {table}"
        );
    }

    #[test]
    fn behavior_engine_matches_replayed_sqlite_for_workspace_invite_core_state() {
        let tmpdir = tempdir().expect("tempdir");
        let creator_db = tmpdir.path().join("creator.db");
        let creator = VirtualDaemon::new(creator_db.to_str().expect("creator db"));

        creator
            .call_ok_value(RpcMethod::CreateWorkspace {
                workspace_name: "sim".to_string(),
                username: "alice".to_string(),
                device_name: "laptop".to_string(),
                message_count: 0,
                network_age: None,
            })
            .expect("create workspace");
        creator
            .call_ok_value(RpcMethod::RotateKey)
            .expect("rotate key");
        let invite: CreateInviteResponse = creator
            .call_ok(RpcMethod::CreateInvite {
                public_addr: None,
                public_spki: None,
            })
            .expect("create invite");
        assert!(!invite.invite_event_id.is_empty());

        let recorded_by = creator
            .call_ok_value(RpcMethod::ActiveTenant)
            .expect("active tenant")["peer_id"]
            .as_str()
            .expect("peer_id")
            .to_string();
        let snapshot_db = tmpdir.path().join("snapshot.db");
        snapshot_replayed_peer_to_path(
            creator_db.to_str().expect("creator db"),
            &recorded_by,
            snapshot_db.to_str().expect("snapshot db"),
        )
        .expect("snapshot replay");
        let imported = import_peer_state(snapshot_db.to_str().expect("snapshot db"), &recorded_by)
            .expect("import snapshot peer state");
        let behavior =
            NodeBehaviorEngine::ingest_imported(&imported, EventProjectionFilter::default())
                .expect("ingest imported events");

        let expected =
            sqlite_behavior_summary(snapshot_db.to_str().expect("snapshot db"), &recorded_by)
                .expect("sqlite behavior summary");
        let actual = behavior.summary();
        if projected_table(&actual, "key_rotations", &[])
            != projected_table(&expected, "key_rotations", &[])
        {
            panic!(
                "actual key_rotations={:?}\nexpected key_rotations={:?}\nactual messages={:?}\nexpected messages={:?}\nactual blocked_events={:?}\nactual blocked_event_deps={:?}\nactual rejected_events={:?}\nactual valid_events={:?}",
                projected_table(&actual, "key_rotations", &[]),
                projected_table(&expected, "key_rotations", &[]),
                projected_table(&actual, "messages", &[]),
                projected_table(&expected, "messages", &[]),
                projected_table(&actual, "blocked_events", &[]),
                projected_table(&actual, "blocked_event_deps", &[]),
                projected_table(&actual, "rejected_events", &[]),
                projected_table(&actual, "valid_events", &[]),
            );
        }
        for table in [
            "admins",
            "bootstrap_context",
            "invite_secrets",
            "invites_accepted",
            "key_secrets",
            "tenants",
            "users",
            "workspaces",
        ] {
            assert_projected_table_eq(&actual, &expected, table, &[]);
        }
    }

    #[test]
    fn behavior_engine_import_matches_replayed_sqlite_for_message_and_rotation_state() {
        let tmpdir = tempdir().expect("tempdir");
        let creator_db = tmpdir.path().join("creator.db");
        let creator = VirtualDaemon::new(creator_db.to_str().expect("creator db"));

        creator
            .call_ok_value(RpcMethod::CreateWorkspace {
                workspace_name: "sim".to_string(),
                username: "alice".to_string(),
                device_name: "laptop".to_string(),
                message_count: 0,
                network_age: None,
            })
            .expect("create workspace");
        creator
            .call_ok_value(RpcMethod::RotateKey)
            .expect("rotate key");
        creator
            .call_ok_value(RpcMethod::Send {
                content: "hello from sim".to_string(),
                client_op_id: None,
            })
            .expect("send message");
        let invite: CreateInviteResponse = creator
            .call_ok(RpcMethod::CreateInvite {
                public_addr: None,
                public_spki: None,
            })
            .expect("create invite");
        assert!(!invite.invite_event_id.is_empty());

        let recorded_by = creator
            .call_ok_value(RpcMethod::ActiveTenant)
            .expect("active tenant")["peer_id"]
            .as_str()
            .expect("peer_id")
            .to_string();
        let snapshot_db = tmpdir.path().join("snapshot.db");
        snapshot_replayed_peer_to_path(
            creator_db.to_str().expect("creator db"),
            &recorded_by,
            snapshot_db.to_str().expect("snapshot db"),
        )
        .expect("snapshot replay");
        let imported = import_peer_state(snapshot_db.to_str().expect("snapshot db"), &recorded_by)
            .expect("import snapshot peer state");
        let behavior =
            NodeBehaviorEngine::ingest_imported(&imported, EventProjectionFilter::default())
                .expect("ingest imported events");

        let expected =
            sqlite_behavior_summary(snapshot_db.to_str().expect("snapshot db"), &recorded_by)
                .expect("sqlite behavior summary");
        assert!(
            imported
                .known_events
                .iter()
                .chain(imported.ambient_shared_events.iter())
                .filter_map(|event| events::parse_event(&event.blob).ok())
                .any(|parsed| matches!(parsed, ParsedEvent::Signed(_) | ParsedEvent::Encrypted(_))),
            "snapshot import should carry signed or encrypted shared event blobs"
        );

        let actual = behavior.summary();
        if projected_table(&actual, "key_rotations", &[])
            != projected_table(&expected, "key_rotations", &[])
        {
            panic!(
                "actual key_rotations={:?}\nexpected key_rotations={:?}\nactual messages={:?}\nexpected messages={:?}\nactual blocked_events={:?}\nactual blocked_event_deps={:?}\nactual rejected_events={:?}\nactual valid_events={:?}",
                projected_table(&actual, "key_rotations", &[]),
                projected_table(&expected, "key_rotations", &[]),
                projected_table(&actual, "messages", &[]),
                projected_table(&expected, "messages", &[]),
                projected_table(&actual, "blocked_events", &[]),
                projected_table(&actual, "blocked_event_deps", &[]),
                projected_table(&actual, "rejected_events", &[]),
                projected_table(&actual, "valid_events", &[]),
            );
        }
        for table in [
            "admins",
            "bootstrap_context",
            "deletion_intents",
            "invite_secrets",
            "invites_accepted",
            "key_secrets",
            "messages",
            "tenants",
            "users",
            "workspaces",
        ] {
            assert_projected_table_eq(&actual, &expected, table, &[]);
        }
    }

    #[test]
    fn behavior_engine_filtered_ingest_preserves_auth_and_key_secret_state() {
        let tmpdir = tempdir().expect("tempdir");
        let creator_db = tmpdir.path().join("creator.db");
        let creator = VirtualDaemon::new(creator_db.to_str().expect("creator db"));

        creator
            .call_ok_value(RpcMethod::CreateWorkspace {
                workspace_name: "sim".to_string(),
                username: "alice".to_string(),
                device_name: "laptop".to_string(),
                message_count: 0,
                network_age: None,
            })
            .expect("create workspace");
        creator
            .call_ok_value(RpcMethod::RotateKey)
            .expect("rotate key");
        creator
            .call_ok_value(RpcMethod::Send {
                content: "ignore encrypted content".to_string(),
                client_op_id: None,
            })
            .expect("send message");
        let invite: CreateInviteResponse = creator
            .call_ok(RpcMethod::CreateInvite {
                public_addr: None,
                public_spki: None,
            })
            .expect("create invite");
        assert!(!invite.invite_event_id.is_empty());

        let recorded_by = creator
            .call_ok_value(RpcMethod::ActiveTenant)
            .expect("active tenant")["peer_id"]
            .as_str()
            .expect("peer_id")
            .to_string();
        let snapshot_db = tmpdir.path().join("snapshot.db");
        snapshot_replayed_peer_to_path(
            creator_db.to_str().expect("creator db"),
            &recorded_by,
            snapshot_db.to_str().expect("snapshot db"),
        )
        .expect("snapshot replay");
        let imported = import_peer_state(snapshot_db.to_str().expect("snapshot db"), &recorded_by)
            .expect("import snapshot peer state");
        let behavior = NodeBehaviorEngine::ingest_imported(
            &imported,
            EventProjectionFilter::with_blocked_type_codes([EVENT_TYPE_ENCRYPTED]),
        )
        .expect("ingest imported events");

        let expected =
            sqlite_behavior_summary(snapshot_db.to_str().expect("snapshot db"), &recorded_by)
                .expect("sqlite behavior summary");
        let actual = behavior.summary();
        for table in [
            "admins",
            "bootstrap_context",
            "invite_secrets",
            "invites_accepted",
            "key_secrets",
            "tenants",
            "users",
            "workspaces",
        ] {
            assert_projected_table_eq(&actual, &expected, table, &[]);
        }
        assert!(
            actual.tables.get("messages").is_none(),
            "filtered ingest should not materialize messages"
        );
    }
}
