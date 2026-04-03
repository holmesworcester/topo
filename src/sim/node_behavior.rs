use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};

use rusqlite::types::ValueRef;
use serde::Serialize;

use crate::contracts::event_pipeline_contract::IngestItem;
use crate::crypto::{event_id_from_base64, event_id_to_base64, hash_event, EventId};
use crate::event_modules::{self as events, parse_event, EncryptedEvent, ParsedEvent};
use crate::projection::apply::{
    project_one::project_one_step_with_backend, run_dep_and_projection_stages_with_backend,
    ProjectionApplyResult, ProjectionBackend,
};
use crate::projection::contract::{
    ContextSnapshot, DeletionIntentInfo, EmitCommand, FileDescriptorInfo, SqlVal, WriteOp,
};
use crate::projection::decision::ProjectionDecision;
use crate::projection::encrypted::decrypt_event_blob;
use crate::projection::queries::{ProjectionQueries, ProjectionQueryResult};
use crate::projection::signer::SignerResolution;
use crate::sim::query_snapshot::ImportedPeerState;

const SUMMARY_TABLES: &[&str] = &[
    "admins",
    "blocked_event_deps",
    "blocked_events",
    "bootstrap_context",
    "deleted_files",
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
struct NodeBehaviorData {
    recorded_by: String,
    local_transport_peer_id: Option<String>,
    local_transport_source: Option<String>,
    events: BTreeMap<String, StoredEvent>,
    recorded_events: BTreeMap<String, StoredRecordedEvent>,
    valid_events: BTreeMap<String, Option<i64>>,
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
        }
        for known in &imported.known_events {
            let event_id =
                event_id_from_base64(&known.event_id).ok_or("invalid imported event id")?;
            engine.ingest_item((
                event_id,
                known.blob.clone(),
                imported.recorded_by.clone(),
                known.source.clone(),
                known.created_at_ms,
                known.created_at_ms,
            ))?;
        }
        Ok(engine)
    }

    pub fn ingest_item(&self, item: IngestItem) -> Result<(), Box<dyn std::error::Error>> {
        let (event_id, blob, _recorded_by, source, _created_at_ms, _inserted_at_ms) = item;
        let event_id_b64 = event_id_to_base64(&event_id);
        let parsed = events::parse_event(&blob)?;
        let _meta = events::registry()
            .lookup(parsed.event_type_code())
            .ok_or("unknown event type")?;

        {
            let mut state = self.state.borrow_mut();
            state
                .events
                .entry(event_id_b64.clone())
                .or_insert_with(|| StoredEvent { blob: blob.clone() });
            state
                .recorded_events
                .entry(event_id_b64.clone())
                .or_insert_with(|| StoredRecordedEvent { source });
        }

        if !self.filter.blocks(parsed.event_type_code()) {
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
                    .map(|(event_id, semantic_type_code)| {
                        let mut values = BTreeMap::new();
                        values.insert(
                            "peer_id".to_string(),
                            BehaviorValue::Text(state.recorded_by.clone()),
                        );
                        values.insert(
                            "event_id".to_string(),
                            BehaviorValue::Text(event_id.clone()),
                        );
                        if let Some(code) = semantic_type_code {
                            values.insert(
                                "semantic_type_code".to_string(),
                                BehaviorValue::Int(*code),
                            );
                        }
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

fn bootstrap_context_snapshot(
    state: &NodeBehaviorData,
    recorded_by: &str,
    invite_event_id_b64: &str,
) -> Option<crate::projection::contract::BootstrapContextSnapshot> {
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
    Some(crate::projection::contract::BootstrapContextSnapshot {
        workspace_id,
        bootstrap_addrs: addrs.into_iter().collect(),
        bootstrap_spki_fingerprint,
    })
}

fn signer_user_mismatch_reason_behavior(
    state: &NodeBehaviorData,
    recorded_by: &str,
    signed_by: &[u8; 32],
    author_id: &[u8; 32],
) -> Option<String> {
    let signed_by_b64 = event_id_to_base64(signed_by);
    let author_id_b64 = event_id_to_base64(author_id);
    let Some(peer_row) = first_row_for_recorded(
        state,
        "peers_shared",
        recorded_by,
        "event_id",
        &signed_by_b64,
    ) else {
        return Some(format!(
            "no peers_shared entry for signer {}",
            signed_by_b64
        ));
    };
    let Some(peer_user_eid) = row_text(peer_row, "user_event_id") else {
        return Some(format!(
            "peers_shared entry for signer {} has no user_event_id (legacy row)",
            signed_by_b64
        ));
    };
    if peer_user_eid.is_empty() {
        return Some(format!(
            "peers_shared entry for signer {} has no user_event_id (legacy row)",
            signed_by_b64
        ));
    }
    if peer_user_eid != author_id_b64 {
        return Some(format!(
            "signer {} belongs to user {} but author_id claims {}",
            signed_by_b64, peer_user_eid, author_id_b64
        ));
    }
    None
}

fn resolve_signer_key_behavior(
    state: &NodeBehaviorData,
    recorded_by: &str,
    signer_type: u8,
    signer_event_id: &[u8; 32],
) -> ProjectionApplyResult<SignerResolution> {
    if state.recorded_by != recorded_by {
        return Ok(SignerResolution::NotFound);
    }
    let valid_type_codes: &[u8] = match signer_type {
        1 => &[8],
        2 => &[10],
        3 => &[12],
        4 => &[14],
        5 => &[16],
        _ => {
            return Ok(SignerResolution::Invalid(format!(
                "unsupported signer_type: {}",
                signer_type
            )))
        }
    };
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
    let actual_type_code = blob[0];
    if !valid_type_codes.contains(&actual_type_code) {
        return Ok(SignerResolution::Invalid(format!(
            "signer event type_code={} not valid for signer_type={}",
            actual_type_code, signer_type
        )));
    }
    let mut public_key = [0u8; 32];
    public_key.copy_from_slice(&blob[9..41]);
    Ok(SignerResolution::Found(public_key))
}

impl ProjectionQueries for NodeBehaviorEngine {
    fn load_workspace_context(
        &self,
        recorded_by: &str,
        _event_id_b64: &str,
        _workspace: &events::WorkspaceEvent,
    ) -> ProjectionQueryResult<ContextSnapshot> {
        let state = self.state.borrow();
        let accepted_workspace_id =
            table_rows_for_recorded(&state, "invites_accepted", recorded_by)
                .into_iter()
                .filter_map(|row| {
                    Some((
                        row_int(row, "created_at").unwrap_or(i64::MAX),
                        row_text(row, "event_id")?.to_string(),
                        row_text(row, "workspace_id")?.to_string(),
                    ))
                })
                .min_by(|left, right| (left.0, &left.1).cmp(&(right.0, &right.1)))
                .map(|(_, _, workspace_id)| workspace_id);
        Ok(ContextSnapshot {
            accepted_workspace_id,
            ..ContextSnapshot::default()
        })
    }

    fn load_admin_context(
        &self,
        recorded_by: &str,
        _event_id_b64: &str,
        admin: &events::AdminEvent,
    ) -> ProjectionQueryResult<ContextSnapshot> {
        let state = self.state.borrow();
        let user_event_id_b64 = event_id_to_base64(&admin.user_event_id);
        let admin_user_key_mismatch_reason = match first_row_for_recorded(
            &state,
            "users",
            recorded_by,
            "event_id",
            &user_event_id_b64,
        ) {
            None => Some(format!(
                "no users row for user_event_id {}",
                user_event_id_b64
            )),
            Some(row) => match row_blob(row, "public_key") {
                Some(user_public_key) if user_public_key.len() != 32 => Some(format!(
                    "user {} has invalid public_key length {}",
                    user_event_id_b64,
                    user_public_key.len()
                )),
                Some(user_public_key) if user_public_key != admin.public_key => Some(format!(
                    "admin public_key does not match user public_key for {}",
                    user_event_id_b64
                )),
                Some(_) => None,
                None => Some(format!(
                    "no users row for user_event_id {}",
                    user_event_id_b64
                )),
            },
        };
        Ok(ContextSnapshot {
            admin_user_key_mismatch_reason,
            ..ContextSnapshot::default()
        })
    }

    fn load_peer_shared_context(
        &self,
        recorded_by: &str,
        _event_id_b64: &str,
        peer_shared: &events::PeerSharedEvent,
    ) -> ProjectionQueryResult<ContextSnapshot> {
        let state = self.state.borrow();
        let signed_by_b64 = event_id_to_base64(&peer_shared.signed_by);
        let Some(blob) = valid_event_blob(&state, recorded_by, &signed_by_b64) else {
            return Ok(ContextSnapshot {
                peer_shared_user_mismatch_reason: Some(format!(
                    "no valid device_invite blob for signer {}",
                    signed_by_b64
                )),
                ..ContextSnapshot::default()
            });
        };

        let parsed_signer = match parse_event(&blob) {
            Ok(parsed_signer) => parsed_signer,
            Err(err) => {
                return Ok(ContextSnapshot {
                    peer_shared_user_mismatch_reason: Some(format!(
                        "failed to parse device_invite signer {}: {}",
                        signed_by_b64, err
                    )),
                    ..ContextSnapshot::default()
                })
            }
        };

        let device_invite = match parsed_signer {
            ParsedEvent::DeviceInvite(device_invite) => device_invite,
            other => {
                return Ok(ContextSnapshot {
                    peer_shared_user_mismatch_reason: Some(format!(
                        "peer_shared signer {} resolved to unexpected event type {}",
                        signed_by_b64,
                        other.event_type_code()
                    )),
                    ..ContextSnapshot::default()
                })
            }
        };

        let expected_user = match device_invite.signer_type {
            4 => Some(event_id_to_base64(&device_invite.authority_event_id)),
            5 => {
                let signer_b64 = event_id_to_base64(&device_invite.signed_by);
                match first_row_for_recorded(&state, "peers_shared", recorded_by, "event_id", &signer_b64) {
                    None => Some(format!(
                        "__ERROR__:no peers_shared row for device_invite signer {}",
                        signer_b64
                    )),
                    Some(row) => match row_text(row, "user_event_id") {
                        Some(value) if !value.is_empty() => Some(value.to_string()),
                        _ => Some(format!(
                            "__ERROR__:device_invite signer {} has empty peers_shared.user_event_id",
                            signer_b64
                        )),
                    },
                }
            }
            other => Some(format!(
                "__ERROR__:unsupported device_invite signer_type {} for peer_shared authorization",
                other
            )),
        };

        let peer_shared_user_mismatch_reason = match expected_user {
            None => None,
            Some(expected_user) => {
                if let Some(detail) = expected_user.strip_prefix("__ERROR__:") {
                    Some(detail.to_string())
                } else {
                    let claimed_user_b64 = event_id_to_base64(&peer_shared.user_event_id);
                    (expected_user != claimed_user_b64).then(|| {
                        format!(
                            "peer_shared signer authorizes user {} but event claims {}",
                            expected_user, claimed_user_b64
                        )
                    })
                }
            }
        };

        Ok(ContextSnapshot {
            peer_shared_user_mismatch_reason,
            ..ContextSnapshot::default()
        })
    }

    fn load_user_invite_context(
        &self,
        recorded_by: &str,
        event_id_b64: &str,
        user_invite: &events::UserInviteEvent,
    ) -> ProjectionQueryResult<ContextSnapshot> {
        let state = self.state.borrow();
        let mut ctx = ContextSnapshot::default();
        ctx.is_local_create = recorded_source(&state, recorded_by, event_id_b64)
            .is_some_and(|source| source == "local" || source == "local_create");
        if user_invite.signer_type == 5 {
            let signer_b64 = event_id_to_base64(&user_invite.signed_by);
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
        ctx.bootstrap_context = bootstrap_context_snapshot(&state, recorded_by, event_id_b64);
        Ok(ctx)
    }

    fn load_device_invite_context(
        &self,
        recorded_by: &str,
        event_id_b64: &str,
        device_invite: &events::DeviceInviteEvent,
    ) -> ProjectionQueryResult<ContextSnapshot> {
        let state = self.state.borrow();
        let mut ctx = ContextSnapshot::default();
        ctx.is_local_create = recorded_source(&state, recorded_by, event_id_b64)
            .is_some_and(|source| source == "local" || source == "local_create");
        if device_invite.signer_type == 5 {
            let signer_b64 = event_id_to_base64(&device_invite.signed_by);
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
        ctx.bootstrap_context = bootstrap_context_snapshot(&state, recorded_by, event_id_b64);
        Ok(ctx)
    }

    fn load_message_context(
        &self,
        recorded_by: &str,
        event_id_b64: &str,
        message: &events::MessageEvent,
    ) -> ProjectionQueryResult<ContextSnapshot> {
        let state = self.state.borrow();
        let signer_user_mismatch_reason = signer_user_mismatch_reason_behavior(
            &state,
            recorded_by,
            &message.signed_by,
            &message.author_id,
        );
        let mut deletion_intents = table_rows_for_recorded(&state, "deletion_intents", recorded_by)
            .into_iter()
            .filter(|row| {
                row_text(row, "target_kind") == Some("message")
                    && row_text(row, "target_id") == Some(event_id_b64)
            })
            .filter_map(|row| {
                Some(DeletionIntentInfo {
                    deletion_event_id: row_text(row, "deletion_event_id")?.to_string(),
                    author_id: row_text(row, "author_id")?.to_string(),
                    created_at: row_int(row, "created_at")?,
                })
            })
            .collect::<Vec<_>>();
        deletion_intents
            .sort_by(|left, right| left.deletion_event_id.cmp(&right.deletion_event_id));
        Ok(ContextSnapshot {
            signer_user_mismatch_reason,
            deletion_intents,
            ..ContextSnapshot::default()
        })
    }

    fn load_message_deletion_context(
        &self,
        recorded_by: &str,
        _event_id_b64: &str,
        message_deletion: &events::MessageDeletionEvent,
    ) -> ProjectionQueryResult<ContextSnapshot> {
        let state = self.state.borrow();
        let mut ctx = ContextSnapshot::default();
        ctx.signer_user_mismatch_reason = signer_user_mismatch_reason_behavior(
            &state,
            recorded_by,
            &message_deletion.signed_by,
            &message_deletion.author_id,
        );

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
        recorded_by: &str,
        _event_id_b64: &str,
        reaction: &events::ReactionEvent,
    ) -> ProjectionQueryResult<ContextSnapshot> {
        let state = self.state.borrow();
        let target_b64 = event_id_to_base64(&reaction.target_event_id);
        let target_message_deleted = first_row_for_recorded(
            &state,
            "deleted_messages",
            recorded_by,
            "message_id",
            &target_b64,
        )
        .is_some();
        let signer_user_mismatch_reason = signer_user_mismatch_reason_behavior(
            &state,
            recorded_by,
            &reaction.signed_by,
            &reaction.author_id,
        );
        Ok(ContextSnapshot {
            signer_user_mismatch_reason,
            target_message_deleted,
            ..ContextSnapshot::default()
        })
    }

    fn load_file_context(
        &self,
        recorded_by: &str,
        _event_id_b64: &str,
        file: &events::FileEvent,
    ) -> ProjectionQueryResult<ContextSnapshot> {
        let state = self.state.borrow();
        let message_id_b64 = event_id_to_base64(&file.message_id);
        let target_message_deleted = first_row_for_recorded(
            &state,
            "deleted_messages",
            recorded_by,
            "message_id",
            &message_id_b64,
        )
        .is_some();
        let deleted_file_message_id = first_row_for_recorded(
            &state,
            "deleted_files",
            recorded_by,
            "file_id",
            &event_id_to_base64(&file.file_id),
        )
        .and_then(|row| row_text(row, "message_id").map(ToOwned::to_owned));
        Ok(ContextSnapshot {
            target_message_deleted,
            deleted_file_message_id,
            ..ContextSnapshot::default()
        })
    }

    fn load_file_slice_context(
        &self,
        recorded_by: &str,
        _event_id_b64: &str,
        file_slice: &events::FileSliceEvent,
    ) -> ProjectionQueryResult<ContextSnapshot> {
        let state = self.state.borrow();
        let file_id_b64 = event_id_to_base64(&file_slice.file_id);
        let mut ctx = ContextSnapshot::default();
        ctx.deleted_file_message_id = first_row_for_recorded(
            &state,
            "deleted_files",
            recorded_by,
            "file_id",
            &file_id_b64,
        )
        .and_then(|row| row_text(row, "message_id").map(ToOwned::to_owned));
        ctx.file_descriptors = table_rows_for_recorded(&state, "files", recorded_by)
            .into_iter()
            .filter(|row| row_text(row, "file_id") == Some(&file_id_b64))
            .filter_map(|row| {
                Some(FileDescriptorInfo {
                    event_id: row_text(row, "event_id")?.to_string(),
                    signer_event_id: row_text(row, "signer_event_id")?.to_string(),
                    key_event_id: row_text(row, "key_event_id")?.to_string(),
                })
            })
            .collect();
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
        recorded_by: &str,
        _event_id_b64: &str,
        invite_accepted: &events::InviteAcceptedEvent,
    ) -> ProjectionQueryResult<ContextSnapshot> {
        let state = self.state.borrow();
        let mut ctx = ContextSnapshot::default();
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
        if let Some(bc) = bootstrap_context_snapshot(&state, recorded_by, &invite_event_id_b64) {
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
        recorded_by: &str,
        _event_id_b64: &str,
        key_shared: &events::KeySharedEvent,
    ) -> ProjectionQueryResult<ContextSnapshot> {
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
            return Ok(ContextSnapshot::default());
        };
        if private_key_bytes.len() != 32 {
            return Ok(ContextSnapshot::default());
        }
        let mut key_arr = [0u8; 32];
        key_arr.copy_from_slice(&private_key_bytes);
        let local_signing_key = ed25519_dalek::SigningKey::from_bytes(&key_arr);
        let sender_key = match resolve_signer_key_behavior(
            &state,
            recorded_by,
            key_shared.signer_type,
            &key_shared.signed_by,
        )? {
            SignerResolution::Found(key) => key,
            _ => return Ok(ContextSnapshot::default()),
        };
        let sender_pub = match ed25519_dalek::VerifyingKey::from_bytes(&sender_key) {
            Ok(key) => key,
            Err(_) => return Ok(ContextSnapshot::default()),
        };
        let plaintext_key = crate::projection::encrypted::unwrap_key_from_sender(
            &local_signing_key,
            &sender_pub,
            &key_shared.wrapped_key,
        );
        Ok(ContextSnapshot {
            unwrapped_secret_material: Some(crate::projection::contract::UnwrappedSecretMaterial {
                key_bytes: plaintext_key,
            }),
            ..ContextSnapshot::default()
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

    fn check_deps_and_block(
        &self,
        recorded_by: &str,
        event_id_b64: &str,
        _parsed: &ParsedEvent,
        deps: &[(&str, EventId)],
    ) -> ProjectionApplyResult<Option<ProjectionDecision>> {
        let state = self.state.borrow();
        if state.recorded_by != recorded_by {
            return Ok(None);
        }
        let mut missing = Vec::new();
        for (_, dep_id) in deps {
            let dep_b64 = event_id_to_base64(dep_id);
            if !state.valid_events.contains_key(&dep_b64) {
                missing.push(*dep_id);
            }
        }
        drop(state);
        if missing.is_empty() {
            return Ok(None);
        }

        missing.sort_unstable();
        missing.dedup();
        let mut state = self.state.borrow_mut();
        let deps_remaining = {
            let blockers = state
                .blocked_event_deps
                .entry(event_id_b64.to_string())
                .or_default();
            for dep_id in &missing {
                blockers.insert(event_id_to_base64(dep_id));
            }
            blockers.len() as i64
        };
        state
            .blocked_events
            .insert(event_id_b64.to_string(), deps_remaining);
        Ok(Some(ProjectionDecision::Block { missing }))
    }

    fn check_dep_types(
        &self,
        _recorded_by: &str,
        _parsed: &ParsedEvent,
        deps: &[(&str, EventId)],
        type_codes: &[&[u8]],
    ) -> ProjectionApplyResult<Option<String>> {
        let state = self.state.borrow();
        for (idx, (field_name, dep_id)) in deps.iter().enumerate() {
            let allowed = type_codes.get(idx).copied().unwrap_or(&[]);
            if allowed.is_empty() {
                continue;
            }
            let dep_b64 = event_id_to_base64(dep_id);
            let actual = match state.valid_events.get(&dep_b64).and_then(|v| *v) {
                Some(code) => u8::try_from(code).map_err(|_| "semantic type out of range")?,
                None => {
                    return Ok(Some(format!(
                        "dep {} missing tenant-scoped semantic type record",
                        field_name
                    )))
                }
            };
            if !allowed.contains(&actual) {
                return Ok(Some(format!(
                    "dep {} has semantic type code {} but expected one of {:?}",
                    field_name, actual, allowed
                )));
            }
        }
        Ok(None)
    }

    fn resolve_signer_key(
        &self,
        recorded_by: &str,
        signer_type: u8,
        signer_event_id: &[u8; 32],
    ) -> ProjectionApplyResult<SignerResolution> {
        let state = self.state.borrow();
        if state.recorded_by != recorded_by {
            return Ok(SignerResolution::NotFound);
        }
        let valid_type_codes: &[u8] = match signer_type {
            1 => &[8],
            2 => &[10],
            3 => &[12],
            4 => &[14],
            5 => &[16],
            _ => {
                return Ok(SignerResolution::Invalid(format!(
                    "unsupported signer_type: {}",
                    signer_type
                )))
            }
        };
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
        let actual_type_code = blob[0];
        if !valid_type_codes.contains(&actual_type_code) {
            return Ok(SignerResolution::Invalid(format!(
                "signer event type_code={} not valid for signer_type={}",
                actual_type_code, signer_type
            )));
        }
        let mut public_key = [0u8; 32];
        public_key.copy_from_slice(&blob[9..41]);
        Ok(SignerResolution::Found(public_key))
    }

    fn project_encrypted(
        &self,
        recorded_by: &str,
        event_id_b64: &str,
        encrypted: &EncryptedEvent,
    ) -> ProjectionApplyResult<(ProjectionDecision, Option<ParsedEvent>)> {
        let Some(key_bytes) =
            key_secret_bytes(&self.state.borrow(), recorded_by, &encrypted.key_event_id)
        else {
            return Ok((
                ProjectionDecision::Reject {
                    reason: "secret key not found in key_secrets table".to_string(),
                },
                None,
            ));
        };
        let plaintext = match decrypt_event_blob(
            &key_bytes,
            &encrypted.nonce,
            &encrypted.ciphertext,
            &encrypted.auth_tag,
        ) {
            Ok(v) => v,
            Err(_) => {
                return Ok((
                    ProjectionDecision::Reject {
                        reason: "decryption failed (wrong key or corrupted)".to_string(),
                    },
                    None,
                ))
            }
        };
        let inner_parsed = match events::parse_event(&plaintext) {
            Ok(v) => v,
            Err(err) => {
                return Ok((
                    ProjectionDecision::Reject {
                        reason: format!("inner event parse error: {}", err),
                    },
                    None,
                ))
            }
        };
        if inner_parsed.event_type_code() != encrypted.inner_type_code {
            return Ok((
                ProjectionDecision::Reject {
                    reason: format!(
                        "inner type mismatch: outer declares {}, inner is {}",
                        encrypted.inner_type_code,
                        inner_parsed.event_type_code()
                    ),
                },
                None,
            ));
        }
        if encrypted.inner_type_code == events::EVENT_TYPE_ENCRYPTED {
            return Ok((
                ProjectionDecision::Reject {
                    reason: "nested encryption not allowed".to_string(),
                },
                None,
            ));
        }
        let Some(inner_meta) = events::registry().lookup(inner_parsed.event_type_code()) else {
            return Ok((
                ProjectionDecision::Reject {
                    reason: format!(
                        "event type {} is not admissible inside encrypted wrappers",
                        inner_parsed.event_type_code()
                    ),
                },
                None,
            ));
        };
        if !inner_meta.encryptable {
            return Ok((
                ProjectionDecision::Reject {
                    reason: format!(
                        "event type {} is not admissible inside encrypted wrappers",
                        inner_parsed.event_type_code()
                    ),
                },
                None,
            ));
        }
        let transport_key_event_id_b64 = event_id_to_base64(&encrypted.key_event_id);
        let (decision, _) = run_dep_and_projection_stages_with_backend(
            self,
            recorded_by,
            event_id_b64,
            &plaintext,
            &inner_parsed,
            true,
            true,
            Some(&transport_key_event_id_b64),
        )?;
        let inner = matches!(decision, ProjectionDecision::Valid).then_some(inner_parsed);
        Ok((decision, inner))
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
                    if !rows.contains(&row) {
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
                    if !self.filter.blocks(parsed.event_type_code()) {
                        let _ = self.project_and_cascade(&event_id)?;
                    }
                }
                EmitCommand::RetryWorkspaceEvent { workspace_id } => {
                    if let Some(event_id) = event_id_from_base64(workspace_id) {
                        let _ = self.project_and_cascade(&event_id)?;
                    }
                }
                EmitCommand::MaterializeTransportIdentity { .. }
                | EmitCommand::HardPurgeMessageGraph { .. }
                | EmitCommand::RetryFileSliceGuards { .. }
                | EmitCommand::RecordFileSliceGuardBlock { .. } => {}
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
    ) -> ProjectionApplyResult<()> {
        if self.state.borrow().recorded_by != recorded_by {
            return Ok(());
        }
        self.state.borrow_mut().valid_events.insert(
            event_id_b64.to_string(),
            Some(i64::from(match sub_event {
                ParsedEvent::Encrypted(enc) => enc.inner_type_code,
                _ => sub_event.event_type_code(),
            })),
        );
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
        .query_map([], |row| row.get::<_, String>(1))?
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

    fn subset_summary(summary: &NodeBehaviorSummary, tables: &[&str]) -> NodeBehaviorSummary {
        let wanted = tables
            .iter()
            .map(|table| (*table).to_string())
            .collect::<BTreeSet<_>>();
        NodeBehaviorSummary {
            recorded_by: summary.recorded_by.clone(),
            tables: summary
                .tables
                .iter()
                .filter(|(table, _)| wanted.contains(*table))
                .map(|(table, rows)| (table.clone(), rows.clone()))
                .collect(),
        }
    }

    #[test]
    fn behavior_engine_matches_replayed_sqlite_for_workspace_invite_and_rotation() {
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
        let imported = import_peer_state(creator_db.to_str().expect("creator db"), &recorded_by)
            .expect("import peer state");
        let behavior =
            NodeBehaviorEngine::ingest_imported(&imported, EventProjectionFilter::default())
                .expect("ingest imported events");

        let snapshot_db = tmpdir.path().join("snapshot.db");
        snapshot_replayed_peer_to_path(
            creator_db.to_str().expect("creator db"),
            &recorded_by,
            snapshot_db.to_str().expect("snapshot db"),
        )
        .expect("snapshot replay");

        let expected =
            sqlite_behavior_summary(snapshot_db.to_str().expect("snapshot db"), &recorded_by)
                .expect("sqlite behavior summary");
        let modeled_tables = [
            "admins",
            "bootstrap_context",
            "device_invites",
            "invite_secrets",
            "invites_accepted",
            "key_rotations",
            "key_secrets",
            "tenants",
            "user_invites",
            "users",
            "workspaces",
        ];
        assert_eq!(
            subset_summary(&behavior.summary(), &modeled_tables),
            subset_summary(&expected, &modeled_tables)
        );
    }

    #[test]
    fn behavior_engine_matches_replayed_sqlite_for_message_and_key_flow() {
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
        let imported = import_peer_state(creator_db.to_str().expect("creator db"), &recorded_by)
            .expect("import peer state");
        let behavior =
            NodeBehaviorEngine::ingest_imported(&imported, EventProjectionFilter::default())
                .expect("ingest imported events");

        let snapshot_db = tmpdir.path().join("snapshot.db");
        snapshot_replayed_peer_to_path(
            creator_db.to_str().expect("creator db"),
            &recorded_by,
            snapshot_db.to_str().expect("snapshot db"),
        )
        .expect("snapshot replay");

        let expected =
            sqlite_behavior_summary(snapshot_db.to_str().expect("snapshot db"), &recorded_by)
                .expect("sqlite behavior summary");
        let modeled_tables = [
            "admins",
            "bootstrap_context",
            "deletion_intents",
            "device_invites",
            "invite_secrets",
            "invites_accepted",
            "key_rotations",
            "key_secrets",
            "messages",
            "tenants",
            "user_invites",
            "users",
            "workspaces",
        ];
        assert_eq!(
            subset_summary(&behavior.summary(), &modeled_tables),
            subset_summary(&expected, &modeled_tables)
        );
    }

    #[test]
    fn behavior_engine_filtered_ingest_preserves_key_and_auth_state() {
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
        let imported = import_peer_state(creator_db.to_str().expect("creator db"), &recorded_by)
            .expect("import peer state");
        let behavior = NodeBehaviorEngine::ingest_imported(
            &imported,
            EventProjectionFilter::with_blocked_type_codes([EVENT_TYPE_ENCRYPTED]),
        )
        .expect("ingest imported events");

        let snapshot_db = tmpdir.path().join("snapshot.db");
        snapshot_replayed_peer_to_path(
            creator_db.to_str().expect("creator db"),
            &recorded_by,
            snapshot_db.to_str().expect("snapshot db"),
        )
        .expect("snapshot replay");

        let expected =
            sqlite_behavior_summary(snapshot_db.to_str().expect("snapshot db"), &recorded_by)
                .expect("sqlite behavior summary");
        let key_auth_tables = [
            "admins",
            "bootstrap_context",
            "device_invites",
            "invite_secrets",
            "invites_accepted",
            "key_rotations",
            "key_secrets",
            "pending_invite_bootstrap_trust",
            "tenants",
            "user_invites",
            "users",
            "workspaces",
        ];
        assert_eq!(
            subset_summary(&behavior.summary(), &key_auth_tables),
            subset_summary(&expected, &key_auth_tables)
        );
    }
}
