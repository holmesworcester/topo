use super::key_request::delivery_target_id;
use super::layout::field_spec::{
    decode_fields, encode_fields, wire_size_for_fields, FieldSpec, FieldValue,
};
use super::registry::{EventTypeMeta, ShareScope};
use super::removal::{
    frontier_hash_from_refs, frontier_refs_from_slots, validate_canonical_frontier_refs,
};
use super::{EventError, ParsedEvent, EVENT_TYPE_KEY_SHARED};

// ---------------------------------------------------------------------------
// Typed row (pattern #1): sole constructor for key_secrets WriteOps.

/// Canonical table name. Matches the verus-verified constant.
pub const KEY_SECRETS_TABLE: &str = "key_secrets";

/// Canonical column order for key_secrets. MUST match verus-proofs constants.
pub const KEY_SECRETS_COLUMNS: [&str; 4] =
    ["event_id", "key_bytes", "created_at", "recorded_by"];

/// Typed row for a single key_secrets insert. Named fields eliminate
/// positional drift between column list and value list. This is the
/// SOLE production-path constructor of a key_secrets WriteOp.
#[derive(Debug, Clone, PartialEq)]
pub struct KeySecretsRow {
    pub event_id_b64: String,
    pub key_bytes: [u8; 32],
    pub created_at_ms: i64,
    pub recorded_by: String,
}

impl KeySecretsRow {
    /// Convert this typed row into the canonical positional WriteOp.
    pub fn to_write_op(&self) -> crate::projection::projector::WriteOp {
        use crate::projection::projector::{SqlVal, WriteOp};
        WriteOp::InsertOrIgnore {
            table: KEY_SECRETS_TABLE,
            columns: KEY_SECRETS_COLUMNS.to_vec(),
            values: vec![
                SqlVal::Text(self.event_id_b64.clone()),
                SqlVal::Blob(self.key_bytes.to_vec()),
                SqlVal::Int(self.created_at_ms),
                SqlVal::Text(self.recorded_by.clone()),
            ],
        }
    }
}

pub const KEY_SHARED_FIELDS: &[FieldSpec] = &[
    FieldSpec::Timestamp("created_at_ms"),
    FieldSpec::EventId("key_event_id"),
    FieldSpec::U8("frontier_count"),
    FieldSpec::EventId("frontier_ref_1"),
    FieldSpec::EventId("frontier_ref_2"),
    FieldSpec::EventId("frontier_ref_3"),
    FieldSpec::EventId("frontier_ref_4"),
    FieldSpec::EventId("frontier_hash"),
    FieldSpec::EventId("delivery_target_id"),
    FieldSpec::EventId("recipient_event_id"),
    FieldSpec::EventId("unwrap_key_event_id"),
    FieldSpec::EventId("wrapped_key"),
];

/// KeyShared (type 22): type(1) + created_at(8) + key_event_id(32) + frontier_count(1)
///   + frontier_ref_1..4(128) + frontier_hash(32) + delivery_target_id(32)
///   + recipient_event_id(32) + unwrap_key_event_id(32) + wrapped_key(32) = 330
pub const KEY_SHARED_WIRE_SIZE: usize = wire_size_for_fields(KEY_SHARED_FIELDS);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeySharedEvent {
    pub created_at_ms: u64,
    pub key_event_id: [u8; 32],
    pub frontier_count: u8,
    pub frontier_ref_1: [u8; 32],
    pub frontier_ref_2: [u8; 32],
    pub frontier_ref_3: [u8; 32],
    pub frontier_ref_4: [u8; 32],
    pub frontier_hash: [u8; 32],
    pub delivery_target_id: [u8; 32],
    pub recipient_event_id: [u8; 32],
    pub unwrap_key_event_id: [u8; 32],
    pub wrapped_key: [u8; 32],
}

impl super::Describe for KeySharedEvent {
    fn human_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            ("key_event_id", super::short_id_b64(&self.key_event_id)),
            ("frontier_hash", super::short_id_b64(&self.frontier_hash)),
            ("wrapped_key", super::trunc_hex(&self.wrapped_key, 16)),
        ]
    }
}

pub fn parse_key_shared(blob: &[u8]) -> Result<ParsedEvent, EventError> {
    let values = decode_fields(EVENT_TYPE_KEY_SHARED, KEY_SHARED_FIELDS, blob)?;

    Ok(ParsedEvent::KeyShared(KeySharedEvent {
        created_at_ms: values[0].as_timestamp().unwrap(),
        key_event_id: values[1].as_event_id().unwrap(),
        frontier_count: values[2].as_u8().unwrap(),
        frontier_ref_1: values[3].as_event_id().unwrap(),
        frontier_ref_2: values[4].as_event_id().unwrap(),
        frontier_ref_3: values[5].as_event_id().unwrap(),
        frontier_ref_4: values[6].as_event_id().unwrap(),
        frontier_hash: values[7].as_event_id().unwrap(),
        delivery_target_id: values[8].as_event_id().unwrap(),
        recipient_event_id: values[9].as_event_id().unwrap(),
        unwrap_key_event_id: values[10].as_event_id().unwrap(),
        wrapped_key: values[11].as_event_id().unwrap(),
    }))
}

pub fn encode_key_shared(event: &ParsedEvent) -> Result<Vec<u8>, EventError> {
    let e = match event {
        ParsedEvent::KeyShared(v) => v,
        _ => return Err(EventError::WrongVariant),
    };
    Ok(
        topo_verus_proofs::event_modules::layout::shapes::encode_ts_id_u8_id9(
            EVENT_TYPE_KEY_SHARED,
            e.created_at_ms,
            &e.key_event_id,
            e.frontier_count,
            &e.frontier_ref_1,
            &e.frontier_ref_2,
            &e.frontier_ref_3,
            &e.frontier_ref_4,
            &e.frontier_hash,
            &e.delivery_target_id,
            &e.recipient_event_id,
            &e.unwrap_key_event_id,
            &e.wrapped_key,
        ),
    )
}

use crate::crypto::event_id_to_base64;
use crate::projection::projector::{
    EmitCommand, ProjectorDecisionContext, ProjectorResult, SqlVal, WriteOp,
};
use crate::projection::decision_context::{ProjectionFrameContext, ProjectionQueries};
use rusqlite::Connection;

pub fn ensure_schema(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS key_shared (
            recorded_by TEXT NOT NULL,
            event_id TEXT NOT NULL,
            key_event_id TEXT NOT NULL,
            frontier_count INTEGER NOT NULL,
            frontier_ref_1 TEXT NOT NULL,
            frontier_ref_2 TEXT NOT NULL,
            frontier_ref_3 TEXT NOT NULL,
            frontier_ref_4 TEXT NOT NULL,
            frontier_hash TEXT NOT NULL,
            delivery_target_id TEXT NOT NULL,
            recipient_event_id TEXT NOT NULL,
            wrapped_key BLOB NOT NULL,
            PRIMARY KEY (recorded_by, event_id)
        );
        ",
    )?;
    Ok(())
}

pub fn build_projector_context(
    queries: &dyn ProjectionQueries,
    frame: &ProjectionFrameContext,
    recorded_by: &str,
    event_id_b64: &str,
    parsed: &ParsedEvent,
) -> Result<crate::projection::decision_context::ContextLoadResult, Box<dyn std::error::Error>> {
    let ss = match parsed {
        ParsedEvent::KeyShared(ss) => ss,
        _ => return Err("key_shared context loader called for non-key_shared event".into()),
    };

    Ok(crate::projection::decision_context::ContextLoadResult::ready(
        queries.load_key_shared_context(frame, recorded_by, event_id_b64, ss)?,
    ))
}

pub fn project_pure(
    recorded_by: &str,
    event_id_b64: &str,
    parsed: &ParsedEvent,
    ctx: &ProjectorDecisionContext,
) -> ProjectorResult {
    use topo_verus_proofs::event_modules::key_shared::{
        decide_key_shared_acceptance_core, KeySharedAcceptanceCore, KeySharedAcceptanceFlags,
    };
    let ss = match parsed {
        ParsedEvent::KeyShared(s) => s,
        _ => return ProjectorResult::reject("not a key_shared event".to_string()),
    };

    // Extract the four primitive flags. Each Result/bool is computed from
    // real input state; the outcome enum is checked against the verified
    // decision. Reject strings are rehydrated from the Err values so we
    // don't lose the specific frontier-refs-from-slots failure messages.
    let slots = [
        ss.frontier_ref_1,
        ss.frontier_ref_2,
        ss.frontier_ref_3,
        ss.frontier_ref_4,
    ];
    let refs_result = frontier_refs_from_slots(ss.frontier_count, &slots);
    let frontier_refs_well_formed = refs_result.is_ok();
    let canonical_result = refs_result
        .as_ref()
        .ok()
        .map(|r| validate_canonical_frontier_refs(r));
    let frontier_refs_canonical = matches!(&canonical_result, Some(Ok(())));
    let frontier_hash_matches = refs_result
        .as_ref()
        .ok()
        .map(|r| ss.frontier_hash == frontier_hash_from_refs(r))
        .unwrap_or(false);
    let expected_delivery_target_id = delivery_target_id(
        &ss.key_event_id,
        &ss.frontier_hash,
        &ss.recipient_event_id,
        &ss.unwrap_key_event_id,
    );
    let delivery_target_matches = ss.delivery_target_id == expected_delivery_target_id;

    let flags = KeySharedAcceptanceFlags {
        frontier_refs_well_formed,
        frontier_refs_canonical,
        frontier_hash_matches,
        delivery_target_matches,
    };
    match decide_key_shared_acceptance_core(flags) {
        KeySharedAcceptanceCore::RejectFrontierRefsMalformed => {
            return ProjectorResult::reject(
                refs_result
                    .err()
                    .expect("verified FrontierRefsMalformed requires refs_result Err"),
            );
        }
        KeySharedAcceptanceCore::RejectFrontierRefsNotCanonical => {
            let reason = match canonical_result {
                Some(Err(reason)) => reason,
                _ => unreachable!(
                    "verified FrontierRefsNotCanonical requires Some(Err)"
                ),
            };
            return ProjectorResult::reject(reason);
        }
        KeySharedAcceptanceCore::RejectFrontierHashMismatch => {
            return ProjectorResult::reject(
                "frontier_hash does not match key_shared frontier".to_string(),
            );
        }
        KeySharedAcceptanceCore::RejectDeliveryTargetMismatch => {
            return ProjectorResult::reject(
                "delivery_target_id does not match key_shared target".to_string(),
            );
        }
        KeySharedAcceptanceCore::Valid => {}
    }

    let key_b64 = event_id_to_base64(&ss.key_event_id);
    let frontier_b64 = event_id_to_base64(&ss.frontier_hash);
    let delivery_target_b64 = event_id_to_base64(&ss.delivery_target_id);
    let recipient_b64 = event_id_to_base64(&ss.recipient_event_id);

    let mut ops = vec![WriteOp::InsertOrIgnore {
        table: "key_shared",
        columns: vec![
            "recorded_by",
            "event_id",
            "key_event_id",
            "frontier_count",
            "frontier_ref_1",
            "frontier_ref_2",
            "frontier_ref_3",
            "frontier_ref_4",
            "frontier_hash",
            "delivery_target_id",
            "recipient_event_id",
            "wrapped_key",
        ],
        values: vec![
            SqlVal::Text(recorded_by.to_string()),
            SqlVal::Text(event_id_b64.to_string()),
            SqlVal::Text(key_b64),
            SqlVal::Int(ss.frontier_count as i64),
            SqlVal::Text(event_id_to_base64(&ss.frontier_ref_1)),
            SqlVal::Text(event_id_to_base64(&ss.frontier_ref_2)),
            SqlVal::Text(event_id_to_base64(&ss.frontier_ref_3)),
            SqlVal::Text(event_id_to_base64(&ss.frontier_ref_4)),
            SqlVal::Text(frontier_b64),
            SqlVal::Text(delivery_target_b64),
            SqlVal::Text(recipient_b64),
            SqlVal::Blob(ss.wrapped_key.to_vec()),
        ],
    }];

    // Access-control gate: delegate the "emit key_secrets row?" decision
    // to the Verus-verified core. The runtime's primitive flag is "did
    // THIS peer's unwrap key decrypt the wrapped_key" — encoded by the
    // context loader as `unwrapped_secret_material.is_some()`.
    use topo_verus_proofs::event_modules::key_shared::{
        decide_key_secrets_materialization_core, KeySecretsMaterializationCore,
    };
    let unwrap_successful_for_this_peer = ctx.unwrapped_secret_material.is_some();
    match decide_key_secrets_materialization_core(unwrap_successful_for_this_peer) {
        KeySecretsMaterializationCore::SkipKeySecretsRow => {
            return ProjectorResult::valid(ops);
        }
        KeySecretsMaterializationCore::EmitKeySecretsRow => {}
    }
    let material = ctx
        .unwrapped_secret_material
        .as_ref()
        .expect("verified EmitKeySecretsRow requires material to be Some");

    // Typed row (pattern #1): sole production-path constructor for a
    // key_secrets WriteOp. The verus-verified ensures on the typed row's
    // table name and column count are cross-checked by the runtime unit
    // tests; the CI gate (scripts/check_projection_write_sites.sh) enforces
    // that no other code path writes key_secrets directly.
    let key_secrets_row = KeySecretsRow {
        event_id_b64: event_id_to_base64(&ss.key_event_id),
        key_bytes: material.key_bytes,
        created_at_ms: ss.created_at_ms as i64,
        recorded_by: recorded_by.to_string(),
    };
    ops.push(key_secrets_row.to_write_op());

    ProjectorResult::valid_with_commands(
        ops,
        vec![EmitCommand::RetryBlockedEncryptedByKey {
            key_event_id: event_id_to_base64(&ss.key_event_id),
        }],
    )
}

pub static KEY_SHARED_META: EventTypeMeta = crate::event_modules::registry::event_type_meta! {
    type_code: EVENT_TYPE_KEY_SHARED,
    type_name: "key_shared",
    projection_table: "key_shared",
    share_scope: ShareScope::Shared,
    dep_fields: &[
        "key_event_id",
        "recipient_event_id",
        "frontier_ref_1",
        "frontier_ref_2",
        "frontier_ref_3",
        "frontier_ref_4",
    ],
    dep_field_type_codes: &[&[super::EVENT_TYPE_KEY_ROTATION], &[10, 12, 16], &[], &[], &[], &[]],
    signer_required: true,
    signature_byte_len: 0,
    encryptable: false,
    parse: parse_key_shared,
    encode: encode_key_shared,
    projector: project_pure,
    context_loader: build_projector_context,
};

#[cfg(test)]
mod typed_row_tests {
    use super::*;
    use crate::projection::projector::{SqlVal, WriteOp};

    #[test]
    fn to_write_op_produces_canonical_column_order() {
        let row = KeySecretsRow {
            event_id_b64: "abc".to_string(),
            key_bytes: [0x42u8; 32],
            created_at_ms: 1_700_000_000_000,
            recorded_by: "tenant_0".to_string(),
        };
        let op = row.to_write_op();
        match op {
            WriteOp::InsertOrIgnore { table, columns, values } => {
                assert_eq!(table, "key_secrets");
                assert_eq!(columns, vec!["event_id", "key_bytes", "created_at", "recorded_by"]);
                assert_eq!(values.len(), 4);
                assert_eq!(values[0], SqlVal::Text("abc".to_string()));
                assert_eq!(values[1], SqlVal::Blob(vec![0x42u8; 32]));
                assert_eq!(values[2], SqlVal::Int(1_700_000_000_000));
                assert_eq!(values[3], SqlVal::Text("tenant_0".to_string()));
            }
            _ => panic!("expected InsertOrIgnore, got {:?}", op),
        }
    }

    #[test]
    fn to_write_op_matches_verus_pinned_table_name() {
        let row = KeySecretsRow {
            event_id_b64: "x".to_string(),
            key_bytes: [0u8; 32],
            created_at_ms: 0,
            recorded_by: "t".to_string(),
        };
        match row.to_write_op() {
            WriteOp::InsertOrIgnore { table, .. } => {
                assert_eq!(
                    table,
                    topo_verus_proofs::event_modules::key_shared::key_secrets_table_name(),
                );
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn to_write_op_matches_verus_pinned_column_count() {
        let row = KeySecretsRow {
            event_id_b64: "x".to_string(),
            key_bytes: [0u8; 32],
            created_at_ms: 0,
            recorded_by: "t".to_string(),
        };
        match row.to_write_op() {
            WriteOp::InsertOrIgnore { columns, .. } => {
                assert_eq!(
                    columns.len() as u8,
                    topo_verus_proofs::event_modules::key_shared::key_secrets_column_count(),
                );
            }
            _ => unreachable!(),
        }
    }
}
