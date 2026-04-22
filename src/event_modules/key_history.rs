use super::layout::field_spec::{
    decode_fields, encode_fields, wire_size_for_fields, FieldSpec, FieldValue,
};
use super::registry::{EventTypeMeta, ShareScope};
use super::{EventError, ParsedEvent, EVENT_TYPE_KEY_HISTORY};

pub const KEY_HISTORY_CAP: usize = 8192;
pub const KEY_HISTORY_ENTRY_BYTES: usize = 64;
pub const KEY_HISTORY_BUNDLE_BYTES: usize = KEY_HISTORY_CAP * KEY_HISTORY_ENTRY_BYTES;
pub const NO_KEY_HISTORY_EVENT_ID: [u8; 32] = [0u8; 32];

pub const KEY_HISTORY_FIELDS: &[FieldSpec] = &[
    FieldSpec::Timestamp("created_at_ms"),
    FieldSpec::EventId("recipient_public_key"),
    FieldSpec::FixedBytes("nonce", 12),
    FieldSpec::FixedBytes("ciphertext", KEY_HISTORY_BUNDLE_BYTES),
    FieldSpec::FixedBytes("auth_tag", 16),
];

pub const KEY_HISTORY_WIRE_SIZE: usize = wire_size_for_fields(KEY_HISTORY_FIELDS);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyHistoryEvent {
    pub created_at_ms: u64,
    pub recipient_public_key: [u8; 32],
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
    pub auth_tag: [u8; 16],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyHistoryEntry {
    pub key_event_id: [u8; 32],
    pub key_bytes: [u8; 32],
}

impl super::Describe for KeyHistoryEvent {
    fn human_fields(&self) -> Vec<(&'static str, String)> {
        vec![("slot_cap", KEY_HISTORY_CAP.to_string())]
    }
}

pub fn encode_key_history_plaintext(
    entries: &[KeyHistoryEntry],
) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    if entries.len() > KEY_HISTORY_CAP {
        return Err(format!(
            "key history entry count {} exceeds cap {}",
            entries.len(),
            KEY_HISTORY_CAP
        )
        .into());
    }
    let mut plaintext = vec![0u8; KEY_HISTORY_BUNDLE_BYTES];
    for (idx, entry) in entries.iter().enumerate() {
        let start = idx * KEY_HISTORY_ENTRY_BYTES;
        plaintext[start..start + 32].copy_from_slice(&entry.key_event_id);
        plaintext[start + 32..start + 64].copy_from_slice(&entry.key_bytes);
    }
    Ok(plaintext)
}

pub fn decode_key_history_plaintext(
    plaintext: &[u8],
) -> Result<Vec<KeyHistoryEntry>, Box<dyn std::error::Error + Send + Sync>> {
    if plaintext.len() != KEY_HISTORY_BUNDLE_BYTES {
        return Err(format!(
            "key history plaintext len {} does not match {}",
            plaintext.len(),
            KEY_HISTORY_BUNDLE_BYTES
        )
        .into());
    }
    let mut entries = Vec::new();
    for chunk in plaintext.chunks_exact(KEY_HISTORY_ENTRY_BYTES) {
        let mut key_event_id = [0u8; 32];
        key_event_id.copy_from_slice(&chunk[..32]);
        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&chunk[32..64]);
        if key_event_id == [0u8; 32] {
            continue;
        }
        entries.push(KeyHistoryEntry {
            key_event_id,
            key_bytes,
        });
    }
    Ok(entries)
}

pub fn parse_key_history(blob: &[u8]) -> Result<ParsedEvent, EventError> {
    let values = decode_fields(EVENT_TYPE_KEY_HISTORY, KEY_HISTORY_FIELDS, blob)?;
    let nonce_bytes = values[2]
        .clone()
        .into_fixed_bytes()
        .ok_or(EventError::WrongVariant)?;
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&nonce_bytes);
    let ciphertext = values[3]
        .clone()
        .into_fixed_bytes()
        .ok_or(EventError::WrongVariant)?;
    if ciphertext.len() != KEY_HISTORY_BUNDLE_BYTES {
        return Err(EventError::InvalidMetadata(
            "ciphertext size does not match key history cap",
        ));
    }
    let auth_tag_bytes = values[4]
        .clone()
        .into_fixed_bytes()
        .ok_or(EventError::WrongVariant)?;
    let mut auth_tag = [0u8; 16];
    auth_tag.copy_from_slice(&auth_tag_bytes);
    Ok(ParsedEvent::KeyHistory(KeyHistoryEvent {
        created_at_ms: values[0].as_timestamp().unwrap(),
        recipient_public_key: values[1].as_event_id().unwrap(),
        nonce,
        ciphertext,
        auth_tag,
    }))
}

pub fn encode_key_history(event: &ParsedEvent) -> Result<Vec<u8>, EventError> {
    let history = match event {
        ParsedEvent::KeyHistory(history) => history,
        _ => return Err(EventError::WrongVariant),
    };
    if history.ciphertext.len() != KEY_HISTORY_BUNDLE_BYTES {
        return Err(EventError::InvalidMetadata(
            "ciphertext size does not match key history cap",
        ));
    }
    let values = vec![
        FieldValue::Timestamp(history.created_at_ms),
        FieldValue::EventId(history.recipient_public_key),
        FieldValue::FixedBytes(history.nonce.to_vec()),
        FieldValue::FixedBytes(history.ciphertext.clone()),
        FieldValue::FixedBytes(history.auth_tag.to_vec()),
    ];
    Ok(encode_fields(
        EVENT_TYPE_KEY_HISTORY,
        KEY_HISTORY_FIELDS,
        &values,
    )?)
}

use crate::projection::decision_context::{
    ContextLoadResult, ProjectionFrameContext, ProjectionQueries,
};
use crate::projection::projector::{
    EmitCommand, ProjectorDecisionContext, ProjectorResult, SqlVal, WriteOp,
};
use rusqlite::Connection;

pub fn ensure_schema(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS key_histories (
            recorded_by TEXT NOT NULL,
            event_id TEXT NOT NULL,
            recipient_public_key BLOB NOT NULL,
            created_at INTEGER NOT NULL,
            materialized_key_count INTEGER NOT NULL,
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
) -> Result<ContextLoadResult, Box<dyn std::error::Error>> {
    let history = match parsed {
        ParsedEvent::KeyHistory(history) => history,
        _ => return Err("key_history context loader called for non-key_history event".into()),
    };
    Ok(ContextLoadResult::ready(queries.load_key_history_context(
        frame,
        recorded_by,
        event_id_b64,
        history,
    )?))
}

pub fn project_pure(
    recorded_by: &str,
    event_id_b64: &str,
    parsed: &ParsedEvent,
    ctx: &ProjectorDecisionContext,
) -> ProjectorResult {
    let history = match parsed {
        ParsedEvent::KeyHistory(history) => history,
        _ => return ProjectorResult::reject("not a key_history event".to_string()),
    };
    if history.ciphertext.len() != KEY_HISTORY_BUNDLE_BYTES {
        return ProjectorResult::reject("ciphertext size does not match key history cap".to_string());
    }
    let mut ops = vec![WriteOp::InsertOrIgnore {
        table: "key_histories",
        columns: vec![
            "recorded_by",
            "event_id",
            "recipient_public_key",
            "created_at",
            "materialized_key_count",
        ],
        values: vec![
            SqlVal::Text(recorded_by.to_string()),
            SqlVal::Text(event_id_b64.to_string()),
            SqlVal::Blob(history.recipient_public_key.to_vec()),
            SqlVal::Int(history.created_at_ms as i64),
            SqlVal::Int(ctx.unwrapped_key_history_material.len() as i64),
        ],
    }];

    for entry in &ctx.unwrapped_key_history_material {
        // Unwrap-gated (same access-control structure as KeyShared): a
        // history entry is only materialized when THIS peer successfully
        // unwrapped that entry's wrapped_key. Routed through the typed
        // row constructor so the CI gate stays closed.
        ops.push(
            super::key_shared::KeySecretsRow::new(
                crate::crypto::event_id_to_base64(&entry.key_event_id),
                entry.key_bytes,
                history.created_at_ms as i64,
                recorded_by.to_string(),
            )
            .to_write_op_from_unwrap(),
        );
    }

    ProjectorResult::valid_with_commands(
        ops,
        ctx.unwrapped_key_history_material
            .iter()
            .map(|entry| EmitCommand::RetryBlockedEncryptedByKey {
                key_event_id: crate::crypto::event_id_to_base64(&entry.key_event_id),
            })
            .collect(),
    )
}

pub static KEY_HISTORY_META: EventTypeMeta = crate::event_modules::registry::event_type_meta! {
    type_code: EVENT_TYPE_KEY_HISTORY,
    type_name: "key_history",
    projection_table: "key_histories",
    share_scope: ShareScope::Shared,
    dep_fields: &[],
    dep_field_type_codes: &[],
    signer_required: true,
    signature_byte_len: 0,
    encryptable: false,
    parse: parse_key_history,
    encode: encode_key_history,
    projector: project_pure,
    context_loader: build_projector_context,
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event_modules::{encode_event, parse_event};

    #[test]
    fn test_key_history_plaintext_roundtrip() {
        let plaintext = encode_key_history_plaintext(&[
            KeyHistoryEntry {
                key_event_id: [0x11; 32],
                key_bytes: [0x22; 32],
            },
            KeyHistoryEntry {
                key_event_id: [0x33; 32],
                key_bytes: [0x44; 32],
            },
        ])
        .expect("encode plaintext");
        let decoded = decode_key_history_plaintext(&plaintext).expect("decode plaintext");
        assert_eq!(
            decoded,
            vec![
                KeyHistoryEntry {
                    key_event_id: [0x11; 32],
                    key_bytes: [0x22; 32],
                },
                KeyHistoryEntry {
                    key_event_id: [0x33; 32],
                    key_bytes: [0x44; 32],
                }
            ]
        );
    }

    #[test]
    fn test_key_history_roundtrip() {
        let event = ParsedEvent::KeyHistory(KeyHistoryEvent {
            created_at_ms: 123,
            recipient_public_key: [0x77; 32],
            nonce: [0x55; 12],
            ciphertext: vec![0x22; KEY_HISTORY_BUNDLE_BYTES],
            auth_tag: [0x44; 16],
        });
        let blob = encode_event(&event).expect("encode");
        assert_eq!(blob.len(), KEY_HISTORY_WIRE_SIZE);
        let parsed = parse_event(&blob).expect("parse");
        assert_eq!(parsed, event);
    }
}
