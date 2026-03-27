use super::layout::field_spec::{
    decode_fields, encode_fields, wire_size_for_fields, FieldSpec, FieldValue,
};
use super::registry::{EventTypeMeta, ShareScope};
use super::{EventError, ParsedEvent, EVENT_TYPE_KEY_SHARED};

// ─── Layout (owned by this module) ───

pub const KEY_SHARED_FIELDS: &[FieldSpec] = &[
    FieldSpec::Timestamp("created_at_ms"),
    FieldSpec::EventId("key_event_id"),
    FieldSpec::EventId("recipient_event_id"),
    FieldSpec::EventId("unwrap_key_event_id"),
    FieldSpec::EventId("wrapped_key"),
    FieldSpec::EventId("signed_by"),
    FieldSpec::U8("signer_type"),
    FieldSpec::FixedBytes("signature", 64),
];

/// KeyShared (type 22): type(1) + created_at(8) + key_event_id(32) + recipient_event_id(32)
///                        + unwrap_key_event_id(32) + wrapped_key(32) + signed_by(32)
///                        + signer_type(1) + signature(64) = 234
pub const KEY_SHARED_WIRE_SIZE: usize = wire_size_for_fields(KEY_SHARED_FIELDS);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeySharedEvent {
    pub created_at_ms: u64,
    pub key_event_id: [u8; 32],        // dep: Secret event
    pub recipient_event_id: [u8; 32],  // dep: invite event of recipient
    pub unwrap_key_event_id: [u8; 32], // dep: local InviteSecret event (recipient side)
    pub wrapped_key: [u8; 32],         // key bytes wrapped for recipient
    pub signed_by: [u8; 32],           // signer event_id (PeerShared event — sender)
    pub signer_type: u8,               // 5 = peer_shared
    pub signature: [u8; 64],
}

impl super::Describe for KeySharedEvent {
    fn human_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            ("key_event_id", super::short_id_b64(&self.key_event_id)),
            ("wrapped_key", super::trunc_hex(&self.wrapped_key, 16)),
        ]
    }
}

/// Wire format (234 bytes fixed):
/// [0]          type_code = 22
/// [1..9]       created_at_ms (u64 LE)
/// [9..41]      key_event_id (32 bytes)
/// [41..73]     recipient_event_id (32 bytes)
/// [73..105]    unwrap_key_event_id (32 bytes)
/// [105..137]   wrapped_key (32 bytes)
/// [137..169]   signed_by (32 bytes)
/// [169]        signer_type (1 byte)
/// [170..234]   signature (64 bytes)
pub fn parse_key_shared(blob: &[u8]) -> Result<ParsedEvent, EventError> {
    let values = decode_fields(EVENT_TYPE_KEY_SHARED, KEY_SHARED_FIELDS, blob)?;

    Ok(ParsedEvent::KeyShared(KeySharedEvent {
        created_at_ms: values[0].as_timestamp().unwrap(),
        key_event_id: values[1].as_event_id().unwrap(),
        recipient_event_id: values[2].as_event_id().unwrap(),
        unwrap_key_event_id: values[3].as_event_id().unwrap(),
        wrapped_key: values[4].as_event_id().unwrap(),
        signed_by: values[5].as_event_id().unwrap(),
        signer_type: values[6].as_u8().unwrap(),
        signature: {
            let bytes = values[7].as_fixed_bytes().unwrap();
            let mut sig = [0u8; 64];
            sig.copy_from_slice(bytes);
            sig
        },
    }))
}

pub fn encode_key_shared(event: &ParsedEvent) -> Result<Vec<u8>, EventError> {
    let e = match event {
        ParsedEvent::KeyShared(v) => v,
        _ => return Err(EventError::WrongVariant),
    };

    let values = vec![
        FieldValue::Timestamp(e.created_at_ms),
        FieldValue::EventId(e.key_event_id),
        FieldValue::EventId(e.recipient_event_id),
        FieldValue::EventId(e.unwrap_key_event_id),
        FieldValue::EventId(e.wrapped_key),
        FieldValue::EventId(e.signed_by),
        FieldValue::U8(e.signer_type),
        FieldValue::FixedBytes(e.signature.to_vec()),
    ];

    Ok(encode_fields(
        EVENT_TYPE_KEY_SHARED,
        KEY_SHARED_FIELDS,
        &values,
    )?)
}

// === Projector (event-module locality) ===

use crate::crypto::event_id_to_base64;
use crate::projection::contract::{ContextSnapshot, EmitCommand, ProjectorResult, SqlVal, WriteOp};
use crate::projection::encrypted::unwrap_key_from_sender;
use crate::projection::signer::{resolve_signer_key, SignerResolution};
use rusqlite::Connection;

pub fn ensure_schema(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS key_shared (
            recorded_by TEXT NOT NULL,
            event_id TEXT NOT NULL,
            key_event_id TEXT NOT NULL,
            recipient_event_id TEXT NOT NULL,
            wrapped_key BLOB NOT NULL,
            PRIMARY KEY (recorded_by, event_id)
        );
        ",
    )?;
    Ok(())
}

/// Build projector-local context for KeyShared projection.
pub fn build_projector_context(
    conn: &Connection,
    recorded_by: &str,
    _event_id_b64: &str,
    parsed: &ParsedEvent,
) -> Result<ContextSnapshot, Box<dyn std::error::Error>> {
    let ss = match parsed {
        ParsedEvent::KeyShared(ss) => ss,
        _ => return Err("key_shared context loader called for non-key_shared event".into()),
    };

    let recipient_b64 = event_id_to_base64(&ss.recipient_event_id);
    let unwrap_key_b64 = event_id_to_base64(&ss.unwrap_key_event_id);

    let invite_secret_row: Option<Vec<u8>> = conn
        .query_row(
            "SELECT private_key
             FROM invite_secrets
             WHERE recorded_by = ?1
               AND event_id = ?2
               AND invite_event_id = ?3
             LIMIT 1",
            rusqlite::params![recorded_by, &unwrap_key_b64, &recipient_b64],
            |row| row.get(0),
        )
        .ok();

    let private_key_bytes = match invite_secret_row {
        Some(v) => v,
        None => return Ok(ContextSnapshot::default()),
    };
    if private_key_bytes.len() != 32 {
        return Ok(ContextSnapshot::default());
    }

    let mut key_arr = [0u8; 32];
    key_arr.copy_from_slice(&private_key_bytes);
    let local_signing_key = ed25519_dalek::SigningKey::from_bytes(&key_arr);

    let sender_key = match resolve_signer_key(conn, recorded_by, ss.signer_type, &ss.signed_by) {
        Ok(SignerResolution::Found(k)) => k,
        _ => return Ok(ContextSnapshot::default()),
    };
    let sender_pub = match ed25519_dalek::VerifyingKey::from_bytes(&sender_key) {
        Ok(vk) => vk,
        Err(_) => return Ok(ContextSnapshot::default()),
    };

    let plaintext_key = unwrap_key_from_sender(&local_signing_key, &sender_pub, &ss.wrapped_key);

    Ok(ContextSnapshot {
        unwrapped_secret_material: Some(crate::projection::contract::UnwrappedSecretMaterial {
            key_bytes: plaintext_key,
        }),
        ..ContextSnapshot::default()
    })
}

/// Pure projector: KeyShared → key_shared table.
pub fn project_pure(
    recorded_by: &str,
    event_id_b64: &str,
    parsed: &ParsedEvent,
    ctx: &ContextSnapshot,
) -> ProjectorResult {
    let ss = match parsed {
        ParsedEvent::KeyShared(s) => s,
        _ => return ProjectorResult::reject("not a key_shared event".to_string()),
    };

    let key_b64 = event_id_to_base64(&ss.key_event_id);
    let recipient_b64 = event_id_to_base64(&ss.recipient_event_id);

    let ops = vec![WriteOp::InsertOrIgnore {
        table: "key_shared",
        columns: vec![
            "recorded_by",
            "event_id",
            "key_event_id",
            "recipient_event_id",
            "wrapped_key",
        ],
        values: vec![
            SqlVal::Text(recorded_by.to_string()),
            SqlVal::Text(event_id_b64.to_string()),
            SqlVal::Text(key_b64),
            SqlVal::Text(recipient_b64),
            SqlVal::Blob(ss.wrapped_key.to_vec()),
        ],
    }];

    let material = match &ctx.unwrapped_secret_material {
        Some(v) => v,
        None => return ProjectorResult::valid(ops),
    };

    let secret_event =
        crate::event_modules::key_secret::deterministic_key_secret_event(material.key_bytes);
    let secret_blob = match crate::event_modules::encode_event(&secret_event) {
        Ok(v) => v,
        Err(err) => {
            return ProjectorResult::reject(format!(
                "failed to encode deterministic secret event: {}",
                err
            ))
        }
    };
    let derived_key_event_id = crate::crypto::hash_event(&secret_blob);
    if derived_key_event_id != ss.key_event_id {
        return ProjectorResult::reject(
            "unwrapped key material does not match claimed key_event_id".to_string(),
        );
    }

    ProjectorResult::valid_with_commands(
        ops,
        vec![EmitCommand::EmitDeterministicBlob { blob: secret_blob }],
    )
}

pub static KEY_SHARED_META: EventTypeMeta = EventTypeMeta {
    type_code: EVENT_TYPE_KEY_SHARED,
    type_name: "key_shared",
    projection_table: "key_shared",
    share_scope: ShareScope::Shared,
    // `unwrap_key_event_id` points at recipient-local invite_secret material.
    // Non-recipient peers legitimately never have that event, so treating it
    // as a universal hard dependency wedges shared observers on foreign links.
    dep_fields: &["recipient_event_id", "signed_by"],
    dep_field_type_codes: &[&[10, 12], &[]],
    signer_required: true,
    signature_byte_len: 64,
    encryptable: false,
    parse: parse_key_shared,
    encode: encode_key_shared,
    projector: project_pure,
    context_loader: build_projector_context,
};
