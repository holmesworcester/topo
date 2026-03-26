use super::layout::field_spec::{
    decode_fields, encode_fields, wire_size_for_fields, FieldSpec, FieldValue,
};
use super::registry::{EventTypeMeta, ShareScope};
use super::{EventError, ParsedEvent, EVENT_TYPE_TENANT};

pub const TENANT_FIELDS: &[FieldSpec] = &[
    FieldSpec::Timestamp("created_at_ms"),
    FieldSpec::EventId("public_key"),
];

pub const TENANT_WIRE_SIZE: usize = wire_size_for_fields(TENANT_FIELDS);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantEvent {
    pub created_at_ms: u64,
    pub public_key: [u8; 32],
}

impl super::Describe for TenantEvent {
    fn human_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            ("public_key", super::trunc_hex(&self.public_key, 16)),
            (
                "peer_id",
                hex::encode(crate::crypto::spki_fingerprint_from_ed25519_pubkey(
                    &self.public_key,
                )),
            ),
        ]
    }
}

pub fn parse_tenant(blob: &[u8]) -> Result<ParsedEvent, EventError> {
    let values = decode_fields(EVENT_TYPE_TENANT, TENANT_FIELDS, blob)?;

    Ok(ParsedEvent::Tenant(TenantEvent {
        created_at_ms: values[0].as_timestamp().unwrap(),
        public_key: values[1].as_event_id().unwrap(),
    }))
}

pub fn encode_tenant(event: &ParsedEvent) -> Result<Vec<u8>, EventError> {
    let e = match event {
        ParsedEvent::Tenant(v) => v,
        _ => return Err(EventError::WrongVariant),
    };

    let values = vec![
        FieldValue::Timestamp(e.created_at_ms),
        FieldValue::EventId(e.public_key),
    ];

    Ok(encode_fields(EVENT_TYPE_TENANT, TENANT_FIELDS, &values)?)
}

use crate::projection::contract::{ContextSnapshot, ProjectorResult, SqlVal, WriteOp};
use rusqlite::Connection;

pub fn ensure_schema(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS tenants (
            recorded_by TEXT NOT NULL,
            event_id TEXT NOT NULL,
            public_key BLOB NOT NULL,
            peer_id TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            PRIMARY KEY (recorded_by, event_id)
        );
        ",
    )?;
    Ok(())
}

pub fn project_pure(
    recorded_by: &str,
    event_id_b64: &str,
    parsed: &ParsedEvent,
    _ctx: &ContextSnapshot,
) -> ProjectorResult {
    let e = match parsed {
        ParsedEvent::Tenant(v) => v,
        _ => return ProjectorResult::reject("not a tenant event".to_string()),
    };

    let peer_id = hex::encode(crate::crypto::spki_fingerprint_from_ed25519_pubkey(
        &e.public_key,
    ));

    ProjectorResult::valid(vec![WriteOp::InsertOrIgnore {
        table: "tenants",
        columns: vec![
            "recorded_by",
            "event_id",
            "public_key",
            "peer_id",
            "created_at",
        ],
        values: vec![
            SqlVal::Text(recorded_by.to_string()),
            SqlVal::Text(event_id_b64.to_string()),
            SqlVal::Blob(e.public_key.to_vec()),
            SqlVal::Text(peer_id),
            SqlVal::Int(e.created_at_ms as i64),
        ],
    }])
}

pub static TENANT_META: EventTypeMeta = EventTypeMeta {
    type_code: EVENT_TYPE_TENANT,
    type_name: "tenant",
    projection_table: "tenants",
    share_scope: ShareScope::Local,
    dep_fields: &[],
    dep_field_type_codes: &[],
    signer_required: false,
    signature_byte_len: 0,
    encryptable: false,
    parse: parse_tenant,
    encode: encode_tenant,
    projector: project_pure,
    context_loader: crate::event_modules::registry::load_empty_context,
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event_modules::{encode_event, parse_event};

    #[test]
    fn test_roundtrip_tenant() {
        let e = ParsedEvent::Tenant(TenantEvent {
            created_at_ms: 987,
            public_key: [9u8; 32],
        });
        let blob = encode_event(&e).unwrap();
        assert_eq!(blob.len(), TENANT_WIRE_SIZE);
        let parsed = parse_event(&blob).unwrap();
        assert_eq!(parsed, e);
    }
}
