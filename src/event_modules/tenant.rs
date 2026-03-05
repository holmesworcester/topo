use super::layout::common::COMMON_HEADER_BYTES;
use super::registry::{EventTypeMeta, ShareScope};
use super::{EventError, ParsedEvent, EVENT_TYPE_TENANT};

pub const TENANT_WIRE_SIZE: usize = COMMON_HEADER_BYTES + 32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantEvent {
    pub created_at_ms: u64,
    pub peer_event_id: [u8; 32],
}

impl super::Describe for TenantEvent {
    fn human_fields(&self) -> Vec<(&'static str, String)> {
        vec![("peer_event_id", super::short_id_b64(&self.peer_event_id))]
    }
}

pub fn parse_tenant(blob: &[u8]) -> Result<ParsedEvent, EventError> {
    if blob.len() < TENANT_WIRE_SIZE {
        return Err(EventError::TooShort {
            expected: TENANT_WIRE_SIZE,
            actual: blob.len(),
        });
    }
    if blob.len() > TENANT_WIRE_SIZE {
        return Err(EventError::TrailingData {
            expected: TENANT_WIRE_SIZE,
            actual: blob.len(),
        });
    }
    if blob[0] != EVENT_TYPE_TENANT {
        return Err(EventError::WrongType {
            expected: EVENT_TYPE_TENANT,
            actual: blob[0],
        });
    }

    let created_at_ms = u64::from_le_bytes(blob[1..9].try_into().unwrap());
    let mut peer_event_id = [0u8; 32];
    peer_event_id.copy_from_slice(&blob[9..41]);

    Ok(ParsedEvent::Tenant(TenantEvent {
        created_at_ms,
        peer_event_id,
    }))
}

pub fn encode_tenant(event: &ParsedEvent) -> Result<Vec<u8>, EventError> {
    let e = match event {
        ParsedEvent::Tenant(v) => v,
        _ => return Err(EventError::WrongVariant),
    };

    let mut buf = Vec::with_capacity(TENANT_WIRE_SIZE);
    buf.push(EVENT_TYPE_TENANT);
    buf.extend_from_slice(&e.created_at_ms.to_le_bytes());
    buf.extend_from_slice(&e.peer_event_id);
    Ok(buf)
}

use crate::crypto::event_id_to_base64;
use crate::projection::contract::{ContextSnapshot, ProjectorResult, SqlVal, WriteOp};
use rusqlite::Connection;

pub fn ensure_schema(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS tenants (
            recorded_by TEXT NOT NULL,
            event_id TEXT NOT NULL,
            peer_event_id TEXT NOT NULL,
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

    ProjectorResult::valid(vec![WriteOp::InsertOrIgnore {
        table: "tenants",
        columns: vec!["recorded_by", "event_id", "peer_event_id", "created_at"],
        values: vec![
            SqlVal::Text(recorded_by.to_string()),
            SqlVal::Text(event_id_b64.to_string()),
            SqlVal::Text(event_id_to_base64(&e.peer_event_id)),
            SqlVal::Int(e.created_at_ms as i64),
        ],
    }])
}

pub static TENANT_META: EventTypeMeta = EventTypeMeta {
    type_code: EVENT_TYPE_TENANT,
    type_name: "tenant",
    projection_table: "tenants",
    share_scope: ShareScope::Local,
    dep_fields: &["peer_event_id"],
    dep_field_type_codes: &[&[super::EVENT_TYPE_PEER]],
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
            peer_event_id: [9u8; 32],
        });
        let blob = encode_event(&e).unwrap();
        assert_eq!(blob.len(), TENANT_WIRE_SIZE);
        let parsed = parse_event(&blob).unwrap();
        assert_eq!(parsed, e);
    }
}
