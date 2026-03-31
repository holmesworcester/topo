use super::layout::field_spec::{
    decode_fields, encode_fields, wire_size_for_fields, FieldSpec, FieldValue,
};
use super::registry::{EventTypeMeta, ShareScope};
use super::{EventError, ParsedEvent, EVENT_TYPE_ENDPOINT_SECRET};

pub const ENDPOINT_SECRET_FIELDS: &[FieldSpec] = &[
    FieldSpec::Timestamp("created_at_ms"),
    FieldSpec::EventId("private_key_bytes"),
];

pub const ENDPOINT_SECRET_WIRE_SIZE: usize = wire_size_for_fields(ENDPOINT_SECRET_FIELDS);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointSecretEvent {
    pub created_at_ms: u64,
    pub private_key_bytes: [u8; 32],
}

impl super::Describe for EndpointSecretEvent {
    fn human_fields(&self) -> Vec<(&'static str, String)> {
        vec![(
            "endpoint_id",
            endpoint_id_from_private_key_bytes(&self.private_key_bytes),
        )]
    }
}

pub fn endpoint_id_from_private_key_bytes(private_key_bytes: &[u8; 32]) -> String {
    let secret_key = iroh::SecretKey::from_bytes(private_key_bytes);
    hex::encode(secret_key.public().as_bytes())
}

pub fn parse_endpoint_secret(blob: &[u8]) -> Result<ParsedEvent, EventError> {
    let values = decode_fields(EVENT_TYPE_ENDPOINT_SECRET, ENDPOINT_SECRET_FIELDS, blob)?;

    Ok(ParsedEvent::EndpointSecret(EndpointSecretEvent {
        created_at_ms: values[0].as_timestamp().unwrap(),
        private_key_bytes: values[1].as_event_id().unwrap(),
    }))
}

pub fn encode_endpoint_secret(event: &ParsedEvent) -> Result<Vec<u8>, EventError> {
    let e = match event {
        ParsedEvent::EndpointSecret(v) => v,
        _ => return Err(EventError::WrongVariant),
    };

    let values = vec![
        FieldValue::Timestamp(e.created_at_ms),
        FieldValue::EventId(e.private_key_bytes),
    ];

    Ok(encode_fields(
        EVENT_TYPE_ENDPOINT_SECRET,
        ENDPOINT_SECRET_FIELDS,
        &values,
    )?)
}

pub fn deterministic_endpoint_secret_created_at_ms(private_key_bytes: &[u8; 32]) -> u64 {
    use blake2::digest::consts::U8;
    use blake2::{Blake2b, Digest};

    let mut hasher = Blake2b::<U8>::new();
    hasher.update(b"poc7-endpoint-secret-created-at-v1");
    hasher.update(private_key_bytes);
    let digest = hasher.finalize();
    let mut out = [0u8; 8];
    out.copy_from_slice(&digest[..8]);
    u64::from_le_bytes(out)
}

pub fn deterministic_endpoint_secret_event(private_key_bytes: [u8; 32]) -> ParsedEvent {
    ParsedEvent::EndpointSecret(EndpointSecretEvent {
        created_at_ms: deterministic_endpoint_secret_created_at_ms(&private_key_bytes),
        private_key_bytes,
    })
}

pub fn deterministic_endpoint_secret_event_id(private_key_bytes: &[u8; 32]) -> [u8; 32] {
    let event = deterministic_endpoint_secret_event(*private_key_bytes);
    let blob =
        super::encode_event(&event).expect("deterministic endpoint_secret encoding should succeed");
    crate::crypto::hash_event(&blob)
}

use crate::projection::contract::{ContextSnapshot, ProjectorResult, SqlVal, WriteOp};
use rusqlite::{Connection, OptionalExtension};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointSecretRow {
    pub endpoint_id: String,
    pub event_id: String,
    pub private_key_bytes: [u8; 32],
    pub created_at_ms: u64,
}

pub fn ensure_schema(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS endpoint_secrets (
            recorded_by TEXT NOT NULL,
            event_id TEXT NOT NULL,
            endpoint_id TEXT NOT NULL,
            private_key BLOB NOT NULL,
            created_at INTEGER NOT NULL,
            PRIMARY KEY (recorded_by, event_id)
        );
        CREATE UNIQUE INDEX IF NOT EXISTS idx_endpoint_secrets_endpoint_id
            ON endpoint_secrets(endpoint_id);
        ",
    )?;
    Ok(())
}

pub fn load_local_endpoint_secret(
    conn: &Connection,
) -> Result<Option<EndpointSecretRow>, Box<dyn std::error::Error + Send + Sync>> {
    let rows = {
        let mut stmt = conn.prepare(
            "SELECT endpoint_id, event_id, private_key, created_at
             FROM endpoint_secrets
             ORDER BY created_at ASC, event_id ASC
             LIMIT 2",
        )?;
        let mapped = stmt.query_map([], |row| {
            let private_key: Vec<u8> = row.get(2)?;
            let private_key_bytes: [u8; 32] = private_key.as_slice().try_into().map_err(|_| {
                rusqlite::Error::FromSqlConversionFailure(
                    2,
                    rusqlite::types::Type::Blob,
                    Box::new(std::io::Error::other(
                        "endpoint_secret private_key must be 32 bytes",
                    )),
                )
            })?;
            Ok(EndpointSecretRow {
                endpoint_id: row.get(0)?,
                event_id: row.get(1)?,
                private_key_bytes,
                created_at_ms: row.get::<_, i64>(3)? as u64,
            })
        })?;
        mapped.collect::<Result<Vec<_>, _>>()?
    };

    match rows.as_slice() {
        [] => Ok(None),
        [row] => Ok(Some(row.clone())),
        [first, second] if first.endpoint_id == second.endpoint_id => Ok(Some(first.clone())),
        _ => Err("multiple endpoint_secret roots found in database".into()),
    }
}

pub fn load_endpoint_secret_event_id_for_scope(
    conn: &Connection,
    endpoint_id: &str,
) -> rusqlite::Result<Option<String>> {
    conn.query_row(
        "SELECT event_id
         FROM endpoint_secrets
         WHERE endpoint_id = ?1
         LIMIT 1",
        rusqlite::params![endpoint_id],
        |row| row.get(0),
    )
    .optional()
}

pub fn project_pure(
    recorded_by: &str,
    event_id_b64: &str,
    parsed: &ParsedEvent,
    _ctx: &ContextSnapshot,
) -> ProjectorResult {
    let e = match parsed {
        ParsedEvent::EndpointSecret(v) => v,
        _ => return ProjectorResult::reject("not an endpoint_secret event".to_string()),
    };

    let endpoint_id = endpoint_id_from_private_key_bytes(&e.private_key_bytes);
    if recorded_by != endpoint_id {
        return ProjectorResult::reject(format!(
            "endpoint_secret recorded_by must equal endpoint_id {}",
            endpoint_id
        ));
    }

    ProjectorResult::valid(vec![WriteOp::InsertOrIgnore {
        table: "endpoint_secrets",
        columns: vec![
            "recorded_by",
            "event_id",
            "endpoint_id",
            "private_key",
            "created_at",
        ],
        values: vec![
            SqlVal::Text(recorded_by.to_string()),
            SqlVal::Text(event_id_b64.to_string()),
            SqlVal::Text(endpoint_id),
            SqlVal::Blob(e.private_key_bytes.to_vec()),
            SqlVal::Int(e.created_at_ms as i64),
        ],
    }])
}

pub static ENDPOINT_SECRET_META: EventTypeMeta = crate::event_modules::registry::event_type_meta! {
    type_code: EVENT_TYPE_ENDPOINT_SECRET,
    type_name: "endpoint_secret",
    projection_table: "endpoint_secrets",
    share_scope: ShareScope::Local,
    dep_fields: &[],
    dep_field_type_codes: &[],
    signer_required: false,
    signature_byte_len: 0,
    encryptable: false,
    parse: parse_endpoint_secret,
    encode: encode_endpoint_secret,
    projector: project_pure,
    context_loader: crate::event_modules::registry::load_empty_context,
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{open_in_memory, schema::create_tables};
    use crate::event_modules::{encode_event, parse_event};

    #[test]
    fn test_roundtrip_endpoint_secret() {
        let e = ParsedEvent::EndpointSecret(EndpointSecretEvent {
            created_at_ms: 12345,
            private_key_bytes: [7u8; 32],
        });
        let blob = encode_event(&e).unwrap();
        assert_eq!(blob.len(), ENDPOINT_SECRET_WIRE_SIZE);
        let parsed = parse_event(&blob).unwrap();
        assert_eq!(parsed, e);
    }

    #[test]
    fn test_deterministic_endpoint_secret_event_id_stable() {
        let key = [11u8; 32];
        let a = deterministic_endpoint_secret_event_id(&key);
        let b = deterministic_endpoint_secret_event_id(&key);
        assert_eq!(a, b);
    }

    #[test]
    fn load_local_endpoint_secret_rejects_multiple_roots() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();

        conn.execute(
            "INSERT INTO endpoint_secrets
             (recorded_by, event_id, endpoint_id, private_key, created_at)
             VALUES (?1, ?2, ?1, ?3, 1)",
            rusqlite::params!["endpoint-a", "event-a", vec![1u8; 32]],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO endpoint_secrets
             (recorded_by, event_id, endpoint_id, private_key, created_at)
             VALUES (?1, ?2, ?1, ?3, 2)",
            rusqlite::params!["endpoint-b", "event-b", vec![2u8; 32]],
        )
        .unwrap();

        let err = load_local_endpoint_secret(&conn).unwrap_err().to_string();
        assert!(err.contains("multiple endpoint_secret roots"), "err={err}");
    }
}
