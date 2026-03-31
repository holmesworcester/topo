use super::layout::field_spec::{
    decode_fields, encode_fields, wire_size_for_fields, FieldSpec, FieldValue,
};
use super::registry::{EventTypeMeta, ShareScope};
use super::{EventError, ParsedEvent, EVENT_TYPE_ENDPOINT_SHARED};
use crate::projection::contract::{ContextSnapshot, ProjectorResult, SqlVal, WriteOp};
use rusqlite::{Connection, OptionalExtension};

pub const ENDPOINT_SHARED_FIELDS: &[FieldSpec] = &[
    FieldSpec::Timestamp("created_at_ms"),
    FieldSpec::EventId("public_key"),
    FieldSpec::FixedBytes("signature", 64),
];

pub const ENDPOINT_SHARED_WIRE_SIZE: usize = wire_size_for_fields(ENDPOINT_SHARED_FIELDS);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointSharedEvent {
    pub created_at_ms: u64,
    pub public_key: [u8; 32],
    pub signature: [u8; 64],
}

impl super::Describe for EndpointSharedEvent {
    fn human_fields(&self) -> Vec<(&'static str, String)> {
        vec![(
            "endpoint_id",
            endpoint_id_from_public_key_bytes(&self.public_key),
        )]
    }
}

pub fn endpoint_id_from_public_key_bytes(public_key: &[u8; 32]) -> String {
    hex::encode(public_key)
}

pub fn deterministic_endpoint_shared_created_at_ms(public_key: &[u8; 32]) -> u64 {
    use blake2::digest::consts::U8;
    use blake2::{Blake2b, Digest};

    let mut hasher = Blake2b::<U8>::new();
    hasher.update(b"poc7-endpoint-shared-created-at-v1");
    hasher.update(public_key);
    let digest = hasher.finalize();
    let mut out = [0u8; 8];
    out.copy_from_slice(&digest[..8]);
    u64::from_le_bytes(out)
}

pub fn endpoint_shared_signing_bytes(
    created_at_ms: u64,
    public_key: [u8; 32],
) -> Result<Vec<u8>, EventError> {
    let values = vec![
        FieldValue::Timestamp(created_at_ms),
        FieldValue::EventId(public_key),
        FieldValue::FixedBytes(vec![0u8; 64]),
    ];
    let blob = encode_fields(EVENT_TYPE_ENDPOINT_SHARED, ENDPOINT_SHARED_FIELDS, &values)?;
    Ok(blob[..blob.len() - 64].to_vec())
}

pub fn deterministic_endpoint_shared_event(private_key_bytes: [u8; 32]) -> ParsedEvent {
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&private_key_bytes);
    let public_key = signing_key.verifying_key().to_bytes();
    let created_at_ms = deterministic_endpoint_shared_created_at_ms(&public_key);
    let signing_bytes =
        endpoint_shared_signing_bytes(created_at_ms, public_key).expect("signing bytes");
    let signature = crate::crypto::sign_event_bytes(&signing_key, &signing_bytes);
    ParsedEvent::EndpointShared(EndpointSharedEvent {
        created_at_ms,
        public_key,
        signature,
    })
}

pub fn parse_endpoint_shared(blob: &[u8]) -> Result<ParsedEvent, EventError> {
    let values = decode_fields(EVENT_TYPE_ENDPOINT_SHARED, ENDPOINT_SHARED_FIELDS, blob)?;
    let signature = {
        let bytes = values[2].as_fixed_bytes().unwrap();
        let mut sig = [0u8; 64];
        sig.copy_from_slice(bytes);
        sig
    };
    Ok(ParsedEvent::EndpointShared(EndpointSharedEvent {
        created_at_ms: values[0].as_timestamp().unwrap(),
        public_key: values[1].as_event_id().unwrap(),
        signature,
    }))
}

pub fn encode_endpoint_shared(event: &ParsedEvent) -> Result<Vec<u8>, EventError> {
    let e = match event {
        ParsedEvent::EndpointShared(v) => v,
        _ => return Err(EventError::WrongVariant),
    };

    let values = vec![
        FieldValue::Timestamp(e.created_at_ms),
        FieldValue::EventId(e.public_key),
        FieldValue::FixedBytes(e.signature.to_vec()),
    ];
    Ok(encode_fields(
        EVENT_TYPE_ENDPOINT_SHARED,
        ENDPOINT_SHARED_FIELDS,
        &values,
    )?)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointSharedRow {
    pub endpoint_id: String,
    pub event_id: String,
    pub public_key: [u8; 32],
    pub created_at_ms: u64,
}

pub fn ensure_schema(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS endpoints_shared (
            recorded_by TEXT NOT NULL,
            event_id TEXT NOT NULL,
            endpoint_id TEXT NOT NULL,
            public_key BLOB NOT NULL,
            created_at INTEGER NOT NULL,
            PRIMARY KEY (recorded_by, event_id)
        );
        CREATE UNIQUE INDEX IF NOT EXISTS idx_endpoints_shared_endpoint_id
            ON endpoints_shared(endpoint_id);
        ",
    )?;
    Ok(())
}

pub fn load_local_endpoint_shared(
    conn: &Connection,
) -> Result<Option<EndpointSharedRow>, Box<dyn std::error::Error + Send + Sync>> {
    let rows = {
        let mut stmt = conn.prepare(
            "SELECT es.endpoint_id, es.event_id, es.public_key, es.created_at
             FROM endpoints_shared es
             JOIN endpoint_secrets sec
               ON sec.endpoint_id = es.endpoint_id
             ORDER BY es.created_at ASC, es.event_id ASC
             LIMIT 2",
        )?;
        let mapped = stmt.query_map([], |row| {
            let public_key: Vec<u8> = row.get(2)?;
            let public_key: [u8; 32] = public_key.as_slice().try_into().map_err(|_| {
                rusqlite::Error::FromSqlConversionFailure(
                    2,
                    rusqlite::types::Type::Blob,
                    Box::new(std::io::Error::other(
                        "endpoint_shared public_key must be 32 bytes",
                    )),
                )
            })?;
            Ok(EndpointSharedRow {
                endpoint_id: row.get(0)?,
                event_id: row.get(1)?,
                public_key,
                created_at_ms: row.get::<_, i64>(3)? as u64,
            })
        })?;
        mapped.collect::<Result<Vec<_>, _>>()?
    };

    match rows.as_slice() {
        [] => Ok(None),
        [row] => Ok(Some(row.clone())),
        [first, second] if first.endpoint_id == second.endpoint_id => Ok(Some(first.clone())),
        _ => Err("multiple endpoint_shared roots found in database".into()),
    }
}

pub fn load_endpoint_shared_event_id_for_scope(
    conn: &Connection,
    endpoint_id: &str,
) -> rusqlite::Result<Option<String>> {
    conn.query_row(
        "SELECT event_id
         FROM endpoints_shared
         WHERE endpoint_id = ?1
         LIMIT 1",
        rusqlite::params![endpoint_id],
        |row| row.get(0),
    )
    .optional()
}

pub fn load_endpoint_shared_by_event_id(
    conn: &Connection,
    event_id: &str,
) -> Result<Option<EndpointSharedRow>, Box<dyn std::error::Error + Send + Sync>> {
    Ok(conn
        .query_row(
            "SELECT endpoint_id, event_id, public_key, created_at
             FROM endpoints_shared
             WHERE event_id = ?1
             LIMIT 1",
            rusqlite::params![event_id],
            |row| {
                let public_key: Vec<u8> = row.get(2)?;
                let public_key: [u8; 32] = public_key.as_slice().try_into().map_err(|_| {
                    rusqlite::Error::FromSqlConversionFailure(
                        2,
                        rusqlite::types::Type::Blob,
                        Box::new(std::io::Error::other(
                            "endpoint_shared public_key must be 32 bytes",
                        )),
                    )
                })?;
                Ok(EndpointSharedRow {
                    endpoint_id: row.get(0)?,
                    event_id: row.get(1)?,
                    public_key,
                    created_at_ms: row.get::<_, i64>(3)? as u64,
                })
            },
        )
        .optional()?)
}

fn endpoint_shared_signature_valid(event: &EndpointSharedEvent) -> bool {
    let Ok(signing_bytes) = endpoint_shared_signing_bytes(event.created_at_ms, event.public_key)
    else {
        return false;
    };
    crate::projection::signer::verify_ed25519_signature(
        &event.public_key,
        &signing_bytes,
        &event.signature,
    )
}

pub fn project_pure(
    recorded_by: &str,
    event_id_b64: &str,
    parsed: &ParsedEvent,
    _ctx: &ContextSnapshot,
) -> ProjectorResult {
    let event = match parsed {
        ParsedEvent::EndpointShared(v) => v,
        _ => return ProjectorResult::reject("not an endpoint_shared event".to_string()),
    };

    let endpoint_id = endpoint_id_from_public_key_bytes(&event.public_key);
    if recorded_by != endpoint_id {
        return ProjectorResult::reject(format!(
            "endpoint_shared recorded_by must equal endpoint_id {}",
            endpoint_id
        ));
    }
    if !endpoint_shared_signature_valid(event) {
        return ProjectorResult::reject(
            "endpoint_shared self-signature verification failed".into(),
        );
    }

    ProjectorResult::valid(vec![WriteOp::InsertOrIgnore {
        table: "endpoints_shared",
        columns: vec![
            "recorded_by",
            "event_id",
            "endpoint_id",
            "public_key",
            "created_at",
        ],
        values: vec![
            SqlVal::Text(recorded_by.to_string()),
            SqlVal::Text(event_id_b64.to_string()),
            SqlVal::Text(endpoint_id),
            SqlVal::Blob(event.public_key.to_vec()),
            SqlVal::Int(event.created_at_ms as i64),
        ],
    }])
}

pub static ENDPOINT_SHARED_META: EventTypeMeta = crate::event_modules::registry::event_type_meta! {
    type_code: EVENT_TYPE_ENDPOINT_SHARED,
    type_name: "endpoint_shared",
    projection_table: "endpoints_shared",
    share_scope: ShareScope::Shared,
    dep_fields: &[],
    dep_field_type_codes: &[],
    signer_required: false,
    signature_byte_len: 0,
    encryptable: false,
    parse: parse_endpoint_shared,
    encode: encode_endpoint_shared,
    projector: project_pure,
    context_loader: crate::event_modules::registry::load_empty_context,
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event_modules::{encode_event, parse_event};
    use crate::projection::create::create_event_synchronous;

    #[test]
    fn test_roundtrip_endpoint_shared() {
        let event = deterministic_endpoint_shared_event([0x44u8; 32]);
        let blob = encode_event(&event).unwrap();
        let parsed = parse_event(&blob).unwrap();
        assert_eq!(parsed, event);
    }

    #[test]
    fn test_deterministic_endpoint_shared_event_id_stable() {
        let key = [0x55u8; 32];
        let a = crate::crypto::hash_event(
            &encode_event(&deterministic_endpoint_shared_event(key)).unwrap(),
        );
        let b = crate::crypto::hash_event(
            &encode_event(&deterministic_endpoint_shared_event(key)).unwrap(),
        );
        assert_eq!(a, b);
    }

    #[test]
    fn test_load_local_endpoint_shared_ignores_remote_endpoint_rows() {
        let conn = crate::db::open_in_memory().unwrap();
        crate::db::schema::create_tables(&conn).unwrap();

        let local_secret =
            crate::event_modules::endpoint_secret::deterministic_endpoint_secret_event([0x61; 32]);
        let local_endpoint_id =
            crate::event_modules::endpoint_secret::endpoint_id_from_private_key_bytes(&[0x61; 32]);
        create_event_synchronous(&conn, &local_endpoint_id, &local_secret).unwrap();
        create_event_synchronous(
            &conn,
            &local_endpoint_id,
            &deterministic_endpoint_shared_event([0x61; 32]),
        )
        .unwrap();

        let remote_endpoint_id =
            crate::event_modules::endpoint_secret::endpoint_id_from_private_key_bytes(&[0x62; 32]);
        create_event_synchronous(
            &conn,
            &remote_endpoint_id,
            &deterministic_endpoint_shared_event([0x62; 32]),
        )
        .unwrap();

        let local = load_local_endpoint_shared(&conn)
            .unwrap()
            .expect("local endpoint_shared row");
        assert_eq!(local.endpoint_id, local_endpoint_id);
    }
}
