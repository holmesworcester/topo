use super::super::layout::field_spec::{decode_fields, wire_size_for_fields, FieldSpec};
use super::super::registry::{EventTypeMeta, ShareScope};
use super::super::{EventError, ParsedEvent, EVENT_TYPE_ADMIN};

pub const ADMIN_FIELDS: &[FieldSpec] = &[
    FieldSpec::Timestamp("created_at_ms"),
    FieldSpec::EventId("public_key"),
    FieldSpec::EventId("authority_event_id"),
    FieldSpec::EventId("user_event_id"),
];

/// Admin (type 18): type(1) + created_at(8) + public_key(32)
/// + authority_event_id(32) + user_event_id(32) = 105
pub const ADMIN_WIRE_SIZE: usize = wire_size_for_fields(ADMIN_FIELDS);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminEvent {
    pub created_at_ms: u64,
    pub public_key: [u8; 32],
    pub authority_event_id: [u8; 32],
    pub user_event_id: [u8; 32],
}

impl super::super::Describe for AdminEvent {
    fn human_fields(&self) -> Vec<(&'static str, String)> {
        vec![("public_key", super::super::trunc_hex(&self.public_key, 16))]
    }
}

pub fn parse_admin(blob: &[u8]) -> Result<ParsedEvent, EventError> {
    if let Some((ts, public_key, authority_event_id, user_event_id)) =
        topo_verus_proofs::event_modules::layout::ts_id3::parse_ts_id3(EVENT_TYPE_ADMIN, blob)
    {
        return Ok(ParsedEvent::Admin(AdminEvent {
            created_at_ms: ts,
            public_key,
            authority_event_id,
            user_event_id,
        }));
    }
    let values = decode_fields(EVENT_TYPE_ADMIN, ADMIN_FIELDS, blob)?;
    Ok(ParsedEvent::Admin(AdminEvent {
        created_at_ms: values[0].as_timestamp().unwrap(),
        public_key: values[1].as_event_id().unwrap(),
        authority_event_id: values[2].as_event_id().unwrap(),
        user_event_id: values[3].as_event_id().unwrap(),
    }))
}

pub fn encode_admin(event: &ParsedEvent) -> Result<Vec<u8>, EventError> {
    let e = match event {
        ParsedEvent::Admin(v) => v,
        _ => return Err(EventError::WrongVariant),
    };
    Ok(
        topo_verus_proofs::event_modules::layout::ts_id3::encode_ts_id3(
            EVENT_TYPE_ADMIN,
            e.created_at_ms,
            &e.public_key,
            &e.authority_event_id,
            &e.user_event_id,
        ),
    )
}

pub static ADMIN_META: EventTypeMeta = crate::event_modules::registry::event_type_meta! {
    type_code: EVENT_TYPE_ADMIN,
    type_name: "admin",
    projection_table: "admins",
    share_scope: ShareScope::Shared,
    dep_fields: &["authority_event_id", "user_event_id"],
    dep_field_type_codes: &[&[super::super::EVENT_TYPE_WORKSPACE, EVENT_TYPE_ADMIN], &[14]],
    signer_required: true,
    signature_byte_len: 0,
    encryptable: false,
    parse: parse_admin,
    encode: encode_admin,
    projector: super::projector::project_pure,
    context_loader: super::projector::build_projector_context,
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event_modules::{encode_event, parse_event};

    #[test]
    fn parse_admin_accepts_workspace_signer_type() {
        let event = ParsedEvent::Admin(AdminEvent {
            created_at_ms: 123,
            public_key: [1u8; 32],
            authority_event_id: [2u8; 32],
            user_event_id: [3u8; 32],
        });

        let blob = encode_event(&event).unwrap();
        let parsed = parse_event(&blob).unwrap();
        assert_eq!(parsed, event);
    }

    #[test]
    fn parse_admin_rejects_wrong_type() {
        let mut blob = vec![0u8; ADMIN_WIRE_SIZE];
        blob[0] = 0xFF;
        let err = parse_admin(&blob).expect_err("should reject wrong type");
        assert!(matches!(err, EventError::WrongType { .. }));
    }
}
