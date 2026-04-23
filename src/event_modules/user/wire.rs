use super::super::layout::common::NAME_BYTES;
use super::super::layout::field_spec::{
    decode_fields, encode_fields, wire_size_for_fields, FieldSpec, FieldValue,
};
use super::super::registry::{EventTypeMeta, ShareScope};
use super::super::{EventError, ParsedEvent, EVENT_TYPE_USER};

pub const USER_FIELDS: &[FieldSpec] = &[
    FieldSpec::Timestamp("created_at_ms"),
    FieldSpec::EventId("public_key"),
    FieldSpec::Text("username", NAME_BYTES),
];

/// User (type 14):
/// type(1) + created_at(8) + public_key(32) + username(64)
/// = 105
pub const USER_WIRE_SIZE: usize = wire_size_for_fields(USER_FIELDS);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserEvent {
    pub created_at_ms: u64,
    pub public_key: [u8; 32],
    pub username: String,
}

impl super::super::Describe for UserEvent {
    fn human_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            ("username", self.username.clone()),
            ("public_key", super::super::trunc_hex(&self.public_key, 16)),
        ]
    }
}

pub fn parse_user(blob: &[u8]) -> Result<ParsedEvent, EventError> {
    if let Some((ts, public_key, name_slot)) =
        topo_verus_proofs::event_modules::layout::shapes::parse_ts_id_fb64(EVENT_TYPE_USER, blob)
    {
        let username = crate::event_modules::layout::common::read_text_slot(&name_slot)
            .map_err(EventError::TextSlot)?;
        return Ok(ParsedEvent::User(UserEvent {
            created_at_ms: ts,
            public_key,
            username,
        }));
    }
    let values = decode_fields(EVENT_TYPE_USER, USER_FIELDS, blob)?;
    Ok(ParsedEvent::User(UserEvent {
        created_at_ms: values[0].as_timestamp().unwrap(),
        public_key: values[1].as_event_id().unwrap(),
        username: values[2].as_text().unwrap().to_string(),
    }))
}

pub fn encode_user(event: &ParsedEvent) -> Result<Vec<u8>, EventError> {
    let e = match event {
        ParsedEvent::User(v) => v,
        _ => return Err(EventError::WrongVariant),
    };
    let mut name_slot: [u8; NAME_BYTES] = [0u8; NAME_BYTES];
    crate::event_modules::layout::common::write_text_slot(&e.username, &mut name_slot)
        .map_err(EventError::TextSlot)?;
    Ok(
        topo_verus_proofs::event_modules::layout::shapes::encode_ts_id_fb64(
            EVENT_TYPE_USER,
            e.created_at_ms,
            &e.public_key,
            &name_slot,
        ),
    )
}

pub static USER_META: EventTypeMeta = crate::event_modules::registry::event_type_meta! {
    type_code: EVENT_TYPE_USER,
    type_name: "user",
    projection_table: "users",
    share_scope: ShareScope::Shared,
    dep_fields: &[],
    dep_field_type_codes: &[],
    signer_required: true,
    signature_byte_len: 0,
    encryptable: false,
    parse: parse_user,
    encode: encode_user,
    projector: super::projector::project_pure,
    context_loader: super::projector::build_projector_context,
};

#[cfg(test)]
mod layout_tests {
    use super::*;
    use crate::event_modules::layout::field_spec::field_offset;
    use crate::event_modules::{encode_event, parse_event};

    #[test]
    fn offsets_consistent() {
        assert_eq!(field_offset(USER_FIELDS, 2) + 64, USER_WIRE_SIZE);
    }

    #[test]
    fn parse_user_accepts_user_invite_signer_type() {
        let event = ParsedEvent::User(UserEvent {
            created_at_ms: 123,
            public_key: [1u8; 32],
            username: "alice".to_string(),
        });

        let blob = encode_event(&event).unwrap();
        let parsed = parse_event(&blob).unwrap();
        assert_eq!(parsed, event);
    }

    #[test]
    fn parse_user_rejects_wrong_type() {
        let mut blob = vec![0u8; USER_WIRE_SIZE];
        blob[0] = 0xFF;
        let err = parse_user(&blob).expect_err("should reject wrong type");
        assert!(matches!(err, EventError::WrongType { .. }));
    }
}
