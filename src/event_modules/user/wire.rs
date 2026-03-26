use super::super::layout::common::NAME_BYTES;
use super::super::layout::field_spec::{decode_fields, encode_fields, wire_size_for_fields, FieldSpec, FieldValue};
use super::super::registry::{EventTypeMeta, ShareScope};
use super::super::{EventError, ParsedEvent, EVENT_TYPE_USER};

/// User (type 14):
/// type(1) + created_at(8) + public_key(32) + username(64)
/// + signed_by(32) + signer_type(1) + signature(64) = 202
pub const USER_FIELDS: &[FieldSpec] = &[
    FieldSpec::Timestamp("created_at_ms"),
    FieldSpec::FixedBytes("public_key", 32),
    FieldSpec::Text("username", NAME_BYTES),
    FieldSpec::EventId("signed_by"),
    FieldSpec::U8("signer_type"),
    FieldSpec::FixedBytes("signature", 64),
];
pub const USER_WIRE_SIZE: usize = wire_size_for_fields(USER_FIELDS);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserEvent {
    pub created_at_ms: u64,
    pub public_key: [u8; 32],
    pub username: String,
    pub signed_by: [u8; 32],
    pub signer_type: u8,
    pub signature: [u8; 64],
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
    let values = decode_fields(EVENT_TYPE_USER, USER_FIELDS, blob)?;
    let created_at_ms = values[0].as_timestamp().unwrap();
    let mut public_key = [0u8; 32];
    public_key.copy_from_slice(values[1].as_fixed_bytes().unwrap());
    let username = values[2].as_text().unwrap().to_string();
    let signed_by = values[3].as_event_id().unwrap();
    let signer_type = values[4].as_u8().unwrap();
    if signer_type != 2 {
        return Err(EventError::InvalidMetadata(
            "user signer_type must be 2 (user_invite_shared)",
        ));
    }
    let mut signature = [0u8; 64];
    signature.copy_from_slice(values[5].as_fixed_bytes().unwrap());

    Ok(ParsedEvent::User(UserEvent {
        created_at_ms,
        public_key,
        username,
        signed_by,
        signer_type,
        signature,
    }))
}

pub fn encode_user(event: &ParsedEvent) -> Result<Vec<u8>, EventError> {
    let e = match event {
        ParsedEvent::User(v) => v,
        _ => return Err(EventError::WrongVariant),
    };

    let values = vec![
        FieldValue::Timestamp(e.created_at_ms),
        FieldValue::FixedBytes(e.public_key.to_vec()),
        FieldValue::Text(e.username.clone()),
        FieldValue::EventId(e.signed_by),
        FieldValue::U8(e.signer_type),
        FieldValue::FixedBytes(e.signature.to_vec()),
    ];
    Ok(encode_fields(EVENT_TYPE_USER, USER_FIELDS, &values)?)
}

pub static USER_META: EventTypeMeta = EventTypeMeta {
    type_code: EVENT_TYPE_USER,
    type_name: "user",
    projection_table: "users",
    share_scope: ShareScope::Shared,
    dep_fields: &["signed_by"],
    dep_field_type_codes: &[&[]],
    signer_required: true,
    signature_byte_len: 64,
    encryptable: false,
    parse: parse_user,
    encode: encode_user,
    projector: super::projector::project_pure,
    context_loader: crate::event_modules::registry::load_empty_context,
};

#[cfg(test)]
mod layout_tests {
    use super::*;
    use crate::event_modules::{encode_event, parse_event};

    #[test]
    fn wire_size_consistent() {
        assert_eq!(USER_WIRE_SIZE, 202);
    }

    #[test]
    fn parse_user_accepts_user_invite_signer_type() {
        let event = ParsedEvent::User(UserEvent {
            created_at_ms: 123,
            public_key: [1u8; 32],
            username: "alice".to_string(),
            signed_by: [2u8; 32],
            signer_type: 2,
            signature: [0u8; 64],
        });

        let blob = encode_event(&event).unwrap();
        let parsed = parse_event(&blob).unwrap();
        assert_eq!(parsed, event);
    }

    #[test]
    fn parse_user_rejects_wrong_signer_type() {
        use crate::event_modules::layout::field_spec::field_offset;
        let signer_type_offset = field_offset(USER_FIELDS, 4);
        let mut blob = vec![0u8; USER_WIRE_SIZE];
        blob[0] = EVENT_TYPE_USER;
        blob[signer_type_offset] = 1;

        let err = parse_user(&blob).expect_err("should reject wrong signer type");
        assert!(matches!(err, EventError::InvalidMetadata(_)));
    }
}
