use super::super::layout::field_spec::{
    decode_fields, encode_fields, wire_size_for_fields, FieldSpec, FieldValue,
};
use super::super::registry::{EventTypeMeta, ShareScope};
use super::super::{EventError, ParsedEvent, EVENT_TYPE_ADMIN};

pub const ADMIN_FIELDS: &[FieldSpec] = &[
    FieldSpec::Timestamp("created_at_ms"),
    FieldSpec::EventId("public_key"),
    FieldSpec::EventId("user_event_id"),
    FieldSpec::EventId("signed_by"),
    FieldSpec::U8("signer_type"),
    FieldSpec::FixedBytes("signature", 64),
];

/// Admin (type 18): type(1) + created_at(8) + public_key(32) + user_event_id(32)
/// + signed_by(32) + signer_type(1) + signature(64) = 170
pub const ADMIN_WIRE_SIZE: usize = wire_size_for_fields(ADMIN_FIELDS);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminEvent {
    pub created_at_ms: u64,
    pub public_key: [u8; 32],
    pub user_event_id: [u8; 32],
    pub signed_by: [u8; 32],
    pub signer_type: u8,
    pub signature: [u8; 64],
}

impl super::super::Describe for AdminEvent {
    fn human_fields(&self) -> Vec<(&'static str, String)> {
        vec![("public_key", super::super::trunc_hex(&self.public_key, 16))]
    }
}

pub fn parse_admin(blob: &[u8]) -> Result<ParsedEvent, EventError> {
    let values = decode_fields(EVENT_TYPE_ADMIN, ADMIN_FIELDS, blob)?;

    let signer_type = values[4].as_u8().unwrap();
    if signer_type != 1 {
        return Err(EventError::InvalidMetadata(
            "admin signer_type must be 1 (workspace)",
        ));
    }

    Ok(ParsedEvent::Admin(AdminEvent {
        created_at_ms: values[0].as_timestamp().unwrap(),
        public_key: values[1].as_event_id().unwrap(),
        user_event_id: values[2].as_event_id().unwrap(),
        signed_by: values[3].as_event_id().unwrap(),
        signer_type,
        signature: {
            let bytes = values[5].as_fixed_bytes().unwrap();
            let mut sig = [0u8; 64];
            sig.copy_from_slice(bytes);
            sig
        },
    }))
}

pub fn encode_admin(event: &ParsedEvent) -> Result<Vec<u8>, EventError> {
    let e = match event {
        ParsedEvent::Admin(v) => v,
        _ => return Err(EventError::WrongVariant),
    };

    let values = vec![
        FieldValue::Timestamp(e.created_at_ms),
        FieldValue::EventId(e.public_key),
        FieldValue::EventId(e.user_event_id),
        FieldValue::EventId(e.signed_by),
        FieldValue::U8(e.signer_type),
        FieldValue::FixedBytes(e.signature.to_vec()),
    ];

    Ok(encode_fields(EVENT_TYPE_ADMIN, ADMIN_FIELDS, &values)?)
}

pub static ADMIN_META: EventTypeMeta = crate::event_modules::registry::event_type_meta! {
    type_code: EVENT_TYPE_ADMIN,
    type_name: "admin",
    projection_table: "admins",
    share_scope: ShareScope::Shared,
    dep_fields: &["user_event_id", "signed_by"],
    dep_field_type_codes: &[&[14], &[]],
    signer_required: true,
    signature_byte_len: 64,
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
            user_event_id: [2u8; 32],
            signed_by: [3u8; 32],
            signer_type: 1,
            signature: [0u8; 64],
        });

        let blob = encode_event(&event).unwrap();
        let parsed = parse_event(&blob).unwrap();
        assert_eq!(parsed, event);
    }

    #[test]
    fn parse_admin_rejects_wrong_signer_type() {
        use crate::event_modules::layout::field_spec::field_offset;
        let signer_type_offset = field_offset(ADMIN_FIELDS, 4);
        let mut blob = vec![0u8; ADMIN_WIRE_SIZE];
        blob[0] = EVENT_TYPE_ADMIN;
        blob[signer_type_offset] = 4;

        let err = parse_admin(&blob).expect_err("should reject wrong signer type");
        assert!(matches!(err, EventError::InvalidMetadata(_)));
    }
}
