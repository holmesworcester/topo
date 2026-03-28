use super::super::layout::field_spec::{
    decode_fields, encode_fields, wire_size_for_fields, FieldSpec, FieldValue,
};
use super::super::registry::{EventTypeMeta, ShareScope};
use super::super::{EventError, ParsedEvent, EVENT_TYPE_USER_INVITE};

pub const USER_INVITE_FIELDS: &[FieldSpec] = &[
    FieldSpec::Timestamp("created_at_ms"),
    FieldSpec::EventId("public_key"),
    FieldSpec::EventId("workspace_id"),
    FieldSpec::EventId("authority_event_id"),
    FieldSpec::EventId("signed_by"),
    FieldSpec::U8("signer_type"),
    FieldSpec::FixedBytes("signature", 64),
];

/// UserInvite (type 10): type(1) + created_at(8) + public_key(32) + workspace_id(32)
/// + authority_event_id(32) + signed_by(32) + signer_type(1) + signature(64) = 202
pub const USER_INVITE_WIRE_SIZE: usize = wire_size_for_fields(USER_INVITE_FIELDS);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserInviteEvent {
    pub created_at_ms: u64,
    pub public_key: [u8; 32],
    pub workspace_id: [u8; 32],
    pub authority_event_id: [u8; 32], // workspace (bootstrap) or admin (ongoing)
    pub signed_by: [u8; 32],
    pub signer_type: u8,
    pub signature: [u8; 64],
}

impl super::super::Describe for UserInviteEvent {
    fn human_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            ("public_key", super::super::trunc_hex(&self.public_key, 16)),
            (
                "workspace_id",
                super::super::short_id_b64(&self.workspace_id),
            ),
        ]
    }
}

pub fn parse_user_invite(blob: &[u8]) -> Result<ParsedEvent, EventError> {
    let values = decode_fields(EVENT_TYPE_USER_INVITE, USER_INVITE_FIELDS, blob)?;

    let signer_type = values[5].as_u8().unwrap();
    if signer_type != 1 && signer_type != 5 {
        return Err(EventError::InvalidMetadata(
            "user_invite signer_type must be 1 (workspace) or 5 (peer_shared)",
        ));
    }

    Ok(ParsedEvent::UserInvite(UserInviteEvent {
        created_at_ms: values[0].as_timestamp().unwrap(),
        public_key: values[1].as_event_id().unwrap(),
        workspace_id: values[2].as_event_id().unwrap(),
        authority_event_id: values[3].as_event_id().unwrap(),
        signed_by: values[4].as_event_id().unwrap(),
        signer_type,
        signature: {
            let bytes = values[6].as_fixed_bytes().unwrap();
            let mut sig = [0u8; 64];
            sig.copy_from_slice(bytes);
            sig
        },
    }))
}

pub fn encode_user_invite(event: &ParsedEvent) -> Result<Vec<u8>, EventError> {
    let e = match event {
        ParsedEvent::UserInvite(v) => v,
        _ => return Err(EventError::WrongVariant),
    };

    let values = vec![
        FieldValue::Timestamp(e.created_at_ms),
        FieldValue::EventId(e.public_key),
        FieldValue::EventId(e.workspace_id),
        FieldValue::EventId(e.authority_event_id),
        FieldValue::EventId(e.signed_by),
        FieldValue::U8(e.signer_type),
        FieldValue::FixedBytes(e.signature.to_vec()),
    ];

    Ok(encode_fields(
        EVENT_TYPE_USER_INVITE,
        USER_INVITE_FIELDS,
        &values,
    )?)
}

pub static USER_INVITE_META: EventTypeMeta = EventTypeMeta {
    type_code: EVENT_TYPE_USER_INVITE,
    type_name: "user_invite_shared",
    projection_table: "user_invites",
    share_scope: ShareScope::Shared,
    dep_fields: &["authority_event_id", "signed_by"],
    dep_field_type_codes: &[&[8, 18], &[8, 16]],
    signer_required: true,
    signature_byte_len: 64,
    encryptable: false,
    parse: parse_user_invite,
    encode: encode_user_invite,
    projector: super::projector::project_pure,
    context_loader: super::projector::build_projector_context,
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event_modules::layout::field_spec::field_offset;

    #[test]
    fn parse_user_invite_accepts_workspace_signer_type() {
        let st_off = field_offset(USER_INVITE_FIELDS, 5);
        let mut blob = vec![0u8; USER_INVITE_WIRE_SIZE];
        blob[0] = EVENT_TYPE_USER_INVITE;
        blob[st_off] = 1;

        assert!(matches!(
            parse_user_invite(&blob),
            Ok(ParsedEvent::UserInvite(_))
        ));
    }

    #[test]
    fn parse_user_invite_accepts_peer_shared_signer_type() {
        let st_off = field_offset(USER_INVITE_FIELDS, 5);
        let mut blob = vec![0u8; USER_INVITE_WIRE_SIZE];
        blob[0] = EVENT_TYPE_USER_INVITE;
        blob[st_off] = 5;

        assert!(matches!(
            parse_user_invite(&blob),
            Ok(ParsedEvent::UserInvite(_))
        ));
    }

    #[test]
    fn parse_user_invite_rejects_wrong_signer_type() {
        let st_off = field_offset(USER_INVITE_FIELDS, 5);
        let mut blob = vec![0u8; USER_INVITE_WIRE_SIZE];
        blob[0] = EVENT_TYPE_USER_INVITE;
        blob[st_off] = 4;

        let err = parse_user_invite(&blob).expect_err("should reject wrong signer type");
        assert!(matches!(err, EventError::InvalidMetadata(_)));
    }
}
