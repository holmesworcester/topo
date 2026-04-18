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
    FieldSpec::EventId("key_history_event_id"),
];

/// UserInvite (type 10): type(1) + created_at(8) + public_key(32) + workspace_id(32)
/// + authority_event_id(32) + key_history_event_id(32) = 137
pub const USER_INVITE_WIRE_SIZE: usize = wire_size_for_fields(USER_INVITE_FIELDS);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserInviteEvent {
    pub created_at_ms: u64,
    pub public_key: [u8; 32],
    pub workspace_id: [u8; 32],
    pub authority_event_id: [u8; 32], // workspace (bootstrap) or admin (ongoing)
    pub key_history_event_id: [u8; 32],
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
    Ok(ParsedEvent::UserInvite(UserInviteEvent {
        created_at_ms: values[0].as_timestamp().unwrap(),
        public_key: values[1].as_event_id().unwrap(),
        workspace_id: values[2].as_event_id().unwrap(),
        authority_event_id: values[3].as_event_id().unwrap(),
        key_history_event_id: values[4].as_event_id().unwrap(),
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
        FieldValue::EventId(e.key_history_event_id),
    ];

    Ok(encode_fields(
        EVENT_TYPE_USER_INVITE,
        USER_INVITE_FIELDS,
        &values,
    )?)
}

pub static USER_INVITE_META: EventTypeMeta = crate::event_modules::registry::event_type_meta! {
    type_code: EVENT_TYPE_USER_INVITE,
    type_name: "user_invite_shared",
    projection_table: "user_invites",
    share_scope: ShareScope::Shared,
    dep_fields: &["authority_event_id", "key_history_event_id"],
    dep_field_type_codes: &[&[8, 18], &[super::super::EVENT_TYPE_KEY_HISTORY]],
    signer_required: true,
    signature_byte_len: 0,
    encryptable: false,
    parse: parse_user_invite,
    encode: encode_user_invite,
    projector: super::projector::project_pure,
    context_loader: super::projector::build_projector_context,
};

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parse_user_invite_roundtrip() {
        let event = ParsedEvent::UserInvite(UserInviteEvent {
            created_at_ms: 123,
            public_key: [1u8; 32],
            workspace_id: [2u8; 32],
            authority_event_id: [3u8; 32],
            key_history_event_id: [4u8; 32],
        });
        let blob = encode_user_invite(&event).unwrap();
        let parsed = parse_user_invite(&blob).unwrap();
        assert_eq!(parsed, event);
    }
}
