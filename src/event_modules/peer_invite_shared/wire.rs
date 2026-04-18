use super::super::layout::field_spec::{
    decode_fields, encode_fields, wire_size_for_fields, FieldSpec, FieldValue,
};
use super::super::registry::{EventTypeMeta, ShareScope};
use super::super::{EventError, ParsedEvent, EVENT_TYPE_DEVICE_INVITE};

pub const DEVICE_INVITE_FIELDS: &[FieldSpec] = &[
    FieldSpec::Timestamp("created_at_ms"),
    FieldSpec::EventId("public_key"),
    FieldSpec::EventId("authority_event_id"),
];

/// DeviceInvite (type 12): type(1) + created_at(8) + public_key(32)
/// + authority_event_id(32) = 73
pub const DEVICE_INVITE_WIRE_SIZE: usize = wire_size_for_fields(DEVICE_INVITE_FIELDS);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceInviteEvent {
    pub created_at_ms: u64,
    pub public_key: [u8; 32],
    pub authority_event_id: [u8; 32], // user (bootstrap or ongoing self-link)
}

impl super::super::Describe for DeviceInviteEvent {
    fn human_fields(&self) -> Vec<(&'static str, String)> {
        vec![("public_key", super::super::trunc_hex(&self.public_key, 16))]
    }
}

/// Wire format (170 bytes fixed):
/// [0]        type_code = 12
/// [1..9]     created_at_ms (u64 LE)
/// [9..41]    public_key (32 bytes)
/// [41..73]   authority_event_id (32 bytes)
pub fn parse_device_invite(blob: &[u8]) -> Result<ParsedEvent, EventError> {
    if let Some((ts, public_key, authority_event_id)) =
        topo_verus_proofs::event_modules::layout::ts_id2::parse_ts_id2(EVENT_TYPE_DEVICE_INVITE, blob)
    {
        return Ok(ParsedEvent::DeviceInvite(DeviceInviteEvent {
            created_at_ms: ts,
            public_key,
            authority_event_id,
        }));
    }
    let values = decode_fields(EVENT_TYPE_DEVICE_INVITE, DEVICE_INVITE_FIELDS, blob)?;
    Ok(ParsedEvent::DeviceInvite(DeviceInviteEvent {
        created_at_ms: values[0].as_timestamp().unwrap(),
        public_key: values[1].as_event_id().unwrap(),
        authority_event_id: values[2].as_event_id().unwrap(),
    }))
}

pub fn encode_device_invite(event: &ParsedEvent) -> Result<Vec<u8>, EventError> {
    let e = match event {
        ParsedEvent::DeviceInvite(v) => v,
        _ => return Err(EventError::WrongVariant),
    };
    Ok(topo_verus_proofs::event_modules::layout::ts_id2::encode_ts_id2(
        EVENT_TYPE_DEVICE_INVITE,
        e.created_at_ms,
        &e.public_key,
        &e.authority_event_id,
    ))
}

pub static DEVICE_INVITE_META: EventTypeMeta = crate::event_modules::registry::event_type_meta! {
    type_code: EVENT_TYPE_DEVICE_INVITE,
    type_name: "peer_invite_shared",
    projection_table: "device_invites",
    share_scope: ShareScope::Shared,
    dep_fields: &["authority_event_id"],
    dep_field_type_codes: &[&[14]],
    signer_required: true,
    signature_byte_len: 0,
    encryptable: false,
    parse: parse_device_invite,
    encode: encode_device_invite,
    projector: super::projector::project_pure,
    context_loader: super::projector::build_projector_context,
};

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parse_device_invite_roundtrip() {
        let event = ParsedEvent::DeviceInvite(DeviceInviteEvent {
            created_at_ms: 123,
            public_key: [1u8; 32],
            authority_event_id: [2u8; 32],
        });
        let blob = encode_device_invite(&event).unwrap();
        let parsed = parse_device_invite(&blob).unwrap();
        assert_eq!(parsed, event);
    }
}
