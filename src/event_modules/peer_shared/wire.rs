use super::super::layout::common::NAME_BYTES;
use super::super::layout::field_spec::{
    decode_fields, encode_fields, wire_size_for_fields, FieldSpec, FieldValue,
};
use super::super::registry::{EventTypeMeta, ShareScope};
use super::super::{EventError, ParsedEvent, EVENT_TYPE_PEER_SHARED};

pub const PEER_SHARED_FIELDS: &[FieldSpec] = &[
    FieldSpec::Timestamp("created_at_ms"),
    FieldSpec::EventId("public_key"),
    FieldSpec::EventId("user_event_id"),
    FieldSpec::EventId("endpoint_shared_event_id"),
    FieldSpec::Text("device_name", NAME_BYTES),
];

/// PeerShared (type 16):
/// type(1) + created_at(8) + public_key(32) + user_event_id(32)
/// + endpoint_shared_event_id(32) + device_name(64) = 169
pub const PEER_SHARED_WIRE_SIZE: usize = wire_size_for_fields(PEER_SHARED_FIELDS);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerSharedEvent {
    pub created_at_ms: u64,
    pub public_key: [u8; 32],
    pub user_event_id: [u8; 32],
    pub endpoint_shared_event_id: [u8; 32],
    pub device_name: String,
}

impl super::super::Describe for PeerSharedEvent {
    fn human_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            ("device_name", self.device_name.clone()),
            ("public_key", super::super::trunc_hex(&self.public_key, 16)),
        ]
    }
}

pub fn parse_peer_shared(blob: &[u8]) -> Result<ParsedEvent, EventError> {
    if let Some((ts, public_key, user_event_id, endpoint_shared_event_id, name_slot)) =
        topo_verus_proofs::state::event_codec_shapes::parse_ts_id3_fb64(
            EVENT_TYPE_PEER_SHARED,
            blob,
        )
    {
        let device_name = crate::event_modules::layout::common::read_text_slot(&name_slot)
            .map_err(EventError::TextSlot)?;
        return Ok(ParsedEvent::PeerShared(PeerSharedEvent {
            created_at_ms: ts,
            public_key,
            user_event_id,
            endpoint_shared_event_id,
            device_name,
        }));
    }
    let values = decode_fields(EVENT_TYPE_PEER_SHARED, PEER_SHARED_FIELDS, blob)?;
    Ok(ParsedEvent::PeerShared(PeerSharedEvent {
        created_at_ms: values[0].as_timestamp().unwrap(),
        public_key: values[1].as_event_id().unwrap(),
        user_event_id: values[2].as_event_id().unwrap(),
        endpoint_shared_event_id: values[3].as_event_id().unwrap(),
        device_name: values[4].as_text().unwrap().to_string(),
    }))
}

pub fn encode_peer_shared(event: &ParsedEvent) -> Result<Vec<u8>, EventError> {
    let e = match event {
        ParsedEvent::PeerShared(v) => v,
        _ => return Err(EventError::WrongVariant),
    };
    let mut name_slot: [u8; NAME_BYTES] = [0u8; NAME_BYTES];
    crate::event_modules::layout::common::write_text_slot(&e.device_name, &mut name_slot)
        .map_err(EventError::TextSlot)?;
    Ok(
        topo_verus_proofs::state::event_codec_shapes::encode_ts_id3_fb64(
            EVENT_TYPE_PEER_SHARED,
            e.created_at_ms,
            &e.public_key,
            &e.user_event_id,
            &e.endpoint_shared_event_id,
            &name_slot,
        ),
    )
}

pub static PEER_SHARED_META: EventTypeMeta = crate::event_modules::registry::event_type_meta! {
    type_code: EVENT_TYPE_PEER_SHARED,
    type_name: "peer_shared",
    projection_table: "peers_shared",
    share_scope: ShareScope::Shared,
    dep_fields: &["user_event_id", "endpoint_shared_event_id"],
    dep_field_type_codes: &[&[14], &[34]],
    signer_required: true,
    signature_byte_len: 0,
    encryptable: false,
    parse: parse_peer_shared,
    encode: encode_peer_shared,
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
        assert_eq!(
            field_offset(PEER_SHARED_FIELDS, 4) + NAME_BYTES,
            PEER_SHARED_WIRE_SIZE
        );
    }

    #[test]
    fn parse_peer_shared_accepts_peer_invite_signer_type() {
        let event = ParsedEvent::PeerShared(PeerSharedEvent {
            created_at_ms: 123,
            public_key: [1u8; 32],
            user_event_id: [2u8; 32],
            endpoint_shared_event_id: [9u8; 32],
            device_name: "device".to_string(),
        });

        let blob = encode_event(&event).unwrap();
        let parsed = parse_event(&blob).unwrap();
        assert_eq!(parsed, event);
    }

    #[test]
    fn parse_peer_shared_rejects_wrong_type() {
        let mut blob = vec![0u8; PEER_SHARED_WIRE_SIZE];
        blob[0] = 0xFF;
        let err = parse_peer_shared(&blob).expect_err("should reject wrong type");
        assert!(matches!(err, EventError::WrongType { .. }));
    }
}
