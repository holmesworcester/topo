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
    FieldSpec::Text("device_name", NAME_BYTES),
    FieldSpec::EventId("signed_by"),
    FieldSpec::U8("signer_type"),
    FieldSpec::FixedBytes("signature", 64),
];

/// PeerShared (type 16):
/// type(1) + created_at(8) + public_key(32) + user_event_id(32)
/// + device_name(64) + signed_by(32) + signer_type(1) + signature(64) = 234
pub const PEER_SHARED_WIRE_SIZE: usize = wire_size_for_fields(PEER_SHARED_FIELDS);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerSharedEvent {
    pub created_at_ms: u64,
    pub public_key: [u8; 32],
    pub user_event_id: [u8; 32],
    pub device_name: String,
    pub signed_by: [u8; 32],
    pub signer_type: u8,
    pub signature: [u8; 64],
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
    let values = decode_fields(EVENT_TYPE_PEER_SHARED, PEER_SHARED_FIELDS, blob)?;

    let signer_type = values[5].as_u8().unwrap();
    if signer_type != 3 {
        return Err(EventError::InvalidMetadata(
            "peer_shared signer_type must be 3 (peer_invite_shared)",
        ));
    }

    Ok(ParsedEvent::PeerShared(PeerSharedEvent {
        created_at_ms: values[0].as_timestamp().unwrap(),
        public_key: values[1].as_event_id().unwrap(),
        user_event_id: values[2].as_event_id().unwrap(),
        device_name: values[3].as_text().unwrap().to_string(),
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

pub fn encode_peer_shared(event: &ParsedEvent) -> Result<Vec<u8>, EventError> {
    let e = match event {
        ParsedEvent::PeerShared(v) => v,
        _ => return Err(EventError::WrongVariant),
    };

    let values = vec![
        FieldValue::Timestamp(e.created_at_ms),
        FieldValue::EventId(e.public_key),
        FieldValue::EventId(e.user_event_id),
        FieldValue::Text(e.device_name.clone()),
        FieldValue::EventId(e.signed_by),
        FieldValue::U8(e.signer_type),
        FieldValue::FixedBytes(e.signature.to_vec()),
    ];

    Ok(encode_fields(
        EVENT_TYPE_PEER_SHARED,
        PEER_SHARED_FIELDS,
        &values,
    )?)
}

pub static PEER_SHARED_META: EventTypeMeta = EventTypeMeta {
    type_code: EVENT_TYPE_PEER_SHARED,
    type_name: "peer_shared",
    projection_table: "peers_shared",
    share_scope: ShareScope::Shared,
    dep_fields: &["user_event_id", "signed_by"],
    dep_field_type_codes: &[&[14], &[]],
    signer_required: true,
    signature_byte_len: 64,
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
            field_offset(PEER_SHARED_FIELDS, 6) + 64,
            PEER_SHARED_WIRE_SIZE
        );
    }

    #[test]
    fn parse_peer_shared_accepts_peer_invite_signer_type() {
        let event = ParsedEvent::PeerShared(PeerSharedEvent {
            created_at_ms: 123,
            public_key: [1u8; 32],
            user_event_id: [2u8; 32],
            device_name: "device".to_string(),
            signed_by: [3u8; 32],
            signer_type: 3,
            signature: [0u8; 64],
        });

        let blob = encode_event(&event).unwrap();
        let parsed = parse_event(&blob).unwrap();
        assert_eq!(parsed, event);
    }

    #[test]
    fn parse_peer_shared_rejects_wrong_signer_type() {
        let signer_type_offset = field_offset(PEER_SHARED_FIELDS, 5);
        let mut blob = vec![0u8; PEER_SHARED_WIRE_SIZE];
        blob[0] = EVENT_TYPE_PEER_SHARED;
        blob[signer_type_offset] = 5;

        let err = parse_peer_shared(&blob).expect_err("should reject wrong signer type");
        assert!(matches!(err, EventError::InvalidMetadata(_)));
    }
}
