use super::registry::{EventTypeMeta, ShareScope};
use super::{EventError, ParsedEvent, EVENT_TYPE_ADMIN, EVENT_TYPE_SIGNED};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedEvent {
    pub signer_event_id: [u8; 32],
    pub inner_type_code: u8,
    pub inner_created_at_ms: u64,
    pub payload: Vec<u8>,
    pub signature: [u8; 64],
}

impl super::Describe for SignedEvent {
    fn human_fields(&self) -> Vec<(&'static str, String)> {
        let registry = super::registry();
        let inner_name = registry
            .lookup(self.inner_type_code)
            .map(|m| m.type_name)
            .unwrap_or("unknown");
        vec![("inner_type", inner_name.to_string())]
    }
}

pub fn outer_payload(blob: &[u8]) -> Option<&[u8]> {
    if blob.first().copied() != Some(EVENT_TYPE_SIGNED) || blob.len() < 1 + 32 + 64 + 1 {
        return None;
    }
    Some(&blob[33..blob.len() - 64])
}

pub fn outer_signer_event_id(blob: &[u8]) -> Option<[u8; 32]> {
    if blob.first().copied() != Some(EVENT_TYPE_SIGNED) || blob.len() < 1 + 32 + 64 + 1 {
        return None;
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&blob[1..33]);
    Some(out)
}

pub fn parse_signed(blob: &[u8]) -> Result<ParsedEvent, EventError> {
    if blob.len() < 1 + 32 + 64 + 1 {
        return Err(EventError::TooShort {
            expected: 98,
            actual: blob.len(),
        });
    }
    if blob[0] != EVENT_TYPE_SIGNED {
        return Err(EventError::WrongType {
            expected: EVENT_TYPE_SIGNED,
            actual: blob[0],
        });
    }

    let mut signer_event_id = [0u8; 32];
    signer_event_id.copy_from_slice(&blob[1..33]);

    let payload = blob[33..blob.len() - 64].to_vec();
    let inner_type_code = payload.first().copied().ok_or(EventError::TooShort {
        expected: 1,
        actual: 0,
    })?;
    let inner_created_at_ms =
        super::extract_created_at_ms(&payload).ok_or(EventError::TooShort {
            expected: 9,
            actual: payload.len(),
        })?;

    let mut signature = [0u8; 64];
    signature.copy_from_slice(&blob[blob.len() - 64..]);

    Ok(ParsedEvent::Signed(SignedEvent {
        signer_event_id,
        inner_type_code,
        inner_created_at_ms,
        payload,
        signature,
    }))
}

pub fn encode_signed(event: &ParsedEvent) -> Result<Vec<u8>, EventError> {
    let signed = match event {
        ParsedEvent::Signed(v) => v,
        _ => return Err(EventError::WrongVariant),
    };
    if signed.payload.is_empty() {
        return Err(EventError::InvalidMetadata(
            "signed payload must not be empty",
        ));
    }
    if signed.payload[0] != signed.inner_type_code {
        return Err(EventError::InvalidMetadata(
            "signed inner_type_code does not match payload type",
        ));
    }
    let actual_created_at =
        super::extract_created_at_ms(&signed.payload).ok_or(EventError::TooShort {
            expected: 9,
            actual: signed.payload.len(),
        })?;
    if actual_created_at != signed.inner_created_at_ms {
        return Err(EventError::InvalidMetadata(
            "signed inner_created_at_ms does not match payload timestamp",
        ));
    }

    let mut out = Vec::with_capacity(1 + 32 + signed.payload.len() + 64);
    out.push(EVENT_TYPE_SIGNED);
    out.extend_from_slice(&signed.signer_event_id);
    out.extend_from_slice(&signed.payload);
    out.extend_from_slice(&signed.signature);
    Ok(out)
}

use crate::projection::contract::{ProjectorDecisionContext, ProjectorResult};

pub fn project_pure(
    _recorded_by: &str,
    _event_id_b64: &str,
    _parsed: &ParsedEvent,
    _ctx: &ProjectorDecisionContext,
) -> ProjectorResult {
    ProjectorResult::reject("signed events should not reach projector dispatch".to_string())
}

pub static SIGNED_META: EventTypeMeta = crate::event_modules::registry::event_type_meta! {
    type_code: EVENT_TYPE_SIGNED,
    type_name: "signed",
    projection_table: "",
    share_scope: ShareScope::Shared,
    dep_fields: &["signer_event_id"],
    dep_field_type_codes: &[&[8, 10, 12, 14, 16, EVENT_TYPE_ADMIN]],
    signer_required: false,
    signature_byte_len: 0,
    encryptable: false,
    parse: parse_signed,
    encode: encode_signed,
    projector: project_pure,
    context_loader: crate::event_modules::registry::load_empty_context,
};
