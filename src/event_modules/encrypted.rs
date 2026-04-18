use super::layout::common::{
    encrypted_inner_wire_size, encrypted_wire_size, ENCRYPTED_AUTH_TAG_BYTES,
};
use super::registry::{EventTypeMeta, ShareScope};
use super::{EventError, ParsedEvent, EVENT_TYPE_ENCRYPTED};

// ─── Layout (owned by this module) ───

mod encrypted_offsets {
    pub const TYPE_CODE: usize = 0;
    pub const CREATED_AT: usize = 1;
    pub const KEY_EVENT_ID: usize = 9;
    pub const OWNER_EVENT_ID: usize = 41;
    pub const INNER_TYPE_CODE: usize = 73;
    pub const NONCE: usize = 74;
    pub const CIPHERTEXT: usize = 86;
    // auth_tag follows ciphertext at CIPHERTEXT + ciphertext_size
}

use encrypted_offsets as off;

pub const NO_OWNER_EVENT_ID: [u8; 32] = [0u8; 32];

pub fn outer_inner_type_code(blob: &[u8]) -> Option<u8> {
    if !topo_verus_proofs::event_modules::encrypted::is_well_formed_encrypted_header(blob) {
        return None;
    }
    blob.get(off::INNER_TYPE_CODE).copied()
}

pub fn outer_owner_event_id(blob: &[u8]) -> Option<[u8; 32]> {
    if !topo_verus_proofs::event_modules::encrypted::is_well_formed_encrypted_header(blob) {
        return None;
    }
    let (start, end) = topo_verus_proofs::event_modules::encrypted::owner_event_id_range();
    let owner = blob.get(start..end)?;
    let mut out = [0u8; 32];
    out.copy_from_slice(owner);
    Some(out)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedEvent {
    pub created_at_ms: u64,
    pub key_event_id: [u8; 32],
    pub owner_event_id: [u8; 32],
    pub inner_type_code: u8,
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
    pub auth_tag: [u8; 16],
}

impl super::Describe for EncryptedEvent {
    fn human_fields(&self) -> Vec<(&'static str, String)> {
        let registry = super::registry();
        let inner_name = registry
            .lookup(self.inner_type_code)
            .map(|m| m.type_name)
            .unwrap_or("unknown");
        let mut fields = vec![
            ("inner_type", inner_name.to_string()),
            ("ciphertext", super::trunc_hex(&self.ciphertext, 40)),
        ];
        if self.owner_event_id != NO_OWNER_EVENT_ID {
            fields.push(("owner", super::short_id_b64(&self.owner_event_id)));
        }
        fields
    }
}

/// Wire format (fixed size per inner_type_code, unsigned):
/// [0]             type_code = 5
/// [1..9]          created_at_ms (u64 LE)
/// [9..41]         key_event_id (32B)
/// [41..73]        owner_event_id (32B, zero = ownerless/root content)
/// [73]            inner_type_code (1B)
/// [74..86]        nonce (12B, AES-256-GCM)
/// [86..86+N]      ciphertext (N = inner type's fixed wire size)
/// [86+N..86+N+16] auth_tag (16B)
///
/// Total size = 102 + inner_wire_size, deterministic by inner_type_code.
/// No ciphertext_len field; size is derived from inner_type_code lookup.
pub fn parse_encrypted(blob: &[u8]) -> Result<ParsedEvent, EventError> {
    // Need at least the header to read inner_type_code
    if blob.len() < off::CIPHERTEXT {
        return Err(EventError::TooShort {
            expected: off::CIPHERTEXT,
            actual: blob.len(),
        });
    }
    if blob[0] != EVENT_TYPE_ENCRYPTED {
        return Err(EventError::WrongType {
            expected: EVENT_TYPE_ENCRYPTED,
            actual: blob[0],
        });
    }

    let inner_type_code = blob[off::INNER_TYPE_CODE];

    // Look up expected ciphertext size from inner_type_code
    let ciphertext_size = encrypted_inner_wire_size(inner_type_code)
        .ok_or(EventError::InvalidEncryptedInnerType(inner_type_code))?;

    let expected_len = encrypted_wire_size(ciphertext_size);
    if blob.len() < expected_len {
        return Err(EventError::TooShort {
            expected: expected_len,
            actual: blob.len(),
        });
    }
    if blob.len() > expected_len {
        return Err(EventError::TrailingData {
            expected: expected_len,
            actual: blob.len(),
        });
    }

    let created_at_ms =
        u64::from_le_bytes(blob[off::CREATED_AT..off::KEY_EVENT_ID].try_into().unwrap());

    let mut key_event_id = [0u8; 32];
    key_event_id.copy_from_slice(&blob[off::KEY_EVENT_ID..off::OWNER_EVENT_ID]);

    let mut owner_event_id = [0u8; 32];
    owner_event_id.copy_from_slice(&blob[off::OWNER_EVENT_ID..off::INNER_TYPE_CODE]);

    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&blob[off::NONCE..off::CIPHERTEXT]);

    let ciphertext = blob[off::CIPHERTEXT..off::CIPHERTEXT + ciphertext_size].to_vec();

    let auth_tag_start = off::CIPHERTEXT + ciphertext_size;
    let mut auth_tag = [0u8; 16];
    auth_tag.copy_from_slice(&blob[auth_tag_start..auth_tag_start + ENCRYPTED_AUTH_TAG_BYTES]);

    Ok(ParsedEvent::Encrypted(EncryptedEvent {
        created_at_ms,
        key_event_id,
        owner_event_id,
        inner_type_code,
        nonce,
        ciphertext,
        auth_tag,
    }))
}

pub fn encode_encrypted(event: &ParsedEvent) -> Result<Vec<u8>, EventError> {
    let enc = match event {
        ParsedEvent::Encrypted(e) => e,
        _ => return Err(EventError::WrongVariant),
    };

    // Validate inner_type_code and get expected ciphertext size
    let expected_ct_size = encrypted_inner_wire_size(enc.inner_type_code)
        .ok_or(EventError::InvalidEncryptedInnerType(enc.inner_type_code))?;

    if enc.ciphertext.len() != expected_ct_size {
        return Err(EventError::InvalidMetadata(
            "ciphertext size does not match inner_type_code",
        ));
    }

    Ok(
        topo_verus_proofs::event_modules::layout::shapes::encode_encrypted_envelope(
            enc.created_at_ms,
            &enc.key_event_id,
            &enc.owner_event_id,
            enc.inner_type_code,
            &enc.nonce,
            &enc.ciphertext,
            &enc.auth_tag,
        ),
    )
}

// === Projector (event-module locality) ===

use crate::projection::projector::{ProjectorDecisionContext, ProjectorResult};

/// Encrypted events are handled by the pipeline before projector dispatch.
/// If this function is reached, it means the encrypted event was not decrypted.
pub fn project_pure(
    _recorded_by: &str,
    _event_id_b64: &str,
    _parsed: &ParsedEvent,
    _ctx: &ProjectorDecisionContext,
) -> ProjectorResult {
    ProjectorResult::reject("encrypted events should not reach projector dispatch".to_string())
}

pub static ENCRYPTED_META: EventTypeMeta = EventTypeMeta {
    type_code: EVENT_TYPE_ENCRYPTED,
    type_name: "encrypted",
    projection_table: "",
    share_scope: ShareScope::Shared,
    dep_fields: &["key_event_id", "owner_event_id"],
    dep_field_type_codes: &[&[6], &[1]],
    signer_required: false,
    signature_byte_len: 0,
    encryptable: false,
    parse: parse_encrypted,
    encode: encode_encrypted,
    projector: project_pure,
    context_loader: crate::event_modules::registry::load_empty_context,
};
