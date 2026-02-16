use base64::Engine;
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};

use crate::crypto::{event_id_from_base64, event_id_to_base64, EventId};
use crate::identity_ops::{InviteData, InviteType};

const INVITE_PREFIX: &str = "quiet://invite/";
const LINK_PREFIX: &str = "quiet://link/";
const INVITE_LINK_VERSION: u8 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InviteLinkKind {
    User,
    DeviceLink,
}

#[derive(Debug, Clone)]
pub struct ParsedInviteLink {
    pub kind: InviteLinkKind,
    pub invite_event_id: EventId,
    pub invite_private_key: [u8; 32],
    pub workspace_id: EventId,
    pub invite_type: InviteType,
    pub bootstrap_addr: String,
    pub bootstrap_spki_fingerprint: [u8; 32],
}

impl ParsedInviteLink {
    pub fn invite_signing_key(&self) -> SigningKey {
        SigningKey::from_bytes(&self.invite_private_key)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum InviteLinkError {
    #[error("invalid invite link prefix")]
    InvalidPrefix,
    #[error("invalid invite link payload: {0}")]
    InvalidPayload(String),
    #[error("invite link decode error: {0}")]
    Decode(String),
    #[error("invite link encode error: {0}")]
    Encode(String),
}

#[derive(Debug, Serialize, Deserialize)]
struct InviteLinkPayload {
    version: u8,
    kind: String,
    invite_event_id: String,
    invite_private_key: String,
    workspace_id: String,
    user_event_id: Option<String>,
    bootstrap_addr: String,
    bootstrap_spki: String,
}

pub fn create_invite_link(
    invite: &InviteData,
    bootstrap_addr: &str,
    bootstrap_spki: &[u8; 32],
) -> Result<String, InviteLinkError> {
    let (kind, prefix, user_event_id) = match invite.invite_type {
        InviteType::User => ("user".to_string(), INVITE_PREFIX, None),
        InviteType::DeviceLink { user_event_id } => (
            "device_link".to_string(),
            LINK_PREFIX,
            Some(event_id_to_base64(&user_event_id)),
        ),
    };

    let payload = InviteLinkPayload {
        version: INVITE_LINK_VERSION,
        kind,
        invite_event_id: event_id_to_base64(&invite.invite_event_id),
        invite_private_key: base64::engine::general_purpose::STANDARD
            .encode(invite.invite_key.to_bytes()),
        workspace_id: event_id_to_base64(&invite.workspace_id),
        user_event_id,
        bootstrap_addr: bootstrap_addr.to_string(),
        bootstrap_spki: hex::encode(bootstrap_spki),
    };

    let json = serde_json::to_vec(&payload).map_err(|e| InviteLinkError::Encode(e.to_string()))?;
    let code = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(json);
    Ok(format!("{}{}", prefix, code))
}

pub fn parse_invite_link(link: &str) -> Result<ParsedInviteLink, InviteLinkError> {
    let (kind, code) = if let Some(code) = link.strip_prefix(INVITE_PREFIX) {
        (InviteLinkKind::User, code)
    } else if let Some(code) = link.strip_prefix(LINK_PREFIX) {
        (InviteLinkKind::DeviceLink, code)
    } else {
        return Err(InviteLinkError::InvalidPrefix);
    };

    let payload_json = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(code)
        .map_err(|e| InviteLinkError::Decode(e.to_string()))?;
    let payload: InviteLinkPayload = serde_json::from_slice(&payload_json)
        .map_err(|e| InviteLinkError::Decode(e.to_string()))?;

    if payload.version != INVITE_LINK_VERSION {
        return Err(InviteLinkError::InvalidPayload(format!(
            "unsupported version {}",
            payload.version
        )));
    }

    let invite_event_id = event_id_from_base64(&payload.invite_event_id)
        .ok_or_else(|| InviteLinkError::InvalidPayload("bad invite_event_id".to_string()))?;
    let workspace_id = event_id_from_base64(&payload.workspace_id)
        .ok_or_else(|| InviteLinkError::InvalidPayload("bad workspace_id".to_string()))?;

    let key_bytes = base64::engine::general_purpose::STANDARD
        .decode(payload.invite_private_key.as_bytes())
        .map_err(|e| InviteLinkError::Decode(e.to_string()))?;
    if key_bytes.len() != 32 {
        return Err(InviteLinkError::InvalidPayload(format!(
            "invite_private_key must be 32 bytes, got {}",
            key_bytes.len()
        )));
    }
    let mut invite_private_key = [0u8; 32];
    invite_private_key.copy_from_slice(&key_bytes);

    let spki_bytes =
        hex::decode(payload.bootstrap_spki).map_err(|e| InviteLinkError::Decode(e.to_string()))?;
    if spki_bytes.len() != 32 {
        return Err(InviteLinkError::InvalidPayload(format!(
            "bootstrap_spki must be 32 bytes, got {}",
            spki_bytes.len()
        )));
    }
    let mut bootstrap_spki_fingerprint = [0u8; 32];
    bootstrap_spki_fingerprint.copy_from_slice(&spki_bytes);

    let invite_type = match (kind, payload.kind.as_str()) {
        (InviteLinkKind::User, "user") => InviteType::User,
        (InviteLinkKind::DeviceLink, "device_link") => {
            let user_event_b64 = payload.user_event_id.ok_or_else(|| {
                InviteLinkError::InvalidPayload("device_link missing user_event_id".to_string())
            })?;
            let user_event_id = event_id_from_base64(&user_event_b64)
                .ok_or_else(|| InviteLinkError::InvalidPayload("bad user_event_id".to_string()))?;
            InviteType::DeviceLink { user_event_id }
        }
        (InviteLinkKind::User, other) => {
            return Err(InviteLinkError::InvalidPayload(format!(
                "prefix expects user kind, payload has {}",
                other
            )))
        }
        (InviteLinkKind::DeviceLink, other) => {
            return Err(InviteLinkError::InvalidPayload(format!(
                "prefix expects device_link kind, payload has {}",
                other
            )))
        }
    };

    Ok(ParsedInviteLink {
        kind,
        invite_event_id,
        invite_private_key,
        workspace_id,
        invite_type,
        bootstrap_addr: payload.bootstrap_addr,
        bootstrap_spki_fingerprint,
    })
}

/// Re-encode an invite link with a different bootstrap address.
/// Decodes the payload, swaps the bootstrap_addr, and re-encodes.
pub fn rewrite_bootstrap_addr(
    link: &str,
    new_addr: &str,
) -> Result<String, InviteLinkError> {
    let (prefix, code) = if let Some(code) = link.strip_prefix(INVITE_PREFIX) {
        (INVITE_PREFIX, code)
    } else if let Some(code) = link.strip_prefix(LINK_PREFIX) {
        (LINK_PREFIX, code)
    } else {
        return Err(InviteLinkError::InvalidPrefix);
    };

    let payload_json = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(code)
        .map_err(|e| InviteLinkError::Decode(e.to_string()))?;
    let mut payload: InviteLinkPayload = serde_json::from_slice(&payload_json)
        .map_err(|e| InviteLinkError::Decode(e.to_string()))?;

    payload.bootstrap_addr = new_addr.to_string();

    let json = serde_json::to_vec(&payload).map_err(|e| InviteLinkError::Encode(e.to_string()))?;
    let new_code = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(json);
    Ok(format!("{}{}", prefix, new_code))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_user_invite_link_roundtrip() {
        let invite = InviteData {
            invite_event_id: [1u8; 32],
            invite_key: SigningKey::from_bytes(&[2u8; 32]),
            workspace_id: [3u8; 32],
            invite_type: InviteType::User,
        };
        let bootstrap_addr = "127.0.0.1:4433";
        let bootstrap_spki = [4u8; 32];
        let link = create_invite_link(&invite, bootstrap_addr, &bootstrap_spki).unwrap();
        assert!(link.starts_with(INVITE_PREFIX));

        let parsed = parse_invite_link(&link).unwrap();
        assert_eq!(parsed.kind, InviteLinkKind::User);
        assert_eq!(parsed.invite_event_id, invite.invite_event_id);
        assert_eq!(parsed.invite_private_key, invite.invite_key.to_bytes());
        assert_eq!(parsed.workspace_id, invite.workspace_id);
        assert_eq!(parsed.bootstrap_addr, bootstrap_addr);
        assert_eq!(parsed.bootstrap_spki_fingerprint, bootstrap_spki);
        assert!(matches!(parsed.invite_type, InviteType::User));
    }

    #[test]
    fn test_device_invite_link_roundtrip() {
        let user_event_id = [9u8; 32];
        let invite = InviteData {
            invite_event_id: [5u8; 32],
            invite_key: SigningKey::from_bytes(&[6u8; 32]),
            workspace_id: [7u8; 32],
            invite_type: InviteType::DeviceLink { user_event_id },
        };
        let bootstrap_addr = "127.0.0.1:5555";
        let bootstrap_spki = [8u8; 32];
        let link = create_invite_link(&invite, bootstrap_addr, &bootstrap_spki).unwrap();
        assert!(link.starts_with(LINK_PREFIX));

        let parsed = parse_invite_link(&link).unwrap();
        assert_eq!(parsed.kind, InviteLinkKind::DeviceLink);
        assert_eq!(parsed.invite_event_id, invite.invite_event_id);
        assert_eq!(parsed.invite_private_key, invite.invite_key.to_bytes());
        assert_eq!(parsed.workspace_id, invite.workspace_id);
        assert_eq!(parsed.bootstrap_addr, bootstrap_addr);
        assert_eq!(parsed.bootstrap_spki_fingerprint, bootstrap_spki);
        match parsed.invite_type {
            InviteType::DeviceLink {
                user_event_id: parsed_user_event_id,
            } => {
                assert_eq!(parsed_user_event_id, user_event_id);
            }
            _ => panic!("expected device link invite type"),
        }
    }
}
