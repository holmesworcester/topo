use ed25519_dalek::SigningKey;
use std::net::SocketAddr;

use super::identity_ops::{InviteData, InviteType};
use crate::crypto::EventId;

// Re-export BootstrapAddress and associated items from the dedicated module
// so existing `invite_link::BootstrapAddress` paths continue to work.
pub use super::bootstrap_address::{
    detect_bootstrap_addrs, parse_bootstrap_address, BootstrapAddress, BootstrapAddressError,
    DEFAULT_PORT,
};

const INVITE_PREFIX: &str = "topo://invite/";
const LINK_PREFIX: &str = "topo://link/";
const INVITE_LINK_VERSION: u8 = 5;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InviteLinkKind {
    User,
    DeviceLink,
}

pub fn resolve_bootstrap_socket_addrs(
    invite: &ParsedInviteLink,
) -> Vec<Result<SocketAddr, InviteLinkError>> {
    invite
        .bootstrap_addrs
        .iter()
        .map(|a| a.to_socket_addr().map_err(InviteLinkError::from))
        .collect()
}

#[derive(Debug, Clone)]
pub struct ParsedInviteLink {
    pub kind: InviteLinkKind,
    pub invite_event_id: EventId,
    pub invite_private_key: [u8; 32],
    pub workspace_id: EventId,
    pub invite_type: InviteType,
    pub bootstrap_addrs: Vec<BootstrapAddress>,
    pub daemon_spki_fingerprint: [u8; 32],
}

impl ParsedInviteLink {
    pub fn invite_signing_key(&self) -> SigningKey {
        SigningKey::from_bytes(&self.invite_private_key)
    }

    /// Return all bootstrap addresses as display strings.
    pub fn bootstrap_addr_strings(&self) -> Vec<String> {
        self.bootstrap_addrs
            .iter()
            .map(|a| a.to_bootstrap_addr_string())
            .collect()
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

impl From<BootstrapAddressError> for InviteLinkError {
    fn from(e: BootstrapAddressError) -> Self {
        InviteLinkError::InvalidPayload(e.to_string())
    }
}

// ---------------------------------------------------------------------------
// Plaintext invite link format (v5)
//
// All fields are hex-encoded and slash-delimited with self-explanatory labels.
// No spaces, no base64 — fully readable and continuously linkifiable.
//
// User invite:
//   topo://invite/v5/user/INVITE_ID.<hex64>/INVITE_PRIVKEY.<hex64>/WORKSPACE.<hex64>/DAEMON_SPKI_PUBKEY.<hex64>/ADDRESS.<a1>,<a2>
//
// Device-link invite:
//   topo://link/v5/device_link/INVITE_ID.<hex64>/INVITE_PRIVKEY.<hex64>/WORKSPACE.<hex64>/USER_ID.<hex64>/DAEMON_SPKI_PUBKEY.<hex64>/ADDRESS.<a1>,<a2>
//
// `ADDRESS.` may be empty, representing an invite that relies entirely on
// later discovery/recovery rather than embedded bootstrap endpoints.
//
// Address tokens: port omitted when default 4433.  IPv6 is fully expanded
// as 8 dash-separated groups of 4 hex digits (no brackets) to stay
// shell-safe and linkifiable.  Non-default port uses `_port` suffix.
// Example: 2601-0645-8881-1d40-0216-3eff-fe8c-0d03_7443
// ---------------------------------------------------------------------------

pub fn create_invite_link(
    invite: &InviteData,
    bootstrap_addrs: &[BootstrapAddress],
    daemon_spki: &[u8; 32],
) -> Result<String, InviteLinkError> {
    for addr in bootstrap_addrs {
        addr.validate()?;
    }

    let (prefix, kind_str, user_segment) = match &invite.invite_type {
        InviteType::User => (INVITE_PREFIX, "user", None),
        InviteType::DeviceLink { user_event_id } => (
            LINK_PREFIX,
            "device_link",
            Some(format!("/USER_ID.{}", hex::encode(user_event_id))),
        ),
    };

    let addr_tokens: Vec<String> = bootstrap_addrs.iter().map(|a| a.to_link_token()).collect();

    Ok(format!(
        "{prefix}v{ver}/{kind}/INVITE_ID.{eid}/INVITE_PRIVKEY.{key}/WORKSPACE.{wid}{uid}/DAEMON_SPKI_PUBKEY.{spki}/ADDRESS.{addrs}",
        prefix = prefix,
        ver = INVITE_LINK_VERSION,
        kind = kind_str,
        eid = hex::encode(invite.invite_event_id),
        key = hex::encode(invite.invite_key.to_bytes()),
        wid = hex::encode(invite.workspace_id),
        uid = user_segment.as_deref().unwrap_or(""),
        spki = hex::encode(daemon_spki),
        addrs = addr_tokens.join(","),
    ))
}

pub fn parse_invite_link(link: &str) -> Result<ParsedInviteLink, InviteLinkError> {
    let (kind, rest) = if let Some(rest) = link.strip_prefix(INVITE_PREFIX) {
        (InviteLinkKind::User, rest)
    } else if let Some(rest) = link.strip_prefix(LINK_PREFIX) {
        (InviteLinkKind::DeviceLink, rest)
    } else {
        return Err(InviteLinkError::InvalidPrefix);
    };

    let segments: Vec<&str> = rest.split('/').collect();

    // First segment: version
    let version_str = segments
        .first()
        .ok_or_else(|| InviteLinkError::Decode("missing version".to_string()))?;
    let version: u8 = version_str
        .strip_prefix('v')
        .and_then(|v| v.parse().ok())
        .ok_or_else(|| InviteLinkError::Decode(format!("bad version: {}", version_str)))?;
    if version != INVITE_LINK_VERSION {
        return Err(InviteLinkError::InvalidPayload(format!(
            "unsupported version {}",
            version
        )));
    }

    // Second segment: kind
    let payload_kind = segments
        .get(1)
        .ok_or_else(|| InviteLinkError::Decode("missing kind".to_string()))?;

    // Remaining segments are labeled key.value pairs
    let labeled: Vec<&str> = segments[2..].to_vec();

    let find_field = |prefix: &str| -> Option<&str> {
        labeled
            .iter()
            .find_map(|s| s.strip_prefix(prefix).map(|v| v))
    };

    let require_hex32 = |prefix: &str, label: &str| -> Result<[u8; 32], InviteLinkError> {
        let hex_str = find_field(prefix)
            .ok_or_else(|| InviteLinkError::Decode(format!("missing {}", label)))?;
        let bytes = hex::decode(hex_str)
            .map_err(|e| InviteLinkError::Decode(format!("{}: {}", label, e)))?;
        if bytes.len() != 32 {
            return Err(InviteLinkError::InvalidPayload(format!(
                "{} must be 32 bytes, got {}",
                label,
                bytes.len()
            )));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(arr)
    };

    let invite_event_id = require_hex32("INVITE_ID.", "invite_event_id")?;
    let invite_private_key = require_hex32("INVITE_PRIVKEY.", "invite_private_key")?;
    let workspace_id = require_hex32("WORKSPACE.", "workspace_id")?;
    let daemon_spki_fingerprint = require_hex32("DAEMON_SPKI_PUBKEY.", "daemon_spki")?;

    // Addresses
    let addr_str = find_field("ADDRESS.")
        .ok_or_else(|| InviteLinkError::Decode("missing ADDRESS".to_string()))?;
    let bootstrap_addrs: Vec<BootstrapAddress> = if addr_str.is_empty() {
        Vec::new()
    } else {
        addr_str
            .split(',')
            .map(|t| BootstrapAddress::from_link_token(t))
            .collect::<Result<Vec<_>, _>>()?
    };
    for addr in &bootstrap_addrs {
        addr.validate()?;
    }

    let invite_type = match (kind, *payload_kind) {
        (InviteLinkKind::User, "user") => InviteType::User,
        (InviteLinkKind::DeviceLink, "device_link") => {
            let user_event_id = require_hex32("USER_ID.", "user_event_id")?;
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
        bootstrap_addrs,
        daemon_spki_fingerprint,
    })
}

/// Re-encode an invite link with different bootstrap addresses.
/// Decodes the payload, swaps bootstrap, and re-encodes.
pub fn rewrite_bootstrap_addrs(
    link: &str,
    new_addrs: &[BootstrapAddress],
) -> Result<String, InviteLinkError> {
    let parsed = parse_invite_link(link)?;
    for addr in new_addrs {
        addr.validate()?;
    }
    let invite_data = InviteData {
        invite_event_id: parsed.invite_event_id,
        invite_key: SigningKey::from_bytes(&parsed.invite_private_key),
        workspace_id: parsed.workspace_id,
        invite_type: parsed.invite_type,
    };
    create_invite_link(&invite_data, new_addrs, &parsed.daemon_spki_fingerprint)
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
        let bootstrap_addrs = vec![BootstrapAddress::Ipv4 {
            ip: "127.0.0.1".parse().unwrap(),
            port: 4433,
        }];
        let bootstrap_spki = [4u8; 32];
        let link = create_invite_link(&invite, &bootstrap_addrs, &bootstrap_spki).unwrap();
        assert!(link.starts_with(INVITE_PREFIX));
        // Verify plaintext fields are visible
        assert!(link.contains("/INVITE_ID."));
        assert!(link.contains("/INVITE_PRIVKEY."));
        assert!(link.contains("/WORKSPACE."));
        assert!(link.contains("/DAEMON_SPKI_PUBKEY."));
        assert!(link.contains("/ADDRESS."));
        assert!(!link.contains(' '));

        let parsed = parse_invite_link(&link).unwrap();
        assert_eq!(parsed.kind, InviteLinkKind::User);
        assert_eq!(parsed.invite_event_id, invite.invite_event_id);
        assert_eq!(parsed.invite_private_key, invite.invite_key.to_bytes());
        assert_eq!(parsed.workspace_id, invite.workspace_id);
        assert_eq!(parsed.bootstrap_addrs, bootstrap_addrs);
        assert_eq!(parsed.daemon_spki_fingerprint, bootstrap_spki);
        assert!(matches!(parsed.invite_type, InviteType::User));
    }

    #[test]
    fn test_multiple_bootstrap_addrs_roundtrip() {
        let invite = InviteData {
            invite_event_id: [10u8; 32],
            invite_key: SigningKey::from_bytes(&[11u8; 32]),
            workspace_id: [12u8; 32],
            invite_type: InviteType::User,
        };
        let bootstrap_addrs = vec![
            BootstrapAddress::Ipv4 {
                ip: "192.168.1.50".parse().unwrap(),
                port: 4433,
            },
            BootstrapAddress::Ipv4 {
                ip: "100.64.1.20".parse().unwrap(),
                port: 4433,
            },
            BootstrapAddress::Hostname {
                host: "myhost.tail1234.ts.net".to_string(),
                port: 7443,
            },
        ];
        let bootstrap_spki = [13u8; 32];
        let link = create_invite_link(&invite, &bootstrap_addrs, &bootstrap_spki).unwrap();
        let parsed = parse_invite_link(&link).unwrap();
        assert_eq!(parsed.bootstrap_addrs.len(), 3);
        assert_eq!(parsed.bootstrap_addrs, bootstrap_addrs);
        assert_eq!(
            parsed.bootstrap_addr_strings(),
            vec![
                "192.168.1.50".to_string(),
                "100.64.1.20".to_string(),
                "myhost.tail1234.ts.net:7443".to_string(),
            ]
        );
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
        let bootstrap_addrs = vec![BootstrapAddress::Ipv4 {
            ip: "127.0.0.1".parse().unwrap(),
            port: 5555,
        }];
        let bootstrap_spki = [8u8; 32];
        let link = create_invite_link(&invite, &bootstrap_addrs, &bootstrap_spki).unwrap();
        assert!(link.starts_with(LINK_PREFIX));
        assert!(link.contains("/USER_ID."));

        let parsed = parse_invite_link(&link).unwrap();
        assert_eq!(parsed.kind, InviteLinkKind::DeviceLink);
        assert_eq!(parsed.invite_event_id, invite.invite_event_id);
        assert_eq!(parsed.invite_private_key, invite.invite_key.to_bytes());
        assert_eq!(parsed.workspace_id, invite.workspace_id);
        assert_eq!(parsed.bootstrap_addrs, bootstrap_addrs);
        assert_eq!(parsed.daemon_spki_fingerprint, bootstrap_spki);
        match parsed.invite_type {
            InviteType::DeviceLink {
                user_event_id: parsed_user_event_id,
            } => {
                assert_eq!(parsed_user_event_id, user_event_id);
            }
            _ => panic!("expected device link invite type"),
        }
    }

    #[test]
    fn test_ipv6_bootstrap_roundtrip() {
        let invite = InviteData {
            invite_event_id: [11u8; 32],
            invite_key: SigningKey::from_bytes(&[12u8; 32]),
            workspace_id: [13u8; 32],
            invite_type: InviteType::User,
        };
        let bootstrap_spki = [14u8; 32];
        let addrs = vec![BootstrapAddress::Ipv6 {
            ip: "2001:4860:4860::8888".parse().unwrap(),
            port: 4433,
        }];
        let link = create_invite_link(&invite, &addrs, &bootstrap_spki).unwrap();
        // Link should NOT contain brackets
        assert!(!link.contains('['));
        assert!(!link.contains(']'));
        // Should contain dash-separated expanded IPv6
        assert!(link.contains("2001-4860-4860-0000-0000-0000-0000-8888"));
        let parsed = parse_invite_link(&link).unwrap();
        assert_eq!(parsed.bootstrap_addrs, addrs);
        // Display strings still use standard bracket notation
        assert_eq!(
            parsed.bootstrap_addr_strings(),
            vec!["[2001:4860:4860::8888]"]
        );
    }

    #[test]
    fn test_ipv6_non_default_port_roundtrip() {
        let invite = InviteData {
            invite_event_id: [15u8; 32],
            invite_key: SigningKey::from_bytes(&[16u8; 32]),
            workspace_id: [17u8; 32],
            invite_type: InviteType::User,
        };
        let bootstrap_spki = [18u8; 32];
        let addrs = vec![BootstrapAddress::Ipv6 {
            ip: "::1".parse().unwrap(),
            port: 7443,
        }];
        let link = create_invite_link(&invite, &addrs, &bootstrap_spki).unwrap();
        assert!(!link.contains('['));
        assert!(!link.contains(']'));
        assert!(link.contains("0000-0000-0000-0000-0000-0000-0000-0001_7443"));
        let parsed = parse_invite_link(&link).unwrap();
        assert_eq!(parsed.bootstrap_addrs, addrs);
    }

    #[test]
    fn test_hostname_bootstrap_roundtrip() {
        let invite = InviteData {
            invite_event_id: [21u8; 32],
            invite_key: SigningKey::from_bytes(&[22u8; 32]),
            workspace_id: [23u8; 32],
            invite_type: InviteType::User,
        };
        let bootstrap_spki = [24u8; 32];
        let addrs = vec![BootstrapAddress::Hostname {
            host: "example.com".to_string(),
            port: 7000,
        }];
        let link = create_invite_link(&invite, &addrs, &bootstrap_spki).unwrap();
        let parsed = parse_invite_link(&link).unwrap();
        assert_eq!(parsed.bootstrap_addrs, addrs);
        assert_eq!(parsed.bootstrap_addr_strings(), vec!["example.com:7000"]);
    }

    #[test]
    fn test_empty_bootstrap_addrs_roundtrip() {
        let invite = InviteData {
            invite_event_id: [1u8; 32],
            invite_key: SigningKey::from_bytes(&[2u8; 32]),
            workspace_id: [3u8; 32],
            invite_type: InviteType::User,
        };
        let bootstrap_spki = [4u8; 32];
        let link = create_invite_link(&invite, &[], &bootstrap_spki).unwrap();
        assert!(link.ends_with("/ADDRESS."));
        let parsed = parse_invite_link(&link).unwrap();
        assert!(parsed.bootstrap_addrs.is_empty());
        assert_eq!(parsed.daemon_spki_fingerprint, bootstrap_spki);
    }

    #[test]
    fn test_rewrite_bootstrap_addrs() {
        let invite = InviteData {
            invite_event_id: [1u8; 32],
            invite_key: SigningKey::from_bytes(&[2u8; 32]),
            workspace_id: [3u8; 32],
            invite_type: InviteType::User,
        };
        let orig_addrs = vec![BootstrapAddress::Ipv4 {
            ip: "127.0.0.1".parse().unwrap(),
            port: 4433,
        }];
        let link = create_invite_link(&invite, &orig_addrs, &[4u8; 32]).unwrap();

        let new_addrs = vec![
            BootstrapAddress::Ipv4 {
                ip: "192.168.1.50".parse().unwrap(),
                port: 4433,
            },
            BootstrapAddress::Ipv4 {
                ip: "100.64.1.20".parse().unwrap(),
                port: 4433,
            },
        ];
        let rewritten = rewrite_bootstrap_addrs(&link, &new_addrs).unwrap();
        let parsed = parse_invite_link(&rewritten).unwrap();
        assert_eq!(parsed.bootstrap_addrs, new_addrs);
    }

    #[test]
    fn test_rewrite_bootstrap_addrs_to_empty() {
        let invite = InviteData {
            invite_event_id: [1u8; 32],
            invite_key: SigningKey::from_bytes(&[2u8; 32]),
            workspace_id: [3u8; 32],
            invite_type: InviteType::User,
        };
        let orig_addrs = vec![BootstrapAddress::Ipv4 {
            ip: "127.0.0.1".parse().unwrap(),
            port: 4433,
        }];
        let link = create_invite_link(&invite, &orig_addrs, &[4u8; 32]).unwrap();
        let rewritten = rewrite_bootstrap_addrs(&link, &[]).unwrap();
        let parsed = parse_invite_link(&rewritten).unwrap();
        assert!(parsed.bootstrap_addrs.is_empty());
    }

    #[test]
    fn test_plaintext_link_is_readable() {
        let invite = InviteData {
            invite_event_id: [0xaa; 32],
            invite_key: SigningKey::from_bytes(&[0xbb; 32]),
            workspace_id: [0xcc; 32],
            invite_type: InviteType::User,
        };
        let addrs = vec![BootstrapAddress::Ipv4 {
            ip: "192.168.1.1".parse().unwrap(),
            port: 4433,
        }];
        let spki = [0xdd; 32];
        let link = create_invite_link(&invite, &addrs, &spki).unwrap();

        // The link should contain readable hex for all fields
        assert!(link.contains(&hex::encode([0xaa; 32])));
        assert!(link.contains(&hex::encode([0xbb; 32])));
        assert!(link.contains(&hex::encode([0xcc; 32])));
        assert!(link.contains(&hex::encode([0xdd; 32])));
        assert!(link.contains("192.168.1.1"));
        // No spaces anywhere
        assert!(!link.contains(' '));
        // No base64 padding characters
        assert!(!link.contains('='));
        // No shell-problematic characters
        assert!(!link.contains('['));
        assert!(!link.contains(']'));
        assert!(!link.contains('('));
        assert!(!link.contains(')'));
        assert!(!link.contains('$'));
        assert!(!link.contains('!'));
        assert!(!link.contains('&'));
        assert!(!link.contains('|'));
        assert!(!link.contains(';'));
        assert!(!link.contains('*'));
        assert!(!link.contains('?'));
        assert!(!link.contains('~'));
        assert!(!link.contains('{'));
        assert!(!link.contains('}'));
    }
}
