use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};

use super::identity_ops::{InviteData, InviteType};
use crate::crypto::EventId;

const INVITE_PREFIX: &str = "topo://invite/";
const LINK_PREFIX: &str = "topo://link/";
const INVITE_LINK_VERSION: u8 = 4;

/// Default QUIC sync port — omitted from display strings when matched.
pub const DEFAULT_PORT: u16 = 4433;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InviteLinkKind {
    User,
    DeviceLink,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum BootstrapAddress {
    Ipv4 { ip: Ipv4Addr, port: u16 },
    Ipv6 { ip: Ipv6Addr, port: u16 },
    Hostname { host: String, port: u16 },
}

impl BootstrapAddress {
    fn validate(&self) -> Result<(), InviteLinkError> {
        if let BootstrapAddress::Hostname { host, .. } = self {
            if host.is_empty() {
                return Err(InviteLinkError::InvalidPayload(
                    "bootstrap hostname is empty".to_string(),
                ));
            }
            if host.contains(':') {
                return Err(InviteLinkError::InvalidPayload(
                    "bootstrap hostname must not contain ':'".to_string(),
                ));
            }
        }
        Ok(())
    }

    pub fn to_bootstrap_addr_string(&self) -> String {
        match self {
            BootstrapAddress::Ipv4 { ip, port } if *port == DEFAULT_PORT => format!("{}", ip),
            BootstrapAddress::Ipv4 { ip, port } => format!("{}:{}", ip, port),
            BootstrapAddress::Ipv6 { ip, port } if *port == DEFAULT_PORT => format!("[{}]", ip),
            BootstrapAddress::Ipv6 { ip, port } => format!("[{}]:{}", ip, port),
            BootstrapAddress::Hostname { host, port } if *port == DEFAULT_PORT => host.clone(),
            BootstrapAddress::Hostname { host, port } => format!("{}:{}", host, port),
        }
    }

    pub fn to_socket_addr(&self) -> Result<SocketAddr, InviteLinkError> {
        match self {
            BootstrapAddress::Ipv4 { ip, port } => Ok(SocketAddr::new(IpAddr::V4(*ip), *port)),
            BootstrapAddress::Ipv6 { ip, port } => Ok(SocketAddr::new(IpAddr::V6(*ip), *port)),
            BootstrapAddress::Hostname { host, port } => {
                let mut it = (host.as_str(), *port)
                    .to_socket_addrs()
                    .map_err(|e| InviteLinkError::InvalidPayload(e.to_string()))?;
                it.next().ok_or_else(|| {
                    InviteLinkError::InvalidPayload(format!(
                        "no addresses resolved for bootstrap host '{}'",
                        host
                    ))
                })
            }
        }
    }

    /// Encode for the comma-separated addr segment. Uses the same display
    /// format as `to_bootstrap_addr_string` (port omitted when default).
    fn to_link_token(&self) -> String {
        self.to_bootstrap_addr_string()
    }

    /// Parse one token from the comma-separated addr segment.
    fn from_link_token(token: &str) -> Result<Self, InviteLinkError> {
        parse_bootstrap_address(token)
    }
}

pub fn parse_bootstrap_address(bootstrap_addr: &str) -> Result<BootstrapAddress, InviteLinkError> {
    // Try full socket addr first (e.g. "1.2.3.4:5555", "[::1]:5555")
    if let Ok(sock) = bootstrap_addr.parse::<SocketAddr>() {
        return Ok(match sock.ip() {
            IpAddr::V4(ip) => BootstrapAddress::Ipv4 {
                ip,
                port: sock.port(),
            },
            IpAddr::V6(ip) => BootstrapAddress::Ipv6 {
                ip,
                port: sock.port(),
            },
        });
    }

    // Bare IPv4 (e.g. "100.64.1.20")
    if let Ok(ip) = bootstrap_addr.parse::<Ipv4Addr>() {
        return Ok(BootstrapAddress::Ipv4 {
            ip,
            port: DEFAULT_PORT,
        });
    }

    // Bracketed IPv6 without port (e.g. "[::1]")
    if bootstrap_addr.starts_with('[') && bootstrap_addr.ends_with(']') {
        let inner = &bootstrap_addr[1..bootstrap_addr.len() - 1];
        if let Ok(ip) = inner.parse::<Ipv6Addr>() {
            return Ok(BootstrapAddress::Ipv6 {
                ip,
                port: DEFAULT_PORT,
            });
        }
    }

    // host:port form
    if let Some((host_raw, port_raw)) = bootstrap_addr.rsplit_once(':') {
        // Only treat as host:port if port_raw parses as u16
        // (avoids misparse of unbracketed IPv6)
        if let Ok(port) = port_raw.parse::<u16>() {
            let host = host_raw.trim();
            if host.is_empty() {
                return Err(InviteLinkError::InvalidPayload(
                    "bootstrap hostname is empty".to_string(),
                ));
            }
            if host.contains(':') {
                return Err(InviteLinkError::InvalidPayload(
                    "bootstrap IPv6 addresses must use [addr]:port form".to_string(),
                ));
            }
            return Ok(BootstrapAddress::Hostname {
                host: host.to_string(),
                port,
            });
        }
    }

    // Bare hostname (e.g. "ryzen", "example.com") — infer default port
    let host = bootstrap_addr.trim();
    if host.is_empty() {
        return Err(InviteLinkError::InvalidPayload(
            "bootstrap hostname is empty".to_string(),
        ));
    }
    if host.contains(':') {
        return Err(InviteLinkError::InvalidPayload(
            "bootstrap IPv6 addresses must use [addr]:port form".to_string(),
        ));
    }
    Ok(BootstrapAddress::Hostname {
        host: host.to_string(),
        port: DEFAULT_PORT,
    })
}

pub fn resolve_bootstrap_socket_addrs(
    invite: &ParsedInviteLink,
) -> Vec<Result<SocketAddr, InviteLinkError>> {
    invite
        .bootstrap_addrs
        .iter()
        .map(|a| a.to_socket_addr())
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
    pub bootstrap_spki_fingerprint: [u8; 32],
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

// ---------------------------------------------------------------------------
// Plaintext invite link format (v4)
//
// All fields are hex-encoded and slash-delimited with self-explanatory labels.
// No spaces, no base64 — fully readable and continuously linkifiable.
//
// User invite:
//   topo://invite/v4/user/INVITE_ID.<hex64>/INVITE_PRIVKEY.<hex64>/WORKSPACE.<hex64>/PEER_SPKI_PUBKEY.<hex64>/ADDRESS.<a1>,<a2>
//
// Device-link invite:
//   topo://link/v4/device_link/INVITE_ID.<hex64>/INVITE_PRIVKEY.<hex64>/WORKSPACE.<hex64>/USER_ID.<hex64>/PEER_SPKI_PUBKEY.<hex64>/ADDRESS.<a1>,<a2>
//
// Address tokens use the same display format as to_bootstrap_addr_string
// (port omitted when default 4433, IPv6 bracketed).
// ---------------------------------------------------------------------------

pub fn create_invite_link(
    invite: &InviteData,
    bootstrap_addrs: &[BootstrapAddress],
    bootstrap_spki: &[u8; 32],
) -> Result<String, InviteLinkError> {
    if bootstrap_addrs.is_empty() {
        return Err(InviteLinkError::InvalidPayload(
            "at least one bootstrap address is required".to_string(),
        ));
    }
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
        "{prefix}v{ver}/{kind}/INVITE_ID.{eid}/INVITE_PRIVKEY.{key}/WORKSPACE.{wid}{uid}/PEER_SPKI_PUBKEY.{spki}/ADDRESS.{addrs}",
        prefix = prefix,
        ver = INVITE_LINK_VERSION,
        kind = kind_str,
        eid = hex::encode(invite.invite_event_id),
        key = hex::encode(invite.invite_key.to_bytes()),
        wid = hex::encode(invite.workspace_id),
        uid = user_segment.as_deref().unwrap_or(""),
        spki = hex::encode(bootstrap_spki),
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
    let bootstrap_spki_fingerprint = require_hex32("PEER_SPKI_PUBKEY.", "bootstrap_spki")?;

    // Addresses
    let addr_str = find_field("ADDRESS.")
        .ok_or_else(|| InviteLinkError::Decode("missing ADDRESS".to_string()))?;
    if addr_str.is_empty() {
        return Err(InviteLinkError::InvalidPayload(
            "at least one bootstrap address is required".to_string(),
        ));
    }
    let bootstrap_addrs: Vec<BootstrapAddress> = addr_str
        .split(',')
        .map(|t| BootstrapAddress::from_link_token(t))
        .collect::<Result<Vec<_>, _>>()?;
    if bootstrap_addrs.is_empty() {
        return Err(InviteLinkError::InvalidPayload(
            "at least one bootstrap address is required".to_string(),
        ));
    }
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
        bootstrap_spki_fingerprint,
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
    create_invite_link(&invite_data, new_addrs, &parsed.bootstrap_spki_fingerprint)
}

/// Detect non-loopback IPv4/IPv6 addresses on this machine, suitable for
/// embedding in invite links. Filters out loopback and link-local addresses.
pub fn detect_bootstrap_addrs(port: u16) -> Vec<BootstrapAddress> {
    let mut addrs = Vec::new();
    if let Ok(ifaces) = if_addrs::get_if_addrs() {
        for iface in ifaces {
            let ip = iface.ip();
            if ip.is_loopback() {
                continue;
            }
            // Skip link-local
            match ip {
                IpAddr::V4(v4) => {
                    if v4.is_link_local() {
                        continue;
                    }
                    addrs.push(BootstrapAddress::Ipv4 { ip: v4, port });
                }
                IpAddr::V6(v6) => {
                    // Skip link-local fe80::/10
                    let seg0 = v6.segments()[0];
                    if seg0 & 0xffc0 == 0xfe80 {
                        continue;
                    }
                    addrs.push(BootstrapAddress::Ipv6 { ip: v6, port });
                }
            }
        }
    }
    addrs
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
        assert!(link.contains("/PEER_SPKI_PUBKEY."));
        assert!(link.contains("/ADDRESS."));
        assert!(!link.contains(' '));

        let parsed = parse_invite_link(&link).unwrap();
        assert_eq!(parsed.kind, InviteLinkKind::User);
        assert_eq!(parsed.invite_event_id, invite.invite_event_id);
        assert_eq!(parsed.invite_private_key, invite.invite_key.to_bytes());
        assert_eq!(parsed.workspace_id, invite.workspace_id);
        assert_eq!(parsed.bootstrap_addrs, bootstrap_addrs);
        assert_eq!(parsed.bootstrap_spki_fingerprint, bootstrap_spki);
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
        let parsed = parse_invite_link(&link).unwrap();
        assert_eq!(parsed.bootstrap_addrs, addrs);
        assert_eq!(
            parsed.bootstrap_addr_strings(),
            vec!["[2001:4860:4860::8888]"]
        );
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
    fn test_empty_bootstrap_addrs_rejected() {
        let invite = InviteData {
            invite_event_id: [1u8; 32],
            invite_key: SigningKey::from_bytes(&[2u8; 32]),
            workspace_id: [3u8; 32],
            invite_type: InviteType::User,
        };
        let err = create_invite_link(&invite, &[], &[4u8; 32]).unwrap_err();
        assert!(err.to_string().contains("at least one bootstrap address"));
    }

    #[test]
    fn test_bare_ipv4_infers_default_port() {
        let addr = parse_bootstrap_address("100.64.1.20").unwrap();
        assert_eq!(
            addr,
            BootstrapAddress::Ipv4 {
                ip: "100.64.1.20".parse().unwrap(),
                port: DEFAULT_PORT
            }
        );
        assert_eq!(addr.to_bootstrap_addr_string(), "100.64.1.20");
    }

    #[test]
    fn test_bare_hostname_infers_default_port() {
        let addr = parse_bootstrap_address("ryzen").unwrap();
        assert_eq!(
            addr,
            BootstrapAddress::Hostname {
                host: "ryzen".to_string(),
                port: DEFAULT_PORT
            }
        );
        assert_eq!(addr.to_bootstrap_addr_string(), "ryzen");
    }

    #[test]
    fn test_bare_bracketed_ipv6_infers_default_port() {
        let addr = parse_bootstrap_address("[::1]").unwrap();
        assert_eq!(
            addr,
            BootstrapAddress::Ipv6 {
                ip: "::1".parse().unwrap(),
                port: DEFAULT_PORT
            }
        );
        assert_eq!(addr.to_bootstrap_addr_string(), "[::1]");
    }

    #[test]
    fn test_non_default_port_shown_in_display() {
        let addr = parse_bootstrap_address("10.0.0.1:5555").unwrap();
        assert_eq!(addr.to_bootstrap_addr_string(), "10.0.0.1:5555");
    }

    #[test]
    fn test_unbracketed_ipv6_bootstrap_is_rejected() {
        let invite = InviteData {
            invite_event_id: [31u8; 32],
            invite_key: SigningKey::from_bytes(&[32u8; 32]),
            workspace_id: [33u8; 32],
            invite_type: InviteType::User,
        };
        let bootstrap_spki = [34u8; 32];
        let addrs = vec![parse_bootstrap_address("10.0.0.1:4433").unwrap()];
        // The unbracketed IPv6 fails at parse_bootstrap_address level
        let err = parse_bootstrap_address("2001:4860:4860::8888:4433").unwrap_err();
        assert!(err.to_string().contains("IPv6"));
        // Ensure normal invite still works
        let _ = create_invite_link(&invite, &addrs, &bootstrap_spki).unwrap();
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
    fn test_detect_bootstrap_addrs_returns_non_loopback() {
        let addrs = detect_bootstrap_addrs(4433);
        // Should have at least no loopback addresses
        for addr in &addrs {
            match addr {
                BootstrapAddress::Ipv4 { ip, .. } => {
                    assert!(!ip.is_loopback(), "loopback should be filtered: {}", ip);
                    assert!(!ip.is_link_local(), "link-local should be filtered: {}", ip);
                }
                BootstrapAddress::Ipv6 { ip, .. } => {
                    assert!(!ip.is_loopback(), "loopback should be filtered: {}", ip);
                    let seg0 = ip.segments()[0];
                    assert!(
                        seg0 & 0xffc0 != 0xfe80,
                        "link-local should be filtered: {}",
                        ip
                    );
                }
                BootstrapAddress::Hostname { .. } => {
                    panic!("detect should not return hostnames");
                }
            }
        }
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
    }
}
