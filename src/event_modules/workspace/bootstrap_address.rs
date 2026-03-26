use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};

/// Default QUIC sync port — omitted from display strings when matched.
pub const DEFAULT_PORT: u16 = 4433;

#[derive(Debug, thiserror::Error)]
pub enum BootstrapAddressError {
    #[error("invalid bootstrap address: {0}")]
    Invalid(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum BootstrapAddress {
    Ipv4 { ip: Ipv4Addr, port: u16 },
    Ipv6 { ip: Ipv6Addr, port: u16 },
    Hostname { host: String, port: u16 },
}

impl BootstrapAddress {
    pub fn validate(&self) -> Result<(), BootstrapAddressError> {
        if let BootstrapAddress::Hostname { host, .. } = self {
            if host.is_empty() {
                return Err(BootstrapAddressError::Invalid(
                    "bootstrap hostname is empty".to_string(),
                ));
            }
            if host.contains(':') {
                return Err(BootstrapAddressError::Invalid(
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

    pub fn to_socket_addr(&self) -> Result<SocketAddr, BootstrapAddressError> {
        match self {
            BootstrapAddress::Ipv4 { ip, port } => Ok(SocketAddr::new(IpAddr::V4(*ip), *port)),
            BootstrapAddress::Ipv6 { ip, port } => Ok(SocketAddr::new(IpAddr::V6(*ip), *port)),
            BootstrapAddress::Hostname { host, port } => {
                let mut it = (host.as_str(), *port)
                    .to_socket_addrs()
                    .map_err(|e| BootstrapAddressError::Invalid(e.to_string()))?;
                it.next().ok_or_else(|| {
                    BootstrapAddressError::Invalid(format!(
                        "no addresses resolved for bootstrap host '{}'",
                        host
                    ))
                })
            }
        }
    }

    /// Encode for the comma-separated addr segment inside invite links.
    ///
    /// IPv6 addresses are fully expanded as 8 dash-separated groups of 4 hex
    /// digits (no square brackets) so the resulting URL is safe for shells and
    /// linkification.  Non-default ports use `_port` suffix.
    pub(crate) fn to_link_token(&self) -> String {
        match self {
            BootstrapAddress::Ipv4 { ip, port } if *port == DEFAULT_PORT => format!("{}", ip),
            BootstrapAddress::Ipv4 { ip, port } => format!("{}:{}", ip, port),
            BootstrapAddress::Ipv6 { ip, port } => {
                let segs = ip.segments();
                let expanded = format!(
                    "{:04x}-{:04x}-{:04x}-{:04x}-{:04x}-{:04x}-{:04x}-{:04x}",
                    segs[0], segs[1], segs[2], segs[3], segs[4], segs[5], segs[6], segs[7]
                );
                if *port == DEFAULT_PORT {
                    expanded
                } else {
                    format!("{}_{}", expanded, port)
                }
            }
            BootstrapAddress::Hostname { host, port } if *port == DEFAULT_PORT => host.clone(),
            BootstrapAddress::Hostname { host, port } => format!("{}:{}", host, port),
        }
    }

    /// Parse one token from the comma-separated addr segment in an invite link.
    pub(crate) fn from_link_token(token: &str) -> Result<Self, BootstrapAddressError> {
        // Try dash-separated fully-expanded IPv6, optionally with _port suffix.
        if let Some(result) = Self::try_parse_dash_ipv6(token) {
            return result;
        }

        // IPv4 (bare or with :port), hostname (bare or with :port).
        parse_bootstrap_address(token)
    }

    /// Try to parse a dash-separated fully-expanded IPv6 link token.
    /// Returns `None` if the token doesn't match the pattern, or
    /// `Some(Ok/Err)` if it does.
    fn try_parse_dash_ipv6(token: &str) -> Option<Result<Self, BootstrapAddressError>> {
        // Split off optional _port suffix
        let (addr_part, port) = if let Some((a, p)) = token.rsplit_once('_') {
            match p.parse::<u16>() {
                Ok(port) => (a, port),
                Err(_) => (token, DEFAULT_PORT),
            }
        } else {
            (token, DEFAULT_PORT)
        };

        let groups: Vec<&str> = addr_part.split('-').collect();
        if groups.len() != 8 {
            return None;
        }

        let mut segments = [0u16; 8];
        for (i, g) in groups.iter().enumerate() {
            if g.len() != 4 {
                return None;
            }
            match u16::from_str_radix(g, 16) {
                Ok(v) => segments[i] = v,
                Err(_) => return None,
            }
        }

        let ip = Ipv6Addr::new(
            segments[0],
            segments[1],
            segments[2],
            segments[3],
            segments[4],
            segments[5],
            segments[6],
            segments[7],
        );
        Some(Ok(BootstrapAddress::Ipv6 { ip, port }))
    }
}

pub fn parse_bootstrap_address(
    bootstrap_addr: &str,
) -> Result<BootstrapAddress, BootstrapAddressError> {
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
                return Err(BootstrapAddressError::Invalid(
                    "bootstrap hostname is empty".to_string(),
                ));
            }
            if host.contains(':') {
                return Err(BootstrapAddressError::Invalid(
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
        return Err(BootstrapAddressError::Invalid(
            "bootstrap hostname is empty".to_string(),
        ));
    }
    if host.contains(':') {
        return Err(BootstrapAddressError::Invalid(
            "bootstrap IPv6 addresses must use [addr]:port form".to_string(),
        ));
    }
    Ok(BootstrapAddress::Hostname {
        host: host.to_string(),
        port: DEFAULT_PORT,
    })
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
        let err = parse_bootstrap_address("2001:4860:4860::8888:4433").unwrap_err();
        assert!(err.to_string().contains("IPv6"));
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
    fn test_ipv6_link_token_roundtrip_default_port() {
        let addr = BootstrapAddress::Ipv6 {
            ip: "2001:4860:4860::8888".parse().unwrap(),
            port: DEFAULT_PORT,
        };
        let token = addr.to_link_token();
        assert_eq!(token, "2001-4860-4860-0000-0000-0000-0000-8888");
        let parsed = BootstrapAddress::from_link_token(&token).unwrap();
        assert_eq!(parsed, addr);
    }

    #[test]
    fn test_ipv6_link_token_roundtrip_non_default_port() {
        let addr = BootstrapAddress::Ipv6 {
            ip: "::1".parse().unwrap(),
            port: 7443,
        };
        let token = addr.to_link_token();
        assert_eq!(token, "0000-0000-0000-0000-0000-0000-0000-0001_7443");
        let parsed = BootstrapAddress::from_link_token(&token).unwrap();
        assert_eq!(parsed, addr);
    }
}
