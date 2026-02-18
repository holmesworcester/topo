//! Best-effort UPnP/IGD port mapping for the QUIC listen port.
//!
//! On daemon start this module attempts to create a UDP port mapping on the
//! local gateway via UPnP IGD. The result is purely informational — startup
//! continues regardless of whether the mapping succeeds.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tracing::{info, warn};

/// Outcome of a UPnP mapping attempt.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum UpnpMappingStatus {
    Success,
    Failed,
    NotAttempted,
}

/// Full report of a UPnP port-mapping attempt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpnpMappingReport {
    pub status: UpnpMappingStatus,
    pub protocol: String,
    pub local_addr: String,
    pub requested_external_port: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mapped_external_port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gateway: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// True when UPnP succeeded but the gateway's external IP is a private
    /// address, indicating double-NAT (e.g. behind CGNAT or a second router).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub double_nat: bool,
}

impl UpnpMappingReport {
    fn not_attempted(local_addr: SocketAddr, port: u16, reason: &str) -> Self {
        Self {
            status: UpnpMappingStatus::NotAttempted,
            protocol: "udp".into(),
            local_addr: local_addr.to_string(),
            requested_external_port: port,
            mapped_external_port: None,
            external_ip: None,
            gateway: None,
            error: Some(reason.into()),
            double_nat: false,
        }
    }

    fn failed(local_addr: SocketAddr, port: u16, gateway: Option<String>, err: &str) -> Self {
        Self {
            status: UpnpMappingStatus::Failed,
            protocol: "udp".into(),
            local_addr: local_addr.to_string(),
            requested_external_port: port,
            mapped_external_port: None,
            external_ip: None,
            gateway,
            error: Some(err.into()),
            double_nat: false,
        }
    }
}

/// Check whether an IP address is in a private/reserved range (RFC 1918, RFC 6598 CGNAT, etc.).
fn is_private_ip(ip_str: &str) -> bool {
    match ip_str.parse::<IpAddr>() {
        Ok(IpAddr::V4(v4)) => {
            v4.is_private()             // 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
            || v4.is_loopback()         // 127.0.0.0/8
            || v4.is_link_local()       // 169.254.0.0/16
            || v4.octets()[0] == 100 && (v4.octets()[1] & 0xC0) == 64  // 100.64.0.0/10 (CGNAT)
        }
        Ok(IpAddr::V6(v6)) => {
            v6.is_loopback() || v6.to_ipv4_mapped().is_some_and(|v4| {
                v4.is_private() || v4.is_loopback() || v4.is_link_local()
            })
        }
        Err(_) => false,
    }
}

/// Discover the LAN IP the OS would use to reach the public internet.
///
/// Reuses the same UDP-connect trick from `discovery.rs`.
fn discover_lan_ip() -> Option<IpAddr> {
    let socket = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("8.8.8.8:80").ok()?;
    Some(socket.local_addr().ok()?.ip())
}

/// Attempt a UDP port mapping via UPnP IGD.
///
/// `local_bind` is the address the QUIC endpoint actually bound to.
/// `timeout` caps the total time spent on gateway discovery + mapping.
///
/// Returns a report regardless of outcome. This function never panics.
pub async fn attempt_udp_port_mapping(
    local_bind: SocketAddr,
    timeout: Duration,
) -> UpnpMappingReport {
    let port = local_bind.port();

    // Determine the LAN IP to use for the mapping target.
    let lan_ip = if local_bind.ip().is_unspecified() || local_bind.ip().is_loopback() {
        match discover_lan_ip() {
            Some(ip) => ip,
            None => {
                return UpnpMappingReport::not_attempted(
                    local_bind,
                    port,
                    "could not discover LAN IP for mapping",
                );
            }
        }
    } else {
        local_bind.ip()
    };

    let mapping_target = SocketAddr::new(lan_ip, port);

    // Search for IGD gateway with timeout.
    let search_opts = igd_next::SearchOptions {
        timeout: Some(timeout),
        ..Default::default()
    };

    let gateway = match tokio::time::timeout(
        timeout,
        igd_next::aio::tokio::search_gateway(search_opts),
    )
    .await
    {
        Ok(Ok(gw)) => gw,
        Ok(Err(e)) => {
            let msg = format!("gateway discovery failed: {}", e);
            warn!("UPnP: {}", msg);
            return UpnpMappingReport::failed(local_bind, port, None, &msg);
        }
        Err(_) => {
            let msg = "gateway discovery timed out";
            warn!("UPnP: {}", msg);
            return UpnpMappingReport::failed(local_bind, port, None, msg);
        }
    };

    let gw_addr = gateway.addr.to_string();
    info!("UPnP: found gateway at {}", gw_addr);

    // Try to get external IP (best-effort).
    let external_ip =
        match tokio::time::timeout(Duration::from_secs(5), gateway.get_external_ip()).await {
            Ok(Ok(ip)) => Some(ip.to_string()),
            _ => None,
        };

    // Try exact port first.
    let lease_duration = 3600; // 1 hour
    let description = "topo-quic";

    match gateway
        .add_port(
            igd_next::PortMappingProtocol::UDP,
            port,
            mapping_target,
            lease_duration,
            description,
        )
        .await
    {
        Ok(()) => {
            let double_nat = external_ip.as_deref().is_some_and(is_private_ip);
            if double_nat {
                warn!(
                    "UPnP: double-NAT detected — gateway external IP {} is private",
                    external_ip.as_deref().unwrap_or("?")
                );
            }
            info!(
                "UPnP: mapped udp external_port={} -> {} (gateway={})",
                port, mapping_target, gw_addr
            );
            return UpnpMappingReport {
                status: UpnpMappingStatus::Success,
                protocol: "udp".into(),
                local_addr: mapping_target.to_string(),
                requested_external_port: port,
                mapped_external_port: Some(port),
                external_ip,
                gateway: Some(gw_addr),
                error: None,
                double_nat,
            };
        }
        Err(e) => {
            warn!("UPnP: exact port {} refused ({}), trying any port", port, e);
        }
    }

    // Fallback: let the router pick any external port.
    match gateway
        .add_any_port(
            igd_next::PortMappingProtocol::UDP,
            mapping_target,
            lease_duration,
            description,
        )
        .await
    {
        Ok(mapped_port) => {
            let double_nat = external_ip.as_deref().is_some_and(is_private_ip);
            if double_nat {
                warn!(
                    "UPnP: double-NAT detected — gateway external IP {} is private",
                    external_ip.as_deref().unwrap_or("?")
                );
            }
            info!(
                "UPnP: mapped udp external_port={} -> {} (gateway={})",
                mapped_port, mapping_target, gw_addr
            );
            UpnpMappingReport {
                status: UpnpMappingStatus::Success,
                protocol: "udp".into(),
                local_addr: mapping_target.to_string(),
                requested_external_port: port,
                mapped_external_port: Some(mapped_port),
                external_ip,
                gateway: Some(gw_addr),
                error: None,
                double_nat,
            }
        }
        Err(e) => {
            let msg = format!("add_any_port failed: {}", e);
            warn!("UPnP: {}", msg);
            UpnpMappingReport::failed(local_bind, port, Some(gw_addr), &msg)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_not_attempted_shape() {
        let addr: SocketAddr = "127.0.0.1:4433".parse().unwrap();
        let report = UpnpMappingReport::not_attempted(addr, 4433, "no LAN IP");
        assert_eq!(report.status, UpnpMappingStatus::NotAttempted);
        assert_eq!(report.protocol, "udp");
        assert_eq!(report.requested_external_port, 4433);
        assert!(report.mapped_external_port.is_none());
        assert!(report.external_ip.is_none());
        assert!(report.gateway.is_none());
        assert_eq!(report.error.as_deref(), Some("no LAN IP"));
    }

    #[test]
    fn report_failed_shape() {
        let addr: SocketAddr = "192.168.1.10:5000".parse().unwrap();
        let report =
            UpnpMappingReport::failed(addr, 5000, Some("192.168.1.1:5431".into()), "refused");
        assert_eq!(report.status, UpnpMappingStatus::Failed);
        assert_eq!(report.local_addr, "192.168.1.10:5000");
        assert_eq!(report.requested_external_port, 5000);
        assert!(report.mapped_external_port.is_none());
        assert_eq!(report.gateway.as_deref(), Some("192.168.1.1:5431"));
        assert_eq!(report.error.as_deref(), Some("refused"));
    }

    #[test]
    fn report_success_shape() {
        let report = UpnpMappingReport {
            status: UpnpMappingStatus::Success,
            protocol: "udp".into(),
            local_addr: "192.168.1.10:4433".into(),
            requested_external_port: 4433,
            mapped_external_port: Some(4433),
            external_ip: Some("203.0.113.5".into()),
            gateway: Some("192.168.1.1:5431".into()),
            error: None,
            double_nat: false,
        };
        assert_eq!(report.status, UpnpMappingStatus::Success);
        assert_eq!(report.mapped_external_port, Some(4433));
        assert_eq!(report.external_ip.as_deref(), Some("203.0.113.5"));
        assert!(report.error.is_none());
        assert!(!report.double_nat);
    }

    #[test]
    fn report_serializes_to_json() {
        let report = UpnpMappingReport {
            status: UpnpMappingStatus::Success,
            protocol: "udp".into(),
            local_addr: "192.168.1.10:4433".into(),
            requested_external_port: 4433,
            mapped_external_port: Some(4433),
            external_ip: Some("203.0.113.5".into()),
            gateway: Some("192.168.1.1:5431".into()),
            error: None,
            double_nat: false,
        };
        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(json["status"], "success");
        assert_eq!(json["protocol"], "udp");
        assert_eq!(json["mapped_external_port"], 4433);
        assert_eq!(json["external_ip"], "203.0.113.5");
        // error and double_nat should be absent (skip_serializing_if)
        assert!(json.get("error").is_none());
        assert!(json.get("double_nat").is_none());
    }

    #[test]
    fn double_nat_detected_for_private_external_ip() {
        assert!(is_private_ip("10.0.0.88"));
        assert!(is_private_ip("192.168.1.1"));
        assert!(is_private_ip("172.16.0.1"));
        assert!(is_private_ip("100.64.0.1"));   // CGNAT
        assert!(is_private_ip("127.0.0.1"));
        assert!(!is_private_ip("203.0.113.5"));
        assert!(!is_private_ip("73.15.131.63"));
        assert!(!is_private_ip("8.8.8.8"));
    }

    #[test]
    fn report_double_nat_serializes() {
        let report = UpnpMappingReport {
            status: UpnpMappingStatus::Success,
            protocol: "udp".into(),
            local_addr: "192.168.1.10:4433".into(),
            requested_external_port: 4433,
            mapped_external_port: Some(4433),
            external_ip: Some("10.0.0.88".into()),
            gateway: Some("192.168.4.1:1900".into()),
            error: None,
            double_nat: true,
        };
        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(json["double_nat"], true);
    }

    #[test]
    fn report_not_attempted_serializes_status() {
        let addr: SocketAddr = "127.0.0.1:4433".parse().unwrap();
        let report = UpnpMappingReport::not_attempted(addr, 4433, "loopback only");
        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(json["status"], "not_attempted");
        assert_eq!(json["error"], "loopback only");
    }

    #[test]
    fn discover_lan_ip_returns_non_loopback() {
        // This test is environment-dependent; skip gracefully in CI with no network.
        if let Some(ip) = discover_lan_ip() {
            assert!(!ip.is_loopback(), "LAN IP should not be loopback");
            assert!(!ip.is_unspecified(), "LAN IP should not be unspecified");
        }
    }
}
