//! Best-effort UPnP/IGD port mapping for the QUIC listen port.
//!
//! On daemon start this module attempts to create a UDP port mapping on the
//! local gateway via UPnP IGD. The result is purely informational — startup
//! continues regardless of whether the mapping succeeds.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
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
    /// True when UPnP succeeded but the gateway's external IP is not publicly
    /// routable, indicating double-NAT (e.g. behind CGNAT or a second router).
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

/// Discover the LAN IP the OS would use to reach the public internet.
///
/// Reuses the same UDP-connect trick from `discovery.rs`.
fn discover_lan_ip() -> Option<IpAddr> {
    let socket = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("8.8.8.8:80").ok()?;
    Some(socket.local_addr().ok()?.ip())
}

fn is_public_ipv4(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    // RFC1918 private ranges.
    if o[0] == 10 || (o[0] == 172 && (16..=31).contains(&o[1])) || (o[0] == 192 && o[1] == 168) {
        return false;
    }
    // Loopback, link-local, multicast/reserved, unspecified, broadcast.
    if o[0] == 127
        || (o[0] == 169 && o[1] == 254)
        || o[0] >= 224
        || o[0] == 0
        || (o[0] == 255 && o[1] == 255 && o[2] == 255 && o[3] == 255)
    {
        return false;
    }
    // Carrier-grade NAT (100.64.0.0/10).
    if o[0] == 100 && (64..=127).contains(&o[1]) {
        return false;
    }
    // Benchmarking range (198.18.0.0/15).
    if o[0] == 198 && (o[1] == 18 || o[1] == 19) {
        return false;
    }
    // Documentation/test ranges.
    if (o[0] == 192 && o[1] == 0 && o[2] == 2)
        || (o[0] == 198 && o[1] == 51 && o[2] == 100)
        || (o[0] == 203 && o[1] == 0 && o[2] == 113)
    {
        return false;
    }
    true
}

fn is_public_ipv6(ip: Ipv6Addr) -> bool {
    if let Some(v4) = ip.to_ipv4() {
        return is_public_ipv4(v4);
    }
    if ip.is_unspecified() || ip.is_loopback() || ip.is_multicast() {
        return false;
    }
    let s = ip.segments();
    // fc00::/7 unique local.
    if (s[0] & 0xfe00) == 0xfc00 {
        return false;
    }
    // fe80::/10 link-local.
    if (s[0] & 0xffc0) == 0xfe80 {
        return false;
    }
    // 2001:db8::/32 documentation range.
    if s[0] == 0x2001 && s[1] == 0x0db8 {
        return false;
    }
    true
}

pub fn is_public_internet_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_public_ipv4(v4),
        IpAddr::V6(v6) => is_public_ipv6(v6),
    }
}

fn external_ip_not_public(external_ip: &Option<String>) -> bool {
    external_ip
        .as_deref()
        .and_then(|ip| ip.parse::<IpAddr>().ok())
        .map(|ip| !is_public_internet_ip(ip))
        .unwrap_or(false)
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

    // Mapping loopback listeners is misleading: traffic is forwarded to LAN IP:port,
    // but a loopback-bound daemon only accepts 127.0.0.1 traffic.
    if local_bind.ip().is_loopback() {
        return UpnpMappingReport::not_attempted(
            local_bind,
            port,
            "listen address is loopback; restart with --bind 0.0.0.0:<port> for UPnP",
        );
    }

    // Determine the LAN IP to use for the mapping target.
    let lan_ip = if local_bind.ip().is_unspecified() {
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
            let double_nat = external_ip_not_public(&external_ip);
            if double_nat {
                warn!(
                    "UPnP: double-NAT detected — gateway external IP {} is not publicly routable",
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
            let double_nat = external_ip_not_public(&external_ip);
            if double_nat {
                warn!(
                    "UPnP: double-NAT detected — gateway external IP {} is not publicly routable",
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
    fn external_ip_not_public_detects_double_nat_like_conditions() {
        assert!(external_ip_not_public(&Some("10.0.0.88".into())));
        assert!(external_ip_not_public(&Some("100.64.0.1".into()))); // CGNAT
        assert!(external_ip_not_public(&Some("fd12::1".into())));
        assert!(!external_ip_not_public(&Some("8.8.8.8".into())));
        assert!(!external_ip_not_public(&Some(
            "2001:4860:4860::8888".into()
        )));
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

    #[test]
    fn public_ip_classifier_filters_private_and_cgnat() {
        assert!(!is_public_internet_ip("10.0.0.88".parse().unwrap()));
        assert!(!is_public_internet_ip("100.64.10.20".parse().unwrap()));
        assert!(!is_public_internet_ip("127.0.0.1".parse().unwrap()));
        assert!(is_public_internet_ip("8.8.8.8".parse().unwrap()));
    }

    #[test]
    fn public_ip_classifier_filters_non_global_ipv6() {
        assert!(!is_public_internet_ip("::1".parse().unwrap()));
        assert!(!is_public_internet_ip("fd12::1".parse().unwrap()));
        assert!(!is_public_internet_ip("fe80::1".parse().unwrap()));
        assert!(is_public_internet_ip(
            "2001:4860:4860::8888".parse().unwrap()
        ));
    }

    #[tokio::test]
    async fn loopback_listener_skips_mapping() {
        let report = attempt_udp_port_mapping(
            "127.0.0.1:4433".parse().unwrap(),
            Duration::from_millis(200),
        )
        .await;
        assert_eq!(report.status, UpnpMappingStatus::NotAttempted);
        assert_eq!(
            report.error.as_deref(),
            Some("listen address is loopback; restart with --bind 0.0.0.0:<port> for UPnP")
        );
    }
}
