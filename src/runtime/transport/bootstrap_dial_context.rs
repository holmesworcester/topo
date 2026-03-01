//! Canonical outbound dial decision after the primary ongoing-cert attempt.
//!
//! This centralizes ongoing-first/bootstrap-fallback policy so connect paths
//! use one deterministic rule:
//! - success on primary attempt => ongoing mode
//! - typed trust rejection + fallback config => bootstrap fallback mode
//! - otherwise => deny (no fallback retry)

use super::connection_lifecycle::ConnectionLifecycleError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootstrapDialMode {
    Ongoing,
    BootstrapFallback,
    Deny,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BootstrapDialContext {
    pub mode: BootstrapDialMode,
}

pub fn derive_bootstrap_dial_context(
    primary_error: Option<&ConnectionLifecycleError>,
    has_bootstrap_fallback_config: bool,
) -> BootstrapDialContext {
    let mode = match primary_error {
        None => BootstrapDialMode::Ongoing,
        Some(ConnectionLifecycleError::DialTrustRejected(_)) if has_bootstrap_fallback_config => {
            BootstrapDialMode::BootstrapFallback
        }
        Some(_) => BootstrapDialMode::Deny,
    };
    BootstrapDialContext { mode }
}

#[cfg(test)]
mod tests {
    use super::{derive_bootstrap_dial_context, BootstrapDialMode};
    use crate::runtime::transport::connection_lifecycle::ConnectionLifecycleError;

    #[test]
    fn primary_success_is_ongoing_mode() {
        let ctx = derive_bootstrap_dial_context(None, false);
        assert_eq!(ctx.mode, BootstrapDialMode::Ongoing);
    }

    #[test]
    fn trust_rejection_with_fallback_uses_bootstrap_mode() {
        let err = ConnectionLifecycleError::DialTrustRejected(
            "handshake to 127.0.0.1:4433: trust_rejected".to_string(),
        );
        let ctx = derive_bootstrap_dial_context(Some(&err), true);
        assert_eq!(ctx.mode, BootstrapDialMode::BootstrapFallback);
    }

    #[test]
    fn trust_rejection_without_fallback_is_deny_mode() {
        let err = ConnectionLifecycleError::DialTrustRejected(
            "handshake to 127.0.0.1:4433: trust_rejected".to_string(),
        );
        let ctx = derive_bootstrap_dial_context(Some(&err), false);
        assert_eq!(ctx.mode, BootstrapDialMode::Deny);
    }

    #[test]
    fn non_trust_errors_do_not_use_fallback() {
        let err = ConnectionLifecycleError::Dial("connection refused".to_string());
        let ctx = derive_bootstrap_dial_context(Some(&err), true);
        assert_eq!(ctx.mode, BootstrapDialMode::Deny);
    }

    #[test]
    fn decision_is_deterministic_for_same_inputs() {
        let err = ConnectionLifecycleError::DialTrustRejected(
            "handshake to 127.0.0.1:4433: trust_rejected".to_string(),
        );
        let a = derive_bootstrap_dial_context(Some(&err), true);
        let b = derive_bootstrap_dial_context(Some(&err), true);
        assert_eq!(a, b);
    }
}
