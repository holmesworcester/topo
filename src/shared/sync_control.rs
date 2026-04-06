//! Sync control policy types: mode enum and per-tenant policy struct.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

/// Sync policy mode for a single lane (requests or responses).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SyncPolicyMode {
    Auto,
    Manual,
    Disabled,
}

impl Default for SyncPolicyMode {
    fn default() -> Self {
        SyncPolicyMode::Auto
    }
}

impl SyncPolicyMode {
    pub fn as_str(self) -> &'static str {
        match self {
            SyncPolicyMode::Auto => "auto",
            SyncPolicyMode::Manual => "manual",
            SyncPolicyMode::Disabled => "disabled",
        }
    }
}

impl fmt::Display for SyncPolicyMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for SyncPolicyMode {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "auto" => Ok(SyncPolicyMode::Auto),
            "manual" => Ok(SyncPolicyMode::Manual),
            "disabled" => Ok(SyncPolicyMode::Disabled),
            other => Err(format!(
                "invalid sync policy mode '{}': expected auto, manual, or disabled",
                other
            )),
        }
    }
}

/// Per-tenant sync policy controlling the request and response lanes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TenantSyncPolicy {
    pub requests: SyncPolicyMode,
    pub responses: SyncPolicyMode,
}

impl Default for TenantSyncPolicy {
    fn default() -> Self {
        TenantSyncPolicy {
            requests: SyncPolicyMode::Auto,
            responses: SyncPolicyMode::Auto,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_auto() {
        let policy = TenantSyncPolicy::default();
        assert_eq!(policy.requests, SyncPolicyMode::Auto);
        assert_eq!(policy.responses, SyncPolicyMode::Auto);
    }

    #[test]
    fn from_str_roundtrip() {
        for mode in &[
            SyncPolicyMode::Auto,
            SyncPolicyMode::Manual,
            SyncPolicyMode::Disabled,
        ] {
            let s = mode.as_str();
            let parsed: SyncPolicyMode = s.parse().unwrap();
            assert_eq!(*mode, parsed);
        }
    }

    #[test]
    fn from_str_case_insensitive() {
        assert_eq!(
            "AUTO".parse::<SyncPolicyMode>().unwrap(),
            SyncPolicyMode::Auto
        );
        assert_eq!(
            "Manual".parse::<SyncPolicyMode>().unwrap(),
            SyncPolicyMode::Manual
        );
        assert_eq!(
            "DISABLED".parse::<SyncPolicyMode>().unwrap(),
            SyncPolicyMode::Disabled
        );
    }

    #[test]
    fn from_str_invalid() {
        assert!("bogus".parse::<SyncPolicyMode>().is_err());
    }

    #[test]
    fn serde_roundtrip() {
        let policy = TenantSyncPolicy {
            requests: SyncPolicyMode::Manual,
            responses: SyncPolicyMode::Disabled,
        };
        let json = serde_json::to_string(&policy).unwrap();
        let parsed: TenantSyncPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(policy, parsed);
    }
}
