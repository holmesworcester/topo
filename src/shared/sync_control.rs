use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SyncPolicyMode {
    Auto,
    Manual,
    Disabled,
}

impl SyncPolicyMode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Manual => "manual",
            Self::Disabled => "disabled",
        }
    }
}

impl Default for SyncPolicyMode {
    fn default() -> Self {
        Self::Auto
    }
}

impl fmt::Display for SyncPolicyMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for SyncPolicyMode {
    type Err = String;

    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "auto" => Ok(Self::Auto),
            "manual" => Ok(Self::Manual),
            "disabled" => Ok(Self::Disabled),
            other => Err(format!(
                "invalid mode '{}'; expected auto, manual, or disabled",
                other
            )),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SyncModePreset {
    Auto,
    Manual,
    Disabled,
}

impl SyncModePreset {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Manual => "manual",
            Self::Disabled => "disabled",
        }
    }

    pub const fn to_policy(self) -> TenantSyncPolicy {
        match self {
            Self::Auto => TenantSyncPolicy {
                requests: SyncPolicyMode::Auto,
                responses: SyncPolicyMode::Auto,
                forward_on_have: SyncPolicyMode::Auto,
            },
            Self::Manual => TenantSyncPolicy {
                requests: SyncPolicyMode::Manual,
                responses: SyncPolicyMode::Auto,
                forward_on_have: SyncPolicyMode::Manual,
            },
            Self::Disabled => TenantSyncPolicy {
                requests: SyncPolicyMode::Disabled,
                responses: SyncPolicyMode::Disabled,
                forward_on_have: SyncPolicyMode::Disabled,
            },
        }
    }
}

impl fmt::Display for SyncModePreset {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for SyncModePreset {
    type Err = String;

    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "auto" => Ok(Self::Auto),
            "manual" => Ok(Self::Manual),
            "disabled" => Ok(Self::Disabled),
            other => Err(format!(
                "invalid preset '{}'; expected auto, manual, or disabled",
                other
            )),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct TenantSyncPolicy {
    pub requests: SyncPolicyMode,
    pub responses: SyncPolicyMode,
    pub forward_on_have: SyncPolicyMode,
}

impl Default for TenantSyncPolicy {
    fn default() -> Self {
        SyncModePreset::Auto.to_policy()
    }
}
