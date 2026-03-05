//! Subscription types: spec, delivery mode, filter definitions.

use serde::{Deserialize, Serialize};

/// How feed items are delivered to consumers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeliveryMode {
    /// Feed rows include minimal render payload.
    Full,
    /// Feed rows include only identifiers and timestamps.
    Id,
    /// No per-item rows; only dirty flag + pending count in state table.
    HasChanged,
}

impl DeliveryMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            DeliveryMode::Full => "full",
            DeliveryMode::Id => "id",
            DeliveryMode::HasChanged => "has_changed",
        }
    }

    pub fn from_str(s: &str) -> Result<Self, String> {
        match s {
            "full" => Ok(DeliveryMode::Full),
            "id" => Ok(DeliveryMode::Id),
            "has_changed" => Ok(DeliveryMode::HasChanged),
            _ => Err(format!(
                "invalid delivery mode '{}'; expected full|id|has_changed",
                s
            )),
        }
    }
}

/// A single filter clause in a subscription spec.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilterClause {
    pub field: String,
    pub op: FilterOp,
    pub value: serde_json::Value,
}

/// Supported filter operators.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FilterOp {
    Eq,
    Neq,
    Gt,
    Gte,
    Lt,
    Lte,
}

impl FilterOp {
    pub fn as_str(&self) -> &'static str {
        match self {
            FilterOp::Eq => "eq",
            FilterOp::Neq => "neq",
            FilterOp::Gt => "gt",
            FilterOp::Gte => "gte",
            FilterOp::Lt => "lt",
            FilterOp::Lte => "lte",
        }
    }
}

/// The full subscription spec as stored in `spec_json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubscriptionSpec {
    pub event_type: String,
    #[serde(default)]
    pub since: Option<SinceCursor>,
    #[serde(default)]
    pub filters: Vec<FilterClause>,
}

/// Cursor for "since" semantics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SinceCursor {
    #[serde(default)]
    pub created_at_ms: u64,
    #[serde(default)]
    pub event_id: String,
}

/// A subscription definition as stored in the database.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubscriptionDef {
    pub recorded_by: String,
    pub subscription_id: String,
    pub name: String,
    pub enabled: bool,
    pub event_type: String,
    pub delivery_mode: DeliveryMode,
    pub spec: SubscriptionSpec,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
}

/// A feed item from the subscription feed table.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeedItem {
    pub subscription_id: String,
    pub seq: i64,
    pub event_type: String,
    pub event_id: String,
    pub created_at_ms: i64,
    pub payload: serde_json::Value,
    pub emitted_at_ms: i64,
}

/// Subscription state (cursors, dirty flag, pending count).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubscriptionState {
    pub subscription_id: String,
    pub next_seq: i64,
    pub pending_count: i64,
    pub dirty: bool,
    pub latest_event_id: String,
    pub latest_created_at_ms: i64,
    pub updated_at_ms: i64,
}
