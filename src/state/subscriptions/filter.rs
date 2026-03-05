//! Generic subscription filter primitives shared by event modules.

use crate::event_modules::ParsedEvent;

use super::types::{DeliveryMode, FilterOp, SubscriptionSpec};

/// The value kind a field produces at runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldKind {
    Str,
    Numeric,
}

/// Field descriptor declared by an event module's subscription filter.
pub struct AllowedField {
    pub name: &'static str,
    pub kind: FieldKind,
    pub extract: fn(&ParsedEvent, &str) -> Option<FieldValue>,
}

/// A comparable value extracted from an event.
#[derive(Debug, Clone)]
pub enum FieldValue {
    Str(String),
    Int(i64),
    UInt(u64),
}

impl FieldValue {
    fn matches_filter(&self, op: FilterOp, json_val: &serde_json::Value) -> bool {
        match self {
            FieldValue::Str(s) => {
                if let Some(target) = json_val.as_str() {
                    match op {
                        FilterOp::Eq => s == target,
                        FilterOp::Neq => s != target,
                        _ => false, // ordering ops not supported for strings
                    }
                } else {
                    false
                }
            }
            FieldValue::Int(n) => {
                if let Some(target) = json_val.as_i64() {
                    cmp_op(*n, op, target)
                } else {
                    false
                }
            }
            FieldValue::UInt(n) => {
                if let Some(target) = json_val.as_u64() {
                    cmp_op(*n, op, target)
                } else if let Some(target) = json_val.as_i64() {
                    cmp_op(*n as i64, op, target)
                } else {
                    false
                }
            }
        }
    }
}

fn cmp_op<T: Ord>(a: T, op: FilterOp, b: T) -> bool {
    match op {
        FilterOp::Eq => a == b,
        FilterOp::Neq => a != b,
        FilterOp::Gt => a > b,
        FilterOp::Gte => a >= b,
        FilterOp::Lt => a < b,
        FilterOp::Lte => a <= b,
    }
}

/// Event-module registration object for subscription filtering + payload shaping.
pub struct SubscriptionFilter {
    pub event_type_name: &'static str,
    pub allowed_fields: &'static [AllowedField],
    pub feed_payload: fn(&ParsedEvent, &str, DeliveryMode) -> serde_json::Value,
}

/// Check if a parsed event matches a subscription spec.
pub fn event_matches(
    filter: &SubscriptionFilter,
    spec: &SubscriptionSpec,
    parsed: &ParsedEvent,
    event_id_b64: &str,
    event_created_at_ms: u64,
) -> bool {
    if spec.event_type != filter.event_type_name {
        return false;
    }

    // Check since cursor.
    // Events strictly before the cursor timestamp are always excluded.
    // At the exact cursor timestamp, only the cursor event_id itself is
    // excluded — other events sharing the same millisecond are allowed.
    if let Some(ref since) = spec.since {
        if since.created_at_ms > 0 {
            if event_created_at_ms < since.created_at_ms {
                return false;
            }
            if event_created_at_ms == since.created_at_ms
                && !since.event_id.is_empty()
                && event_id_b64 == since.event_id
            {
                return false;
            }
        }
    }

    // Check property filters.
    for clause in &spec.filters {
        let extractor = filter
            .allowed_fields
            .iter()
            .find(|f| f.name == clause.field);
        match extractor {
            Some(allowed) => match (allowed.extract)(parsed, event_id_b64) {
                Some(value) => {
                    if !value.matches_filter(clause.op, &clause.value) {
                        return false;
                    }
                }
                None => return false,
            },
            None => return false, // unknown field -> no match
        }
    }

    true
}

/// Validate filter clauses against an event module's declared fields.
pub fn validate_spec(filter: &SubscriptionFilter, spec: &SubscriptionSpec) -> Result<(), String> {
    if spec.event_type != filter.event_type_name {
        return Err(format!(
            "spec.event_type '{}' does not match event type '{}'",
            spec.event_type, filter.event_type_name
        ));
    }

    for (i, clause) in spec.filters.iter().enumerate() {
        let allowed = filter
            .allowed_fields
            .iter()
            .find(|f| f.name == clause.field)
            .ok_or_else(|| {
                format!(
                    "filter[{}]: unknown field '{}'; allowed: {}",
                    i,
                    clause.field,
                    filter
                        .allowed_fields
                        .iter()
                        .map(|f| f.name)
                        .collect::<Vec<_>>()
                        .join(", "),
                )
            })?;

        match allowed.kind {
            FieldKind::Str => {
                if !clause.value.is_string() {
                    return Err(format!(
                        "filter[{}]: field '{}' is a string field but value is not a string",
                        i, allowed.name,
                    ));
                }
            }
            FieldKind::Numeric => {
                if !clause.value.is_i64() && !clause.value.is_u64() {
                    return Err(format!(
                        "filter[{}]: field '{}' is a numeric field but value is not an integer",
                        i, allowed.name,
                    ));
                }
            }
        }

        let is_ordering_op = matches!(
            clause.op,
            FilterOp::Gt | FilterOp::Gte | FilterOp::Lt | FilterOp::Lte
        );
        if is_ordering_op && allowed.kind == FieldKind::Str {
            return Err(format!(
                "filter[{}]: operator '{}' is not supported for string field '{}'",
                i,
                clause.op.as_str(),
                allowed.name,
            ));
        }
    }

    Ok(())
}
