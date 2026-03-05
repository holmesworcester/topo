//! Subscription matcher: evaluates projected events against active subscriptions.
//!
//! Called from the projection hook after a Valid event is written.
//! Each event module provides its own field extraction + matching logic.

use rusqlite::Connection;
use tracing::info;

use super::queries;
use super::types::*;
use crate::event_modules::ParsedEvent;

/// The value kind a field produces at runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldKind {
    Str,
    Numeric,
}

/// Field descriptor declared by an event module's matcher.
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

/// Event-module matcher registration. Each module that supports subscriptions
/// registers one of these.
pub struct EventMatcher {
    pub event_type_name: &'static str,
    pub allowed_fields: &'static [AllowedField],
    pub feed_payload:
        fn(&ParsedEvent, &str, DeliveryMode) -> serde_json::Value,
}

/// Check if a parsed event matches a subscription's filters.
#[cfg_attr(test, allow(dead_code))]
pub(crate) fn event_matches(
    matcher: &EventMatcher,
    spec: &SubscriptionSpec,
    parsed: &ParsedEvent,
    event_id_b64: &str,
    event_created_at_ms: u64,
) -> bool {
    // Check since cursor.
    // Events strictly before the cursor timestamp are always excluded.
    // At the exact cursor timestamp, only the cursor event_id itself is
    // excluded — other events sharing the same millisecond are allowed
    // through to avoid dropping legitimate concurrent events.
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
    for filter in &spec.filters {
        let extractor = matcher
            .allowed_fields
            .iter()
            .find(|f| f.name == filter.field);
        match extractor {
            Some(af) => match (af.extract)(parsed, event_id_b64) {
                Some(val) => {
                    if !val.matches_filter(filter.op, &filter.value) {
                        return false;
                    }
                }
                None => return false,
            },
            None => return false, // unknown field → no match
        }
    }

    true
}

// ---------------------------------------------------------------------------
// Event module matchers registry
// ---------------------------------------------------------------------------

/// Check if an event type has a registered subscription matcher.
pub fn is_supported_event_type(event_type: &str) -> bool {
    matcher_for_type(event_type).is_some()
}

/// Return the list of event types that support subscriptions.
pub fn supported_event_types() -> Vec<&'static str> {
    vec!["message"] // extend as matchers are added
}

/// Validate a subscription spec's filters against the matcher for the given
/// event type. Returns `Ok(())` if all filter fields exist and operators are
/// compatible, or an error string describing the first problem found.
pub fn validate_spec(event_type: &str, spec: &SubscriptionSpec) -> Result<(), String> {
    let matcher = matcher_for_type(event_type)
        .ok_or_else(|| format!("no matcher for event type '{}'", event_type))?;

    for (i, filter) in spec.filters.iter().enumerate() {
        let af = matcher
            .allowed_fields
            .iter()
            .find(|f| f.name == filter.field)
            .ok_or_else(|| {
                format!(
                    "filter[{}]: unknown field '{}'; allowed: {}",
                    i,
                    filter.field,
                    matcher
                        .allowed_fields
                        .iter()
                        .map(|f| f.name)
                        .collect::<Vec<_>>()
                        .join(", "),
                )
            })?;

        // Validate that filter value JSON type matches the field kind.
        match af.kind {
            FieldKind::Str => {
                if !filter.value.is_string() {
                    return Err(format!(
                        "filter[{}]: field '{}' is a string field but value is not a string",
                        i, af.name,
                    ));
                }
            }
            FieldKind::Numeric => {
                if !filter.value.is_i64() && !filter.value.is_u64() {
                    return Err(format!(
                        "filter[{}]: field '{}' is a numeric field but value is not an integer",
                        i, af.name,
                    ));
                }
            }
        }

        // String fields only support eq/neq; ordering ops require numeric fields.
        let is_ordering_op = matches!(
            filter.op,
            FilterOp::Gt | FilterOp::Gte | FilterOp::Lt | FilterOp::Lte
        );
        if is_ordering_op && af.kind == FieldKind::Str {
            return Err(format!(
                "filter[{}]: operator '{}' is not supported for string field '{}'",
                i,
                filter.op.as_str(),
                af.name,
            ));
        }
    }

    Ok(())
}

/// Get the matcher for an event type name, if one exists.
fn matcher_for_type(event_type: &str) -> Option<&'static EventMatcher> {
    match event_type {
        "message" => Some(&MESSAGE_MATCHER),
        // Future: "reaction", "message_attachment", etc.
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Message matcher
// ---------------------------------------------------------------------------

fn extract_message_author_id(parsed: &ParsedEvent, _eid: &str) -> Option<FieldValue> {
    match parsed {
        ParsedEvent::Message(m) => {
            Some(FieldValue::Str(crate::crypto::event_id_to_base64(&m.author_id)))
        }
        _ => None,
    }
}

fn extract_message_created_at_ms(parsed: &ParsedEvent, _eid: &str) -> Option<FieldValue> {
    match parsed {
        ParsedEvent::Message(m) => Some(FieldValue::UInt(m.created_at_ms)),
        _ => None,
    }
}

fn extract_message_workspace_id(parsed: &ParsedEvent, _eid: &str) -> Option<FieldValue> {
    match parsed {
        ParsedEvent::Message(m) => {
            Some(FieldValue::Str(crate::crypto::event_id_to_base64(&m.workspace_id)))
        }
        _ => None,
    }
}

fn message_feed_payload(
    parsed: &ParsedEvent,
    event_id_b64: &str,
    mode: DeliveryMode,
) -> serde_json::Value {
    match parsed {
        ParsedEvent::Message(m) => match mode {
            DeliveryMode::Full => serde_json::json!({
                "event_id": event_id_b64,
                "author_id": crate::crypto::event_id_to_base64(&m.author_id),
                "content": m.content,
                "created_at_ms": m.created_at_ms,
            }),
            DeliveryMode::Id => serde_json::json!({
                "event_id": event_id_b64,
                "created_at_ms": m.created_at_ms,
            }),
            DeliveryMode::HasChanged => serde_json::Value::Null,
        },
        _ => serde_json::Value::Null,
    }
}

static MESSAGE_ALLOWED_FIELDS: &[AllowedField] = &[
    AllowedField {
        name: "author_id",
        kind: FieldKind::Str,
        extract: extract_message_author_id,
    },
    AllowedField {
        name: "created_at_ms",
        kind: FieldKind::Numeric,
        extract: extract_message_created_at_ms,
    },
    AllowedField {
        name: "workspace_id",
        kind: FieldKind::Str,
        extract: extract_message_workspace_id,
    },
];

static MESSAGE_MATCHER: EventMatcher = EventMatcher {
    event_type_name: "message",
    allowed_fields: MESSAGE_ALLOWED_FIELDS,
    feed_payload: message_feed_payload,
};

// ---------------------------------------------------------------------------
// Projection hook: called for every Valid event
// ---------------------------------------------------------------------------

/// Evaluate all active subscriptions for a projected event.
/// Called from project_one after a Valid projection.
///
/// Returns `Ok(())` on success. Errors from feed writes propagate so the
/// caller can fail the projection and retry, avoiding permanently lost
/// subscription deliveries.
pub fn on_projected_event(
    conn: &Connection,
    recorded_by: &str,
    event_id_b64: &str,
    parsed: &ParsedEvent,
) -> Result<(), String> {
    let event_type_name = parsed_event_type_name(parsed);
    let matcher = match matcher_for_type(event_type_name) {
        Some(m) => m,
        None => return Ok(()), // no subscriptions for this event type
    };

    let subs =
        queries::load_active_subscriptions_for_type(conn, recorded_by, event_type_name)?;

    if subs.is_empty() {
        return Ok(());
    }

    let created_at_ms = parsed.created_at_ms();

    for sub in &subs {
        if !event_matches(matcher, &sub.spec, parsed, event_id_b64, created_at_ms) {
            continue;
        }

        match sub.delivery_mode {
            DeliveryMode::Full | DeliveryMode::Id => {
                let payload = (matcher.feed_payload)(parsed, event_id_b64, sub.delivery_mode);
                let seq = queries::append_feed_item(
                    conn,
                    recorded_by,
                    &sub.subscription_id,
                    event_type_name,
                    event_id_b64,
                    created_at_ms as i64,
                    &payload,
                )?;
                let short_eid = &event_id_b64[..event_id_b64.len().min(8)];
                info!(
                    target: "topo::subscriptions",
                    "[sub \"{}\"] {} (event {}…) — {} delivery, seq {}",
                    sub.name,
                    event_type_name,
                    short_eid,
                    sub.delivery_mode.as_str(),
                    seq,
                );
            }
            DeliveryMode::HasChanged => {
                let pending = queries::mark_changed(
                    conn,
                    recorded_by,
                    &sub.subscription_id,
                    event_id_b64,
                    created_at_ms as i64,
                )?;
                info!(
                    target: "topo::subscriptions",
                    "[sub \"{}\"] {} — has_changed, pending: {}",
                    sub.name,
                    event_type_name,
                    pending,
                );
            }
        }
    }

    Ok(())
}

/// Expose the message matcher for tests.
#[cfg(test)]
pub(crate) fn message_matcher() -> &'static EventMatcher {
    &MESSAGE_MATCHER
}

/// Map ParsedEvent variant to its event type name string.
fn parsed_event_type_name(parsed: &ParsedEvent) -> &'static str {
    match parsed {
        ParsedEvent::Message(_) => "message",
        ParsedEvent::Reaction(_) => "reaction",
        ParsedEvent::MessageDeletion(_) => "message_deletion",
        ParsedEvent::MessageAttachment(_) => "message_attachment",
        ParsedEvent::Workspace(_) => "workspace",
        ParsedEvent::InviteAccepted(_) => "invite_accepted",
        ParsedEvent::User(_) => "user",
        ParsedEvent::UserInvite(_) => "user_invite",
        ParsedEvent::DeviceInvite(_) => "device_invite",
        ParsedEvent::PeerShared(_) => "peer_shared",
        ParsedEvent::Admin(_) => "admin",
        ParsedEvent::UserRemoved(_) => "user_removed",
        ParsedEvent::PeerRemoved(_) => "peer_removed",
        ParsedEvent::Encrypted(_) => "encrypted",
        ParsedEvent::SecretKey(_) => "secret_key",
        ParsedEvent::SecretShared(_) => "secret_shared",
        ParsedEvent::FileSlice(_) => "file_slice",
        ParsedEvent::BenchDep(_) => "bench_dep",
        ParsedEvent::LocalSignerSecret(_) => "local_signer_secret",
        ParsedEvent::LocalKey(_) => "local_key",
        ParsedEvent::SecretSharedUnwrap(_) => "secret_shared_unwrap",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event_modules::message::MessageEvent;

    fn make_message(author: [u8; 32], workspace: [u8; 32], created_at_ms: u64) -> ParsedEvent {
        ParsedEvent::Message(MessageEvent {
            created_at_ms,
            workspace_id: workspace,
            author_id: author,
            content: "hello".to_string(),
            signed_by: [3u8; 32],
            signer_type: 5,
            signature: [0u8; 64],
        })
    }

    fn spec_no_filters() -> SubscriptionSpec {
        SubscriptionSpec {
            event_type: "message".to_string(),
            since: None,
            filters: vec![],
        }
    }

    fn b64(id: &[u8; 32]) -> String {
        crate::crypto::event_id_to_base64(id)
    }

    // ── event_matches: no filters ──

    #[test]
    fn test_match_no_filters_matches_any_message() {
        let msg = make_message([1; 32], [2; 32], 1000);
        let spec = spec_no_filters();
        assert!(event_matches(message_matcher(), &spec, &msg, "eid_1", 1000));
    }

    // ── event_matches: since cursor ──

    #[test]
    fn test_since_excludes_older_events() {
        let msg = make_message([1; 32], [2; 32], 500);
        let spec = SubscriptionSpec {
            event_type: "message".to_string(),
            since: Some(SinceCursor {
                created_at_ms: 1000,
                event_id: String::new(),
            }),
            filters: vec![],
        };
        assert!(!event_matches(message_matcher(), &spec, &msg, "eid_1", 500));
    }

    #[test]
    fn test_since_includes_newer_events() {
        let msg = make_message([1; 32], [2; 32], 2000);
        let spec = SubscriptionSpec {
            event_type: "message".to_string(),
            since: Some(SinceCursor {
                created_at_ms: 1000,
                event_id: String::new(),
            }),
            filters: vec![],
        };
        assert!(event_matches(message_matcher(), &spec, &msg, "eid_1", 2000));
    }

    #[test]
    fn test_since_same_ms_excludes_cursor_event_id() {
        let msg = make_message([1; 32], [2; 32], 1000);
        let spec = SubscriptionSpec {
            event_type: "message".to_string(),
            since: Some(SinceCursor {
                created_at_ms: 1000,
                event_id: "cursor_eid".to_string(),
            }),
            filters: vec![],
        };
        // The cursor event itself is excluded
        assert!(!event_matches(
            message_matcher(),
            &spec,
            &msg,
            "cursor_eid",
            1000
        ));
    }

    #[test]
    fn test_since_same_ms_allows_different_event_id() {
        let msg = make_message([1; 32], [2; 32], 1000);
        let spec = SubscriptionSpec {
            event_type: "message".to_string(),
            since: Some(SinceCursor {
                created_at_ms: 1000,
                event_id: "cursor_eid".to_string(),
            }),
            filters: vec![],
        };
        // A different event at the same timestamp is allowed through
        assert!(event_matches(
            message_matcher(),
            &spec,
            &msg,
            "other_eid",
            1000
        ));
    }

    // ── event_matches: property filters ──

    #[test]
    fn test_filter_author_id_eq_match() {
        let author = [7u8; 32];
        let msg = make_message(author, [2; 32], 1000);
        let spec = SubscriptionSpec {
            event_type: "message".to_string(),
            since: None,
            filters: vec![FilterClause {
                field: "author_id".to_string(),
                op: FilterOp::Eq,
                value: serde_json::Value::String(b64(&author)),
            }],
        };
        assert!(event_matches(message_matcher(), &spec, &msg, "eid_1", 1000));
    }

    #[test]
    fn test_filter_author_id_eq_mismatch() {
        let msg = make_message([7u8; 32], [2; 32], 1000);
        let spec = SubscriptionSpec {
            event_type: "message".to_string(),
            since: None,
            filters: vec![FilterClause {
                field: "author_id".to_string(),
                op: FilterOp::Eq,
                value: serde_json::Value::String(b64(&[99u8; 32])),
            }],
        };
        assert!(!event_matches(message_matcher(), &spec, &msg, "eid_1", 1000));
    }

    #[test]
    fn test_filter_author_id_neq() {
        let msg = make_message([7u8; 32], [2; 32], 1000);
        let spec = SubscriptionSpec {
            event_type: "message".to_string(),
            since: None,
            filters: vec![FilterClause {
                field: "author_id".to_string(),
                op: FilterOp::Neq,
                value: serde_json::Value::String(b64(&[99u8; 32])),
            }],
        };
        assert!(event_matches(message_matcher(), &spec, &msg, "eid_1", 1000));
    }

    #[test]
    fn test_filter_created_at_gte() {
        let msg = make_message([1; 32], [2; 32], 5000);
        let spec = SubscriptionSpec {
            event_type: "message".to_string(),
            since: None,
            filters: vec![FilterClause {
                field: "created_at_ms".to_string(),
                op: FilterOp::Gte,
                value: serde_json::json!(5000u64),
            }],
        };
        assert!(event_matches(message_matcher(), &spec, &msg, "eid_1", 5000));
    }

    #[test]
    fn test_filter_created_at_lt_rejects() {
        let msg = make_message([1; 32], [2; 32], 5000);
        let spec = SubscriptionSpec {
            event_type: "message".to_string(),
            since: None,
            filters: vec![FilterClause {
                field: "created_at_ms".to_string(),
                op: FilterOp::Lt,
                value: serde_json::json!(5000u64),
            }],
        };
        assert!(!event_matches(message_matcher(), &spec, &msg, "eid_1", 5000));
    }

    #[test]
    fn test_filter_unknown_field_no_match() {
        let msg = make_message([1; 32], [2; 32], 1000);
        let spec = SubscriptionSpec {
            event_type: "message".to_string(),
            since: None,
            filters: vec![FilterClause {
                field: "nonexistent".to_string(),
                op: FilterOp::Eq,
                value: serde_json::json!("x"),
            }],
        };
        assert!(!event_matches(message_matcher(), &spec, &msg, "eid_1", 1000));
    }

    #[test]
    fn test_filter_multiple_all_must_match() {
        let author = [7u8; 32];
        let workspace = [8u8; 32];
        let msg = make_message(author, workspace, 1000);
        let spec = SubscriptionSpec {
            event_type: "message".to_string(),
            since: None,
            filters: vec![
                FilterClause {
                    field: "author_id".to_string(),
                    op: FilterOp::Eq,
                    value: serde_json::Value::String(b64(&author)),
                },
                FilterClause {
                    field: "workspace_id".to_string(),
                    op: FilterOp::Eq,
                    value: serde_json::Value::String(b64(&workspace)),
                },
            ],
        };
        assert!(event_matches(message_matcher(), &spec, &msg, "eid_1", 1000));
    }

    #[test]
    fn test_filter_multiple_one_fails_rejects() {
        let msg = make_message([7u8; 32], [8u8; 32], 1000);
        let spec = SubscriptionSpec {
            event_type: "message".to_string(),
            since: None,
            filters: vec![
                FilterClause {
                    field: "author_id".to_string(),
                    op: FilterOp::Eq,
                    value: serde_json::Value::String(b64(&[7u8; 32])),
                },
                FilterClause {
                    field: "workspace_id".to_string(),
                    op: FilterOp::Eq,
                    value: serde_json::Value::String(b64(&[99u8; 32])), // wrong
                },
            ],
        };
        assert!(!event_matches(message_matcher(), &spec, &msg, "eid_1", 1000));
    }

    // ── event_matches: non-message events don't match message matcher ──

    #[test]
    fn test_reaction_does_not_match_message_matcher() {
        let _rxn = ParsedEvent::Reaction(crate::event_modules::reaction::ReactionEvent {
            created_at_ms: 1000,
            target_event_id: [0u8; 32],
            author_id: [1u8; 32],
            emoji: "thumbs_up".to_string(),
            signed_by: [2u8; 32],
            signer_type: 5,
            signature: [0u8; 64],
        });
        let _spec = spec_no_filters();
        // Extract returns None for non-message → if there are filters they fail,
        // but with no filters it's vacuously true. The matcher_for_type gate in
        // on_projected_event prevents reactions from ever being matched against
        // the message matcher. Test that unsupported type returns false for
        // is_supported_event_type.
        assert!(!is_supported_event_type("reaction"));
    }

    // ── validate_spec ──

    #[test]
    fn test_validate_spec_accepts_valid() {
        let spec = SubscriptionSpec {
            event_type: "message".to_string(),
            since: None,
            filters: vec![FilterClause {
                field: "author_id".to_string(),
                op: FilterOp::Eq,
                value: serde_json::json!("some_b64"),
            }],
        };
        assert!(validate_spec("message", &spec).is_ok());
    }

    #[test]
    fn test_validate_spec_rejects_unknown_field() {
        let spec = SubscriptionSpec {
            event_type: "message".to_string(),
            since: None,
            filters: vec![FilterClause {
                field: "bogus".to_string(),
                op: FilterOp::Eq,
                value: serde_json::json!("x"),
            }],
        };
        let err = validate_spec("message", &spec).unwrap_err();
        assert!(err.contains("unknown field 'bogus'"));
    }

    #[test]
    fn test_validate_spec_rejects_ordering_op_on_string() {
        let spec = SubscriptionSpec {
            event_type: "message".to_string(),
            since: None,
            filters: vec![FilterClause {
                field: "author_id".to_string(),
                op: FilterOp::Gt,
                value: serde_json::json!("x"),
            }],
        };
        let err = validate_spec("message", &spec).unwrap_err();
        assert!(err.contains("not supported for string field"));
    }

    #[test]
    fn test_validate_spec_rejects_string_value_for_numeric_field() {
        let spec = SubscriptionSpec {
            event_type: "message".to_string(),
            since: None,
            filters: vec![FilterClause {
                field: "created_at_ms".to_string(),
                op: FilterOp::Eq,
                value: serde_json::json!("not_a_number"),
            }],
        };
        let err = validate_spec("message", &spec).unwrap_err();
        assert!(err.contains("not an integer"));
    }

    #[test]
    fn test_validate_spec_rejects_float_for_numeric_field() {
        let spec = SubscriptionSpec {
            event_type: "message".to_string(),
            since: None,
            filters: vec![FilterClause {
                field: "created_at_ms".to_string(),
                op: FilterOp::Eq,
                value: serde_json::json!(1.5),
            }],
        };
        let err = validate_spec("message", &spec).unwrap_err();
        assert!(err.contains("not an integer"));
    }

    #[test]
    fn test_validate_spec_rejects_numeric_value_for_string_field() {
        let spec = SubscriptionSpec {
            event_type: "message".to_string(),
            since: None,
            filters: vec![FilterClause {
                field: "author_id".to_string(),
                op: FilterOp::Eq,
                value: serde_json::json!(42),
            }],
        };
        let err = validate_spec("message", &spec).unwrap_err();
        assert!(err.contains("not a string"));
    }

    #[test]
    fn test_validate_spec_rejects_unsupported_event_type() {
        let spec = spec_no_filters();
        let err = validate_spec("reaction", &spec).unwrap_err();
        assert!(err.contains("no matcher"));
    }

    // ── payload shaping ──

    #[test]
    fn test_message_payload_full_mode() {
        let author = [5u8; 32];
        let msg = make_message(author, [2; 32], 3000);
        let payload = message_feed_payload(&msg, "eid_abc", DeliveryMode::Full);
        assert_eq!(payload["event_id"], "eid_abc");
        assert_eq!(payload["content"], "hello");
        assert_eq!(payload["created_at_ms"], 3000);
        assert!(payload["author_id"].is_string());
    }

    #[test]
    fn test_message_payload_id_mode() {
        let msg = make_message([5; 32], [2; 32], 3000);
        let payload = message_feed_payload(&msg, "eid_abc", DeliveryMode::Id);
        assert_eq!(payload["event_id"], "eid_abc");
        assert_eq!(payload["created_at_ms"], 3000);
        assert!(payload.get("content").is_none());
    }

    #[test]
    fn test_message_payload_has_changed_mode() {
        let msg = make_message([5; 32], [2; 32], 3000);
        let payload = message_feed_payload(&msg, "eid_abc", DeliveryMode::HasChanged);
        assert!(payload.is_null());
    }

    // ── supported event types ──

    #[test]
    fn test_supported_event_types() {
        assert!(is_supported_event_type("message"));
        assert!(!is_supported_event_type("reaction"));
        assert!(!is_supported_event_type(""));
        let types = supported_event_types();
        assert!(types.contains(&"message"));
    }
}
