//! Message-specific subscription filter semantics.

use crate::event_modules::ParsedEvent;
use crate::state::subscriptions::filter::{
    AllowedField, FieldKind, FieldValue, SubscriptionFilter,
};
use crate::state::subscriptions::DeliveryMode;

fn extract_message_author_id(parsed: &ParsedEvent, _eid: &str) -> Option<FieldValue> {
    match parsed {
        ParsedEvent::Message(m) => Some(FieldValue::Str(crate::crypto::event_id_to_base64(
            &m.author_id,
        ))),
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
        ParsedEvent::Message(m) => Some(FieldValue::Str(crate::crypto::event_id_to_base64(
            &m.workspace_id,
        ))),
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

static MESSAGE_SUBSCRIPTION_FILTER: SubscriptionFilter = SubscriptionFilter {
    event_type_name: "message",
    allowed_fields: MESSAGE_ALLOWED_FIELDS,
    feed_payload: message_feed_payload,
};

pub fn subscription_filter() -> &'static SubscriptionFilter {
    &MESSAGE_SUBSCRIPTION_FILTER
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event_modules::message::MessageEvent;
    use crate::state::subscriptions::filter::{
        event_matches as filter_event_matches, validate_spec as validate_filter_spec,
    };
    use crate::state::subscriptions::{FilterClause, FilterOp, SinceCursor, SubscriptionSpec};

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

    #[test]
    fn test_match_no_filters_matches_any_message() {
        let msg = make_message([1; 32], [2; 32], 1000);
        let spec = spec_no_filters();
        assert!(filter_event_matches(
            subscription_filter(),
            &spec,
            &msg,
            "eid_1",
            1000,
        ));
    }

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
        assert!(!filter_event_matches(
            subscription_filter(),
            &spec,
            &msg,
            "eid_1",
            500,
        ));
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
        assert!(filter_event_matches(
            subscription_filter(),
            &spec,
            &msg,
            "eid_1",
            2000,
        ));
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
        assert!(!filter_event_matches(
            subscription_filter(),
            &spec,
            &msg,
            "cursor_eid",
            1000,
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
        assert!(filter_event_matches(
            subscription_filter(),
            &spec,
            &msg,
            "other_eid",
            1000,
        ));
    }

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
        assert!(filter_event_matches(
            subscription_filter(),
            &spec,
            &msg,
            "eid_1",
            1000,
        ));
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
        assert!(!filter_event_matches(
            subscription_filter(),
            &spec,
            &msg,
            "eid_1",
            1000,
        ));
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
        assert!(filter_event_matches(
            subscription_filter(),
            &spec,
            &msg,
            "eid_1",
            1000,
        ));
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
        assert!(filter_event_matches(
            subscription_filter(),
            &spec,
            &msg,
            "eid_1",
            5000,
        ));
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
        assert!(!filter_event_matches(
            subscription_filter(),
            &spec,
            &msg,
            "eid_1",
            5000,
        ));
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
        assert!(!filter_event_matches(
            subscription_filter(),
            &spec,
            &msg,
            "eid_1",
            1000,
        ));
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
        assert!(filter_event_matches(
            subscription_filter(),
            &spec,
            &msg,
            "eid_1",
            1000,
        ));
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
                    value: serde_json::Value::String(b64(&[99u8; 32])),
                },
            ],
        };
        assert!(!filter_event_matches(
            subscription_filter(),
            &spec,
            &msg,
            "eid_1",
            1000,
        ));
    }

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
        assert!(validate_filter_spec(subscription_filter(), &spec).is_ok());
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
        let err = validate_filter_spec(subscription_filter(), &spec).unwrap_err();
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
        let err = validate_filter_spec(subscription_filter(), &spec).unwrap_err();
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
        let err = validate_filter_spec(subscription_filter(), &spec).unwrap_err();
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
        let err = validate_filter_spec(subscription_filter(), &spec).unwrap_err();
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
        let err = validate_filter_spec(subscription_filter(), &spec).unwrap_err();
        assert!(err.contains("not a string"));
    }

    #[test]
    fn test_validate_spec_rejects_event_type_mismatch() {
        let spec = SubscriptionSpec {
            event_type: "reaction".to_string(),
            since: None,
            filters: vec![],
        };
        let err = validate_filter_spec(subscription_filter(), &spec).unwrap_err();
        assert!(err.contains("spec.event_type"));
        assert!(err.contains("does not match event type 'message'"));
    }

    #[test]
    fn test_event_matches_rejects_event_type_mismatch() {
        let msg = make_message([1; 32], [2; 32], 1000);
        let spec = SubscriptionSpec {
            event_type: "reaction".to_string(),
            since: None,
            filters: vec![],
        };
        assert!(!filter_event_matches(
            subscription_filter(),
            &spec,
            &msg,
            "eid_1",
            1000,
        ));
    }

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
}
