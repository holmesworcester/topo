//! Subscription engine: dispatches projected events to event-module filters.

use rusqlite::Connection;
use tracing::info;

use super::filter::{self, SubscriptionFilter};
use super::queries;
use super::types::*;
use crate::event_modules::ParsedEvent;

/// Check if an event type has a registered subscription filter.
pub fn is_supported_event_type(event_type: &str) -> bool {
    subscription_filter_for_type(event_type).is_some()
}

/// Return the list of event types that support subscriptions.
pub fn supported_event_types() -> Vec<&'static str> {
    registered_subscription_filters()
        .iter()
        .map(|f| f.event_type_name)
        .collect()
}

/// Validate a subscription spec's filters against the event module filter for
/// the given event type.
pub fn validate_spec(event_type: &str, spec: &SubscriptionSpec) -> Result<(), String> {
    let subscription_filter = subscription_filter_for_type(event_type)
        .ok_or_else(|| format!("no subscription filter for event type '{}'", event_type))?;
    filter::validate_spec(subscription_filter, spec)
}

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
    let subscription_filter = match subscription_filter_for_type(event_type_name) {
        Some(filter) => filter,
        None => return Ok(()), // no subscriptions for this event type
    };

    let subs = queries::load_active_subscriptions_for_type(conn, recorded_by, event_type_name)?;

    if subs.is_empty() {
        return Ok(());
    }

    let created_at_ms = parsed.created_at_ms();

    for sub in &subs {
        if !filter::event_matches(
            subscription_filter,
            &sub.spec,
            parsed,
            event_id_b64,
            created_at_ms,
        ) {
            continue;
        }

        match sub.delivery_mode {
            DeliveryMode::Full | DeliveryMode::Id => {
                let payload =
                    (subscription_filter.feed_payload)(parsed, event_id_b64, sub.delivery_mode);
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

fn subscription_filter_for_type(event_type: &str) -> Option<&'static SubscriptionFilter> {
    registered_subscription_filters()
        .iter()
        .copied()
        .find(|f| f.event_type_name == event_type)
}

fn registered_subscription_filters() -> [&'static SubscriptionFilter; 1] {
    // Message is intentionally the only implemented filter right now.
    [crate::event_modules::message::subscription_filter::subscription_filter()]
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
        ParsedEvent::UserInvite(_) => "user_invite_shared",
        ParsedEvent::DeviceInvite(_) => "peer_invite_shared",
        ParsedEvent::PeerShared(_) => "peer_shared",
        ParsedEvent::Admin(_) => "admin",
        ParsedEvent::UserRemoved(_) => "user_removed",
        ParsedEvent::PeerRemoved(_) => "peer_removed",
        ParsedEvent::Encrypted(_) => "encrypted",
        ParsedEvent::KeySecret(_) => "key_secret",
        ParsedEvent::KeyShared(_) => "key_shared",
        ParsedEvent::Tenant(_) => "tenant",
        ParsedEvent::FileSlice(_) => "file_slice",
        ParsedEvent::BenchDep(_) => "bench_dep",
        ParsedEvent::PeerSecret(_) => "peer_secret",
        ParsedEvent::InviteSecret(_) => "invite_secret",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec_no_filters() -> SubscriptionSpec {
        SubscriptionSpec {
            event_type: "message".to_string(),
            since: None,
            filters: vec![],
        }
    }

    #[test]
    fn test_supported_event_types() {
        assert_eq!(supported_event_types(), vec!["message"]);
        assert!(is_supported_event_type("message"));
        assert!(!is_supported_event_type("reaction"));
        assert!(!is_supported_event_type(""));
    }

    #[test]
    fn test_registry_lookup_tracks_filter_event_type_name() {
        let message_filter =
            crate::event_modules::message::subscription_filter::subscription_filter();
        let looked_up = subscription_filter_for_type(message_filter.event_type_name);
        assert!(looked_up.is_some());
        assert_eq!(looked_up.unwrap().event_type_name, "message");
    }

    #[test]
    fn test_validate_spec_rejects_unsupported_event_type() {
        let spec = spec_no_filters();
        let err = validate_spec("reaction", &spec).unwrap_err();
        assert!(err.contains("no subscription filter"));
    }
}
