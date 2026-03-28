use crate::event_modules::ParsedEvent;
use crate::projection::contract::ContextSnapshot;
use crate::projection::queries::ProjectionQueries;

/// Build projector-local context for Message projection.
pub fn build_projector_context(
    queries: &dyn ProjectionQueries,
    recorded_by: &str,
    event_id_b64: &str,
    parsed: &ParsedEvent,
) -> Result<ContextSnapshot, Box<dyn std::error::Error>> {
    let message = match parsed {
        ParsedEvent::Message(message) => message,
        _ => return Err("message context loader called for non-message event".into()),
    };

    queries.load_message_context(recorded_by, event_id_b64, message)
}
