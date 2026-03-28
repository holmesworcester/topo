use crate::event_modules::ParsedEvent;
use crate::projection::contract::ContextSnapshot;
use crate::projection::queries::ProjectionQueries;

/// Build projector-local context for MessageDeletion projection.
pub fn build_projector_context(
    queries: &dyn ProjectionQueries,
    recorded_by: &str,
    event_id_b64: &str,
    parsed: &ParsedEvent,
) -> Result<ContextSnapshot, Box<dyn std::error::Error>> {
    let message_deletion = match parsed {
        ParsedEvent::MessageDeletion(message_deletion) => message_deletion,
        _ => {
            return Err(
                "message_deletion context loader called for non-message_deletion event".into(),
            )
        }
    };

    queries.load_message_deletion_context(recorded_by, event_id_b64, message_deletion)
}
