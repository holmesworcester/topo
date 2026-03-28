use crate::event_modules::ParsedEvent;
use crate::projection::contract::ContextSnapshot;
use crate::projection::queries::ProjectionQueries;

/// Build projector-local context for File projection.
pub fn build_projector_context(
    queries: &dyn ProjectionQueries,
    recorded_by: &str,
    event_id_b64: &str,
    parsed: &ParsedEvent,
) -> Result<ContextSnapshot, Box<dyn std::error::Error>> {
    let file = match parsed {
        ParsedEvent::File(file) => file,
        _ => return Err("file context loader called for non-file event".into()),
    };

    queries.load_file_context(recorded_by, event_id_b64, file)
}
