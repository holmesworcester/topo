use crate::event_modules::ParsedEvent;
use crate::projection::contract::ContextSnapshot;
use crate::projection::queries::ProjectionQueries;

/// Build projector-local context for Reaction projection.
pub fn build_projector_context(
    queries: &dyn ProjectionQueries,
    recorded_by: &str,
    event_id_b64: &str,
    parsed: &ParsedEvent,
) -> Result<ContextSnapshot, Box<dyn std::error::Error>> {
    let reaction = match parsed {
        ParsedEvent::Reaction(reaction) => reaction,
        _ => return Err("reaction context loader called for non-reaction event".into()),
    };

    queries.load_reaction_context(recorded_by, event_id_b64, reaction)
}
