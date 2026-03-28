use crate::event_modules::ParsedEvent;
use crate::projection::contract::ContextSnapshot;
use crate::projection::queries::ProjectionQueries;

/// Build projector-local context for Workspace projection.
pub fn build_projector_context(
    queries: &dyn ProjectionQueries,
    recorded_by: &str,
    event_id_b64: &str,
    parsed: &ParsedEvent,
) -> Result<ContextSnapshot, Box<dyn std::error::Error>> {
    let workspace = match parsed {
        ParsedEvent::Workspace(workspace) => workspace,
        _ => return Err("workspace context loader called for non-workspace event".into()),
    };

    queries.load_workspace_context(recorded_by, event_id_b64, workspace)
}
