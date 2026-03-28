use crate::event_modules::ParsedEvent;
use crate::projection::contract::ContextSnapshot;
use crate::projection::queries::ProjectionQueries;

/// Build projector-local context for Admin projection.
pub fn build_projector_context(
    queries: &dyn ProjectionQueries,
    recorded_by: &str,
    event_id_b64: &str,
    parsed: &ParsedEvent,
) -> Result<ContextSnapshot, Box<dyn std::error::Error>> {
    let admin = match parsed {
        ParsedEvent::Admin(admin) => admin,
        _ => return Err("admin context loader called for non-admin event".into()),
    };

    queries.load_admin_context(recorded_by, event_id_b64, admin)
}
