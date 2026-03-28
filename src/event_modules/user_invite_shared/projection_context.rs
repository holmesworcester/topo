use crate::event_modules::ParsedEvent;
use crate::projection::contract::ContextSnapshot;
use crate::projection::queries::ProjectionQueries;

/// Build projector-local context for UserInvite projection.
pub fn build_projector_context(
    queries: &dyn ProjectionQueries,
    recorded_by: &str,
    event_id_b64: &str,
    parsed: &ParsedEvent,
) -> Result<ContextSnapshot, Box<dyn std::error::Error>> {
    let user_invite = match parsed {
        ParsedEvent::UserInvite(user_invite) => user_invite,
        _ => return Err("user_invite context loader called for non-user_invite event".into()),
    };

    queries.load_user_invite_context(recorded_by, event_id_b64, user_invite)
}
