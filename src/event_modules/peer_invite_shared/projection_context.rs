use crate::event_modules::ParsedEvent;
use crate::projection::contract::ContextSnapshot;
use crate::projection::queries::ProjectionQueries;

/// Build projector-local context for DeviceInvite projection.
pub fn build_projector_context(
    queries: &dyn ProjectionQueries,
    recorded_by: &str,
    event_id_b64: &str,
    parsed: &ParsedEvent,
) -> Result<ContextSnapshot, Box<dyn std::error::Error>> {
    let device_invite = match parsed {
        ParsedEvent::DeviceInvite(device_invite) => device_invite,
        _ => return Err("device_invite context loader called for non-device_invite event".into()),
    };

    queries.load_device_invite_context(recorded_by, event_id_b64, device_invite)
}
