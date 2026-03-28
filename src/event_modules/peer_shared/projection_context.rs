use crate::event_modules::ParsedEvent;
use crate::projection::contract::ContextSnapshot;
use crate::projection::queries::ProjectionQueries;

/// Build projector-local context for PeerShared projection.
pub fn build_projector_context(
    queries: &dyn ProjectionQueries,
    recorded_by: &str,
    event_id_b64: &str,
    parsed: &ParsedEvent,
) -> Result<ContextSnapshot, Box<dyn std::error::Error>> {
    let peer_shared = match parsed {
        ParsedEvent::PeerShared(peer_shared) => peer_shared,
        _ => return Err("peer_shared context loader called for non-peer_shared event".into()),
    };

    queries.load_peer_shared_context(recorded_by, event_id_b64, peer_shared)
}
