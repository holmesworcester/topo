pub mod wire;
pub mod projector;
pub mod queries;

// Re-export stable public API so callers import from `event_modules::peer_shared`.
pub use wire::{
    PeerSharedFirstEvent, PeerSharedOngoingEvent,
    parse_peer_shared_first, encode_peer_shared_first,
    parse_peer_shared_ongoing, encode_peer_shared_ongoing,
    PEER_SHARED_WIRE_SIZE,
    PEER_SHARED_FIRST_META, PEER_SHARED_ONGOING_META,
};
pub use queries::{count, list_event_ids, first_event_id, AccountRow, list_accounts};
pub use projector::project_pure;
