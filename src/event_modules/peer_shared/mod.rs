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
pub use queries::{
    count, list_event_ids, first_event_id, AccountRow, list_accounts,
    load_local_peer_signer, load_local_peer_signer_required, resolve_user_event_id,
    load_local_user_key,
    AccountItem, list_account_items, IdentityResponse, identity,
};
pub use projector::project_pure;
