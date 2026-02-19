pub mod wire;
pub mod projector;

// Re-export stable public API so callers import from `event_modules::device_invite`.
pub use wire::{
    DeviceInviteFirstEvent, DeviceInviteOngoingEvent,
    parse_device_invite_first, encode_device_invite_first,
    parse_device_invite_ongoing, encode_device_invite_ongoing,
    DEVICE_INVITE_FIRST_META, DEVICE_INVITE_ONGOING_META,
};
pub use projector::project_pure;
