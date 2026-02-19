pub mod projector;
pub mod wire;

// Re-export stable public API so callers import from `event_modules::device_invite`.
pub use projector::project_pure;
pub use wire::{
    encode_device_invite_first, encode_device_invite_ongoing, parse_device_invite_first,
    parse_device_invite_ongoing, DeviceInviteFirstEvent, DeviceInviteOngoingEvent,
    DEVICE_INVITE_FIRST_META, DEVICE_INVITE_FIRST_WIRE_SIZE, DEVICE_INVITE_ONGOING_META,
    DEVICE_INVITE_ONGOING_WIRE_SIZE,
};
