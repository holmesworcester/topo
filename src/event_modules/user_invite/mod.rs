pub mod projector;
pub mod wire;

// Re-export stable public API so callers import from `event_modules::user_invite`.
pub use projector::project_pure;
pub use wire::{
    encode_user_invite_boot, encode_user_invite_ongoing, parse_user_invite_boot,
    parse_user_invite_ongoing, UserInviteBootEvent, UserInviteOngoingEvent, USER_INVITE_BOOT_META,
    USER_INVITE_BOOT_WIRE_SIZE, USER_INVITE_ONGOING_META, USER_INVITE_ONGOING_WIRE_SIZE,
};
