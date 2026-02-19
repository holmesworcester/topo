pub mod wire;
pub mod projector;

// Re-export stable public API so callers import from `event_modules::user_invite`.
pub use wire::{
    UserInviteBootEvent, UserInviteOngoingEvent,
    parse_user_invite_boot, encode_user_invite_boot,
    parse_user_invite_ongoing, encode_user_invite_ongoing,
    USER_INVITE_BOOT_WIRE_SIZE,
    USER_INVITE_BOOT_META, USER_INVITE_ONGOING_META,
};
pub use projector::project_pure;
