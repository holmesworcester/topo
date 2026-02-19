pub mod wire;
pub mod projector;
pub mod queries;

// Re-export stable public API so callers import from `event_modules::user`.
pub use wire::{
    UserBootEvent, UserOngoingEvent,
    parse_user_boot, encode_user_boot,
    parse_user_ongoing, encode_user_ongoing,
    USER_WIRE_SIZE,
    USER_BOOT_META, USER_ONGOING_META,
};
pub use queries::{UserRow, list, count, first_event_id};
pub use projector::project_pure;
