pub mod wire;
pub mod projector;
pub mod queries;

// Re-export stable public API so callers import from `event_modules::admin`.
pub use wire::{
    AdminBootEvent, AdminOngoingEvent,
    parse_admin_boot, encode_admin_boot,
    parse_admin_ongoing, encode_admin_ongoing,
    ADMIN_BOOT_WIRE_SIZE,
    ADMIN_BOOT_META, ADMIN_ONGOING_META,
};
pub use queries::count;
pub use projector::project_pure;
