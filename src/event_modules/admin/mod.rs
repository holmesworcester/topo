pub mod projector;
pub mod queries;
pub mod wire;

// Re-export stable public API so callers import from `event_modules::admin`.
pub use projector::project_pure;
pub use queries::count;
pub use wire::{
    encode_admin_boot, encode_admin_ongoing, parse_admin_boot, parse_admin_ongoing, AdminBootEvent,
    AdminOngoingEvent, ADMIN_BOOT_META, ADMIN_BOOT_WIRE_SIZE, ADMIN_ONGOING_META,
    ADMIN_ONGOING_WIRE_SIZE,
};
