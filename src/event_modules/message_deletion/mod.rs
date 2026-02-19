pub mod wire;
pub mod projector;
pub mod commands;
pub mod queries;

// Re-export stable public API so callers import from `event_modules::message_deletion`.
pub use wire::{MessageDeletionEvent, parse_message_deletion, encode_message_deletion, MESSAGE_DELETION_META};
pub use commands::{CreateMessageDeletionCmd, create, delete_message};
pub use queries::list_deleted_ids;
pub use projector::project_pure;
