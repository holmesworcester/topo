pub mod wire;
pub mod projector;

// Re-export stable public API so callers import from `event_modules::message_attachment`.
pub use wire::{
    MessageAttachmentEvent, MESSAGE_ATTACHMENT_WIRE_SIZE,
    attachment_offsets,
    parse_message_attachment, encode_message_attachment,
    MESSAGE_ATTACHMENT_META,
};
pub use projector::project_pure;
