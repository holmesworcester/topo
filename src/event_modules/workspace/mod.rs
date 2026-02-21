pub mod wire;
pub mod projector;
pub mod queries;
pub mod commands;
pub mod identity_ops;
pub mod invite_link;

// Re-export stable public API so callers import from `event_modules::workspace`.
pub use wire::{WorkspaceEvent, parse_workspace, encode_workspace, WORKSPACE_META, WORKSPACE_WIRE_SIZE};
pub use projector::project_pure;
pub use queries::{WorkspaceRow, list, name};
