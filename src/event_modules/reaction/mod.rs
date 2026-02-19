pub mod create;
pub mod wire;
pub mod projector;
pub mod commands;
pub mod queries;

// Re-export stable public API so callers import from `event_modules::reaction`.
pub use wire::{
    ReactionEvent,
    parse_reaction,
    encode_reaction,
    offsets,
    REACTION_WIRE_SIZE,
    REACTION_TYPE_META,
};
pub use create::{CreateReactionCmd, create};
pub use commands::{react, ReactResponse};
pub use queries::{ReactionRow, list_rows, list_for_message, count, ReactionItem, list};
pub use projector::project_pure;
