pub mod wire;
pub mod commands;
pub mod queries;
pub mod projector;

// Re-export stable public API so callers import from `event_modules::message`.
pub use wire::{MessageEvent, parse_message, encode_message, MESSAGE_META};
pub use commands::{CreateMessageCmd, create, send_conn};
pub use queries::{
    MessageRow, query_list, query_count,
    resolve_by_number, resolve_selector,
    messages_conn,
};
pub use projector::project_pure;

// --- Response types (moved from service.rs) ---

use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct MessageItem {
    pub id: String,
    pub id_b64: String,
    pub author_id: String,
    pub author_name: String,
    pub content: String,
    pub created_at: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MessagesResponse {
    pub messages: Vec<MessageItem>,
    pub total: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SendResponse {
    pub content: String,
    pub event_id: String,
}
