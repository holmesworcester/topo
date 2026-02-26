pub mod layout;
pub mod wire;
pub mod commands;
pub mod queries;
pub mod projector;

// Re-export stable public API so callers import from `event_modules::message`.
pub use wire::{MessageEvent, parse_message, encode_message, MESSAGE_META, MESSAGE_WIRE_SIZE};
pub use commands::{
    CreateMessageCmd, create, send, DeleteResponse,
    CreateMessageDeletionCmd, create_deletion, delete_message,
    GenerateResponse, send_for_peer, delete_message_for_peer, generate_for_peer,
};
pub use queries::{
    MessageRow, list_rows, count,
    resolve_number, resolve,
    list, list_deleted_ids,
};
pub use projector::project_pure;

use rusqlite::Connection;

pub fn ensure_schema(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS messages (
            message_id TEXT NOT NULL,
            workspace_id TEXT NOT NULL,
            author_id TEXT NOT NULL,
            content TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            recorded_by TEXT NOT NULL DEFAULT '',
            PRIMARY KEY (recorded_by, message_id)
        );
        CREATE INDEX IF NOT EXISTS idx_messages_workspace
            ON messages(workspace_id, created_at DESC);
        CREATE INDEX IF NOT EXISTS idx_messages_recorded
            ON messages(recorded_by, created_at DESC);
        ",
    )?;
    Ok(())
}

pub fn identity_rebind_recorded_by_tables() -> &'static [&'static str] {
    &["messages"]
}

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
