pub mod commands;
pub mod layout;
mod projection_context;
pub mod projector;
pub mod queries;
pub mod wire;

// Re-export stable public API so callers import from `event_modules::message`.
pub use commands::{
    create, create_deletion, delete_message, delete_message_for_peer, generate_files_for_peer,
    generate_for_peer, send, send_file_for_peer, send_for_peer, CreateMessageCmd,
    CreateMessageDeletionCmd, DeleteResponse, GenerateFilesResponse, GenerateResponse,
    SendFileResponse,
};
pub use projector::project_pure;
pub use queries::{count, list, list_deleted_ids, list_rows, resolve, resolve_number, MessageRow};
pub use wire::{encode_message, parse_message, MessageEvent, MESSAGE_META, MESSAGE_WIRE_SIZE};

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

// --- Response types (moved from service.rs) ---

use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct ReactionSummary {
    pub emoji: String,
    pub reactor_name: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AttachmentSummary {
    pub filename: String,
    pub mime_type: String,
    pub blob_bytes: i64,
    pub total_slices: i64,
    pub slices_received: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MessageItem {
    pub id: String,
    pub id_b64: String,
    pub author_id: String,
    pub author_name: String,
    pub content: String,
    pub created_at: i64,
    pub reactions: Vec<ReactionSummary>,
    pub attachments: Vec<AttachmentSummary>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_op_id: Option<String>,
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
