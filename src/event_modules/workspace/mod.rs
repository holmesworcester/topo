pub mod commands;
mod commands_api;
pub mod identity_ops;
pub mod invite_link;
mod projection_context;
pub mod projector;
pub mod queries;
pub mod wire;

// Re-export stable public API so callers import from `event_modules::workspace`.
pub use projector::project_pure;
pub use queries::{
    keys, list, list_items, name, resolve_workspace_for_peer, status, view, view_for_peer,
    KeysResponse, StatusResponse, ViewMessage, ViewReaction, ViewResponse, WorkspaceItem,
    WorkspaceRow,
};
pub use wire::{
    encode_workspace, parse_workspace, WorkspaceEvent, WORKSPACE_META, WORKSPACE_WIRE_SIZE,
};

use rusqlite::Connection;

pub fn ensure_schema(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS workspaces (
            recorded_by TEXT NOT NULL,
            event_id TEXT NOT NULL,
            workspace_id TEXT NOT NULL,
            public_key BLOB NOT NULL,
            name TEXT,
            PRIMARY KEY (recorded_by, event_id)
        );
        CREATE UNIQUE INDEX IF NOT EXISTS idx_workspaces_single_per_peer
            ON workspaces(recorded_by, workspace_id);
        ",
    )?;
    Ok(())
}
