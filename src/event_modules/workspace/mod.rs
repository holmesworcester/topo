pub mod wire;
pub mod projector;
pub mod queries;
pub mod commands;
pub mod identity_ops;
pub mod invite_link;

// Re-export stable public API so callers import from `event_modules::workspace`.
pub use wire::{WorkspaceEvent, parse_workspace, encode_workspace, WORKSPACE_META, WORKSPACE_WIRE_SIZE};
pub use projector::project_pure;
pub use queries::{
    WorkspaceRow, list, name, resolve_workspace_for_peer,
    WorkspaceItem, list_items, StatusResponse, status, KeysResponse, keys,
    ViewReaction, ViewMessage, ViewResponse, view, view_for_peer,
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

pub fn identity_rebind_recorded_by_tables() -> &'static [&'static str] {
    &["workspaces"]
}
