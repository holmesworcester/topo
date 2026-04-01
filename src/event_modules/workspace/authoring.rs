use ed25519_dalek::SigningKey;
use rusqlite::{Connection, OptionalExtension};

use crate::crypto::{event_id_to_base64, EventId};
use crate::event_modules::{
    parse_event, peer_shared, ParsedEvent, EVENT_TYPE_USER, EVENT_TYPE_WORKSPACE,
};

use super::queries::resolve_workspace_for_peer;

pub struct LocalAuthoringContext {
    pub signer_event_id: EventId,
    pub signing_key: SigningKey,
    pub workspace_id: [u8; 32],
    pub author_id: [u8; 32],
}

pub fn load_local_authoring_context(
    db: &Connection,
    recorded_by: &str,
) -> Result<LocalAuthoringContext, Box<dyn std::error::Error + Send + Sync>> {
    let (signer_event_id, signing_key) =
        peer_shared::load_local_peer_signer_required(db, recorded_by)?;
    let workspace_id = resolve_workspace_for_peer(db, recorded_by)?;
    let author_id = peer_shared::resolve_user_event_id(db, recorded_by, &signer_event_id)?;
    let workspace_id_b64 = event_id_to_base64(&workspace_id);
    let author_id_b64 = event_id_to_base64(&author_id);

    let workspace_projected: bool = db.query_row(
        "SELECT EXISTS(
             SELECT 1
             FROM workspaces
             WHERE recorded_by = ?1
               AND workspace_id = ?2
         )",
        rusqlite::params![recorded_by, workspace_id_b64],
        |row| row.get(0),
    )?;
    let workspace_recorded =
        semantic_event_recorded(db, recorded_by, &workspace_id_b64, EVENT_TYPE_WORKSPACE)?;
    let author_projected: bool = db.query_row(
        "SELECT EXISTS(
             SELECT 1
             FROM users
             WHERE recorded_by = ?1
               AND event_id = ?2
         )",
        rusqlite::params![recorded_by, author_id_b64],
        |row| row.get(0),
    )?;
    let author_recorded =
        semantic_event_recorded(db, recorded_by, &author_id_b64, EVENT_TYPE_USER)?;
    if (!workspace_projected && !workspace_recorded) || (!author_projected && !author_recorded) {
        return Err(
            "workspace has not completed initial sync yet — local authoring deps are still syncing"
                .into(),
        );
    }

    Ok(LocalAuthoringContext {
        signer_event_id,
        signing_key,
        workspace_id,
        author_id,
    })
}

fn semantic_event_recorded(
    db: &Connection,
    recorded_by: &str,
    event_id_b64: &str,
    expected_type_code: u8,
) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
    let blob: Option<Vec<u8>> = db
        .query_row(
            "SELECT e.blob
             FROM recorded_events re
             JOIN events e ON e.event_id = re.event_id
             WHERE re.peer_id = ?1
               AND re.event_id = ?2
             LIMIT 1",
            rusqlite::params![recorded_by, event_id_b64],
            |row| row.get(0),
        )
        .optional()?;
    let Some(blob) = blob else {
        return Ok(false);
    };
    let parsed = parse_event(&blob)?;
    let semantic = match parsed {
        ParsedEvent::Signed(signed) => parse_event(&signed.payload)?,
        other => other,
    };
    Ok(semantic.event_type_code() == expected_type_code)
}
