use ed25519_dalek::SigningKey;
use rusqlite::Connection;

use crate::crypto::EventId;
use crate::event_modules::peer_shared;

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

    Ok(LocalAuthoringContext {
        signer_event_id,
        signing_key,
        workspace_id,
        author_id,
    })
}
