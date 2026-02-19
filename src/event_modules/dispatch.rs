//! Typed command dispatch for event creation.
//!
//! Provides an `EventCommand` enum that routes creation to the appropriate event module,
//! keeping service.rs as a thin orchestrator.

use crate::crypto::EventId;
use ed25519_dalek::SigningKey;
use rusqlite::Connection;

use super::message;
use super::reaction;
use super::message_deletion;
use super::user_removed;

pub enum EventCommand {
    Message(message::CreateMessageCmd),
    Reaction(reaction::CreateReactionCmd),
    MessageDeletion(message_deletion::CreateMessageDeletionCmd),
    UserRemoved(user_removed::CreateUserRemovedCmd),
}

pub fn execute_command(
    db: &Connection,
    recorded_by: &str,
    signer_eid: &EventId,
    signing_key: &SigningKey,
    created_at_ms: u64,
    cmd: EventCommand,
) -> Result<EventId, Box<dyn std::error::Error + Send + Sync>> {
    match cmd {
        EventCommand::Message(c) => {
            message::create(db, recorded_by, signer_eid, signing_key, created_at_ms, c)
        }
        EventCommand::Reaction(c) => {
            reaction::create(db, recorded_by, signer_eid, signing_key, created_at_ms, c)
        }
        EventCommand::MessageDeletion(c) => {
            message_deletion::create(db, recorded_by, signer_eid, signing_key, created_at_ms, c)
        }
        EventCommand::UserRemoved(c) => {
            user_removed::create(db, recorded_by, signer_eid, signing_key, created_at_ms, c)
        }
    }
}
