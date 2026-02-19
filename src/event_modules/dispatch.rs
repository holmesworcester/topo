//! Typed command and query dispatch for event modules.
//!
//! Provides `EventCommand` and `EventQuery` enums that route operations to
//! the appropriate event module, keeping service.rs as a thin orchestrator.

use crate::crypto::EventId;
use ed25519_dalek::SigningKey;
use rusqlite::Connection;

use super::message;
use super::message_deletion;
use super::reaction;
use super::user_removed;

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Queries
// ---------------------------------------------------------------------------

use super::{admin, peer_shared, transport_key, user, workspace};

/// Typed query enum for event-module-owned read operations.
/// Service routes through these instead of inlining event-specific SQL.
pub enum EventQuery {
    /// List messages (returns QueryResult::Messages).
    MessageList { limit: usize },
    /// Count messages (returns QueryResult::Count).
    MessageCount,
    /// Resolve a message selector to an EventId (returns QueryResult::EventId).
    MessageResolve { selector: String },
    /// Resolve a 1-based message number to an EventId (returns QueryResult::EventId).
    MessageResolveNumber { msg_num: usize },
    /// List reactions (returns QueryResult::Reactions).
    ReactionList,
    /// Count reactions (returns QueryResult::Count).
    ReactionCount,
    /// List reactions for a message with author names (returns QueryResult::ReactionsWithAuthors).
    ReactionListForMessageWithAuthors { target_event_id_b64: String },
    /// List emojis for a message (returns QueryResult::Strings).
    ReactionListForMessage { target_event_id_b64: String },
    /// List deleted message IDs (returns QueryResult::Strings).
    DeletedMessageIds,
    /// List users (returns QueryResult::Users).
    UserList,
    /// Count users (returns QueryResult::Count).
    UserCount,
    /// First user event_id (returns QueryResult::OptionalString).
    UserFirstEventId,
    /// List workspaces (returns QueryResult::Workspaces).
    WorkspaceList,
    /// Workspace display name (returns QueryResult::String).
    WorkspaceName,
    /// List peer_shared event_ids (returns QueryResult::Strings).
    PeerSharedEventIds,
    /// Count peer_shared rows (returns QueryResult::Count).
    PeerSharedCount,
    /// First peer_shared event_id (returns QueryResult::OptionalString).
    PeerSharedFirstEventId,
    /// List peer accounts with usernames (returns QueryResult::Accounts).
    PeerSharedAccounts,
    /// List admin event_ids (returns QueryResult::Strings).
    AdminEventIds,
    /// Count admin rows (returns QueryResult::Count).
    AdminCount,
    /// Count transport key rows (returns QueryResult::Count).
    TransportKeyCount,
}

/// Result type for event queries. Callers destructure the expected variant.
pub enum QueryResult {
    Messages(message::MessagesResponse),
    Reactions(Vec<reaction::ReactionItem>),
    ReactionsWithAuthors(Vec<reaction::ReactionWithAuthor>),
    Users(Vec<user::UserRow>),
    Workspaces(Vec<workspace::WorkspaceRow>),
    Accounts(Vec<peer_shared::AccountRow>),
    Strings(Vec<String>),
    String(String),
    OptionalString(Option<String>),
    Count(i64),
    EventId(EventId),
}

pub fn execute_query(
    db: &Connection,
    recorded_by: &str,
    query: EventQuery,
) -> Result<QueryResult, Box<dyn std::error::Error + Send + Sync>> {
    match query {
        EventQuery::MessageList { limit } => Ok(QueryResult::Messages(message::list(
            db,
            recorded_by,
            limit,
        )?)),
        EventQuery::MessageCount => Ok(QueryResult::Count(message::count(db, recorded_by)?)),
        EventQuery::MessageResolve { selector } => {
            let eid = message::resolve(db, recorded_by, &selector)
                .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e.into() })?;
            Ok(QueryResult::EventId(eid))
        }
        EventQuery::MessageResolveNumber { msg_num } => {
            let eid = message::resolve_number(db, recorded_by, msg_num)
                .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e.into() })?;
            Ok(QueryResult::EventId(eid))
        }
        EventQuery::ReactionList => Ok(QueryResult::Reactions(reaction::list(db, recorded_by)?)),
        EventQuery::ReactionCount => Ok(QueryResult::Count(reaction::count(db, recorded_by)?)),
        EventQuery::ReactionListForMessageWithAuthors {
            target_event_id_b64,
        } => Ok(QueryResult::ReactionsWithAuthors(
            reaction::list_for_message_with_authors(db, recorded_by, &target_event_id_b64)?,
        )),
        EventQuery::ReactionListForMessage {
            target_event_id_b64,
        } => Ok(QueryResult::Strings(reaction::list_for_message(
            db,
            recorded_by,
            &target_event_id_b64,
        )?)),
        EventQuery::DeletedMessageIds => Ok(QueryResult::Strings(
            message_deletion::list_deleted_ids(db, recorded_by)?,
        )),
        EventQuery::UserList => Ok(QueryResult::Users(user::list(db, recorded_by)?)),
        EventQuery::UserCount => Ok(QueryResult::Count(user::count(db, recorded_by)?)),
        EventQuery::UserFirstEventId => Ok(QueryResult::OptionalString(user::first_event_id(
            db,
            recorded_by,
        )?)),
        EventQuery::WorkspaceList => Ok(QueryResult::Workspaces(workspace::list(db, recorded_by)?)),
        EventQuery::WorkspaceName => Ok(QueryResult::String(workspace::name(db, recorded_by)?)),
        EventQuery::PeerSharedEventIds => Ok(QueryResult::Strings(peer_shared::list_event_ids(
            db,
            recorded_by,
        )?)),
        EventQuery::PeerSharedCount => Ok(QueryResult::Count(peer_shared::count(db, recorded_by)?)),
        EventQuery::PeerSharedFirstEventId => Ok(QueryResult::OptionalString(
            peer_shared::first_event_id(db, recorded_by)?,
        )),
        EventQuery::PeerSharedAccounts => Ok(QueryResult::Accounts(peer_shared::list_accounts(
            db,
            recorded_by,
        )?)),
        EventQuery::AdminEventIds => Ok(QueryResult::Strings(admin::list_event_ids(
            db,
            recorded_by,
        )?)),
        EventQuery::AdminCount => Ok(QueryResult::Count(admin::count(db, recorded_by)?)),
        EventQuery::TransportKeyCount => {
            Ok(QueryResult::Count(transport_key::count(db, recorded_by)?))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::open_connection;
    use crate::testutil::Peer;

    #[test]
    fn test_execute_query_routes_correctly() {
        let peer = Peer::new_with_identity("dispatch-q");
        let db = open_connection(&peer.db_path).unwrap();

        // WorkspaceName
        let res = execute_query(&db, &peer.identity, EventQuery::WorkspaceName).unwrap();
        match res {
            QueryResult::String(name) => assert!(!name.is_empty()),
            _ => panic!("expected QueryResult::String"),
        }

        // MessageCount (should be 0 before any messages)
        let res = execute_query(&db, &peer.identity, EventQuery::MessageCount).unwrap();
        match res {
            QueryResult::Count(n) => assert_eq!(n, 0),
            _ => panic!("expected QueryResult::Count"),
        }

        // UserList
        let res = execute_query(&db, &peer.identity, EventQuery::UserList).unwrap();
        match res {
            QueryResult::Users(users) => assert!(!users.is_empty()),
            _ => panic!("expected QueryResult::Users"),
        }

        // PeerSharedAccounts
        let res = execute_query(&db, &peer.identity, EventQuery::PeerSharedAccounts).unwrap();
        match res {
            QueryResult::Accounts(accts) => assert!(!accts.is_empty()),
            _ => panic!("expected QueryResult::Accounts"),
        }

        // AdminEventIds
        let res = execute_query(&db, &peer.identity, EventQuery::AdminEventIds).unwrap();
        match res {
            QueryResult::Strings(ids) => assert!(!ids.is_empty()),
            _ => panic!("expected QueryResult::Strings"),
        }
    }

    #[test]
    fn test_execute_command_creates_message() {
        let peer = Peer::new_with_identity("dispatch-c");
        let db = open_connection(&peer.db_path).unwrap();
        let signer_eid = peer.peer_shared_event_id.as_ref().unwrap();
        let signing_key = peer.peer_shared_signing_key.as_ref().unwrap();

        let eid = execute_command(
            &db,
            &peer.identity,
            signer_eid,
            signing_key,
            1000,
            EventCommand::Message(message::CreateMessageCmd {
                workspace_id: peer.workspace_id,
                author_id: peer.author_id,
                content: "hello dispatch".to_string(),
            }),
        )
        .unwrap();

        // Verify via query dispatch
        let res = execute_query(&db, &peer.identity, EventQuery::MessageCount).unwrap();
        match res {
            QueryResult::Count(n) => assert_eq!(n, 1),
            _ => panic!("expected QueryResult::Count"),
        }

        let _ = eid; // suppress unused warning
    }
}
