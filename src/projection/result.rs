//! Pure projector contract types.
//!
//! Projectors are pure functions over `(ParsedEvent, ContextSnapshot)` that
//! return a `ProjectorResult`. They do not execute SQL or any other side
//! effects directly. The apply engine in `apply.rs` executes the returned
//! `write_ops` transactionally, then runs `emit_commands` via explicit handlers.

/// Value that can be bound to a SQL parameter in a WriteOp.
#[derive(Debug, Clone, PartialEq)]
pub enum SqlVal {
    Text(String),
    Int(i64),
    Blob(Vec<u8>),
}

/// A single idempotent database write operation returned by a pure projector.
#[derive(Debug, Clone, PartialEq)]
pub enum WriteOp {
    /// INSERT OR IGNORE INTO table (columns...) VALUES (values...).
    InsertOrIgnore {
        table: &'static str,
        columns: Vec<&'static str>,
        values: Vec<SqlVal>,
    },
    /// DELETE FROM table WHERE col1 = v1 AND col2 = v2 ...
    Delete {
        table: &'static str,
        where_clause: Vec<(&'static str, SqlVal)>,
    },
}

/// A follow-on command to execute after write_ops are applied.
///
/// Commands represent non-deterministic or cascading actions that must happen
/// after the projection writes commit. Command identities are derived from
/// event identity for idempotence.
#[derive(Debug, Clone, PartialEq)]
pub enum EmitCommand {
    /// Re-project a specific workspace event after a trust anchor was set.
    /// Emitted by invite_accepted when it knows the workspace_id.
    /// Flows through normal projection + cascade.
    RetryWorkspaceEvent { workspace_id: String },
    /// Retry file_slice guard-blocked events for a specific file_id.
    RetryFileSliceGuards { file_id: String },
    /// Record a guard-block for a file_slice awaiting its descriptor.
    RecordFileSliceGuardBlock { file_id: String, event_id: String },
    /// Write pending invite bootstrap trust from projection (inviter side).
    /// Emitted by invite projectors when local bootstrap_context exists.
    WritePendingBootstrapTrust {
        invite_event_id: String,
        workspace_id: String,
        expected_bootstrap_spki_fingerprint: [u8; 32],
    },
    /// Write accepted invite bootstrap trust from projection (joiner side).
    /// Emitted by InviteAccepted projector when bootstrap_context exists.
    WriteAcceptedBootstrapTrust {
        invite_accepted_event_id: String,
        invite_event_id: String,
        workspace_id: String,
        bootstrap_addr: String,
        bootstrap_spki_fingerprint: [u8; 32],
    },
    /// Supersede bootstrap trust rows whose SPKI matches a newly-projected
    /// PeerShared-derived SPKI. Emitted by PeerShared projectors so that
    /// trust check reads are pure (no write side-effects).
    SupersedeBootstrapTrust { peer_shared_public_key: [u8; 32] },
    /// Refresh transport credentials from projected local_signer_material (peer_shared key).
    RefreshTransportCreds,
}

/// The pure projector contract: everything a projector returns.
///
/// `decision` carries the same semantics as the old `ProjectionDecision` —
/// Valid, Block, Reject, AlreadyProcessed.
///
/// `write_ops` are the deterministic state mutations to apply transactionally.
/// They are only applied when `decision` is `Valid`.
///
/// `emit_commands` are follow-on actions to run after write_ops commit.
/// They are only executed when `decision` is `Valid`.
#[derive(Debug, Clone)]
pub struct ProjectorResult {
    pub decision: super::decision::ProjectionDecision,
    pub write_ops: Vec<WriteOp>,
    pub emit_commands: Vec<EmitCommand>,
}

impl ProjectorResult {
    /// Convenience: create a Valid result with the given write_ops.
    pub fn valid(write_ops: Vec<WriteOp>) -> Self {
        Self {
            decision: super::decision::ProjectionDecision::Valid,
            write_ops,
            emit_commands: Vec::new(),
        }
    }

    /// Convenience: create a Valid result with write_ops and commands.
    pub fn valid_with_commands(write_ops: Vec<WriteOp>, emit_commands: Vec<EmitCommand>) -> Self {
        Self {
            decision: super::decision::ProjectionDecision::Valid,
            write_ops,
            emit_commands,
        }
    }

    /// Convenience: create a Reject result (no writes, no commands).
    pub fn reject(reason: String) -> Self {
        Self {
            decision: super::decision::ProjectionDecision::Reject { reason },
            write_ops: Vec::new(),
            emit_commands: Vec::new(),
        }
    }

    /// Convenience: create a Block result (no writes, no commands).
    pub fn block(missing: Vec<[u8; 32]>) -> Self {
        Self {
            decision: super::decision::ProjectionDecision::Block { missing },
            write_ops: Vec::new(),
            emit_commands: Vec::new(),
        }
    }

    /// Convenience: create an AlreadyProcessed result.
    pub fn already_processed() -> Self {
        Self {
            decision: super::decision::ProjectionDecision::AlreadyProcessed,
            write_ops: Vec::new(),
            emit_commands: Vec::new(),
        }
    }
}

/// Info from a pre-existing deletion_intent row.
#[derive(Debug, Clone)]
pub struct DeletionIntentInfo {
    pub deletion_event_id: String,
    pub author_id: String,
    pub created_at: i64,
}

/// Read-model snapshot passed to pure projectors for context queries.
///
/// Projectors must not access the database directly. Instead, the pipeline
/// populates this struct with whatever the projector needs to make its
/// decision. Fields are `Option` — only populated when the projector's
/// event type requires them.
#[derive(Debug, Clone, Default)]
pub struct ContextSnapshot {
    /// Trust anchor workspace_id for this tenant (from trust_anchors table).
    pub trust_anchor_workspace_id: Option<String>,

    /// Semantic signer-user mismatch for content events with `author_id`.
    ///
    /// This is computed by the pipeline from `peers_shared.user_event_id` so
    /// pure projectors can reject deterministically without issuing SQL.
    pub signer_user_mismatch_reason: Option<String>,

    /// For MessageDeletion: the author_id of the target message (if it exists in messages).
    pub target_message_author: Option<String>,
    /// For MessageDeletion: the author_id from an existing tombstone (if any).
    pub target_tombstone_author: Option<String>,
    /// For MessageDeletion: true if the target event_id is in valid_events but is NOT
    /// a message (no row in messages or deleted_messages). This means the deletion
    /// references a non-message event and should be rejected.
    pub target_is_non_message: bool,

    /// For Message: pre-existing deletion intents for this message_id.
    /// Multiple intents may exist (one per deletion event targeting this message).
    /// Used for delete-before-create convergence — the message projector finds the
    /// first intent whose author matches the message author.
    pub deletion_intents: Vec<DeletionIntentInfo>,

    /// For Reaction: whether the target message has been tombstoned
    /// (row in deleted_messages). Note: pending deletion_intents are NOT
    /// included — an unverified intent does not mean the message is deleted.
    pub target_message_deleted: bool,

    /// For SecretShared: whether the recipient has been removed.
    pub recipient_removed: bool,

    /// For FileSlice: descriptor info (event_id, signer_event_id) for the file_id.
    /// Empty vec means no descriptor exists yet (guard-block).
    pub file_descriptors: Vec<(String, String)>,
    /// For FileSlice: existing slice info (event_id, descriptor_event_id) if slot occupied.
    pub existing_file_slice: Option<(String, String)>,

    /// For Encrypted: the decryption key bytes (if secret_key is available).
    pub secret_key_bytes: Option<Vec<u8>>,

    /// For invite events (UserInviteBoot, DeviceInviteFirst, InviteAccepted):
    /// local bootstrap context if available. Populated from `bootstrap_context`
    /// table so projectors can emit trust writes without the service layer.
    pub bootstrap_context: Option<BootstrapContextSnapshot>,

    /// Whether this event was locally created (source = 'local' in recorded_events).
    /// Used to gate pending bootstrap trust emission: only locally-created invite
    /// events should emit WritePendingBootstrapTrust. Synced invite events on the
    /// joiner side must NOT emit pending trust even if bootstrap_context exists.
    pub is_local_create: bool,
}

/// Bootstrap context read from the `bootstrap_context` table, passed to
/// projectors as part of `ContextSnapshot`.
#[derive(Debug, Clone)]
pub struct BootstrapContextSnapshot {
    pub workspace_id: String,
    pub bootstrap_addr: String,
    pub bootstrap_spki_fingerprint: [u8; 32],
}
