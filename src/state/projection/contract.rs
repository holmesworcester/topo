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
    /// Re-project a specific workspace event after accepted-workspace binding was set.
    /// Emitted by invite_accepted when it knows the workspace_id.
    /// Flows through normal projection + cascade.
    RetryWorkspaceEvent { workspace_id: String },
    /// Retry file_slice guard-blocked events for a specific file_id.
    RetryFileSliceGuards { file_id: String },
    /// Record a guard-block for a file_slice awaiting its descriptor.
    RecordFileSliceGuardBlock { file_id: String, event_id: String },
    /// Apply a typed transport identity transition via the adapter boundary.
    /// Replaces the former ad-hoc RefreshTransportCreds marker.
    ApplyTransportIdentityIntent {
        intent: crate::contracts::transport_identity_contract::TransportIdentityIntent,
    },
    /// Emit a canonical deterministic event blob through the normal event
    /// pipeline (events + recorded_events + project_one).
    EmitDeterministicBlob { blob: Vec<u8> },
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
/// They are executed for:
/// - `Valid` decisions (normal post-write follow-ons), and
/// - `Block` decisions (block-side effects such as file-slice guard rows).
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
    /// Accepted workspace_id for this tenant (from invites_accepted projection rows).
    pub accepted_workspace_id: Option<String>,

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

    /// For KeyShared: whether the recipient has been removed.
    pub recipient_removed: bool,
    /// For KeyShared: DH-unwrapped key material, if available.
    pub unwrapped_secret_material: Option<UnwrappedSecretMaterial>,

    /// For FileSlice: descriptor info (event_id, signer_event_id) for the file_id.
    /// Empty vec means no descriptor exists yet (guard-block).
    pub file_descriptors: Vec<(String, String)>,
    /// For FileSlice: existing slice info (event_id, descriptor_event_id) if slot occupied.
    pub existing_file_slice: Option<(String, String)>,

    /// For invite events (UserInvite, DeviceInvite, InviteAccepted):
    /// local bootstrap context if available. Populated from `bootstrap_context`
    /// table so projectors can emit trust writes without the service layer.
    pub bootstrap_context: Option<BootstrapContextSnapshot>,

    /// For invite events signed by peer_shared: whether `authority_event_id`
    /// resolves to an admin event for the same user identity as `signed_by`.
    pub invite_authority_matches_signer: Option<bool>,

    /// Whether this event was locally created (source = 'local' in recorded_events).
    /// Used to gate pending bootstrap trust writes: only locally-created invite
    /// events should write pending trust rows. Synced invite events on the
    /// joiner side must NOT write pending trust even if bootstrap_context exists.
    pub is_local_create: bool,

    /// True when `bootstrap_context.bootstrap_spki_fingerprint` is already present
    /// as a projected (non-removed) `peers_shared.transport_fingerprint`.
    /// Used to avoid writing bootstrap trust rows that are already superseded by
    /// steady-state peer trust.
    pub bootstrap_spki_already_peer_shared: bool,

    /// True when local invite_secret material exists for this invite event.
    /// Used by invite_accepted projection to emit bootstrap identity install
    /// intent through the normal command path.
    pub has_local_invite_secret: bool,

    /// True when peer_shared transport creds are already active for this tenant.
    /// Used to prevent bootstrap-identity re-install attempts after convergence.
    pub peer_shared_transport_identity_active: bool,
}

/// Unwrapped symmetric key material derived from KeyShared.
#[derive(Debug, Clone)]
pub struct UnwrappedSecretMaterial {
    pub key_bytes: [u8; 32],
}

/// Bootstrap context read from the `bootstrap_context` table, passed to
/// projectors as part of `ContextSnapshot`.
#[derive(Debug, Clone)]
pub struct BootstrapContextSnapshot {
    pub workspace_id: String,
    pub bootstrap_addrs: Vec<String>,
    pub bootstrap_spki_fingerprint: [u8; 32],
}
