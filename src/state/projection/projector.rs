//! Pure projector contract types.
//!
//! Projectors are pure functions over `(ParsedEvent, ProjectorDecisionContext)` that
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
    /// Dedicated typed write variant for the `key_secrets` table.
    ///
    /// This variant exists so that EVERY production-path construction of a
    /// key_secrets WriteOp must go through `KeySecretsRow`. The constructor
    /// for the inner typed row lives in a single file (`key_shared.rs`);
    /// the access-control chain for "user cannot read messages unless
    /// invited" relies on `KeySecretsRow::new` being the only entry point.
    ///
    /// The executor substitutes canonical columns + values at apply time.
    InsertKeySecret(crate::event_modules::key_shared::KeySecretsRow),
}

/// A follow-on command to execute after write_ops are applied.
///
/// Commands represent non-deterministic or cascading actions that must happen
/// after the projection writes commit. Command identities are derived from
/// event identity for idempotence.
#[derive(Debug, Clone, PartialEq)]
pub enum EmitCommand {
    /// Hard-purge a tombstoned message event and all discovered dependents for
    /// the current tenant inside the current projection transaction.
    HardPurgeMessageGraph { message_event_id: String },
    /// Re-project a specific workspace event after accepted-workspace binding was set.
    /// Emitted by invite_accepted when it knows the workspace_id.
    /// Flows through normal projection + cascade.
    RetryWorkspaceEvent { workspace_id: String },
    /// Materialise a transport identity transition via the materializer boundary.
    /// Replaces the former ad-hoc RefreshTransportCreds marker.
    MaterializeTransportIdentity {
        spec: crate::contracts::transport_identity_contract::TransportIdentitySpec,
    },
    /// Emit a canonical deterministic event blob through the normal event
    /// pipeline (events + recorded_events + project_one).
    EmitDeterministicBlob { blob: Vec<u8> },
    /// Index a shared endpoint identity into the workspace event set once a
    /// peer_shared event proves which workspace it belongs to.
    IndexEndpointSharedForWorkspace {
        workspace_id: String,
        endpoint_shared_event_id: String,
    },
    /// Retry blocked encrypted events that reference this logical key id after
    /// local key material becomes available.
    RetryBlockedEncryptedByKey { key_event_id: String },
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
/// They are executed for both `Valid` and `Block` decisions.
#[derive(Debug, Clone)]
pub struct ProjectorResult {
    pub decision: super::decision::ProjectionDecision,
    pub write_ops: Vec<WriteOp>,
    pub emit_commands: Vec<EmitCommand>,
    pub suppress_sharing: bool,
}

impl ProjectorResult {
    /// Convenience: create a Valid result with the given write_ops.
    pub fn valid(write_ops: Vec<WriteOp>) -> Self {
        Self::valid_with_sharing(write_ops, false)
    }

    /// Convenience: create a Valid result with the given write_ops and a
    /// projection-owned suppress_sharing decision.
    pub fn valid_with_sharing(write_ops: Vec<WriteOp>, suppress_sharing: bool) -> Self {
        Self {
            decision: super::decision::ProjectionDecision::Valid,
            write_ops,
            emit_commands: Vec::new(),
            suppress_sharing,
        }
    }

    /// Convenience: create a Valid result with write_ops and commands.
    pub fn valid_with_commands(write_ops: Vec<WriteOp>, emit_commands: Vec<EmitCommand>) -> Self {
        Self {
            decision: super::decision::ProjectionDecision::Valid,
            write_ops,
            emit_commands,
            suppress_sharing: false,
        }
    }

    /// Convenience: create a Reject result (no writes, no commands).
    pub fn reject(reason: String) -> Self {
        Self {
            decision: super::decision::ProjectionDecision::Reject { reason },
            write_ops: Vec::new(),
            emit_commands: Vec::new(),
            suppress_sharing: false,
        }
    }

    /// Convenience: create a Block result (no writes, no commands).
    pub fn block(missing: Vec<[u8; 32]>) -> Self {
        Self {
            decision: super::decision::ProjectionDecision::BlockOnMissingDeps { missing },
            write_ops: Vec::new(),
            emit_commands: Vec::new(),
            suppress_sharing: false,
        }
    }

    /// Convenience: create an AlreadyProcessed result.
    pub fn already_processed() -> Self {
        Self {
            decision: super::decision::ProjectionDecision::AlreadyProcessed,
            write_ops: Vec::new(),
            emit_commands: Vec::new(),
            suppress_sharing: false,
        }
    }
}

/// Info from a pre-existing deletion_intent row.
#[derive(Debug, Clone)]
pub struct DeletionIntentInfo {
    pub deletion_event_id: String,
    pub author_id: String,
    pub authorized_by_admin: bool,
    pub created_at: i64,
}

#[derive(Debug, Clone)]
pub struct FileDescriptorInfo {
    pub event_id: String,
    pub message_id: String,
    pub signer_event_id: String,
    pub key_event_id: String,
    /// BLAKE3 bao root hash for content verification ([0;32] = no verification).
    pub root_hash: [u8; 32],
    /// Original file size in bytes.
    pub blob_bytes: u64,
    /// Effective plaintext bytes per slice.
    pub slice_bytes: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CurrentSignerInfo {
    pub event_id: String,
    pub semantic_type_code: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemovalTargetKind {
    User,
    Peer,
}

impl RemovalTargetKind {
    pub fn as_str(self) -> &'static str {
        match self {
            RemovalTargetKind::User => "user",
            RemovalTargetKind::Peer => "peer",
        }
    }
}

/// Read-model decision context passed to pure projectors for decision-context queries.
///
/// Projectors must not access the database directly. Instead, the pipeline
/// populates this struct with whatever the projector needs to make its
/// decision. Fields are `Option` — only populated when the projector's
/// event type requires them.
#[derive(Debug, Clone, Default)]
pub struct ProjectorDecisionContext {
    /// Accepted workspace_id for this tenant (from invites_accepted projection rows).
    pub accepted_workspace_id: Option<String>,

    /// Semantic signer-user mismatch for content events with `author_id`.
    ///
    /// This is computed by the pipeline from `peers_shared.user_event_id` so
    /// pure projectors can reject deterministically without issuing SQL.
    pub signer_user_mismatch_reason: Option<String>,

    /// For PeerShared: the claimed `user_event_id` must match the user identity
    /// authorized by the signing device-invite chain.
    pub peer_shared_user_mismatch_reason: Option<String>,

    /// For PeerShared/AccountShared: the referenced endpoint_shared root must
    /// already be projected, and this carries the bound endpoint_id when so.
    pub peer_shared_endpoint_id: Option<String>,
    pub peer_shared_endpoint_binding_reason: Option<String>,

    /// For Admin: the claimed `public_key` must match the referenced
    /// `users.public_key` for `user_event_id`.
    pub admin_user_key_mismatch_reason: Option<String>,

    /// For MessageDeletion: the author_id of the target message (if it exists in messages).
    pub target_message_author: Option<String>,
    /// For MessageDeletion: the author_id from an existing tombstone (if any).
    pub target_tombstone_author: Option<String>,
    /// For MessageDeletion: resolved user identity for a peer_shared signer.
    pub deletion_signer_user_id: Option<String>,
    /// For MessageDeletion: whether the current signer is an admin event.
    pub deletion_signer_is_admin: bool,
    /// For MessageDeletion: signer-family or signer-resolution failure.
    pub deletion_signer_reject_reason: Option<String>,
    /// For MessageDeletion: true if the target event_id is in valid_events but is NOT
    /// a message (no row in messages or deleted_messages). This means the deletion
    /// references a non-message event and should be rejected.
    pub target_is_non_message: bool,

    /// For Message: pre-existing deletion intents for this message_id.
    /// Multiple intents may exist (one per deletion event targeting this message).
    /// Used for delete-before-create convergence — the message projector finds the
    /// first intent whose author matches the message author, or an admin-auth intent.
    pub deletion_intents: Vec<DeletionIntentInfo>,

    /// For dependent event context loaders that must fast-purge before
    /// projector dispatch, the root message graph to purge.
    pub purge_message_event_id: Option<String>,

    /// For KeyRotation/KeyShared: DH-unwrapped key material, if available.
    pub unwrapped_secret_material: Option<UnwrappedSecretMaterial>,
    /// For KeyHistory: invite-DH-unwrapped historical key material.
    pub unwrapped_key_history_material: Vec<HistoricalKeyMaterial>,

    /// For FileSlice: descriptor info for the file_id.
    /// Empty vec means no descriptor exists yet (dep-block on file_id).
    pub file_descriptors: Vec<FileDescriptorInfo>,
    /// For FileSlice: existing slice info (event_id, descriptor_event_id) if slot occupied.
    pub existing_file_slice: Option<(String, String)>,
    /// For encrypted events: outer wrapper key_event_id, if present.
    pub current_transport_key_event_id: Option<String>,
    /// For encrypted dependent events: outer wrapper owner_event_id, if present.
    pub current_owner_event_id: Option<String>,
    /// For signed events: currently verified outer signer, if present.
    pub current_signer: Option<CurrentSignerInfo>,

    /// For invite events (UserInvite, DeviceInvite, InviteAccepted):
    /// local bootstrap context if available. Populated from `bootstrap_context`
    /// table so projectors can emit trust writes without the service layer.
    pub bootstrap_context: Option<BootstrapDecisionContext>,

    /// For invite events signed by peer_shared: whether `authority_event_id`
    /// resolves to the identity authorized by `signed_by`.
    /// UserInvite requires admin authority; DeviceInvite requires the signer's user.
    pub invite_authority_matches_signer: Option<bool>,

    /// For InviteAccepted: external accepts must match the workspace_id
    /// recorded from the accepted invite link. Local self-create remains
    /// valid when invite_event_id == workspace_id.
    pub invite_accepted_link_workspace_mismatch_reason: Option<String>,

    /// For Removal: only admin peer_shared signers may author removal events.
    pub removal_signer_reject_reason: Option<String>,
    /// For Removal: whether the target resolves to a user or peer_shared row.
    pub removal_target_kind: Option<RemovalTargetKind>,

    /// For KeyRequest: projection may suppress later sharing once a projected
    /// response already exists for the same delivery target.
    pub key_request_suppress_sharing: bool,

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

/// Unwrapped historical key material derived from KeyHistory.
#[derive(Debug, Clone)]
pub struct HistoricalKeyMaterial {
    pub key_event_id: [u8; 32],
    pub key_bytes: [u8; 32],
}

/// Bootstrap context read from the `bootstrap_context` table, passed to
/// projectors as part of `ProjectorDecisionContext`.
#[derive(Debug, Clone)]
pub struct BootstrapDecisionContext {
    pub workspace_id: String,
    pub bootstrap_addrs: Vec<String>,
    pub bootstrap_spki_fingerprint: [u8; 32],
}
