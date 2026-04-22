//! Typed dep/guard facts — the bundle a projector's pure decision fn consumes.
//!
//! Shape (see `docs/planning/REAL_PROOFS_SIMPLIFICATION_RECOMMENDATIONS.md`):
//!
//! ```text
//! self_event + DepFacts + GuardFacts -> pure decide fn -> plan
//! ```
//!
//! `DepFacts` carries typed summaries of immediate *valid event* deps —
//! anything the event-sourced graph already justifies. `GuardFacts` is the
//! narrow current-state / local-only surface that cannot yet be eventized
//! (bootstrap-link bindings, local invite-secret material, etc.).
//!
//! Both bundles start small. Fields are added per projector as the
//! DepFacts-pilot (Priority 1 in the simplification plan) migrates each
//! context loader off ad-hoc SQL branching. The seed here serves the
//! InviteAccepted pilot; later projectors extend these structs rather
//! than introducing parallel bundles.
//!
//! The decide fns are pure in the `(event, deps, guards) -> decision`
//! sense — no `Connection`, no `&dyn ProjectionQueries`. That makes them
//! a natural Verus proof target without dragging SQL into the spec.

use crate::event_modules::{
    AdminEvent, DeviceInviteEvent, InviteAcceptedEvent, MessageDeletionEvent, MessageEvent,
    PeerSharedEvent, ReactionEvent,
};
use crate::projection::projector::{
    BootstrapDecisionContext, DeletionIntentInfo, RemovalTargetKind,
};

/// Typed summaries of immediate valid event dependencies.
///
/// Empty for events whose decision does not read anything off its deps
/// beyond their mere validity (e.g. `InviteAccepted` — `tenant_event_id`
/// is a dep-ordering constraint, not a semantic input). Kept as an
/// explicit parameter anyway so the dep-derivation step is uniform
/// across projectors and can grow without reshaping call sites.
#[derive(Debug, Clone, Default)]
pub struct DepFacts {}

// ─────────────────────────────────────────────────────────────
// Workspace
//
// Workspace projection reads a rollup over previously-projected
// `InviteAccepted` events (a guard: "what has been accepted so far").
// There is no immediate event dep at projection time, so DepFacts
// stays empty and GuardFacts carries the rollup.
// ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default)]
pub struct WorkspaceDepFacts {}

#[derive(Debug, Clone, Default)]
pub struct WorkspaceGuardFacts {
    /// Distinct workspace_ids projected for this tenant via
    /// `invites_accepted`. Sorted/deduped, limit 2 — the projector
    /// only needs to distinguish 0, 1, ≥2.
    pub accepted_workspace_ids: Vec<String>,
    /// True when any malformed row was observed while reading the
    /// rollup. Currently always false; reserved for future schemas.
    pub malformed: bool,
}

/// Pure Workspace decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkspaceDecision {
    /// No accept yet. The projector blocks on the workspace accept.
    MissingAcceptedWorkspace,
    /// Exactly one workspace accepted; projector uses this id.
    UniqueAcceptedWorkspace { workspace_id: String },
    /// >1 distinct workspace accepted — reject.
    RejectAmbiguous,
    /// Malformed rollup row — reject.
    RejectMalformed,
}

pub fn decide_workspace(
    _deps: &WorkspaceDepFacts,
    guards: &WorkspaceGuardFacts,
) -> WorkspaceDecision {
    if guards.malformed {
        return WorkspaceDecision::RejectMalformed;
    }
    let mut workspace_ids = guards.accepted_workspace_ids.clone();
    workspace_ids.sort();
    workspace_ids.dedup();
    if workspace_ids
        .iter()
        .any(|w| crate::crypto::event_id_from_base64(w).is_none())
    {
        return WorkspaceDecision::RejectMalformed;
    }
    match workspace_ids.as_slice() {
        [] => WorkspaceDecision::MissingAcceptedWorkspace,
        [w] => WorkspaceDecision::UniqueAcceptedWorkspace {
            workspace_id: w.clone(),
        },
        _ => WorkspaceDecision::RejectAmbiguous,
    }
}

// ─────────────────────────────────────────────────────────────
// Shared: signer-chain resolution.
//
// Many projectors check authority via the outer `current_signer`
// envelope. Under the clean dep-derived model the signer is a
// semantic dep of the event — its full parsed form (`DeviceInviteEvent`,
// `PeerSharedEvent`, …) is what the decision reads. We surface that
// directly so decide fns can read `device_invite.authority_event_id`
// instead of chasing derived string summaries.
// ─────────────────────────────────────────────────────────────

/// How the outer signer resolved for the event under projection.
///
/// `DeviceInvite` / `PeerShared` carry the parsed event so pure
/// decision fns read fields off the real dep. Error arms preserve
/// the `signer_event_id` so the decision can surface a precise reject
/// reason.
#[derive(Debug, Clone)]
pub enum SignerResolution {
    /// No outer signer attached to this event (e.g. unsigned path).
    Missing,
    /// Signer exists but is of a kind this projector doesn't accept.
    UnsupportedKind { semantic_type_code: u8 },
    /// Signer id was recorded but its blob isn't available / didn't
    /// parse as a projectable event at all.
    MissingBlob { signer_event_id: String },
    /// Signer blob parsed but not as the expected variant, or parsing
    /// failed inside the signed envelope.
    Malformed {
        signer_event_id: String,
        reason: String,
    },
    /// Signer resolved (stripping any outer `Signed` envelope) to a
    /// `DeviceInviteEvent`.
    DeviceInvite {
        signer_event_id: String,
        event: DeviceInviteEvent,
    },
    /// Signer resolved to a `PeerSharedEvent`.
    PeerShared {
        signer_event_id: String,
        event: PeerSharedEvent,
    },
    /// Signer resolved to an `AdminEvent`. Used by projectors that
    /// accept admin signers directly (e.g. `MessageDeletion`).
    Admin {
        signer_event_id: String,
        event: AdminEvent,
    },
}

// ─────────────────────────────────────────────────────────────
// PeerShared
// ─────────────────────────────────────────────────────────────

/// Typed dep bundle for PeerShared.
///
/// PeerShared's authority dep is its signer, which must resolve to a
/// DeviceInvite whose `authority_event_id` matches the PeerShared's
/// `user_event_id`. The endpoint dep is `endpoint_shared_event_id` —
/// carried as the already-resolved `endpoint_id` (None when the
/// endpoint_shared event has not projected yet).
#[derive(Debug, Clone)]
pub struct PeerSharedDepFacts {
    pub signer: SignerResolution,
    /// endpoint_id for the referenced endpoint_shared_event_id, when
    /// its row has already been projected. Missing means dep-block
    /// should have happened upstream — we surface a precise reject
    /// if it did not.
    pub endpoint_shared_endpoint_id: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct PeerSharedGuardFacts {}

#[derive(Debug, Clone)]
pub enum PeerSharedDecision {
    Ready {
        endpoint_id: String,
    },
    RejectMissingCurrentSigner,
    RejectUnsupportedSignerType {
        semantic_type_code: u8,
    },
    RejectMissingDeviceInviteBlob {
        signer_event_id: String,
    },
    RejectMalformedDeviceInvite {
        signer_event_id: String,
        reason: String,
    },
    RejectUserMismatch {
        authorized_user_id: [u8; 32],
        claimed_user_id: [u8; 32],
    },
    RejectMissingEndpointBinding {
        endpoint_shared_event_id: [u8; 32],
    },
}

impl PeerSharedDecision {
    /// Reject-reason string compatible with the previous authority-plan
    /// reject strings; runtime callers depend on the exact wording.
    pub fn user_mismatch_reason(&self) -> Option<String> {
        match self {
            Self::RejectMissingCurrentSigner => {
                Some("peer_shared missing current signer envelope".to_string())
            }
            Self::RejectUnsupportedSignerType { semantic_type_code } => Some(format!(
                "peer_shared signer must be device_invite, got semantic type {}",
                semantic_type_code
            )),
            Self::RejectMissingDeviceInviteBlob { signer_event_id } => Some(format!(
                "no valid device_invite blob for signer {}",
                signer_event_id
            )),
            Self::RejectMalformedDeviceInvite { reason, .. } => Some(reason.clone()),
            Self::RejectUserMismatch {
                authorized_user_id,
                claimed_user_id,
            } => Some(format!(
                "peer_shared signer authorizes user {} but event claims {}",
                crate::crypto::event_id_to_base64(authorized_user_id),
                crate::crypto::event_id_to_base64(claimed_user_id)
            )),
            Self::Ready { .. } | Self::RejectMissingEndpointBinding { .. } => None,
        }
    }

    pub fn endpoint_binding_reason(&self) -> Option<String> {
        match self {
            Self::RejectMissingEndpointBinding {
                endpoint_shared_event_id,
            } => Some(format!(
                "no projected endpoint_shared row for {}",
                crate::crypto::event_id_to_base64(endpoint_shared_event_id)
            )),
            _ => None,
        }
    }
}

/// Pure PeerShared decision.
///
/// Authority: the outer signer must resolve to a DeviceInvite whose
/// `authority_event_id` equals the PeerShared's `user_event_id`. That
/// equality is the single semantic claim — it's read off the parsed
/// DeviceInviteEvent directly, no derived summary field.
///
/// Endpoint binding: the referenced `endpoint_shared_event_id` must
/// already be projected (carried in `deps.endpoint_shared_endpoint_id`).
pub fn decide_peer_shared(
    event: &PeerSharedEvent,
    deps: &PeerSharedDepFacts,
    _guards: &PeerSharedGuardFacts,
) -> PeerSharedDecision {
    match &deps.signer {
        SignerResolution::Missing => PeerSharedDecision::RejectMissingCurrentSigner,
        SignerResolution::UnsupportedKind { semantic_type_code } => {
            PeerSharedDecision::RejectUnsupportedSignerType {
                semantic_type_code: *semantic_type_code,
            }
        }
        SignerResolution::MissingBlob { signer_event_id } => {
            PeerSharedDecision::RejectMissingDeviceInviteBlob {
                signer_event_id: signer_event_id.clone(),
            }
        }
        SignerResolution::Malformed {
            signer_event_id,
            reason,
        } => PeerSharedDecision::RejectMalformedDeviceInvite {
            signer_event_id: signer_event_id.clone(),
            reason: reason.clone(),
        },
        SignerResolution::PeerShared { .. } => {
            PeerSharedDecision::RejectUnsupportedSignerType {
                semantic_type_code: crate::event_modules::EVENT_TYPE_PEER_SHARED,
            }
        }
        SignerResolution::Admin { .. } => PeerSharedDecision::RejectUnsupportedSignerType {
            semantic_type_code: crate::event_modules::EVENT_TYPE_ADMIN,
        },
        SignerResolution::DeviceInvite {
            event: device_invite,
            ..
        } => {
            if device_invite.authority_event_id != event.user_event_id {
                return PeerSharedDecision::RejectUserMismatch {
                    authorized_user_id: device_invite.authority_event_id,
                    claimed_user_id: event.user_event_id,
                };
            }
            match &deps.endpoint_shared_endpoint_id {
                Some(endpoint_id) => PeerSharedDecision::Ready {
                    endpoint_id: endpoint_id.clone(),
                },
                None => PeerSharedDecision::RejectMissingEndpointBinding {
                    endpoint_shared_event_id: event.endpoint_shared_event_id,
                },
            }
        }
    }
}


/// Narrow current-state / local-only / runtime-only constraints.
///
/// Populated by each projector's guard-facts loader from materialized
/// tables. The surface is intentionally small — each field is either
/// eventually eventizable (and will migrate to `DepFacts`) or stays here
/// as an explicit ambient-state dependency.
#[derive(Debug, Clone, Default)]
pub struct GuardFacts {
    /// InviteAccepted: local invite-link binding recorded at shared-link
    /// time (workspace id, bootstrap addrs, bootstrap SPKI). When present,
    /// the event's `workspace_id` must match `bootstrap_context.workspace_id`.
    pub bootstrap_context: Option<BootstrapDecisionContext>,

    /// InviteAccepted: the bootstrap SPKI is already projected as an
    /// active peer — bootstrap-trust writes would be superseded and are
    /// suppressed.
    pub bootstrap_spki_already_peer_shared: bool,

    /// InviteAccepted: a local `invite_secrets` row exists for this
    /// invite — the bootstrap-identity install intent can be emitted.
    pub has_local_invite_secret: bool,

    /// InviteAccepted: a peer_shared transport identity is already
    /// active, so bootstrap-identity install must not re-run.
    pub peer_shared_transport_identity_active: bool,
}

/// Decision output of `decide_invite_accepted`.
///
/// The `Ready` arms carry through the guard-derived values the projector
/// needs at emit time (`bootstrap_context`, `has_local_invite_secret`,
/// etc.), so the materialization into `ProjectorDecisionContext` is
/// mechanical.
#[derive(Debug, Clone)]
pub enum InviteAcceptedDecision {
    Ready {
        bootstrap_context: Option<BootstrapDecisionContext>,
        bootstrap_spki_already_peer_shared: bool,
        has_local_invite_secret: bool,
        peer_shared_transport_identity_active: bool,
    },
    RejectLinkWorkspaceMismatch,
    RejectMissingLinkBinding,
}

impl InviteAcceptedDecision {
    pub fn reject_reason(&self) -> Option<&'static str> {
        match self {
            Self::Ready { .. } => None,
            Self::RejectLinkWorkspaceMismatch => Some(
                "invite_accepted workspace_id does not match locally recorded invite-link workspace",
            ),
            Self::RejectMissingLinkBinding => Some(
                "invite_accepted missing locally recorded invite-link workspace binding",
            ),
        }
    }
}

/// Pure InviteAccepted decision.
///
/// Inputs:
///   - `event` — parsed InviteAccepted (`invite_event_id`, `workspace_id`).
///   - `_deps` — present for uniformity; InviteAccepted's semantic gate
///     does not read any typed dep summaries today.
///   - `guards` — local-only facts (bootstrap link binding + install
///     suppression state).
///
/// Two reject arms:
///   - If the inviter's locally-recorded `bootstrap_context.workspace_id`
///     disagrees with the event's `workspace_id`, the accept is rejected
///     as workspace-mismatch.
///   - If there is no local bootstrap binding AND the accept is not a
///     self-create (`invite_event_id != workspace_id`), the accept is
///     rejected as missing-link-binding.
///
/// Otherwise the decision is `Ready` and carries through the guard
/// values the projector emits on.
pub fn decide_invite_accepted(
    event: &crate::event_modules::InviteAcceptedEvent,
    _deps: &DepFacts,
    guards: &GuardFacts,
) -> InviteAcceptedDecision {
    if let Some(bc) = &guards.bootstrap_context {
        let workspace_id_b64 = crate::crypto::event_id_to_base64(&event.workspace_id);
        if bc.workspace_id != workspace_id_b64 {
            return InviteAcceptedDecision::RejectLinkWorkspaceMismatch;
        }
        return InviteAcceptedDecision::Ready {
            bootstrap_context: Some(bc.clone()),
            bootstrap_spki_already_peer_shared: guards.bootstrap_spki_already_peer_shared,
            has_local_invite_secret: guards.has_local_invite_secret,
            peer_shared_transport_identity_active: guards.peer_shared_transport_identity_active,
        };
    }
    if event.invite_event_id != event.workspace_id {
        return InviteAcceptedDecision::RejectMissingLinkBinding;
    }
    InviteAcceptedDecision::Ready {
        bootstrap_context: None,
        bootstrap_spki_already_peer_shared: guards.bootstrap_spki_already_peer_shared,
        has_local_invite_secret: guards.has_local_invite_secret,
        peer_shared_transport_identity_active: guards.peer_shared_transport_identity_active,
    }
}

// ─────────────────────────────────────────────────────────────
// Removal
//
// Positive authority is dep-derived: Removal names an explicit
// `admin_authority_event_id` dep. When resolved, it parses to an
// `AdminEvent` whose `user_event_id` must equal the signer
// peer_shared's `user_event_id`. No admin-rollup JOIN, no "is this
// signer currently an admin" guard — the event graph's dep validity
// carries the positive authority. Revocation remains a guard layer
// (future `RemovalGuardFacts` extension).
// ─────────────────────────────────────────────────────────────

/// Resolution of a Removal's `admin_authority_event_id` dep.
///
/// The dep system guarantees the named event is valid before this
/// resolution runs — so only the happy `Valid { event }` shape and a
/// wrong-kind arm are interesting at decide time. Other failure modes
/// (missing blob, malformed) are absorbed by the shared dep-loading
/// pipeline.
#[derive(Debug, Clone)]
pub enum AdminResolution {
    Valid {
        event_id: [u8; 32],
        event: AdminEvent,
    },
    /// Blob was parseable but not an Admin event — the dep field
    /// landed on a wrong-kind event. Normally precluded by
    /// `dep_field_type_codes`, surfaced here for diagnostic symmetry.
    WrongKind {
        event_id: [u8; 32],
        semantic_type_code: u8,
    },
}

#[derive(Debug, Clone)]
pub struct RemovalDepFacts {
    /// Outer signer, parsed. Removal requires a PeerShared signer.
    pub signer: SignerResolution,
    /// Admin event named by `admin_authority_event_id`. The event
    /// graph's dep validity check ensures this event has projected.
    pub admin_authority: AdminResolution,
}

#[derive(Debug, Clone, Default)]
pub struct RemovalGuardFacts {
    /// Semantic kind of the `removed_member_ref` target, looked up
    /// from `valid_events`. `None` means target hasn't projected yet
    /// (dep-blocked upstream via the target's dep field) or isn't a
    /// removable kind.
    pub target_kind: Option<RemovalTargetKind>,
}

#[derive(Debug, Clone)]
pub enum RemovalDecision {
    Ready {
        target_kind: RemovalTargetKind,
    },
    RejectMissingCurrentSigner,
    RejectUnsupportedSignerType {
        semantic_type_code: u8,
    },
    /// Signer blob resolved but the peer_shared structure was
    /// malformed. Rare — preserved for parity with existing rejects.
    RejectMalformedSigner {
        signer_event_id: String,
        reason: String,
    },
    /// Admin event's `user_event_id` does not equal the signer
    /// peer_shared's `user_event_id`. This is the core positive-
    /// authority equality check: a removal is authorized iff it
    /// cites an admin that grants the signer's user admin status.
    RejectAdminUserMismatch {
        admin_user: [u8; 32],
        signer_user: [u8; 32],
    },
    /// Named admin_authority dep resolved to an event of the wrong
    /// kind. Normally the dep_field_type_codes machinery rejects
    /// this upstream; arm exists for completeness.
    RejectAdminAuthorityWrongKind {
        admin_event_id: [u8; 32],
        semantic_type_code: u8,
    },
    /// `removed_member_ref` target is not a user or peer_shared.
    /// Happens when the target event kind is unsupported (e.g., a
    /// workspace or tenant can't be "removed").
    RejectTargetUnsupported,
}

impl RemovalDecision {
    /// Compatibility shim: map decision to the pre-existing
    /// `removal_signer_reject_reason` string so existing test asserts
    /// continue to pass during the typed-reject migration. Once tests
    /// flip to variant matching, this collapses to a `Display` impl.
    pub fn signer_reject_reason(&self) -> Option<String> {
        match self {
            Self::Ready { .. } | Self::RejectTargetUnsupported => None,
            Self::RejectMissingCurrentSigner => {
                Some("removal missing current signer envelope".to_string())
            }
            Self::RejectUnsupportedSignerType { .. } => {
                Some("removal signer must be peer_shared".to_string())
            }
            Self::RejectMalformedSigner { reason, .. } => Some(reason.clone()),
            Self::RejectAdminUserMismatch { .. }
            | Self::RejectAdminAuthorityWrongKind { .. } => {
                Some("removal signer must be an admin peer_shared identity".to_string())
            }
        }
    }
}

/// Pure Removal decision.
///
/// Authorization proof obligation reduces to a single structural
/// equality: `admin.user_event_id == signer_peer_shared.user_event_id`.
/// Both sides are fields of parsed event structs — no JOINs, no
/// rollups, directly provable in Verus once lifted.
pub fn decide_removal(
    _event: &crate::event_modules::RemovalEvent,
    deps: &RemovalDepFacts,
    guards: &RemovalGuardFacts,
) -> RemovalDecision {
    // Signer authority.
    let signer_user = match &deps.signer {
        SignerResolution::Missing => {
            return RemovalDecision::RejectMissingCurrentSigner;
        }
        SignerResolution::UnsupportedKind { semantic_type_code } => {
            return RemovalDecision::RejectUnsupportedSignerType {
                semantic_type_code: *semantic_type_code,
            };
        }
        SignerResolution::MissingBlob { signer_event_id } => {
            return RemovalDecision::RejectMalformedSigner {
                signer_event_id: signer_event_id.clone(),
                reason: format!(
                    "removal signer {} peer_shared blob is not available",
                    signer_event_id
                ),
            };
        }
        SignerResolution::Malformed {
            signer_event_id,
            reason,
        } => {
            return RemovalDecision::RejectMalformedSigner {
                signer_event_id: signer_event_id.clone(),
                reason: reason.clone(),
            };
        }
        SignerResolution::DeviceInvite { .. } => {
            return RemovalDecision::RejectUnsupportedSignerType {
                semantic_type_code: crate::event_modules::EVENT_TYPE_DEVICE_INVITE,
            };
        }
        SignerResolution::Admin { .. } => {
            return RemovalDecision::RejectUnsupportedSignerType {
                semantic_type_code: crate::event_modules::EVENT_TYPE_ADMIN,
            };
        }
        SignerResolution::PeerShared { event, .. } => event.user_event_id,
    };

    // Admin authority, read off the parsed dep event directly.
    let admin_user = match &deps.admin_authority {
        AdminResolution::Valid { event, .. } => event.user_event_id,
        AdminResolution::WrongKind {
            event_id,
            semantic_type_code,
        } => {
            return RemovalDecision::RejectAdminAuthorityWrongKind {
                admin_event_id: *event_id,
                semantic_type_code: *semantic_type_code,
            };
        }
    };

    if admin_user != signer_user {
        return RemovalDecision::RejectAdminUserMismatch {
            admin_user,
            signer_user,
        };
    }

    match guards.target_kind {
        Some(kind) => RemovalDecision::Ready { target_kind: kind },
        None => RemovalDecision::RejectTargetUnsupported,
    }
}

// ─────────────────────────────────────────────────────────────
// Message
//
// Message's only semantic gate is content-authority: the outer
// signer (a peer_shared) must authorize the `author_id` claimed by
// the event. Positive authority is the signer dep; the
// materialized `peers_shared` rollup is kept as a guard fact so
// DB-level corruption (malformed/ambiguous/missing row) is still
// detected — preserving existing defence-in-depth reject strings.
//
// Deletion intents (pre-existing `deletion_intents` rows keyed on
// the message's own event_id) are a local materialized guard: they
// govern whether the projector immediately tombstones on first
// projection. Surfaced as guard facts.
// ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct MessageDepFacts {
    /// Outer signer, parsed. Message requires a peer_shared signer.
    pub signer: SignerResolution,
}

/// Materialized `peers_shared` rollup for the current signer_event_id.
/// Carries the user_event_ids (0, 1, or >1 — the decision only
/// distinguishes those cardinalities) and a `malformed` flag that
/// surfaces DB corruption.
#[derive(Debug, Clone, Default)]
pub struct SignerPeerSharedRollup {
    pub signer_user_ids: Vec<Option<String>>,
    pub malformed: bool,
}

#[derive(Debug, Clone, Default)]
pub struct MessageGuardFacts {
    /// Pre-existing deletion intents for this message_id. Consumed
    /// by the projector to tombstone on first materialization.
    pub deletion_intents: Vec<DeletionIntentInfo>,
    /// Materialized `peers_shared` rollup for the outer signer. Only
    /// populated when the dep-derived signer is `PeerShared`; for
    /// other signer arms the dep decision is taken before the rollup
    /// is consulted.
    pub signer_rollup: SignerPeerSharedRollup,
}

#[derive(Debug, Clone)]
pub enum MessageDecision {
    Ready,
    RejectMissingCurrentSigner,
    RejectUnsupportedSignerType {
        semantic_type_code: u8,
    },
    RejectMissingSignerBlob {
        signer_event_id: String,
    },
    RejectMalformedSigner {
        signer_event_id: String,
        reason: String,
    },
    /// Materialized rollup missing (no `peers_shared` row for signer).
    RejectNoPeersSharedRow { signer_event_id: String },
    /// Materialized rollup carries >1 distinct user_event_id.
    RejectAmbiguousPeersSharedRow { signer_event_id: String },
    /// Materialized rollup user_event_id is not a valid base64 EventId.
    RejectMalformedPeersSharedRow { signer_event_id: String },
    /// Signer's peers_shared user_event_id differs from claimed author.
    RejectAuthorMismatch {
        signer_event_id: String,
        signer_user_id: String,
        claimed_author_id: String,
    },
}

impl MessageDecision {
    /// Compat shim: map decision to the pre-existing
    /// `signer_user_mismatch_reason` string so existing runtime
    /// tests and callers continue to see byte-identical reject text.
    pub fn signer_user_mismatch_reason(&self) -> Option<String> {
        match self {
            Self::Ready => None,
            Self::RejectMissingCurrentSigner => {
                Some("missing current signer envelope".to_string())
            }
            Self::RejectUnsupportedSignerType { semantic_type_code } => Some(format!(
                "content signer must be peer_shared, got semantic type {}",
                semantic_type_code
            )),
            Self::RejectMissingSignerBlob { signer_event_id }
            | Self::RejectNoPeersSharedRow { signer_event_id } => Some(format!(
                "no peers_shared entry for signer {}",
                signer_event_id
            )),
            Self::RejectAmbiguousPeersSharedRow { signer_event_id } => Some(format!(
                "ambiguous peers_shared user binding for signer {}",
                signer_event_id
            )),
            Self::RejectMalformedSigner { signer_event_id, .. }
            | Self::RejectMalformedPeersSharedRow { signer_event_id } => Some(format!(
                "malformed peers_shared user binding for signer {}",
                signer_event_id
            )),
            Self::RejectAuthorMismatch {
                signer_event_id,
                signer_user_id,
                claimed_author_id,
            } => Some(format!(
                "signer {} belongs to user {} but author_id claims {}",
                signer_event_id, signer_user_id, claimed_author_id
            )),
        }
    }
}

/// Normalise a `SignerPeerSharedRollup` into `(signer_user_id_opt, err)`
/// where err carries a typed rollup-level reject (missing / ambiguous /
/// malformed). Single source of truth for rollup sanity — shared
/// between Message, Reaction, and MessageDeletion decisions.
fn resolve_peers_shared_rollup(
    signer_event_id: &str,
    rollup: &SignerPeerSharedRollup,
) -> Result<String, PeersSharedRollupError> {
    if rollup.malformed || crate::crypto::event_id_from_base64(signer_event_id).is_none() {
        return Err(PeersSharedRollupError::Malformed);
    }
    let mut user_ids = Vec::with_capacity(rollup.signer_user_ids.len());
    for user_id in &rollup.signer_user_ids {
        let Some(user_id) = user_id.as_ref() else {
            return Err(PeersSharedRollupError::Malformed);
        };
        if user_id.is_empty() || crate::crypto::event_id_from_base64(user_id).is_none() {
            return Err(PeersSharedRollupError::Malformed);
        }
        user_ids.push(user_id.clone());
    }
    user_ids.sort();
    user_ids.dedup();
    match user_ids.as_slice() {
        [] => Err(PeersSharedRollupError::Missing),
        [user_id] => Ok(user_id.clone()),
        _ => Err(PeersSharedRollupError::Ambiguous),
    }
}

enum PeersSharedRollupError {
    Missing,
    Ambiguous,
    Malformed,
}

/// Pure Message decision.
///
/// Authority: outer signer must resolve (via `SignerResolution`) to a
/// PeerShared *and* the materialized `peers_shared` rollup must agree
/// with the event's `author_id`. The rollup-level checks preserve
/// defence-in-depth against DB corruption.
pub fn decide_message(
    event: &MessageEvent,
    deps: &MessageDepFacts,
    guards: &MessageGuardFacts,
) -> MessageDecision {
    match &deps.signer {
        SignerResolution::Missing => MessageDecision::RejectMissingCurrentSigner,
        SignerResolution::UnsupportedKind { semantic_type_code } => {
            MessageDecision::RejectUnsupportedSignerType {
                semantic_type_code: *semantic_type_code,
            }
        }
        SignerResolution::MissingBlob { signer_event_id } => {
            MessageDecision::RejectMissingSignerBlob {
                signer_event_id: signer_event_id.clone(),
            }
        }
        SignerResolution::Malformed {
            signer_event_id,
            reason,
        } => MessageDecision::RejectMalformedSigner {
            signer_event_id: signer_event_id.clone(),
            reason: reason.clone(),
        },
        SignerResolution::DeviceInvite { .. } => MessageDecision::RejectUnsupportedSignerType {
            semantic_type_code: crate::event_modules::EVENT_TYPE_DEVICE_INVITE,
        },
        SignerResolution::Admin { .. } => MessageDecision::RejectUnsupportedSignerType {
            semantic_type_code: crate::event_modules::EVENT_TYPE_ADMIN,
        },
        SignerResolution::PeerShared { signer_event_id, .. } => {
            let author_b64 = crate::crypto::event_id_to_base64(&event.author_id);
            match resolve_peers_shared_rollup(signer_event_id, &guards.signer_rollup) {
                Err(PeersSharedRollupError::Missing) => MessageDecision::RejectNoPeersSharedRow {
                    signer_event_id: signer_event_id.clone(),
                },
                Err(PeersSharedRollupError::Ambiguous) => {
                    MessageDecision::RejectAmbiguousPeersSharedRow {
                        signer_event_id: signer_event_id.clone(),
                    }
                }
                Err(PeersSharedRollupError::Malformed) => {
                    MessageDecision::RejectMalformedPeersSharedRow {
                        signer_event_id: signer_event_id.clone(),
                    }
                }
                Ok(signer_user_id) => {
                    if signer_user_id == author_b64 {
                        MessageDecision::Ready
                    } else {
                        MessageDecision::RejectAuthorMismatch {
                            signer_event_id: signer_event_id.clone(),
                            signer_user_id,
                            claimed_author_id: author_b64,
                        }
                    }
                }
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────
// Reaction
//
// Reaction's semantic gate mirrors Message's: signer peer_shared
// must authorize the claimed `author_id`, with the materialized
// `peers_shared` rollup acting as a DB-consistency guard.
// ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ReactionDepFacts {
    pub signer: SignerResolution,
}

#[derive(Debug, Clone, Default)]
pub struct ReactionGuardFacts {
    pub signer_rollup: SignerPeerSharedRollup,
}

#[derive(Debug, Clone)]
pub enum ReactionDecision {
    Ready,
    RejectMissingCurrentSigner,
    RejectUnsupportedSignerType {
        semantic_type_code: u8,
    },
    RejectMissingSignerBlob {
        signer_event_id: String,
    },
    RejectMalformedSigner {
        signer_event_id: String,
        reason: String,
    },
    RejectNoPeersSharedRow { signer_event_id: String },
    RejectAmbiguousPeersSharedRow { signer_event_id: String },
    RejectMalformedPeersSharedRow { signer_event_id: String },
    RejectAuthorMismatch {
        signer_event_id: String,
        signer_user_id: String,
        claimed_author_id: String,
    },
}

impl ReactionDecision {
    pub fn signer_user_mismatch_reason(&self) -> Option<String> {
        match self {
            Self::Ready => None,
            Self::RejectMissingCurrentSigner => {
                Some("missing current signer envelope".to_string())
            }
            Self::RejectUnsupportedSignerType { semantic_type_code } => Some(format!(
                "content signer must be peer_shared, got semantic type {}",
                semantic_type_code
            )),
            Self::RejectMissingSignerBlob { signer_event_id }
            | Self::RejectNoPeersSharedRow { signer_event_id } => Some(format!(
                "no peers_shared entry for signer {}",
                signer_event_id
            )),
            Self::RejectAmbiguousPeersSharedRow { signer_event_id } => Some(format!(
                "ambiguous peers_shared user binding for signer {}",
                signer_event_id
            )),
            Self::RejectMalformedSigner { signer_event_id, .. }
            | Self::RejectMalformedPeersSharedRow { signer_event_id } => Some(format!(
                "malformed peers_shared user binding for signer {}",
                signer_event_id
            )),
            Self::RejectAuthorMismatch {
                signer_event_id,
                signer_user_id,
                claimed_author_id,
            } => Some(format!(
                "signer {} belongs to user {} but author_id claims {}",
                signer_event_id, signer_user_id, claimed_author_id
            )),
        }
    }
}

pub fn decide_reaction(
    event: &ReactionEvent,
    deps: &ReactionDepFacts,
    guards: &ReactionGuardFacts,
) -> ReactionDecision {
    match &deps.signer {
        SignerResolution::Missing => ReactionDecision::RejectMissingCurrentSigner,
        SignerResolution::UnsupportedKind { semantic_type_code } => {
            ReactionDecision::RejectUnsupportedSignerType {
                semantic_type_code: *semantic_type_code,
            }
        }
        SignerResolution::MissingBlob { signer_event_id } => {
            ReactionDecision::RejectMissingSignerBlob {
                signer_event_id: signer_event_id.clone(),
            }
        }
        SignerResolution::Malformed {
            signer_event_id,
            reason,
        } => ReactionDecision::RejectMalformedSigner {
            signer_event_id: signer_event_id.clone(),
            reason: reason.clone(),
        },
        SignerResolution::DeviceInvite { .. } => ReactionDecision::RejectUnsupportedSignerType {
            semantic_type_code: crate::event_modules::EVENT_TYPE_DEVICE_INVITE,
        },
        SignerResolution::Admin { .. } => ReactionDecision::RejectUnsupportedSignerType {
            semantic_type_code: crate::event_modules::EVENT_TYPE_ADMIN,
        },
        SignerResolution::PeerShared { signer_event_id, .. } => {
            let author_b64 = crate::crypto::event_id_to_base64(&event.author_id);
            match resolve_peers_shared_rollup(signer_event_id, &guards.signer_rollup) {
                Err(PeersSharedRollupError::Missing) => {
                    ReactionDecision::RejectNoPeersSharedRow {
                        signer_event_id: signer_event_id.clone(),
                    }
                }
                Err(PeersSharedRollupError::Ambiguous) => {
                    ReactionDecision::RejectAmbiguousPeersSharedRow {
                        signer_event_id: signer_event_id.clone(),
                    }
                }
                Err(PeersSharedRollupError::Malformed) => {
                    ReactionDecision::RejectMalformedPeersSharedRow {
                        signer_event_id: signer_event_id.clone(),
                    }
                }
                Ok(signer_user_id) => {
                    if signer_user_id == author_b64 {
                        ReactionDecision::Ready
                    } else {
                        ReactionDecision::RejectAuthorMismatch {
                            signer_event_id: signer_event_id.clone(),
                            signer_user_id,
                            claimed_author_id: author_b64,
                        }
                    }
                }
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────
// MessageDeletion
//
// MessageDeletion accepts two signer kinds:
//   - Admin → projector treats as authorized for any message
//     (authorized_by_admin = true).
//   - PeerShared → signer's user_event_id is the deletion author
//     and must match the target message's author_id at write time.
//
// Target-message guard state comes from materialized `messages` and
// `deleted_messages` rows. Both may be absent (intent-only path).
// ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct MessageDeletionDepFacts {
    pub signer: SignerResolution,
}

#[derive(Debug, Clone, Default)]
pub struct MessageDeletionGuardFacts {
    /// author_id from `messages` row for the target, if present.
    pub target_message_author: Option<String>,
    /// author_id from `deleted_messages` tombstone for the target, if present.
    pub target_tombstone_author: Option<String>,
    /// True when the target event_id is in valid_events but is NOT a
    /// message (no row in messages or deleted_messages). Only
    /// populated when both message/tombstone author are absent.
    pub target_is_non_message: bool,
    /// Materialized `peers_shared` rollup for a peer_shared outer
    /// signer; unused for admin signers.
    pub signer_rollup: SignerPeerSharedRollup,
}

/// Result of resolving the MessageDeletion signer to its (user_id, is_admin, reject_reason)
/// triple — the exact shape the projector's decision context expects.
#[derive(Debug, Clone)]
pub enum MessageDeletionDecision {
    /// Admin signer: authorized for any message.
    ReadyAdmin,
    /// PeerShared signer: deletion carries the signer's user_event_id.
    ReadyPeerSharedUser { signer_user_id: String },
    RejectMissingCurrentSigner,
    RejectUnsupportedSignerType {
        semantic_type_code: u8,
    },
    RejectMissingSignerBlob {
        signer_event_id: String,
    },
    RejectMalformedSigner {
        signer_event_id: String,
        reason: String,
    },
    RejectNoPeersSharedRow { signer_event_id: String },
    RejectAmbiguousPeersSharedRow { signer_event_id: String },
    RejectMalformedPeersSharedRow { signer_event_id: String },
}

impl MessageDeletionDecision {
    /// Compat shim: fold into the three legacy context fields
    /// `(deletion_signer_user_id, deletion_signer_is_admin, deletion_signer_reject_reason)`.
    pub fn context_fields(&self) -> (Option<String>, bool, Option<String>) {
        match self {
            Self::ReadyAdmin => (None, true, None),
            Self::ReadyPeerSharedUser { signer_user_id } => {
                (Some(signer_user_id.clone()), false, None)
            }
            Self::RejectMissingCurrentSigner => (
                None,
                false,
                Some("missing current signer envelope".to_string()),
            ),
            Self::RejectUnsupportedSignerType { semantic_type_code } => (
                None,
                false,
                Some(format!(
                    "message_deletion signer must be peer_shared or admin, got semantic type {}",
                    semantic_type_code
                )),
            ),
            Self::RejectMissingSignerBlob { signer_event_id }
            | Self::RejectNoPeersSharedRow { signer_event_id } => (
                None,
                false,
                Some(format!(
                    "no peers_shared entry for signer {}",
                    signer_event_id
                )),
            ),
            Self::RejectAmbiguousPeersSharedRow { signer_event_id } => (
                None,
                false,
                Some(format!(
                    "ambiguous peers_shared user binding for message_deletion signer {}",
                    signer_event_id
                )),
            ),
            Self::RejectMalformedSigner {
                signer_event_id, ..
            }
            | Self::RejectMalformedPeersSharedRow { signer_event_id } => (
                None,
                false,
                Some(format!(
                    "malformed peers_shared user binding for message_deletion signer {}",
                    signer_event_id
                )),
            ),
        }
    }
}

/// Pure MessageDeletion signer decision.
///
/// Admin signers are authorized directly; peer_shared signers route
/// through the materialized `peers_shared` rollup (DB-consistency
/// guard) to produce the deletion author. The target-message author
/// match is applied *inside* the projector at emit time.
pub fn decide_message_deletion(
    _event: &MessageDeletionEvent,
    deps: &MessageDeletionDepFacts,
    guards: &MessageDeletionGuardFacts,
) -> MessageDeletionDecision {
    match &deps.signer {
        SignerResolution::Missing => MessageDeletionDecision::RejectMissingCurrentSigner,
        SignerResolution::UnsupportedKind { semantic_type_code } => {
            MessageDeletionDecision::RejectUnsupportedSignerType {
                semantic_type_code: *semantic_type_code,
            }
        }
        SignerResolution::MissingBlob { signer_event_id } => {
            MessageDeletionDecision::RejectMissingSignerBlob {
                signer_event_id: signer_event_id.clone(),
            }
        }
        SignerResolution::Malformed {
            signer_event_id,
            reason,
        } => MessageDeletionDecision::RejectMalformedSigner {
            signer_event_id: signer_event_id.clone(),
            reason: reason.clone(),
        },
        SignerResolution::DeviceInvite { .. } => {
            MessageDeletionDecision::RejectUnsupportedSignerType {
                semantic_type_code: crate::event_modules::EVENT_TYPE_DEVICE_INVITE,
            }
        }
        SignerResolution::Admin { .. } => MessageDeletionDecision::ReadyAdmin,
        SignerResolution::PeerShared { signer_event_id, .. } => {
            match resolve_peers_shared_rollup(signer_event_id, &guards.signer_rollup) {
                Err(PeersSharedRollupError::Missing) => {
                    MessageDeletionDecision::RejectNoPeersSharedRow {
                        signer_event_id: signer_event_id.clone(),
                    }
                }
                Err(PeersSharedRollupError::Ambiguous) => {
                    MessageDeletionDecision::RejectAmbiguousPeersSharedRow {
                        signer_event_id: signer_event_id.clone(),
                    }
                }
                Err(PeersSharedRollupError::Malformed) => {
                    MessageDeletionDecision::RejectMalformedPeersSharedRow {
                        signer_event_id: signer_event_id.clone(),
                    }
                }
                Ok(signer_user_id) => {
                    MessageDeletionDecision::ReadyPeerSharedUser { signer_user_id }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event_modules::{DeviceInviteEvent, InviteAcceptedEvent, PeerSharedEvent};

    fn ev(invite_eq_workspace: bool) -> InviteAcceptedEvent {
        let invite = [7u8; 32];
        let workspace = if invite_eq_workspace { invite } else { [9u8; 32] };
        InviteAcceptedEvent {
            created_at_ms: 0,
            tenant_event_id: [1u8; 32],
            invite_event_id: invite,
            workspace_id: workspace,
        }
    }

    fn bc_for(workspace_id: [u8; 32]) -> BootstrapDecisionContext {
        BootstrapDecisionContext {
            workspace_id: crate::crypto::event_id_to_base64(&workspace_id),
            bootstrap_addrs: vec!["127.0.0.1:1".into()],
            bootstrap_spki_fingerprint: [0u8; 32],
        }
    }

    #[test]
    fn ready_when_no_local_binding_and_self_create() {
        let event = ev(true);
        let d = decide_invite_accepted(&event, &DepFacts::default(), &GuardFacts::default());
        assert!(matches!(d, InviteAcceptedDecision::Ready { .. }));
        assert!(d.reject_reason().is_none());
    }

    #[test]
    fn reject_when_no_local_binding_and_not_self_create() {
        let event = ev(false);
        let d = decide_invite_accepted(&event, &DepFacts::default(), &GuardFacts::default());
        assert!(matches!(d, InviteAcceptedDecision::RejectMissingLinkBinding));
        assert!(d.reject_reason().is_some());
    }

    #[test]
    fn ready_when_local_binding_matches_workspace() {
        let event = ev(false);
        let guards = GuardFacts {
            bootstrap_context: Some(bc_for(event.workspace_id)),
            ..Default::default()
        };
        let d = decide_invite_accepted(&event, &DepFacts::default(), &guards);
        match d {
            InviteAcceptedDecision::Ready {
                bootstrap_context: Some(_),
                ..
            } => {}
            other => panic!("expected Ready with bootstrap_context, got {:?}", other),
        }
    }

    #[test]
    fn reject_when_local_binding_mismatches_workspace() {
        let event = ev(false);
        let guards = GuardFacts {
            bootstrap_context: Some(bc_for([42u8; 32])),
            ..Default::default()
        };
        let d = decide_invite_accepted(&event, &DepFacts::default(), &guards);
        assert!(matches!(
            d,
            InviteAcceptedDecision::RejectLinkWorkspaceMismatch
        ));
    }

    // ── PeerShared pilot ──────────────────────────────────────

    fn ps_event(user: [u8; 32], endpoint: [u8; 32]) -> PeerSharedEvent {
        PeerSharedEvent {
            created_at_ms: 0,
            public_key: [3u8; 32],
            user_event_id: user,
            endpoint_shared_event_id: endpoint,
            device_name: String::new(),
        }
    }

    fn di_event(authority: [u8; 32]) -> DeviceInviteEvent {
        DeviceInviteEvent {
            created_at_ms: 0,
            public_key: [5u8; 32],
            authority_event_id: authority,
            key_history_event_id: [6u8; 32],
        }
    }

    #[test]
    fn peer_shared_ready_when_authority_matches_and_endpoint_bound() {
        let user = [10u8; 32];
        let endpoint = [11u8; 32];
        let event = ps_event(user, endpoint);
        let deps = PeerSharedDepFacts {
            signer: SignerResolution::DeviceInvite {
                signer_event_id: "sig".into(),
                event: di_event(user),
            },
            endpoint_shared_endpoint_id: Some("endpoint-1".into()),
        };
        let d = decide_peer_shared(&event, &deps, &PeerSharedGuardFacts::default());
        assert!(matches!(d, PeerSharedDecision::Ready { ref endpoint_id } if endpoint_id == "endpoint-1"));
        assert!(d.user_mismatch_reason().is_none());
        assert!(d.endpoint_binding_reason().is_none());
    }

    #[test]
    fn peer_shared_rejects_user_mismatch_when_device_invite_authority_differs() {
        let event = ps_event([10u8; 32], [11u8; 32]);
        let deps = PeerSharedDepFacts {
            signer: SignerResolution::DeviceInvite {
                signer_event_id: "sig".into(),
                event: di_event([42u8; 32]), // wrong authority
            },
            endpoint_shared_endpoint_id: Some("endpoint-1".into()),
        };
        let d = decide_peer_shared(&event, &deps, &PeerSharedGuardFacts::default());
        assert!(matches!(d, PeerSharedDecision::RejectUserMismatch { .. }));
        assert!(d.user_mismatch_reason().is_some());
    }

    #[test]
    fn peer_shared_rejects_missing_endpoint_even_when_authority_ok() {
        let user = [10u8; 32];
        let event = ps_event(user, [11u8; 32]);
        let deps = PeerSharedDepFacts {
            signer: SignerResolution::DeviceInvite {
                signer_event_id: "sig".into(),
                event: di_event(user),
            },
            endpoint_shared_endpoint_id: None,
        };
        let d = decide_peer_shared(&event, &deps, &PeerSharedGuardFacts::default());
        assert!(matches!(
            d,
            PeerSharedDecision::RejectMissingEndpointBinding { .. }
        ));
    }

    #[test]
    fn peer_shared_rejects_peer_shared_signer_as_unsupported() {
        let event = ps_event([10u8; 32], [11u8; 32]);
        let deps = PeerSharedDepFacts {
            signer: SignerResolution::PeerShared {
                signer_event_id: "sig".into(),
                event: ps_event([7u8; 32], [8u8; 32]),
            },
            endpoint_shared_endpoint_id: Some("endpoint-1".into()),
        };
        let d = decide_peer_shared(&event, &deps, &PeerSharedGuardFacts::default());
        assert!(matches!(
            d,
            PeerSharedDecision::RejectUnsupportedSignerType { .. }
        ));
    }

    // ── Removal pilot ─────────────────────────────────────────

    fn removal_event() -> crate::event_modules::RemovalEvent {
        crate::event_modules::RemovalEvent {
            created_at_ms: 0,
            removed_member_ref: [0xAA; 32],
            parent_count: 0,
            parent_1: [0u8; 32],
            parent_2: [0u8; 32],
            parent_3: [0u8; 32],
            parent_4: [0u8; 32],
            frontier_hash: [0u8; 32],
            removed_by: [0xBB; 32],
            admin_authority_event_id: [0xCC; 32],
        }
    }

    fn peer_shared_signer(user_event_id: [u8; 32]) -> SignerResolution {
        SignerResolution::PeerShared {
            signer_event_id: "ps".into(),
            event: PeerSharedEvent {
                created_at_ms: 0,
                public_key: [1u8; 32],
                user_event_id,
                endpoint_shared_event_id: [2u8; 32],
                device_name: String::new(),
            },
        }
    }

    fn admin_resolution(user_event_id: [u8; 32]) -> AdminResolution {
        AdminResolution::Valid {
            event_id: [0xCC; 32],
            event: AdminEvent {
                created_at_ms: 0,
                public_key: [3u8; 32],
                authority_event_id: [0u8; 32],
                user_event_id,
            },
        }
    }

    #[test]
    fn removal_ready_when_admin_user_matches_signer_user_and_target_is_user() {
        let user = [42u8; 32];
        let deps = RemovalDepFacts {
            signer: peer_shared_signer(user),
            admin_authority: admin_resolution(user),
        };
        let guards = RemovalGuardFacts {
            target_kind: Some(RemovalTargetKind::User),
        };
        let d = decide_removal(&removal_event(), &deps, &guards);
        assert!(matches!(
            d,
            RemovalDecision::Ready {
                target_kind: RemovalTargetKind::User
            }
        ));
    }

    #[test]
    fn removal_rejects_when_admin_user_differs_from_signer_user() {
        let deps = RemovalDepFacts {
            signer: peer_shared_signer([1u8; 32]),
            admin_authority: admin_resolution([2u8; 32]),
        };
        let guards = RemovalGuardFacts {
            target_kind: Some(RemovalTargetKind::User),
        };
        let d = decide_removal(&removal_event(), &deps, &guards);
        match d {
            RemovalDecision::RejectAdminUserMismatch {
                admin_user,
                signer_user,
            } => {
                assert_eq!(admin_user, [2u8; 32]);
                assert_eq!(signer_user, [1u8; 32]);
            }
            other => panic!("expected RejectAdminUserMismatch, got {:?}", other),
        }
    }

    #[test]
    fn removal_rejects_missing_signer() {
        let deps = RemovalDepFacts {
            signer: SignerResolution::Missing,
            admin_authority: admin_resolution([1u8; 32]),
        };
        let d = decide_removal(
            &removal_event(),
            &deps,
            &RemovalGuardFacts {
                target_kind: Some(RemovalTargetKind::User),
            },
        );
        assert!(matches!(d, RemovalDecision::RejectMissingCurrentSigner));
    }

    #[test]
    fn removal_rejects_unsupported_signer_kind() {
        let deps = RemovalDepFacts {
            signer: SignerResolution::DeviceInvite {
                signer_event_id: "ps".into(),
                event: DeviceInviteEvent {
                    created_at_ms: 0,
                    public_key: [1u8; 32],
                    authority_event_id: [2u8; 32],
                    key_history_event_id: [3u8; 32],
                },
            },
            admin_authority: admin_resolution([1u8; 32]),
        };
        let d = decide_removal(
            &removal_event(),
            &deps,
            &RemovalGuardFacts {
                target_kind: Some(RemovalTargetKind::User),
            },
        );
        assert!(matches!(
            d,
            RemovalDecision::RejectUnsupportedSignerType { .. }
        ));
    }

    #[test]
    fn removal_rejects_target_unsupported_when_target_kind_missing() {
        let user = [1u8; 32];
        let deps = RemovalDepFacts {
            signer: peer_shared_signer(user),
            admin_authority: admin_resolution(user),
        };
        let d = decide_removal(
            &removal_event(),
            &deps,
            &RemovalGuardFacts { target_kind: None },
        );
        assert!(matches!(d, RemovalDecision::RejectTargetUnsupported));
    }

    // ── Message pilot ─────────────────────────────────────────

    fn msg_event(author: [u8; 32]) -> MessageEvent {
        MessageEvent {
            created_at_ms: 0,
            workspace_id: [9u8; 32],
            author_id: author,
            content: "hello".to_string(),
        }
    }

    fn peer_shared_signer_with(user: [u8; 32]) -> SignerResolution {
        SignerResolution::PeerShared {
            signer_event_id: "sig".into(),
            event: PeerSharedEvent {
                created_at_ms: 0,
                public_key: [1u8; 32],
                user_event_id: user,
                endpoint_shared_event_id: [2u8; 32],
                device_name: String::new(),
            },
        }
    }

    fn ps_signer_id_b64() -> String {
        // Matches `peer_shared_signer_with`: any valid 32-byte b64 works.
        crate::crypto::event_id_to_base64(&[0xFFu8; 32])
    }

    fn peer_shared_signer_full(signer_id: &str, user: [u8; 32]) -> SignerResolution {
        SignerResolution::PeerShared {
            signer_event_id: signer_id.to_string(),
            event: PeerSharedEvent {
                created_at_ms: 0,
                public_key: [1u8; 32],
                user_event_id: user,
                endpoint_shared_event_id: [2u8; 32],
                device_name: String::new(),
            },
        }
    }

    fn rollup_single_user(user: [u8; 32]) -> SignerPeerSharedRollup {
        SignerPeerSharedRollup {
            signer_user_ids: vec![Some(crate::crypto::event_id_to_base64(&user))],
            malformed: false,
        }
    }

    #[test]
    fn message_ready_when_signer_user_matches_author_id() {
        let user = [10u8; 32];
        let signer_id = ps_signer_id_b64();
        let deps = MessageDepFacts {
            signer: peer_shared_signer_full(&signer_id, user),
        };
        let guards = MessageGuardFacts {
            signer_rollup: rollup_single_user(user),
            ..Default::default()
        };
        let d = decide_message(&msg_event(user), &deps, &guards);
        assert!(matches!(d, MessageDecision::Ready));
        assert!(d.signer_user_mismatch_reason().is_none());
    }

    #[test]
    fn message_rejects_when_signer_user_differs_from_author() {
        let signer_id = ps_signer_id_b64();
        let deps = MessageDepFacts {
            signer: peer_shared_signer_full(&signer_id, [1u8; 32]),
        };
        let guards = MessageGuardFacts {
            signer_rollup: rollup_single_user([1u8; 32]),
            ..Default::default()
        };
        let d = decide_message(&msg_event([2u8; 32]), &deps, &guards);
        assert!(matches!(d, MessageDecision::RejectAuthorMismatch { .. }));
        let reason = d.signer_user_mismatch_reason().expect("reason");
        assert!(reason.contains("author_id claims"));
    }

    #[test]
    fn message_rejects_missing_signer() {
        let deps = MessageDepFacts {
            signer: SignerResolution::Missing,
        };
        let d = decide_message(&msg_event([0u8; 32]), &deps, &MessageGuardFacts::default());
        assert!(matches!(d, MessageDecision::RejectMissingCurrentSigner));
        assert_eq!(
            d.signer_user_mismatch_reason().as_deref(),
            Some("missing current signer envelope")
        );
    }

    #[test]
    fn message_rejects_unsupported_signer_kind() {
        let deps = MessageDepFacts {
            signer: SignerResolution::DeviceInvite {
                signer_event_id: "sig".into(),
                event: DeviceInviteEvent {
                    created_at_ms: 0,
                    public_key: [1u8; 32],
                    authority_event_id: [2u8; 32],
                    key_history_event_id: [3u8; 32],
                },
            },
        };
        let d = decide_message(&msg_event([0u8; 32]), &deps, &MessageGuardFacts::default());
        assert!(matches!(
            d,
            MessageDecision::RejectUnsupportedSignerType { .. }
        ));
    }

    #[test]
    fn message_rejects_malformed_peers_shared_rollup() {
        let signer_id = ps_signer_id_b64();
        let user = [10u8; 32];
        let deps = MessageDepFacts {
            signer: peer_shared_signer_full(&signer_id, user),
        };
        let guards = MessageGuardFacts {
            signer_rollup: SignerPeerSharedRollup {
                signer_user_ids: vec![Some("not-base64".to_string())],
                malformed: false,
            },
            ..Default::default()
        };
        let d = decide_message(&msg_event(user), &deps, &guards);
        assert!(matches!(
            d,
            MessageDecision::RejectMalformedPeersSharedRow { .. }
        ));
        assert!(d.signer_user_mismatch_reason().unwrap().contains("malformed"));
    }

    // ── Reaction pilot ────────────────────────────────────────

    fn rxn_event(author: [u8; 32]) -> ReactionEvent {
        ReactionEvent {
            created_at_ms: 0,
            target_event_id: [9u8; 32],
            author_id: author,
            emoji: "👍".to_string(),
        }
    }

    #[test]
    fn reaction_ready_when_signer_user_matches_author_id() {
        let user = [10u8; 32];
        let signer_id = ps_signer_id_b64();
        let deps = ReactionDepFacts {
            signer: peer_shared_signer_full(&signer_id, user),
        };
        let guards = ReactionGuardFacts {
            signer_rollup: rollup_single_user(user),
        };
        let d = decide_reaction(&rxn_event(user), &deps, &guards);
        assert!(matches!(d, ReactionDecision::Ready));
        assert!(d.signer_user_mismatch_reason().is_none());
    }

    #[test]
    fn reaction_rejects_when_signer_user_differs_from_author() {
        let signer_id = ps_signer_id_b64();
        let deps = ReactionDepFacts {
            signer: peer_shared_signer_full(&signer_id, [1u8; 32]),
        };
        let guards = ReactionGuardFacts {
            signer_rollup: rollup_single_user([1u8; 32]),
        };
        let d = decide_reaction(&rxn_event([2u8; 32]), &deps, &guards);
        assert!(matches!(d, ReactionDecision::RejectAuthorMismatch { .. }));
        assert!(d.signer_user_mismatch_reason().is_some());
    }

    #[test]
    fn reaction_rejects_missing_signer() {
        let deps = ReactionDepFacts {
            signer: SignerResolution::Missing,
        };
        let d = decide_reaction(&rxn_event([0u8; 32]), &deps, &ReactionGuardFacts::default());
        assert!(matches!(d, ReactionDecision::RejectMissingCurrentSigner));
    }

    // ── MessageDeletion pilot ─────────────────────────────────

    fn del_event() -> MessageDeletionEvent {
        MessageDeletionEvent {
            created_at_ms: 0,
            target_event_id: [0xAB; 32],
        }
    }

    fn admin_signer(user: [u8; 32]) -> SignerResolution {
        SignerResolution::Admin {
            signer_event_id: "admin-sig".into(),
            event: AdminEvent {
                created_at_ms: 0,
                public_key: [5u8; 32],
                authority_event_id: [0u8; 32],
                user_event_id: user,
            },
        }
    }

    #[test]
    fn message_deletion_ready_admin_when_signer_is_admin() {
        let deps = MessageDeletionDepFacts {
            signer: admin_signer([1u8; 32]),
        };
        let d = decide_message_deletion(
            &del_event(),
            &deps,
            &MessageDeletionGuardFacts::default(),
        );
        assert!(matches!(d, MessageDeletionDecision::ReadyAdmin));
        let (user, is_admin, reject) = d.context_fields();
        assert!(user.is_none());
        assert!(is_admin);
        assert!(reject.is_none());
    }

    #[test]
    fn message_deletion_ready_peer_shared_user_carries_user_event_id() {
        let user = [42u8; 32];
        let signer_id = ps_signer_id_b64();
        let deps = MessageDeletionDepFacts {
            signer: peer_shared_signer_full(&signer_id, user),
        };
        let guards = MessageDeletionGuardFacts {
            signer_rollup: rollup_single_user(user),
            ..Default::default()
        };
        let d = decide_message_deletion(&del_event(), &deps, &guards);
        match &d {
            MessageDeletionDecision::ReadyPeerSharedUser { signer_user_id } => {
                assert_eq!(
                    signer_user_id.as_str(),
                    crate::crypto::event_id_to_base64(&user).as_str()
                );
            }
            other => panic!("expected ReadyPeerSharedUser, got {:?}", other),
        }
        let (resolved_user, is_admin, reject) = d.context_fields();
        assert_eq!(
            resolved_user.as_deref(),
            Some(crate::crypto::event_id_to_base64(&user).as_str())
        );
        assert!(!is_admin);
        assert!(reject.is_none());
    }

    #[test]
    fn message_deletion_rejects_malformed_peers_shared_rollup() {
        let user = [42u8; 32];
        let signer_id = ps_signer_id_b64();
        let deps = MessageDeletionDepFacts {
            signer: peer_shared_signer_full(&signer_id, user),
        };
        let guards = MessageDeletionGuardFacts {
            signer_rollup: SignerPeerSharedRollup {
                signer_user_ids: vec![Some("not-base64".to_string())],
                malformed: false,
            },
            ..Default::default()
        };
        let d = decide_message_deletion(&del_event(), &deps, &guards);
        assert!(matches!(
            d,
            MessageDeletionDecision::RejectMalformedPeersSharedRow { .. }
        ));
    }

    #[test]
    fn message_deletion_rejects_missing_signer() {
        let deps = MessageDeletionDepFacts {
            signer: SignerResolution::Missing,
        };
        let d = decide_message_deletion(
            &del_event(),
            &deps,
            &MessageDeletionGuardFacts::default(),
        );
        assert!(matches!(
            d,
            MessageDeletionDecision::RejectMissingCurrentSigner
        ));
        let (user, is_admin, reject) = d.context_fields();
        assert!(user.is_none());
        assert!(!is_admin);
        assert_eq!(reject.as_deref(), Some("missing current signer envelope"));
    }

    #[test]
    fn message_deletion_rejects_unsupported_signer_kind() {
        let deps = MessageDeletionDepFacts {
            signer: SignerResolution::DeviceInvite {
                signer_event_id: "sig".into(),
                event: DeviceInviteEvent {
                    created_at_ms: 0,
                    public_key: [1u8; 32],
                    authority_event_id: [2u8; 32],
                    key_history_event_id: [3u8; 32],
                },
            },
        };
        let d = decide_message_deletion(
            &del_event(),
            &deps,
            &MessageDeletionGuardFacts::default(),
        );
        assert!(matches!(
            d,
            MessageDeletionDecision::RejectUnsupportedSignerType { .. }
        ));
        let (_, _, reject) = d.context_fields();
        assert!(reject.expect("reason").contains("peer_shared or admin"));
    }

    // ── Guard passthrough ─────────────────────────────────────

    #[test]
    fn ready_carries_guard_flags_through() {
        let event = ev(true);
        let guards = GuardFacts {
            bootstrap_context: None,
            bootstrap_spki_already_peer_shared: true,
            has_local_invite_secret: true,
            peer_shared_transport_identity_active: true,
        };
        let d = decide_invite_accepted(&event, &DepFacts::default(), &guards);
        match d {
            InviteAcceptedDecision::Ready {
                bootstrap_spki_already_peer_shared,
                has_local_invite_secret,
                peer_shared_transport_identity_active,
                bootstrap_context,
            } => {
                assert!(bootstrap_spki_already_peer_shared);
                assert!(has_local_invite_secret);
                assert!(peer_shared_transport_identity_active);
                assert!(bootstrap_context.is_none());
            }
            other => panic!("expected Ready, got {:?}", other),
        }
    }
}
