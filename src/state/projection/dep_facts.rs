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
    AdminEvent, DeviceInviteEvent, InviteAcceptedEvent, KeyHistoryEvent, KeyRequestEvent,
    KeyRotationEvent, MessageDeletionEvent, MessageEvent, PeerSharedEvent, ReactionEvent,
    UserInviteEvent, WorkspaceEvent,
};
use crate::projection::projector::{
    BootstrapDecisionContext, DeletionIntentInfo, HistoricalKeyMaterial, RemovalTargetKind,
    UnwrappedSecretMaterial,
};
use ed25519_dalek::{SigningKey, VerifyingKey};

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
    /// Signer resolved to a `WorkspaceEvent` (bootstrap-admin path).
    Workspace {
        signer_event_id: String,
        event: WorkspaceEvent,
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
        SignerResolution::Workspace { .. } => {
            PeerSharedDecision::RejectUnsupportedSignerType {
                semantic_type_code: crate::event_modules::EVENT_TYPE_WORKSPACE,
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
        SignerResolution::Workspace { .. } => {
            return RemovalDecision::RejectUnsupportedSignerType {
                semantic_type_code: crate::event_modules::EVENT_TYPE_WORKSPACE,
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
// Admin
//
// An Admin event binds an admin `public_key` to a `user_event_id`.
// Two authorization shapes are accepted:
//
//   - Bootstrap admin: the outer signer is the Workspace, and the
//     admin's `authority_event_id` names that same workspace.
//   - Promoted admin: the outer signer is a PeerShared whose user is
//     *itself* already an admin — specifically, the admin named by
//     `authority_event_id`. This is the "admin-promotes-admin" chain.
//
// In both shapes the final semantic check is: the admin `public_key`
// equals the user's `public_key` (read from the `users` table, which
// is populated by the User projector). Preserving the exact reject
// strings is part of the migration contract.
// ─────────────────────────────────────────────────────────────

/// Resolution of an Admin's `authority_event_id` dep.
///
/// Admin's authority dep accepts `Workspace` (bootstrap) or `Admin`
/// (promotion). Other kinds are blocked upstream by the dep
/// type-code check; the `WrongKind` arm exists for diagnostic
/// symmetry.
#[derive(Debug, Clone)]
pub enum AdminAuthorityEventResolution {
    Workspace {
        event_id: String,
        event: WorkspaceEvent,
    },
    Admin {
        event_id: String,
        event: AdminEvent,
    },
    WrongKind {
        event_id: String,
        semantic_type_code: u8,
    },
}

#[derive(Debug, Clone)]
pub struct AdminDepFacts {
    /// Outer signer, parsed. Admin accepts Workspace or PeerShared.
    pub signer: SignerResolution,
    /// Authority event named by `authority_event_id`. Resolved via the
    /// dep system's valid_events guarantee. Carried through for
    /// future structural refinements; the decide fn currently reads
    /// authority identity off `event.authority_event_id` (b64) and
    /// the SQL-derived `peer_signer_admin_match`.
    pub authority: AdminAuthorityEventResolution,
    /// Whether the signer peer_shared's user is an admin whose
    /// admin-event-id equals `authority_event_id`. Carried here as a
    /// typed bool because translating the current
    /// peers_shared × users × admins JOIN into a purely structural
    /// check requires tightening the user-public-key uniqueness
    /// invariant beyond the Admin migration's scope.
    pub peer_signer_admin_match: bool,
}

#[derive(Debug, Clone, Default)]
pub struct AdminGuardFacts {
    /// b64 of `admin.user_event_id`, carried for reject-string parity.
    pub user_event_id_b64: String,
    /// Distinct `public_key` values for `users` rows keyed on
    /// `(recorded_by, admin.user_event_id)`. LIMIT 2 — only 0 / 1 / ≥2
    /// distinguishable. `Some(bytes)` for readable rows, `None` for
    /// rows whose column value failed to decode as BLOB.
    pub user_public_keys: Vec<Option<Vec<u8>>>,
    /// True if a row in `users` had a malformed `public_key` column
    /// (non-blob / wrong type). Rare but preserved for parity.
    pub malformed: bool,
}

#[derive(Debug, Clone)]
pub enum AdminDecision {
    Ready,
    RejectMissingCurrentSigner,
    RejectUnsupportedSignerType {
        semantic_type_code: u8,
    },
    /// Bootstrap path: workspace signer but `authority_event_id` does
    /// not point back at that workspace (signer.event_id ≠ authority).
    RejectBootstrapAuthorityMismatch,
    /// Promotion path: peer_shared signer, but the SQL chain
    /// (peers_shared → users → admins) does not establish that the
    /// signer's user is the admin named by `authority_event_id`.
    RejectPeerSignerAuthorityMismatch,
    /// `users[admin.user_event_id]` has no row. The admin cannot
    /// certify a user whose record is not present.
    RejectMissingUser {
        user_event_id_b64: String,
    },
    /// Multiple distinct user public keys for `admin.user_event_id`.
    /// Defensive — PRIMARY KEY prevents this in practice.
    RejectAmbiguousUser {
        user_event_id_b64: String,
    },
    /// The user row exists but the stored public_key is not a 32-byte
    /// blob (or the column failed to decode).
    RejectMalformedUserKey {
        user_event_id_b64: String,
    },
    /// User row exists but its `public_key` does not equal
    /// `admin.public_key` — the core "this admin is not who they
    /// claim to be" reject.
    RejectAdminUserKeyMismatch {
        user_event_id_b64: String,
    },
}

impl AdminDecision {
    /// Compatibility shim: map decision to the pre-existing
    /// `admin_user_key_mismatch_reason` string so existing runtime
    /// callers (and byte-identical reject assertions) keep working.
    pub fn mismatch_reason(&self) -> Option<String> {
        match self {
            Self::Ready => None,
            Self::RejectMissingCurrentSigner => {
                Some("admin event missing current signer envelope".to_string())
            }
            Self::RejectUnsupportedSignerType { semantic_type_code } => Some(format!(
                "admin signer must be workspace or peer_shared, got semantic type {}",
                semantic_type_code
            )),
            Self::RejectBootstrapAuthorityMismatch => {
                Some("bootstrap admin must use workspace as signer and authority".to_string())
            }
            Self::RejectPeerSignerAuthorityMismatch => Some(
                "peer-signed admin authority does not match signer admin identity".to_string(),
            ),
            Self::RejectMissingUser { user_event_id_b64 } => Some(format!(
                "no users row for user_event_id {}",
                user_event_id_b64
            )),
            Self::RejectAmbiguousUser { user_event_id_b64 } => Some(format!(
                "ambiguous users rows for user_event_id {}",
                user_event_id_b64
            )),
            Self::RejectMalformedUserKey { user_event_id_b64 } => Some(format!(
                "user {} has invalid public_key length or type",
                user_event_id_b64
            )),
            Self::RejectAdminUserKeyMismatch { user_event_id_b64 } => Some(format!(
                "admin public_key does not match user public_key for {}",
                user_event_id_b64
            )),
        }
    }
}

/// Pure Admin decision.
///
/// The check order mirrors the old normalize + decide pipeline so
/// reject strings remain byte-identical:
///   1. Missing outer signer envelope.
///   2. Unsupported signer kind (anything but Workspace / PeerShared).
///   3. Malformed / missing / ambiguous `users[admin.user_event_id]`.
///   4. Authority-match check (bootstrap vs peer-signed shape).
///   5. `admin.public_key == users[admin.user_event_id].public_key`.
///
/// Signer-side authority is split by `SignerResolution` kind:
///   - `Workspace` signer: the admin's `authority_event_id` must name
///     that workspace (`signer_event_id == authority_event_id_b64`).
///   - `PeerShared` signer: the signer's user must be the admin named
///     by `authority_event_id` (currently proven by the
///     `peer_signer_admin_match` SQL-derived bool).
///
/// User-side authority is a single equality:
/// `users[admin.user_event_id].public_key == admin.public_key`. The
/// users row is carried in `AdminGuardFacts` (raw malformed /
/// missing / ambiguous arms preserved for parity).
pub fn decide_admin(
    event: &AdminEvent,
    deps: &AdminDepFacts,
    guards: &AdminGuardFacts,
) -> AdminDecision {
    // 1. Signer envelope present + kind check.
    let signer_is_workspace_authority_match;
    let signer_is_peer_shared_authority_match;
    match &deps.signer {
        SignerResolution::Missing => return AdminDecision::RejectMissingCurrentSigner,
        SignerResolution::UnsupportedKind { semantic_type_code } => {
            return AdminDecision::RejectUnsupportedSignerType {
                semantic_type_code: *semantic_type_code,
            };
        }
        SignerResolution::DeviceInvite { .. } => {
            return AdminDecision::RejectUnsupportedSignerType {
                semantic_type_code: crate::event_modules::EVENT_TYPE_DEVICE_INVITE,
            };
        }
        SignerResolution::Admin { .. } => {
            return AdminDecision::RejectUnsupportedSignerType {
                semantic_type_code: crate::event_modules::EVENT_TYPE_ADMIN,
            };
        }
        SignerResolution::MissingBlob { .. } | SignerResolution::Malformed { .. } => {
            // Old pipeline never parsed the signer blob — these arms
            // are only reachable when the resolver loader has failed
            // to rewrite to the Workspace / PeerShared arm (e.g.
            // frame.current_signer missing). Treat as "no authority
            // match" to stay parity-safe.
            signer_is_workspace_authority_match = false;
            signer_is_peer_shared_authority_match = false;
        }
        SignerResolution::Workspace {
            signer_event_id, ..
        } => {
            signer_is_workspace_authority_match =
                *signer_event_id == crate::crypto::event_id_to_base64(&event.authority_event_id);
            signer_is_peer_shared_authority_match = false;
        }
        SignerResolution::PeerShared { .. } => {
            signer_is_workspace_authority_match = false;
            signer_is_peer_shared_authority_match = deps.peer_signer_admin_match;
        }
    }

    // 2. User-row normalization (malformed / missing / ambiguous).
    //    Precedence matters: in the old pipeline these fire BEFORE
    //    authority-match rejects.
    if guards.malformed
        || crate::crypto::event_id_from_base64(&guards.user_event_id_b64).is_none()
    {
        return AdminDecision::RejectMalformedUserKey {
            user_event_id_b64: guards.user_event_id_b64.clone(),
        };
    }
    let mut keys = Vec::with_capacity(guards.user_public_keys.len());
    for k in &guards.user_public_keys {
        let Some(k) = k.as_ref() else {
            return AdminDecision::RejectMalformedUserKey {
                user_event_id_b64: guards.user_event_id_b64.clone(),
            };
        };
        if k.len() != 32 {
            return AdminDecision::RejectMalformedUserKey {
                user_event_id_b64: guards.user_event_id_b64.clone(),
            };
        }
        keys.push(k.clone());
    }
    keys.sort();
    keys.dedup();
    let unique_user_key = match keys.as_slice() {
        [] => {
            return AdminDecision::RejectMissingUser {
                user_event_id_b64: guards.user_event_id_b64.clone(),
            };
        }
        [user_public_key] => user_public_key.clone(),
        _ => {
            return AdminDecision::RejectAmbiguousUser {
                user_event_id_b64: guards.user_event_id_b64.clone(),
            };
        }
    };

    // 3. Authority-match check (signer-kind dependent).
    //
    // Note: the authority event's *kind* is not read here — the old
    // pipeline decided off `current_signer.semantic_type_code` and
    // either the `signer_event_id == authority_event_id` string
    // equality (workspace signer) or the peers_shared × users ×
    // admins JOIN (peer-shared signer). `deps.authority` is carried
    // through for future structural refinements but does not
    // participate in this arm today.
    match &deps.signer {
        SignerResolution::Workspace { .. } => {
            if !signer_is_workspace_authority_match {
                return AdminDecision::RejectBootstrapAuthorityMismatch;
            }
        }
        SignerResolution::PeerShared { .. } => {
            if !signer_is_peer_shared_authority_match {
                return AdminDecision::RejectPeerSignerAuthorityMismatch;
            }
        }
        // MissingBlob / Malformed only survive here if the loader's
        // kind-rewrite (Workspace/PeerShared) did not fire. Defensive
        // fall-through to peer-signer mismatch.
        SignerResolution::MissingBlob { .. } | SignerResolution::Malformed { .. } => {
            return AdminDecision::RejectPeerSignerAuthorityMismatch;
        }
        // Unreachable: Missing / UnsupportedKind / DeviceInvite
        // already returned above.
        _ => unreachable!("earlier signer-kind check returned"),
    }

    // 4. admin.public_key must equal users[admin.user_event_id].public_key.
    if unique_user_key.as_slice() == event.public_key.as_slice() {
        AdminDecision::Ready
    } else {
        AdminDecision::RejectAdminUserKeyMismatch {
            user_event_id_b64: guards.user_event_id_b64.clone(),
        }
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
        SignerResolution::Workspace { .. } => MessageDecision::RejectUnsupportedSignerType {
            semantic_type_code: crate::event_modules::EVENT_TYPE_WORKSPACE,
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
        SignerResolution::Workspace { .. } => ReactionDecision::RejectUnsupportedSignerType {
            semantic_type_code: crate::event_modules::EVENT_TYPE_WORKSPACE,
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
        SignerResolution::Workspace { .. } => {
            MessageDeletionDecision::RejectUnsupportedSignerType {
                semantic_type_code: crate::event_modules::EVENT_TYPE_WORKSPACE,
            }
        }
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

// ─────────────────────────────────────────────────────────────
// File
//
// File projection currently has no dep-derived semantic gate and
// no ambient-state guard: the context loader is a pass-through.
// The empty DepFacts/GuardFacts pair is here for *uniformity* with
// the other migrated projectors so call sites look identical.
// Future work may migrate the File-owner / message authorization
// checks into these bundles.
// ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default)]
pub struct FileDepFacts {}

#[derive(Debug, Clone, Default)]
pub struct FileGuardFacts {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileDecision {
    /// Projection proceeds with the default (empty) context. File's
    /// pure decision today has no reject arms at the context-load
    /// layer — downstream projector dispatch handles semantics.
    Ready,
}

pub fn decide_file(
    _event: &crate::event_modules::FileEvent,
    _deps: &FileDepFacts,
    _guards: &FileGuardFacts,
) -> FileDecision {
    FileDecision::Ready
}

// ─────────────────────────────────────────────────────────────
// FileSlice
//
// FileSlice authorization reads three ambient rollups (all over
// already-projected tables):
//
//   * `files` rows for the slice's `file_id`          — the set of
//     file descriptors carrying the authorizing signer / key / bao
//     root hash / slice size. The file_slice projector fans out
//     authorization across these descriptors.
//
//   * `file_slices` row for `(file_id, slice_number)` — the
//     existing slice at the slot, if any, for idempotent re-project
//     / conflict diagnostics.
//
//   * `deleted_messages` join     — if the enclosing encrypted
//     wrapper's owner message is tombstoned, or any descriptor's
//     owning message is tombstoned, the slice must be purged rather
//     than stored.
//
// The encrypted-wrapper owner lives on `frame.current_owner_event_id`
// (same ambient-frame pattern as `resolve_signer_from_frame`). For
// now the owner is surfaced on GuardFacts verbatim — full dep-ification
// is a later migration.
// ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default)]
pub struct FileSliceDepFacts {}

/// Ambient-state guard bundle for FileSlice projection.
///
/// All three fields are rollups over previously-projected tables.
/// `purge_owner_event_id` captures the owner-deleted guard (before
/// any descriptor-deleted sweep); `purge_message_event_id` in the
/// materialized `ProjectorDecisionContext` is the *winner* of the
/// owner/descriptor race, chosen by `decide_file_slice`.
#[derive(Debug, Clone, Default)]
pub struct FileSliceGuardFacts {
    /// Outer encrypted-wrapper owner event_id (from `frame.current_owner_event_id`),
    /// if present and currently tombstoned in `deleted_messages`.
    ///
    /// Carrying the owner id verbatim (not the full frame field) keeps
    /// `decide_file_slice` decoupled from the frame structure while
    /// preserving the owner-wins purge order.
    pub purge_owner_event_id: Option<String>,
    /// File descriptor rollup for `file_id`, ordered by created_at ASC
    /// then event_id ASC (matches previous SQL).
    pub file_descriptors: Vec<crate::projection::projector::FileDescriptorInfo>,
    /// `(event_id, descriptor_event_id)` for a previously projected
    /// slice occupying this `(file_id, slice_number)` slot, if any.
    pub existing_file_slice: Option<(String, String)>,
    /// First descriptor whose `message_id` is tombstoned in
    /// `deleted_messages`, if any — ordered the same way as
    /// `file_descriptors` so the "first hit" is deterministic.
    pub purge_descriptor_message_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileSliceDecision {
    Ready {
        purge_message_event_id: Option<String>,
    },
}

/// Pure FileSlice decision.
///
/// Today the decision's only output is *which* purge id (owner vs.
/// descriptor-owning message) to surface, if any. The chosen order
/// matches the previous SQL: owner-deleted wins over descriptor-
/// deleted, and the first descriptor hit is chosen in iteration
/// order. Everything else — authorization against `file_descriptors`,
/// existing-slice conflict handling — is performed by the projector
/// dispatch layer off the materialized `ProjectorDecisionContext`.
pub fn decide_file_slice(
    _event: &crate::event_modules::FileSliceEvent,
    _deps: &FileSliceDepFacts,
    guards: &FileSliceGuardFacts,
) -> FileSliceDecision {
    let purge_message_event_id = guards
        .purge_owner_event_id
        .clone()
        .or_else(|| guards.purge_descriptor_message_id.clone());
    FileSliceDecision::Ready {
        purge_message_event_id,
    }
}

// ─────────────────────────────────────────────────────────────
// UserInvite
//
// UserInvite's outer signer may be a Workspace (bootstrap path) or
// a PeerShared (ongoing path). The context loader here does not gate
// rejection on signer kind — that check lives in the projector's
// `build_projector_context`. This loader only answers:
//   "when signed by a peer_shared, does the named admin authority
//    authorize that signer's user?"
// Expressed as an Option<bool>: None for the workspace path, Some(..)
// for peer-signed.
//
// Authority resolution: `user_invite.authority_event_id` may resolve
// to an AdminEvent (ongoing) or a Workspace (bootstrap). For the
// peer-signed match we only care about the Admin case; Workspace (or
// any other kind) collapses to `authority_matches_signer = false`.
// ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct UserInviteDepFacts {
    /// Outer signer, parsed. The UserInvite projector accepts only a
    /// `peer_shared` or a workspace signer at the outer-dispatch layer;
    /// this loader treats everything except `PeerShared` as "not a
    /// peer-signed UserInvite" (no authority-match opinion).
    pub signer: SignerResolution,
    /// Admin event named by `authority_event_id`, when the signer is
    /// a peer_shared and the authority blob parses as an Admin. `None`
    /// otherwise (workspace-signed path, or authority event is not an
    /// Admin — e.g. a Workspace on the bootstrap path).
    pub admin_authority: Option<AdminResolution>,
}

#[derive(Debug, Clone, Default)]
pub struct UserInviteGuardFacts {
    /// True when this event was created locally on this peer — drives
    /// the projector's `pending_invite_bootstrap_trust` write.
    pub is_local_create: bool,
    /// Locally-recorded invite-link binding (workspace id, bootstrap
    /// addrs, bootstrap SPKI), when present.
    pub bootstrap_context: Option<BootstrapDecisionContext>,
}

/// Pure UserInvite decision.
///
/// There is no reject arm here: the loader's job is to surface the
/// Option<bool> authority-match signal the projector's dispatch layer
/// consumes. Rejection (workspace-signer mismatch, peer-signed
/// authority mismatch, unsupported signer) happens in the projector's
/// `build_projector_context`, which reads the Option<bool> this
/// decision carries.
#[derive(Debug, Clone)]
pub enum UserInviteDecision {
    Ready {
        /// None when signer isn't a peer_shared. Some(true) when the
        /// admin_authority's user_event_id matches the signer peer_shared's
        /// user_event_id. Some(false) otherwise (admin kind mismatch,
        /// admin missing, or user-event ids differ).
        authority_matches_signer: Option<bool>,
        is_local_create: bool,
        bootstrap_context: Option<BootstrapDecisionContext>,
    },
}

pub fn decide_user_invite(
    _event: &UserInviteEvent,
    deps: &UserInviteDepFacts,
    guards: &UserInviteGuardFacts,
) -> UserInviteDecision {
    let authority_matches_signer = match &deps.signer {
        SignerResolution::PeerShared { event: ps, .. } => {
            let matches = match &deps.admin_authority {
                Some(AdminResolution::Valid { event: admin, .. }) => {
                    admin.user_event_id == ps.user_event_id
                }
                _ => false,
            };
            Some(matches)
        }
        _ => None,
    };
    UserInviteDecision::Ready {
        authority_matches_signer,
        is_local_create: guards.is_local_create,
        bootstrap_context: guards.bootstrap_context.clone(),
    }
}

// ─────────────────────────────────────────────────────────────
// KeyRequest
//
// Trivial shape: projection reads a single rollup flag that says
// "has a key_shared response for this delivery_target already been
// projected?" — used to suppress duplicate sharing. No rejects.
// Kept as typed Decision for uniformity with the rest of the
// DepFacts/GuardFacts migration.
// ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default)]
pub struct KeyRequestDepFacts {}

#[derive(Debug, Clone, Default)]
pub struct KeyRequestGuardFacts {
    /// True when a `key_shared` row already exists for this
    /// `delivery_target_id` under this tenant — later sharing
    /// should be suppressed.
    pub has_projected_response: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyRequestDecision {
    Ready { suppress_sharing: bool },
}

pub fn decide_key_request(
    _event: &KeyRequestEvent,
    _deps: &KeyRequestDepFacts,
    guards: &KeyRequestGuardFacts,
) -> KeyRequestDecision {
    KeyRequestDecision::Ready {
        suppress_sharing: guards.has_projected_response,
    }
}

// ─────────────────────────────────────────────────────────────
// KeyRotation
//
// Projection may unwrap the caller's slot when:
//   - a local peer_shared signing key exists (the recipient),
//   - that recipient's event_id appears in `recipient_slots`,
//   - the outer signer resolves to a sender with a usable Ed25519
//     verifying key.
// All three are guard-shaped (ambient local state / frame signer).
// No rejects — missing guards just produce `NoUnwrap`, matching
// the pre-migration behaviour of returning a default
// `ProjectorDecisionContext` with no `unwrapped_secret_material`.
// ─────────────────────────────────────────────────────────────

/// Local peer-shared signer data (recipient identity) used to
/// DH-unwrap a KeyRotation slot.
#[derive(Debug, Clone)]
pub struct LocalPeerSigner {
    /// The local peer_shared event_id — matched against
    /// `KeyRotationEvent::recipient_slots` to find our slot.
    pub recipient_event_id: [u8; 32],
    /// The local signing key corresponding to `recipient_event_id`.
    pub signing_key: SigningKey,
}

#[derive(Debug, Clone, Default)]
pub struct KeyRotationDepFacts {}

#[derive(Debug, Clone, Default)]
pub struct KeyRotationGuardFacts {
    /// Local peer_shared signer, when present. `None` means the
    /// tenant has no active peer_shared identity — nothing to
    /// unwrap.
    pub local_peer_signer: Option<LocalPeerSigner>,
    /// Sender's verifying key, looked up off the current signer
    /// frame. `None` means the signer could not be resolved or
    /// the key failed to parse.
    pub sender_verifying_key: Option<VerifyingKey>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyRotationDecision {
    /// Either the local signer is absent, our recipient slot is
    /// not in the rotation, or the sender signer did not resolve.
    /// In all cases: emit no unwrapped material.
    NoUnwrap,
    /// Unwrapped key material for our slot, ready to install.
    Ready {
        unwrapped_key: [u8; 32],
    },
}

impl KeyRotationDecision {
    pub fn unwrapped_secret_material(&self) -> Option<UnwrappedSecretMaterial> {
        match self {
            Self::NoUnwrap => None,
            Self::Ready { unwrapped_key } => Some(UnwrappedSecretMaterial {
                key_bytes: *unwrapped_key,
            }),
        }
    }
}

/// Pure KeyRotation decision.
///
/// Finds the local recipient's slot (if any) and XORs the
/// sender-derived wrap-key against the wrapped slot bytes.
pub fn decide_key_rotation(
    event: &KeyRotationEvent,
    _deps: &KeyRotationDepFacts,
    guards: &KeyRotationGuardFacts,
) -> KeyRotationDecision {
    let Some(local) = guards.local_peer_signer.as_ref() else {
        return KeyRotationDecision::NoUnwrap;
    };
    let Some(slot_index) = event
        .recipient_slots
        .iter()
        .position(|slot| *slot == local.recipient_event_id)
    else {
        return KeyRotationDecision::NoUnwrap;
    };
    let Some(sender_pub) = guards.sender_verifying_key.as_ref() else {
        return KeyRotationDecision::NoUnwrap;
    };
    if slot_index >= event.wrapped_keys.len() {
        return KeyRotationDecision::NoUnwrap;
    }
    let unwrapped = crate::crypto::unwrap_key_from_sender(
        &local.signing_key,
        sender_pub,
        &event.wrapped_keys[slot_index],
    );
    KeyRotationDecision::Ready {
        unwrapped_key: unwrapped,
    }
}

// ─────────────────────────────────────────────────────────────
// KeyHistory
//
// Guard-only: projection decrypts the history bundle with a local
// invite_secret signing key (matched by recipient_public_key) and
// the sender's verifying key (off the signer frame). On any
// missing input or decrypt/decode failure: no unwrapped material
// (matches pre-migration default-ctx return).
// ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default)]
pub struct KeyHistoryDepFacts {}

#[derive(Debug, Clone, Default)]
pub struct KeyHistoryGuardFacts {
    /// Local invite_secret signing key whose verifying key equals
    /// `KeyHistoryEvent::recipient_public_key`. `None` means no
    /// such secret exists for this tenant.
    pub local_recipient_signing_key: Option<SigningKey>,
    /// Sender's verifying key from the current signer frame.
    pub sender_verifying_key: Option<VerifyingKey>,
}

#[derive(Debug, Clone)]
pub enum KeyHistoryDecision {
    /// No local recipient secret, no signer, decrypt failure, or
    /// decode failure. Emit empty history material.
    NoUnwrap,
    /// Decoded historical key material, ready to install.
    Ready { entries: Vec<HistoricalKeyMaterial> },
}

impl KeyHistoryDecision {
    pub fn into_material(self) -> Vec<HistoricalKeyMaterial> {
        match self {
            Self::NoUnwrap => Vec::new(),
            Self::Ready { entries } => entries,
        }
    }
}

/// Pure KeyHistory decision.
///
/// Decrypts the bundle with (local signing key, sender pub key,
/// nonce, ciphertext, auth_tag). On decrypt or decode failure the
/// decision is `NoUnwrap` — matching the pre-migration default.
pub fn decide_key_history(
    event: &KeyHistoryEvent,
    _deps: &KeyHistoryDepFacts,
    guards: &KeyHistoryGuardFacts,
) -> KeyHistoryDecision {
    let Some(local_signing_key) = guards.local_recipient_signing_key.as_ref() else {
        return KeyHistoryDecision::NoUnwrap;
    };
    let Some(sender_pub) = guards.sender_verifying_key.as_ref() else {
        return KeyHistoryDecision::NoUnwrap;
    };
    let plaintext = match crate::crypto::decrypt_bundle_from_sender(
        local_signing_key,
        sender_pub,
        &event.nonce,
        &event.ciphertext,
        &event.auth_tag,
    ) {
        Ok(p) => p,
        Err(_) => return KeyHistoryDecision::NoUnwrap,
    };
    let entries =
        match crate::event_modules::key_history::decode_key_history_plaintext(&plaintext) {
            Ok(e) => e,
            Err(_) => return KeyHistoryDecision::NoUnwrap,
        };
    KeyHistoryDecision::Ready {
        entries: entries
            .into_iter()
            .map(|entry| HistoricalKeyMaterial {
                key_event_id: entry.key_event_id,
                key_bytes: entry.key_bytes,
            })
            .collect(),
    }
}

// ─────────────────────────────────────────────────────────────
// DeviceInvite
//
// DeviceInvite's outer signer may be a User (bootstrap path) or a
// PeerShared (ongoing path). Same shape as UserInvite: the loader
// answers the peer-signed authority match question, the projector's
// dispatch layer handles signer-kind gating and rejection.
//
// Authority: `device_invite.authority_event_id` is a user event_id.
// For the peer-signed match, the signer peer_shared's user_event_id
// must equal `authority_event_id`. No blob load is needed — the
// equality is over event_ids, and the dep system has already
// validated that `authority_event_id` is a User (type 14).
// ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct DeviceInviteDepFacts {
    /// Outer signer, parsed.
    pub signer: SignerResolution,
}

#[derive(Debug, Clone, Default)]
pub struct DeviceInviteGuardFacts {
    pub is_local_create: bool,
    pub bootstrap_context: Option<BootstrapDecisionContext>,
}

#[derive(Debug, Clone)]
pub enum DeviceInviteDecision {
    Ready {
        authority_matches_signer: Option<bool>,
        is_local_create: bool,
        bootstrap_context: Option<BootstrapDecisionContext>,
    },
}

pub fn decide_device_invite(
    event: &DeviceInviteEvent,
    deps: &DeviceInviteDepFacts,
    guards: &DeviceInviteGuardFacts,
) -> DeviceInviteDecision {
    let authority_matches_signer = match &deps.signer {
        SignerResolution::PeerShared { event: ps, .. } => {
            Some(ps.user_event_id == event.authority_event_id)
        }
        _ => None,
    };
    DeviceInviteDecision::Ready {
        authority_matches_signer,
        is_local_create: guards.is_local_create,
        bootstrap_context: guards.bootstrap_context.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event_modules::{
        DeviceInviteEvent, InviteAcceptedEvent, PeerSharedEvent, UserInviteEvent,
    };

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

    // ── Admin pilot ───────────────────────────────────────────

    fn admin_event_for(
        public_key: [u8; 32],
        authority_event_id: [u8; 32],
        user_event_id: [u8; 32],
    ) -> AdminEvent {
        AdminEvent {
            created_at_ms: 0,
            public_key,
            authority_event_id,
            user_event_id,
        }
    }

    fn workspace_signer_res(signer_event_id: &str) -> SignerResolution {
        SignerResolution::Workspace {
            signer_event_id: signer_event_id.to_string(),
            event: crate::event_modules::WorkspaceEvent {
                created_at_ms: 0,
                public_key: [0u8; 32],
                name: "ws".to_string(),
            },
        }
    }

    fn peer_shared_signer_res(user_event_id: [u8; 32]) -> SignerResolution {
        SignerResolution::PeerShared {
            signer_event_id: "peer-signer".into(),
            event: PeerSharedEvent {
                created_at_ms: 0,
                public_key: [1u8; 32],
                user_event_id,
                endpoint_shared_event_id: [2u8; 32],
                device_name: String::new(),
            },
        }
    }

    fn admin_authority_workspace(event_id_b64: &str) -> AdminAuthorityEventResolution {
        AdminAuthorityEventResolution::Workspace {
            event_id: event_id_b64.to_string(),
            event: crate::event_modules::WorkspaceEvent {
                created_at_ms: 0,
                public_key: [0u8; 32],
                name: "ws".to_string(),
            },
        }
    }

    fn admin_authority_admin(
        event_id_b64: &str,
        user_event_id: [u8; 32],
    ) -> AdminAuthorityEventResolution {
        AdminAuthorityEventResolution::Admin {
            event_id: event_id_b64.to_string(),
            event: AdminEvent {
                created_at_ms: 0,
                public_key: [9u8; 32],
                authority_event_id: [0u8; 32],
                user_event_id,
            },
        }
    }

    // ── UserInvite pilot ──────────────────────────────────────

    fn user_invite_event(authority: [u8; 32], workspace: [u8; 32]) -> UserInviteEvent {
        UserInviteEvent {
            created_at_ms: 0,
            public_key: [1u8; 32],
            workspace_id: workspace,
            authority_event_id: authority,
            key_history_event_id: [2u8; 32],
        }
    }

    fn admin_event_with_user(user: [u8; 32]) -> AdminResolution {
        AdminResolution::Valid {
            event_id: [0xAB; 32],
            event: AdminEvent {
                created_at_ms: 0,
                public_key: [3u8; 32],
                authority_event_id: [0u8; 32],
                user_event_id: user,
            },
        }
    }

    fn admin_user_key_guard(
        user_event_id: [u8; 32],
        keys: Vec<Option<Vec<u8>>>,
    ) -> AdminGuardFacts {
        AdminGuardFacts {
            user_event_id_b64: crate::crypto::event_id_to_base64(&user_event_id),
            user_public_keys: keys,
            malformed: false,
        }
    }

    #[test]
    fn admin_ready_when_workspace_signs_itself_and_user_key_matches() {
        let admin_public = [7u8; 32];
        let workspace_id = [4u8; 32];
        let user_id = [5u8; 32];
        let authority_b64 = crate::crypto::event_id_to_base64(&workspace_id);
        let deps = AdminDepFacts {
            signer: workspace_signer_res(&authority_b64),
            authority: admin_authority_workspace(&authority_b64),
            peer_signer_admin_match: false,
        };
        let guards = admin_user_key_guard(user_id, vec![Some(admin_public.to_vec())]);
        let d = decide_admin(
            &admin_event_for(admin_public, workspace_id, user_id),
            &deps,
            &guards,
        );
        assert!(matches!(d, AdminDecision::Ready));
        assert!(d.mismatch_reason().is_none());
    }

    #[test]
    fn admin_rejects_bootstrap_mismatch_when_workspace_signer_differs_from_authority() {
        let admin_public = [7u8; 32];
        let workspace_id = [4u8; 32];
        let user_id = [5u8; 32];
        let deps = AdminDepFacts {
            signer: workspace_signer_res("other-workspace-id"),
            authority: admin_authority_workspace(&crate::crypto::event_id_to_base64(
                &workspace_id,
            )),
            peer_signer_admin_match: false,
        };
        let guards = admin_user_key_guard(user_id, vec![Some(admin_public.to_vec())]);
        let d = decide_admin(
            &admin_event_for(admin_public, workspace_id, user_id),
            &deps,
            &guards,
        );
        assert!(matches!(d, AdminDecision::RejectBootstrapAuthorityMismatch));
        assert_eq!(
            d.mismatch_reason().as_deref(),
            Some("bootstrap admin must use workspace as signer and authority"),
        );
    }

    #[test]
    fn admin_ready_when_peer_signer_admin_chain_matches_and_user_key_matches() {
        let admin_public = [7u8; 32];
        let user_id = [5u8; 32];
        let authority_user_id = [6u8; 32];
        let authority_admin_id = [3u8; 32];
        let deps = AdminDepFacts {
            signer: peer_shared_signer_res(authority_user_id),
            authority: admin_authority_admin(
                &crate::crypto::event_id_to_base64(&authority_admin_id),
                authority_user_id,
            ),
            peer_signer_admin_match: true,
        };
        let guards = admin_user_key_guard(user_id, vec![Some(admin_public.to_vec())]);
        let d = decide_admin(
            &admin_event_for(admin_public, authority_admin_id, user_id),
            &deps,
            &guards,
        );
        assert!(matches!(d, AdminDecision::Ready));
    }

    #[test]
    fn admin_rejects_peer_signer_authority_mismatch_when_join_fails() {
        let admin_public = [7u8; 32];
        let user_id = [5u8; 32];
        let authority_admin_id = [3u8; 32];
        let deps = AdminDepFacts {
            signer: peer_shared_signer_res([9u8; 32]),
            authority: admin_authority_admin(
                &crate::crypto::event_id_to_base64(&authority_admin_id),
                [6u8; 32],
            ),
            peer_signer_admin_match: false,
        };
        let guards = admin_user_key_guard(user_id, vec![Some(admin_public.to_vec())]);
        let d = decide_admin(
            &admin_event_for(admin_public, authority_admin_id, user_id),
            &deps,
            &guards,
        );
        assert!(matches!(d, AdminDecision::RejectPeerSignerAuthorityMismatch));
        assert_eq!(
            d.mismatch_reason().as_deref(),
            Some("peer-signed admin authority does not match signer admin identity"),
        );
    }

    #[test]
    fn admin_rejects_missing_current_signer() {
        let admin_public = [7u8; 32];
        let user_id = [5u8; 32];
        let deps = AdminDepFacts {
            signer: SignerResolution::Missing,
            authority: admin_authority_workspace("authority-id"),
            peer_signer_admin_match: false,
        };
        let guards = admin_user_key_guard(user_id, vec![Some(admin_public.to_vec())]);
        let d = decide_admin(
            &admin_event_for(admin_public, [0u8; 32], user_id),
            &deps,
            &guards,
        );
        assert!(matches!(d, AdminDecision::RejectMissingCurrentSigner));
        assert_eq!(
            d.mismatch_reason().as_deref(),
            Some("admin event missing current signer envelope"),
        );
    }

    #[test]
    fn admin_rejects_unsupported_signer_type() {
        let admin_public = [7u8; 32];
        let user_id = [5u8; 32];
        let deps = AdminDepFacts {
            signer: SignerResolution::UnsupportedKind {
                semantic_type_code: 99,
            },
            authority: admin_authority_workspace("authority-id"),
            peer_signer_admin_match: false,
        };
        let guards = admin_user_key_guard(user_id, vec![Some(admin_public.to_vec())]);
        let d = decide_admin(
            &admin_event_for(admin_public, [0u8; 32], user_id),
            &deps,
            &guards,
        );
        match d {
            AdminDecision::RejectUnsupportedSignerType { semantic_type_code } => {
                assert_eq!(semantic_type_code, 99);
            }
            other => panic!("expected RejectUnsupportedSignerType, got {:?}", other),
        }
    }

    #[test]
    fn user_invite_ready_with_no_peer_signer_leaves_match_none() {
        let event = user_invite_event([1u8; 32], [2u8; 32]);
        let deps = UserInviteDepFacts {
            signer: SignerResolution::UnsupportedKind {
                semantic_type_code: crate::event_modules::EVENT_TYPE_WORKSPACE,
            },
            admin_authority: None,
        };
        let d = decide_user_invite(&event, &deps, &UserInviteGuardFacts::default());
        match d {
            UserInviteDecision::Ready {
                authority_matches_signer,
                ..
            } => assert_eq!(authority_matches_signer, None),
        }
    }

    #[test]
    fn admin_rejects_user_key_mismatch_when_users_row_has_different_public_key() {
        let admin_public = [7u8; 32];
        let user_id = [5u8; 32];
        let workspace_id = [4u8; 32];
        let authority_b64 = crate::crypto::event_id_to_base64(&workspace_id);
        let deps = AdminDepFacts {
            signer: workspace_signer_res(&authority_b64),
            authority: admin_authority_workspace(&authority_b64),
            peer_signer_admin_match: false,
        };
        let guards = admin_user_key_guard(user_id, vec![Some(vec![0xFF; 32])]);
        let d = decide_admin(
            &admin_event_for(admin_public, workspace_id, user_id),
            &deps,
            &guards,
        );
        match &d {
            AdminDecision::RejectAdminUserKeyMismatch { user_event_id_b64 } => {
                assert_eq!(
                    user_event_id_b64,
                    &crate::crypto::event_id_to_base64(&user_id)
                );
            }
            other => panic!("expected RejectAdminUserKeyMismatch, got {:?}", other),
        }
        let reason = d.mismatch_reason().unwrap();
        assert!(reason.starts_with("admin public_key does not match user public_key for "));
    }

    #[test]
    fn admin_rejects_missing_user_row() {
        let admin_public = [7u8; 32];
        let user_id = [5u8; 32];
        let workspace_id = [4u8; 32];
        let authority_b64 = crate::crypto::event_id_to_base64(&workspace_id);
        let deps = AdminDepFacts {
            signer: workspace_signer_res(&authority_b64),
            authority: admin_authority_workspace(&authority_b64),
            peer_signer_admin_match: false,
        };
        let guards = admin_user_key_guard(user_id, Vec::new());
        let d = decide_admin(
            &admin_event_for(admin_public, workspace_id, user_id),
            &deps,
            &guards,
        );
        assert!(matches!(d, AdminDecision::RejectMissingUser { .. }));
        let reason = d.mismatch_reason().unwrap();
        assert!(reason.starts_with("no users row for user_event_id "));
    }

    #[test]
    fn admin_rejects_malformed_user_key_when_length_wrong() {
        let admin_public = [7u8; 32];
        let user_id = [5u8; 32];
        let workspace_id = [4u8; 32];
        let authority_b64 = crate::crypto::event_id_to_base64(&workspace_id);
        let deps = AdminDepFacts {
            signer: workspace_signer_res(&authority_b64),
            authority: admin_authority_workspace(&authority_b64),
            peer_signer_admin_match: false,
        };
        let guards = admin_user_key_guard(user_id, vec![Some(vec![1u8; 16])]);
        let d = decide_admin(
            &admin_event_for(admin_public, workspace_id, user_id),
            &deps,
            &guards,
        );
        assert!(matches!(d, AdminDecision::RejectMalformedUserKey { .. }));
        let reason = d.mismatch_reason().unwrap();
        assert!(reason.ends_with(" has invalid public_key length or type"));
    }

    #[test]
    fn admin_rejects_ambiguous_user_when_two_keys() {
        let admin_public = [7u8; 32];
        let user_id = [5u8; 32];
        let workspace_id = [4u8; 32];
        let authority_b64 = crate::crypto::event_id_to_base64(&workspace_id);
        let deps = AdminDepFacts {
            signer: workspace_signer_res(&authority_b64),
            authority: admin_authority_workspace(&authority_b64),
            peer_signer_admin_match: false,
        };
        let guards =
            admin_user_key_guard(user_id, vec![Some(vec![1u8; 32]), Some(vec![2u8; 32])]);
        let d = decide_admin(
            &admin_event_for(admin_public, workspace_id, user_id),
            &deps,
            &guards,
        );
        assert!(matches!(d, AdminDecision::RejectAmbiguousUser { .. }));
        let reason = d.mismatch_reason().unwrap();
        assert!(reason.starts_with("ambiguous users rows for user_event_id "));
    }

    #[test]
    fn user_invite_ready_peer_signed_match_true_when_admin_user_equals_signer_user() {
        let user = [42u8; 32];
        let event = user_invite_event([0xAB; 32], [7u8; 32]);
        let deps = UserInviteDepFacts {
            signer: peer_shared_signer(user),
            admin_authority: Some(admin_event_with_user(user)),
        };
        let d = decide_user_invite(&event, &deps, &UserInviteGuardFacts::default());
        match d {
            UserInviteDecision::Ready {
                authority_matches_signer,
                ..
            } => assert_eq!(authority_matches_signer, Some(true)),
        }
    }

    #[test]
    fn user_invite_ready_peer_signed_match_false_when_admin_user_differs() {
        let event = user_invite_event([0xAB; 32], [7u8; 32]);
        let deps = UserInviteDepFacts {
            signer: peer_shared_signer([1u8; 32]),
            admin_authority: Some(admin_event_with_user([2u8; 32])),
        };
        let d = decide_user_invite(&event, &deps, &UserInviteGuardFacts::default());
        match d {
            UserInviteDecision::Ready {
                authority_matches_signer,
                ..
            } => assert_eq!(authority_matches_signer, Some(false)),
        }
    }

    #[test]
    fn user_invite_ready_peer_signed_match_false_when_admin_missing() {
        let event = user_invite_event([0xAB; 32], [7u8; 32]);
        let deps = UserInviteDepFacts {
            signer: peer_shared_signer([42u8; 32]),
            admin_authority: None,
        };
        let d = decide_user_invite(&event, &deps, &UserInviteGuardFacts::default());
        match d {
            UserInviteDecision::Ready {
                authority_matches_signer,
                ..
            } => assert_eq!(authority_matches_signer, Some(false)),
        }
    }

    #[test]
    fn user_invite_ready_peer_signed_match_false_when_authority_wrong_kind() {
        let event = user_invite_event([0xAB; 32], [7u8; 32]);
        let deps = UserInviteDepFacts {
            signer: peer_shared_signer([42u8; 32]),
            admin_authority: Some(AdminResolution::WrongKind {
                event_id: [0xAB; 32],
                semantic_type_code: crate::event_modules::EVENT_TYPE_WORKSPACE,
            }),
        };
        let d = decide_user_invite(&event, &deps, &UserInviteGuardFacts::default());
        match d {
            UserInviteDecision::Ready {
                authority_matches_signer,
                ..
            } => assert_eq!(authority_matches_signer, Some(false)),
        }
    }

    #[test]
    fn user_invite_carries_guard_flags_through() {
        let event = user_invite_event([1u8; 32], [2u8; 32]);
        let guards = UserInviteGuardFacts {
            is_local_create: true,
            bootstrap_context: Some(BootstrapDecisionContext {
                workspace_id: "ws".into(),
                bootstrap_addrs: vec!["127.0.0.1:1".into()],
                bootstrap_spki_fingerprint: [0u8; 32],
            }),
        };
        let deps = UserInviteDepFacts {
            signer: SignerResolution::Missing,
            admin_authority: None,
        };
        let d = decide_user_invite(&event, &deps, &guards);
        match d {
            UserInviteDecision::Ready {
                is_local_create,
                bootstrap_context,
                authority_matches_signer,
            } => {
                assert!(is_local_create);
                assert!(bootstrap_context.is_some());
                assert_eq!(authority_matches_signer, None);
            }
        }
    }

    // ── DeviceInvite pilot ────────────────────────────────────

    fn device_invite_event(authority: [u8; 32]) -> DeviceInviteEvent {
        DeviceInviteEvent {
            created_at_ms: 0,
            public_key: [1u8; 32],
            authority_event_id: authority,
            key_history_event_id: [2u8; 32],
        }
    }

    #[test]
    fn device_invite_ready_with_no_peer_signer_leaves_match_none() {
        let event = device_invite_event([5u8; 32]);
        let deps = DeviceInviteDepFacts {
            signer: SignerResolution::UnsupportedKind {
                semantic_type_code: crate::event_modules::EVENT_TYPE_USER,
            },
        };
        let d = decide_device_invite(&event, &deps, &DeviceInviteGuardFacts::default());
        match d {
            DeviceInviteDecision::Ready {
                authority_matches_signer,
                ..
            } => assert_eq!(authority_matches_signer, None),
        }
    }

    #[test]
    fn device_invite_ready_peer_signed_match_true_when_signer_user_equals_authority() {
        let user = [42u8; 32];
        let event = device_invite_event(user);
        let deps = DeviceInviteDepFacts {
            signer: peer_shared_signer(user),
        };
        let d = decide_device_invite(&event, &deps, &DeviceInviteGuardFacts::default());
        match d {
            DeviceInviteDecision::Ready {
                authority_matches_signer,
                ..
            } => assert_eq!(authority_matches_signer, Some(true)),
        }
    }

    #[test]
    fn device_invite_ready_peer_signed_match_false_when_signer_user_differs() {
        let event = device_invite_event([1u8; 32]);
        let deps = DeviceInviteDepFacts {
            signer: peer_shared_signer([2u8; 32]),
        };
        let d = decide_device_invite(&event, &deps, &DeviceInviteGuardFacts::default());
        match d {
            DeviceInviteDecision::Ready {
                authority_matches_signer,
                ..
            } => assert_eq!(authority_matches_signer, Some(false)),
        }
    }

    #[test]
    fn device_invite_carries_guard_flags_through() {
        let event = device_invite_event([1u8; 32]);
        let guards = DeviceInviteGuardFacts {
            is_local_create: true,
            bootstrap_context: Some(BootstrapDecisionContext {
                workspace_id: "ws".into(),
                bootstrap_addrs: vec!["127.0.0.1:1".into()],
                bootstrap_spki_fingerprint: [0u8; 32],
            }),
        };
        let deps = DeviceInviteDepFacts {
            signer: SignerResolution::Missing,
        };
        let d = decide_device_invite(&event, &deps, &guards);
        match d {
            DeviceInviteDecision::Ready {
                is_local_create,
                bootstrap_context,
                authority_matches_signer,
            } => {
                assert!(is_local_create);
                assert!(bootstrap_context.is_some());
                assert_eq!(authority_matches_signer, None);
            }
        }
    }

    // ── Guard passthrough ─────────────────────────────────────

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

    // ── File pilot ────────────────────────────────────────────

    fn file_event() -> crate::event_modules::FileEvent {
        crate::event_modules::FileEvent {
            created_at_ms: 0,
            message_id: [1u8; 32],
            file_id: [2u8; 32],
            blob_bytes: 1024,
            total_slices: 1,
            slice_bytes: 1024,
            root_hash: [3u8; 32],
            key_event_id: [4u8; 32],
            filename: "test.bin".into(),
            mime_type: "application/octet-stream".into(),
        }
    }

    #[test]
    fn file_ready_always() {
        let d = decide_file(&file_event(), &FileDepFacts::default(), &FileGuardFacts::default());
        assert!(matches!(d, FileDecision::Ready));
    }

    // ── FileSlice pilot ───────────────────────────────────────

    fn file_slice_event() -> crate::event_modules::FileSliceEvent {
        crate::event_modules::FileSliceEvent {
            created_at_ms: 0,
            file_id: [2u8; 32],
            slice_number: 0,
            ciphertext: vec![0u8; 32],
        }
    }

    #[test]
    fn file_slice_ready_no_purge_when_nothing_deleted() {
        let d = decide_file_slice(
            &file_slice_event(),
            &FileSliceDepFacts::default(),
            &FileSliceGuardFacts::default(),
        );
        assert!(matches!(
            d,
            FileSliceDecision::Ready {
                purge_message_event_id: None
            }
        ));
    }

    // ── KeyRequest pilot ──────────────────────────────────────

    fn kr_event() -> KeyRequestEvent {
        KeyRequestEvent {
            created_at_ms: 0,
            blocked_event_id: [1u8; 32],
            key_event_id: [2u8; 32],
            frontier_hash: [3u8; 32],
            delivery_target_id: [4u8; 32],
            recipient_event_id: [5u8; 32],
            unwrap_key_event_id: [6u8; 32],
        }
    }

    #[test]
    fn key_request_ready_passes_through_suppress_flag() {
        let d = decide_key_request(
            &kr_event(),
            &KeyRequestDepFacts::default(),
            &KeyRequestGuardFacts {
                has_projected_response: true,
            },
        );
        assert!(matches!(
            d,
            KeyRequestDecision::Ready {
                suppress_sharing: true
            }
        ));
    }

    #[test]
    fn file_slice_owner_purge_wins_over_descriptor_purge() {
        let guards = FileSliceGuardFacts {
            purge_owner_event_id: Some("owner-msg".into()),
            purge_descriptor_message_id: Some("desc-msg".into()),
            ..Default::default()
        };
        let d = decide_file_slice(&file_slice_event(), &FileSliceDepFacts::default(), &guards);
        match d {
            FileSliceDecision::Ready {
                purge_message_event_id,
            } => {
                assert_eq!(purge_message_event_id.as_deref(), Some("owner-msg"));
            }
        }
    }

    #[test]
    fn key_request_ready_when_no_existing_response() {
        let d = decide_key_request(
            &kr_event(),
            &KeyRequestDepFacts::default(),
            &KeyRequestGuardFacts::default(),
        );
        assert!(matches!(
            d,
            KeyRequestDecision::Ready {
                suppress_sharing: false
            }
        ));
    }

    // ── KeyRotation pilot ─────────────────────────────────────

    fn key_rotation_event(
        recipient_slots: Vec<[u8; 32]>,
        wrapped_keys: Vec<[u8; 32]>,
    ) -> KeyRotationEvent {
        KeyRotationEvent {
            created_at_ms: 0,
            frontier_count: 0,
            frontier_ref_1: [0u8; 32],
            frontier_ref_2: [0u8; 32],
            frontier_ref_3: [0u8; 32],
            frontier_ref_4: [0u8; 32],
            frontier_hash: [0u8; 32],
            rotated_by: [0u8; 32],
            recipient_slots,
            wrapped_keys,
        }
    }

    fn test_signing_key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    #[test]
    fn key_rotation_no_unwrap_when_no_local_signer() {
        let event = key_rotation_event(vec![[7u8; 32]], vec![[0u8; 32]]);
        let d = decide_key_rotation(
            &event,
            &KeyRotationDepFacts::default(),
            &KeyRotationGuardFacts::default(),
        );
        assert!(matches!(d, KeyRotationDecision::NoUnwrap));
        assert!(d.unwrapped_secret_material().is_none());
    }

    #[test]
    fn key_rotation_no_unwrap_when_slot_absent() {
        let signing = test_signing_key(9);
        let sender = test_signing_key(11);
        let event = key_rotation_event(vec![[7u8; 32]], vec![[0u8; 32]]);
        let guards = KeyRotationGuardFacts {
            local_peer_signer: Some(LocalPeerSigner {
                recipient_event_id: [42u8; 32],
                signing_key: signing,
            }),
            sender_verifying_key: Some(sender.verifying_key()),
        };
        let d = decide_key_rotation(&event, &KeyRotationDepFacts::default(), &guards);
        assert!(matches!(d, KeyRotationDecision::NoUnwrap));
    }

    #[test]
    fn key_rotation_no_unwrap_when_sender_missing() {
        let signing = test_signing_key(9);
        let recipient_id = [7u8; 32];
        let event = key_rotation_event(vec![recipient_id], vec![[0u8; 32]]);
        let guards = KeyRotationGuardFacts {
            local_peer_signer: Some(LocalPeerSigner {
                recipient_event_id: recipient_id,
                signing_key: signing,
            }),
            sender_verifying_key: None,
        };
        let d = decide_key_rotation(&event, &KeyRotationDepFacts::default(), &guards);
        assert!(matches!(d, KeyRotationDecision::NoUnwrap));
    }

    #[test]
    fn key_rotation_ready_unwraps_slot() {
        // Round-trip: since unwrap_key_from_sender is a symmetric XOR
        // against the derived wrap-key, wrap(plain) ≡ unwrap(plain). We
        // use that property to produce a wrapped slot and verify decide
        // recovers the plaintext.
        let recipient_sk = test_signing_key(3);
        let sender_sk = test_signing_key(5);
        let plaintext = [0x5Au8; 32];
        let recipient_id = [7u8; 32];

        let wrapped = crate::crypto::unwrap_key_from_sender(
            &recipient_sk,
            &sender_sk.verifying_key(),
            &plaintext,
        );

        let event = key_rotation_event(vec![recipient_id], vec![wrapped]);
        let guards = KeyRotationGuardFacts {
            local_peer_signer: Some(LocalPeerSigner {
                recipient_event_id: recipient_id,
                signing_key: recipient_sk,
            }),
            sender_verifying_key: Some(sender_sk.verifying_key()),
        };
        let d = decide_key_rotation(&event, &KeyRotationDepFacts::default(), &guards);
        match &d {
            KeyRotationDecision::Ready { unwrapped_key } => {
                assert_eq!(*unwrapped_key, plaintext);
            }
            other => panic!("expected Ready, got {:?}", other),
        }
        assert_eq!(
            d.unwrapped_secret_material().map(|m| m.key_bytes),
            Some(plaintext)
        );
    }

    // ── KeyHistory pilot ──────────────────────────────────────

    fn empty_key_history_event() -> KeyHistoryEvent {
        KeyHistoryEvent {
            created_at_ms: 0,
            recipient_public_key: [0u8; 32],
            nonce: [0u8; 12],
            ciphertext: vec![0u8; crate::event_modules::key_history::KEY_HISTORY_BUNDLE_BYTES],
            auth_tag: [0u8; 16],
        }
    }

    #[test]
    fn file_slice_descriptor_purge_used_when_owner_absent() {
        let guards = FileSliceGuardFacts {
            purge_owner_event_id: None,
            purge_descriptor_message_id: Some("desc-msg".into()),
            ..Default::default()
        };
        let d = decide_file_slice(&file_slice_event(), &FileSliceDepFacts::default(), &guards);
        match d {
            FileSliceDecision::Ready {
                purge_message_event_id,
            } => {
                assert_eq!(purge_message_event_id.as_deref(), Some("desc-msg"));
            }
        }
    }

    #[test]
    fn key_history_no_unwrap_when_no_local_key() {
        let event = empty_key_history_event();
        let d = decide_key_history(
            &event,
            &KeyHistoryDepFacts::default(),
            &KeyHistoryGuardFacts::default(),
        );
        assert!(matches!(d, KeyHistoryDecision::NoUnwrap));
        assert!(d.into_material().is_empty());
    }

    #[test]
    fn key_history_no_unwrap_when_sender_missing() {
        let event = empty_key_history_event();
        let guards = KeyHistoryGuardFacts {
            local_recipient_signing_key: Some(test_signing_key(1)),
            sender_verifying_key: None,
        };
        let d = decide_key_history(&event, &KeyHistoryDepFacts::default(), &guards);
        assert!(matches!(d, KeyHistoryDecision::NoUnwrap));
    }

    #[test]
    fn key_history_no_unwrap_on_decrypt_failure() {
        // Provide both keys but a bogus ciphertext/auth_tag so decrypt fails.
        let event = empty_key_history_event();
        let guards = KeyHistoryGuardFacts {
            local_recipient_signing_key: Some(test_signing_key(1)),
            sender_verifying_key: Some(test_signing_key(2).verifying_key()),
        };
        let d = decide_key_history(&event, &KeyHistoryDepFacts::default(), &guards);
        assert!(matches!(d, KeyHistoryDecision::NoUnwrap));
    }
}
