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
    AdminEvent, DeviceInviteEvent, InviteAcceptedEvent, PeerSharedEvent, WorkspaceEvent,
};
use crate::projection::projector::{BootstrapDecisionContext, RemovalTargetKind};

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
