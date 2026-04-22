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
    AdminEvent, DeviceInviteEvent, InviteAcceptedEvent, PeerSharedEvent,
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
}
