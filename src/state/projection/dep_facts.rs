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
    KeyRotationEvent, PeerSharedEvent,
};
use crate::projection::projector::{
    BootstrapDecisionContext, HistoricalKeyMaterial, RemovalTargetKind, UnwrappedSecretMaterial,
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
