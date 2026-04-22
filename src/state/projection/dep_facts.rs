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

use crate::projection::projector::BootstrapDecisionContext;

/// Typed summaries of immediate valid event dependencies.
///
/// Empty for events whose decision does not read anything off its deps
/// beyond their mere validity (e.g. `InviteAccepted` — `tenant_event_id`
/// is a dep-ordering constraint, not a semantic input). Kept as an
/// explicit parameter anyway so the dep-derivation step is uniform
/// across projectors and can grow without reshaping call sites.
#[derive(Debug, Clone, Default)]
pub struct DepFacts {}

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event_modules::InviteAcceptedEvent;

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
