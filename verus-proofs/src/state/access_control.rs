//! System-level invariant: a peer that has not been invited to a workspace
//! cannot decrypt messages belonging to that workspace.
//!
//! This is a SCAFFOLD. The top-level composition `non_invited_cannot_decrypt`
//! is SMT-proven here. It composes four projector lemmas that are currently
//! axiomatized (`#[verifier::external_body]`) — each corresponds one-to-one
//! with a TLA invariant already checked by TLC:
//!
//! - `lemma_decrypt_requires_secret`               ↔ TLA `InvEncryptedKey`
//! - `lemma_secret_requires_secret_shared`         ↔ TLA `InvSecretSharedKey`
//! - `lemma_secret_shared_requires_peer_shared`    ↔ TLA `InvPeerSharedTrustSource`
//! - `lemma_peer_shared_requires_invite_accepted`  ↔ TLA `InvTrustedPeerSetMembers`
//!
//! Turning each axiom into a Verus-proven lemma against the real runtime
//! projector is the stage-3/4 work described in the access-control roadmap.
//! This file makes the top-level theorem statable and SMT-checks the
//! composition — so a future PR that discharges one lemma automatically
//! strengthens the overall chain, without restating the top-level proof.

use vstd::prelude::*;

verus! {

// ---------------------------------------------------------------------------
// Abstract event graph — minimal slice needed for the access-control chain.
// The real runtime has richer types; this is a spec-level projection.

pub type PeerId = nat;
pub type WorkspaceId = nat;
pub type EventId = nat;

#[derive(PartialEq, Eq)]
pub enum EventKind {
    Workspace,
    UserInvite,
    InviteAccepted,
    PeerShared,
    Secret,
    SecretShared,
    Encrypted,
    Message,
    Other,
}

pub struct Event {
    pub id: EventId,
    pub kind: EventKind,
    pub workspace: WorkspaceId,
    /// For SecretShared / InviteAccepted: the peer this event targets.
    pub recipient: Option<PeerId>,
    /// For Encrypted: id of the Secret it was encrypted under.
    pub encrypted_under: Option<EventId>,
    /// For SecretShared: id of the Secret it wraps.
    pub wraps_secret: Option<EventId>,
    /// For SecretShared: id of the PeerShared that authenticated the recipient.
    pub via_peer_shared: Option<EventId>,
    /// For PeerShared: id of the InviteAccepted that established the peer's membership.
    pub via_invite_accepted: Option<EventId>,
}

pub struct PeerState {
    pub peer: PeerId,
    pub valid: Set<EventId>,
    pub events: Map<EventId, Event>,
    /// Content events this peer has decrypted plaintext for.
    pub decrypted: Set<EventId>,
}

// ---------------------------------------------------------------------------
// Spec predicates.

pub open spec fn is_invited_to(state: PeerState, ws: WorkspaceId) -> bool {
    exists|ia: EventId|
        #[trigger] state.valid.contains(ia)
        && state.events.dom().contains(ia)
        && state.events[ia].kind == EventKind::InviteAccepted
        && state.events[ia].workspace == ws
        && state.events[ia].recipient == Some::<PeerId>(state.peer)
}

pub open spec fn message_belongs_to_workspace(
    state: PeerState,
    msg_id: EventId,
    ws: WorkspaceId,
) -> bool {
    state.events.dom().contains(msg_id)
    && state.events[msg_id].workspace == ws
}

pub open spec fn can_decrypt(state: PeerState, msg_id: EventId) -> bool {
    state.valid.contains(msg_id) && state.decrypted.contains(msg_id)
}

pub open spec fn system_invariant(state: PeerState) -> bool {
    forall|m: EventId, ws: WorkspaceId|
        #[trigger] message_belongs_to_workspace(state, m, ws)
            && !is_invited_to(state, ws)
            ==> !can_decrypt(state, m)
}

// ---------------------------------------------------------------------------
// Projector lemmas — axiomatized. Each encodes one TLA invariant. Proving
// them is stage-3/4 work; every discharge tightens the trust surface by one.

/// L1 (TLA `InvEncryptedKey`): decrypting a content event implies the Secret
/// it was encrypted under is Valid for this peer AND shares the same workspace.
#[verifier::external_body]
pub proof fn lemma_decrypt_requires_secret(state: PeerState, msg_id: EventId) -> (secret_id: EventId)
    requires
        can_decrypt(state, msg_id),
        state.events.dom().contains(msg_id),
    ensures
        state.valid.contains(secret_id),
        state.events.dom().contains(secret_id),
        state.events[secret_id].kind == EventKind::Secret,
        state.events[secret_id].workspace == state.events[msg_id].workspace,
{
    unimplemented!()
}

/// L2 (TLA `InvSecretSharedKey`): a Valid Secret for this peer (with plaintext
/// available) implies a Valid SecretShared that wraps it and targets this peer.
#[verifier::external_body]
pub proof fn lemma_secret_requires_secret_shared(
    state: PeerState,
    secret_id: EventId,
) -> (ss_id: EventId)
    requires
        state.valid.contains(secret_id),
        state.events.dom().contains(secret_id),
        state.events[secret_id].kind == EventKind::Secret,
    ensures
        state.valid.contains(ss_id),
        state.events.dom().contains(ss_id),
        state.events[ss_id].kind == EventKind::SecretShared,
        state.events[ss_id].recipient == Some::<PeerId>(state.peer),
        state.events[ss_id].workspace == state.events[secret_id].workspace,
        state.events[ss_id].via_peer_shared.is_some(),
{
    unimplemented!()
}

/// L3 (TLA `InvPeerSharedTrustSource`): SecretShared's authenticator is a
/// Valid PeerShared in the same workspace for this peer.
#[verifier::external_body]
pub proof fn lemma_secret_shared_requires_peer_shared(
    state: PeerState,
    ss_id: EventId,
) -> (ps_id: EventId)
    requires
        state.valid.contains(ss_id),
        state.events.dom().contains(ss_id),
        state.events[ss_id].kind == EventKind::SecretShared,
        state.events[ss_id].recipient == Some::<PeerId>(state.peer),
        state.events[ss_id].via_peer_shared.is_some(),
    ensures
        state.valid.contains(ps_id),
        state.events.dom().contains(ps_id),
        state.events[ps_id].kind == EventKind::PeerShared,
        state.events[ps_id].recipient == Some::<PeerId>(state.peer),
        state.events[ps_id].workspace == state.events[ss_id].workspace,
        state.events[ps_id].via_invite_accepted.is_some(),
{
    unimplemented!()
}

/// L4 (TLA `InvTrustedPeerSetMembers`): PeerShared derives from a Valid
/// InviteAccepted for this peer in the same workspace.
#[verifier::external_body]
pub proof fn lemma_peer_shared_requires_invite_accepted(
    state: PeerState,
    ps_id: EventId,
) -> (ia_id: EventId)
    requires
        state.valid.contains(ps_id),
        state.events.dom().contains(ps_id),
        state.events[ps_id].kind == EventKind::PeerShared,
        state.events[ps_id].recipient == Some::<PeerId>(state.peer),
        state.events[ps_id].via_invite_accepted.is_some(),
    ensures
        state.valid.contains(ia_id),
        state.events.dom().contains(ia_id),
        state.events[ia_id].kind == EventKind::InviteAccepted,
        state.events[ia_id].recipient == Some::<PeerId>(state.peer),
        state.events[ia_id].workspace == state.events[ps_id].workspace,
{
    unimplemented!()
}

// ---------------------------------------------------------------------------
// Top-level composition: SMT-proven from L1..L4.

pub proof fn non_invited_cannot_decrypt(
    state: PeerState,
    ws: WorkspaceId,
    msg_id: EventId,
)
    requires
        message_belongs_to_workspace(state, msg_id, ws),
        !is_invited_to(state, ws),
    ensures
        !can_decrypt(state, msg_id),
{
    if can_decrypt(state, msg_id) {
        // Chain L1..L4 to extract an InviteAccepted witness.
        let secret_id = lemma_decrypt_requires_secret(state, msg_id);
        let ss_id = lemma_secret_requires_secret_shared(state, secret_id);
        let ps_id = lemma_secret_shared_requires_peer_shared(state, ss_id);
        let ia_id = lemma_peer_shared_requires_invite_accepted(state, ps_id);

        // Workspace identity propagates through the chain. Hand these to SMT
        // so it sees `state.events[ia_id].workspace == ws`.
        assert(state.events[msg_id].workspace == ws);
        assert(state.events[secret_id].workspace == ws);
        assert(state.events[ss_id].workspace == ws);
        assert(state.events[ps_id].workspace == ws);
        assert(state.events[ia_id].workspace == ws);

        // `ia_id` witnesses the existential in `is_invited_to`.
        assert(is_invited_to(state, ws));

        // Contradicts the precondition.
        assert(false);
    }
}

/// Top-level system invariant — a single flat `forall` over (message, workspace)
/// pairs. Delegates to `non_invited_cannot_decrypt` per witness.
pub proof fn system_invariant_holds(state: PeerState)
    ensures
        system_invariant(state),
{
    assert forall|m: EventId, ws: WorkspaceId|
        #[trigger] message_belongs_to_workspace(state, m, ws)
            && !is_invited_to(state, ws)
            implies !can_decrypt(state, m) by {
        non_invited_cannot_decrypt(state, ws, m);
    };
}

} // verus!
