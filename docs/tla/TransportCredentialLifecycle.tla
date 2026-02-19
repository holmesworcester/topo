---- MODULE TransportCredentialLifecycle ----
EXTENDS FiniteSets

\* Standalone TLA+ model of the runtime transport credential and trust store.
\*
\* This module models the layer BELOW EventGraphSchema: actual SPKI credentials
\* held by peers and the materialized trust store that determines who can
\* authenticate over mTLS.
\*
\* EventGraphSchema models trust at the event-graph level (TrustedPeerSet,
\* peerSharedTrustPeer, bootstrapTrustPeer, pendingBootstrapTrustPeer).
\* This module models the runtime realization: concrete SPKI fingerprints,
\* credential generation (event-derived, no rotation), and the three-source
\* trust union (PeerShared-derived SPKIs ∪ invite_bootstrap_trust ∪
\* pending_invite_bootstrap_trust).
\*
\* POC simplification (TODO 11): each peer holds exactly one credential for its
\* lifetime, derived deterministically from its PeerShared Ed25519 signing key.
\* No rotation or revocation machinery exists in this POC model.
\*
\* Trust-source inputs (AddPeerSharedTrust, AddBootstrapTrust,
\* AddPendingBootstrapTrust) are modeled as nondeterministic, abstracting
\* over the event graph.
\*
\* Invite ownership: inviteCreator tracks which peer created each invite SPKI.
\* Pending bootstrap trust may only be added by the invite creator (inviter).
\* This prevents the joiner from materializing inviter-side pending trust when
\* syncing the invite event — a bug caught during eventization review.
\*
\* Rust mapping:
\*   localCred              → install_peer_key_transport_identity() active cert SPKI
\*   peerSharedTrust        → PeerShared-derived SPKIs (peer_shared_spki_fingerprints())
\*   bootstrapTrust         → invite_bootstrap_trust (non-expired, non-superseded)
\*   pendingBootstrapTrust  → pending_invite_bootstrap_trust (non-expired, non-superseded)
\*   inviteCreator          → is_local_create check on UserInviteBoot/DeviceInviteFirst
\*
\* CONSTANTS:
\*   Peers — set of peer identifiers
\*   SPKIs — set of abstract SPKI fingerprint values

CONSTANTS Peers, SPKIs

VARIABLES localCred, peerSharedTrust, bootstrapTrust, pendingBootstrapTrust, inviteCreator

vars == <<localCred, peerSharedTrust, bootstrapTrust, pendingBootstrapTrust, inviteCreator>>

\* ---- Helper: "none" sentinel for absent credential ----
None == "none"

\* ---- Derived operators ----

\* Union of all three trust sources for a peer.
\* Mirrors allowed_peers_from_db(): PeerShared_SPKIs ∪ bootstrap ∪ pending.
TrustedSPKIs(p) ==
    peerSharedTrust[p] \union bootstrapTrust[p] \union pendingBootstrapTrust[p]

\* Whether peer p can authenticate peer q's current credential.
\* Mirrors is_peer_allowed() (database path, excluding CLI pins).
\*
\* Rust note (collapse-single-tenant): on multi-tenant nodes, inbound (server)
\* connections use a union gate (accept if ANY tenant trusts q), but post-handshake
\* routing binds the session to the specific tenant p that trusts q.  Outbound
\* (client) connections use per-tenant workspace_client_config which enforces
\* exactly this per-peer CanAuthenticate check at the TLS layer.
CanAuthenticate(p, q) ==
    /\ localCred[q] # None
    /\ localCred[q] \in TrustedSPKIs(p)

\* All SPKIs currently in use as active credentials.
AllActiveCredentials == {localCred[p] : p \in Peers} \ {None}

\* ---- Type invariant ----

TypeOK ==
    /\ \A p \in Peers :
        /\ localCred[p] \in SPKIs \union {None}
        /\ peerSharedTrust[p] \subseteq SPKIs
        /\ bootstrapTrust[p] \subseteq SPKIs
        /\ pendingBootstrapTrust[p] \subseteq SPKIs
    /\ inviteCreator \in [SPKIs -> Peers \union {None}]

\* ---- Init ----

Init ==
    /\ localCred = [p \in Peers |-> None]
    /\ peerSharedTrust = [p \in Peers |-> {}]
    /\ bootstrapTrust = [p \in Peers |-> {}]
    /\ pendingBootstrapTrust = [p \in Peers |-> {}]
    /\ inviteCreator = [s \in SPKIs |-> None]

\* ---- Actions ----

\* 1. GenerateCredential(p, s)
\*    Event-derived credential: deterministic cert from PeerShared signing key.
\*    Rust: install_peer_key_transport_identity().
\*    Guard: no active credential, SPKI never used by any peer (freshness).
\*    POC: credentials are permanent — no rotation action exists.
GenerateCredential(p, s) ==
    /\ localCred[p] = None
    /\ s \notin AllActiveCredentials
    /\ localCred' = [localCred EXCEPT ![p] = s]
    /\ UNCHANGED <<peerSharedTrust, bootstrapTrust, pendingBootstrapTrust, inviteCreator>>

\* 2. AddPeerSharedTrust(p, s)
\*    Steady-state trust derived from a valid PeerShared event.
\*    Automatically supersedes matching bootstrap and pending bootstrap entries.
\*    Rust: peer_shared_spki_fingerprints() + supersede_*_if_peer_shared_trust_exists().
AddPeerSharedTrust(p, s) ==
    /\ s \in SPKIs
    /\ s \notin peerSharedTrust[p]
    /\ peerSharedTrust' = [peerSharedTrust EXCEPT ![p] = @ \union {s}]
    \* Supersede: remove from bootstrap and pending if present
    /\ bootstrapTrust' = [bootstrapTrust EXCEPT ![p] = @ \ {s}]
    /\ pendingBootstrapTrust' = [pendingBootstrapTrust EXCEPT ![p] = @ \ {s}]
    /\ UNCHANGED <<localCred, inviteCreator>>

\* 3. AddBootstrapTrust(p, s)
\*    Accepted invite bootstrap trust (joiner side).
\*    Blocked if SPKI already has steady-state PeerShared-derived trust.
\*    Rust: record_invite_bootstrap_trust().
AddBootstrapTrust(p, s) ==
    /\ s \in SPKIs
    /\ s \notin peerSharedTrust[p]
    /\ s \notin bootstrapTrust[p]
    /\ bootstrapTrust' = [bootstrapTrust EXCEPT ![p] = @ \union {s}]
    /\ UNCHANGED <<localCred, peerSharedTrust, pendingBootstrapTrust, inviteCreator>>

\* 4a. CreateInvite(p, s)
\*    Inviter creates an invite, establishing ownership of the invite SPKI.
\*    Must happen before AddPendingBootstrapTrust for this SPKI.
\*    Rust: create_user_invite / create_device_link_invite (local create).
CreateInvite(p, s) ==
    /\ s \in SPKIs
    /\ inviteCreator[s] = None
    /\ inviteCreator' = [inviteCreator EXCEPT ![s] = p]
    /\ UNCHANGED <<localCred, peerSharedTrust, bootstrapTrust, pendingBootstrapTrust>>

\* 4b. AddPendingBootstrapTrust(p, s)
\*    Inviter-side pending bootstrap trust.
\*    CRITICAL: Only the invite creator may add pending trust for this SPKI.
\*    Blocked if SPKI already has steady-state PeerShared-derived trust.
\*    Rust: record_pending_invite_bootstrap_trust() gated by is_local_create.
AddPendingBootstrapTrust(p, s) ==
    /\ s \in SPKIs
    /\ inviteCreator[s] = p   \* Only the inviter can add pending trust
    /\ s \notin peerSharedTrust[p]
    /\ s \notin pendingBootstrapTrust[p]
    /\ pendingBootstrapTrust' = [pendingBootstrapTrust EXCEPT ![p] = @ \union {s}]
    /\ UNCHANGED <<localCred, peerSharedTrust, bootstrapTrust, inviteCreator>>

\* 5. ExpireBootstrapTrust(p, s)
\*    TTL expiry of accepted bootstrap trust.
\*    Rust: expires_at > now filter in allowed_peers_from_db().
ExpireBootstrapTrust(p, s) ==
    /\ s \in bootstrapTrust[p]
    /\ bootstrapTrust' = [bootstrapTrust EXCEPT ![p] = @ \ {s}]
    /\ UNCHANGED <<localCred, peerSharedTrust, pendingBootstrapTrust, inviteCreator>>

\* 6. ExpirePendingBootstrapTrust(p, s)
\*    TTL expiry of pending bootstrap trust.
\*    Rust: expires_at > now filter in allowed_peers_from_db().
ExpirePendingBootstrapTrust(p, s) ==
    /\ s \in pendingBootstrapTrust[p]
    /\ pendingBootstrapTrust' = [pendingBootstrapTrust EXCEPT ![p] = @ \ {s}]
    /\ UNCHANGED <<localCred, peerSharedTrust, bootstrapTrust, inviteCreator>>

\* 7. RemovePeerSharedTrust(p, s)
\*    Removal of steady-state trust (e.g. peer_removed projection).
\*    Rust: cascading from removal projection (PeerShared excluded via removed_entities).
RemovePeerSharedTrust(p, s) ==
    /\ s \in peerSharedTrust[p]
    /\ peerSharedTrust' = [peerSharedTrust EXCEPT ![p] = @ \ {s}]
    /\ UNCHANGED <<localCred, bootstrapTrust, pendingBootstrapTrust, inviteCreator>>

\* ---- Next-state relation ----

Next ==
    \/ \E p \in Peers, s \in SPKIs :
        \/ GenerateCredential(p, s)
        \/ AddPeerSharedTrust(p, s)
        \/ AddBootstrapTrust(p, s)
        \/ CreateInvite(p, s)
        \/ AddPendingBootstrapTrust(p, s)
        \/ ExpireBootstrapTrust(p, s)
        \/ ExpirePendingBootstrapTrust(p, s)
        \/ RemovePeerSharedTrust(p, s)

\* ---- Specification ----

Spec == Init /\ [][Next]_vars

\* ---- Invariants ----

\* Inv1: No SPKI collision across peers (follows from deterministic derivation).
InvSPKIUniqueness ==
    \A p, q \in Peers :
        /\ p # q
        /\ localCred[p] # None
        /\ localCred[q] # None
        => localCred[p] # localCred[q]

\* Inv2: Bootstrap trust is disjoint from PeerShared-derived trust (supersession invariant).
\* Mirrors InvBootstrapTrustConsumedByPeerShared from EventGraphSchema.
InvBootstrapConsumedByPeerShared ==
    \A p \in Peers :
        bootstrapTrust[p] \intersect peerSharedTrust[p] = {}

\* Inv3: Pending bootstrap trust is disjoint from PeerShared-derived trust.
InvPendingConsumedByPeerShared ==
    \A p \in Peers :
        pendingBootstrapTrust[p] \intersect peerSharedTrust[p] = {}

\* Inv4: TrustedSPKIs is exactly the union of the three sources.
InvTrustSetIsExactUnion ==
    \A p \in Peers :
        TrustedSPKIs(p) = peerSharedTrust[p] \union bootstrapTrust[p] \union pendingBootstrapTrust[p]

\* Inv5: All trust sets contain only valid SPKIs.
InvTrustSourcesWellFormed ==
    \A p \in Peers :
        /\ peerSharedTrust[p] \subseteq SPKIs
        /\ bootstrapTrust[p] \subseteq SPKIs
        /\ pendingBootstrapTrust[p] \subseteq SPKIs

\* Inv6: Mutual authentication requires both peers to have active credentials.
InvMutualAuthSymmetry ==
    \A p, q \in Peers :
        (CanAuthenticate(p, q) /\ CanAuthenticate(q, p))
        => (localCred[p] # None /\ localCred[q] # None)

\* Inv7: Pending bootstrap trust can only exist on the invite creator's trust store.
\* This catches the joiner-side pending trust emission bug: if a joiner syncs a
\* UserInviteBoot event and the projector emits WritePendingBootstrapTrust without
\* checking is_local_create, the joiner's trust store gets a pending trust row that
\* should only exist on the inviter side.
\*
\* Rust check: is_local_create flag in ContextSnapshot gates WritePendingBootstrapTrust
\* emission in UserInviteBoot and DeviceInviteFirst projectors.
InvPendingTrustOnlyOnInviter ==
    \A p \in Peers, s \in SPKIs :
        s \in pendingBootstrapTrust[p] => inviteCreator[s] = p

====
