---- MODULE TransportCredentialLifecycle ----
EXTENDS FiniteSets

\* Standalone TLA+ model of the runtime transport credential and trust store.
\*
\* This module models the layer BELOW EventGraphSchema: actual SPKI credentials
\* held by peers and the materialized trust store that determines who can
\* authenticate over mTLS.
\*
\* EventGraphSchema models trust at the event-graph level (TrustedPeerSet,
\* transportKeyTrustPeer, bootstrapTrustPeer, pendingBootstrapTrustPeer).
\* This module models the runtime realization: concrete SPKI fingerprints,
\* credential generation/rotation/revocation, and the three-source trust
\* union (transport_keys ∪ invite_bootstrap_trust ∪ pending_invite_bootstrap_trust).
\*
\* Trust-source inputs (AddTransportKeyTrust, AddBootstrapTrust,
\* AddPendingBootstrapTrust) are modeled as nondeterministic, abstracting
\* over the event graph — following the same pattern BootstrapGraph uses
\* for its standalone concrete model.
\*
\* Rust mapping:
\*   localCred              → load_or_generate_cert() active cert SPKI
\*   localCredHistory       → all SPKIs a peer has ever held
\*   localCredRevoked       → explicitly revoked SPKIs
\*   transportKeyTrust      → transport_keys table rows
\*   bootstrapTrust         → invite_bootstrap_trust (non-expired, non-superseded)
\*   pendingBootstrapTrust  → pending_invite_bootstrap_trust (non-expired, non-superseded)
\*
\* CONSTANTS:
\*   Peers — set of peer identifiers
\*   SPKIs — set of abstract SPKI fingerprint values

CONSTANTS Peers, SPKIs

VARIABLES localCred, localCredHistory, localCredRevoked,
          transportKeyTrust, bootstrapTrust, pendingBootstrapTrust

vars == <<localCred, localCredHistory, localCredRevoked,
          transportKeyTrust, bootstrapTrust, pendingBootstrapTrust>>

\* ---- Helper: "none" sentinel for absent credential ----
None == "none"

\* ---- Derived operators ----

\* Union of all three trust sources for a peer.
\* Mirrors allowed_peers_from_db(): transport_keys ∪ bootstrap ∪ pending.
TrustedSPKIs(p) ==
    transportKeyTrust[p] \union bootstrapTrust[p] \union pendingBootstrapTrust[p]

\* Whether peer p can authenticate peer q's current credential.
\* Mirrors is_peer_allowed() (database path, excluding CLI pins).
CanAuthenticate(p, q) ==
    /\ localCred[q] # None
    /\ localCred[q] \in TrustedSPKIs(p)

\* All SPKIs currently in use as active credentials.
AllActiveCredentials == {localCred[p] : p \in Peers} \ {None}

\* ---- Type invariant ----

TypeOK ==
    /\ \A p \in Peers :
        /\ localCred[p] \in SPKIs \union {None}
        /\ localCredHistory[p] \subseteq SPKIs
        /\ localCredRevoked[p] \subseteq SPKIs
        /\ transportKeyTrust[p] \subseteq SPKIs
        /\ bootstrapTrust[p] \subseteq SPKIs
        /\ pendingBootstrapTrust[p] \subseteq SPKIs

\* ---- Init ----

Init ==
    /\ localCred = [p \in Peers |-> None]
    /\ localCredHistory = [p \in Peers |-> {}]
    /\ localCredRevoked = [p \in Peers |-> {}]
    /\ transportKeyTrust = [p \in Peers |-> {}]
    /\ bootstrapTrust = [p \in Peers |-> {}]
    /\ pendingBootstrapTrust = [p \in Peers |-> {}]

\* ---- Actions ----

\* 1. GenerateCredential(p, s)
\*    First credential generation when peer has none.
\*    Rust: load_or_generate_cert() generate path.
\*    Guard: no active credential, SPKI never used by any peer (freshness).
GenerateCredential(p, s) ==
    /\ localCred[p] = None
    /\ s \notin UNION {localCredHistory[q] : q \in Peers}
    /\ localCred' = [localCred EXCEPT ![p] = s]
    /\ localCredHistory' = [localCredHistory EXCEPT ![p] = @ \union {s}]
    /\ UNCHANGED <<localCredRevoked, transportKeyTrust, bootstrapTrust, pendingBootstrapTrust>>

\* 2. RotateCredential(p, s)
\*    Replace active credential with a fresh SPKI.
\*    Rust: future cert rotation + new TransportKey event.
\*    Guard: has active credential, new SPKI never used by any peer.
RotateCredential(p, s) ==
    /\ localCred[p] # None
    /\ s \notin UNION {localCredHistory[q] : q \in Peers}
    /\ localCred' = [localCred EXCEPT ![p] = s]
    /\ localCredHistory' = [localCredHistory EXCEPT ![p] = @ \union {s}]
    /\ UNCHANGED <<localCredRevoked, transportKeyTrust, bootstrapTrust, pendingBootstrapTrust>>

\* 3. RevokeCredential(p, s)
\*    Mark a non-active historical SPKI as revoked.
\*    Rust: future revocation event processing.
\*    Guard: s in history, s is not the active credential.
\*    Also cleans up bootstrap/pending trust for the revoked SPKI (revocation
\*    invalidates trust, mirroring how a revocation event would update the
\*    trust store).
RevokeCredential(p, s) ==
    /\ s \in localCredHistory[p]
    /\ s # localCred[p]
    /\ s \notin localCredRevoked[p]
    /\ localCredRevoked' = [localCredRevoked EXCEPT ![p] = @ \union {s}]
    /\ bootstrapTrust' = [bootstrapTrust EXCEPT ![p] = @ \ {s}]
    /\ pendingBootstrapTrust' = [pendingBootstrapTrust EXCEPT ![p] = @ \ {s}]
    /\ UNCHANGED <<localCred, localCredHistory, transportKeyTrust>>

\* 4. AddTransportKeyTrust(p, s)
\*    Steady-state trust from a valid TransportKey event.
\*    Automatically supersedes matching bootstrap and pending bootstrap entries.
\*    Rust: project_transport_key() + supersede_*_if_steady_trust_exists().
AddTransportKeyTrust(p, s) ==
    /\ s \in SPKIs
    /\ s \notin transportKeyTrust[p]
    /\ transportKeyTrust' = [transportKeyTrust EXCEPT ![p] = @ \union {s}]
    \* Supersede: remove from bootstrap and pending if present
    /\ bootstrapTrust' = [bootstrapTrust EXCEPT ![p] = @ \ {s}]
    /\ pendingBootstrapTrust' = [pendingBootstrapTrust EXCEPT ![p] = @ \ {s}]
    /\ UNCHANGED <<localCred, localCredHistory, localCredRevoked>>

\* 5. AddBootstrapTrust(p, s)
\*    Accepted invite bootstrap trust.
\*    Blocked if SPKI already has steady-state transport-key trust or is revoked.
\*    Rust: record_invite_bootstrap_trust().
AddBootstrapTrust(p, s) ==
    /\ s \in SPKIs
    /\ s \notin transportKeyTrust[p]
    /\ s \notin bootstrapTrust[p]
    /\ s \notin localCredRevoked[p]
    /\ bootstrapTrust' = [bootstrapTrust EXCEPT ![p] = @ \union {s}]
    /\ UNCHANGED <<localCred, localCredHistory, localCredRevoked, transportKeyTrust, pendingBootstrapTrust>>

\* 6. AddPendingBootstrapTrust(p, s)
\*    Inviter-side pending bootstrap trust.
\*    Blocked if SPKI already has steady-state transport-key trust or is revoked.
\*    Rust: record_pending_invite_bootstrap_trust().
AddPendingBootstrapTrust(p, s) ==
    /\ s \in SPKIs
    /\ s \notin transportKeyTrust[p]
    /\ s \notin pendingBootstrapTrust[p]
    /\ s \notin localCredRevoked[p]
    /\ pendingBootstrapTrust' = [pendingBootstrapTrust EXCEPT ![p] = @ \union {s}]
    /\ UNCHANGED <<localCred, localCredHistory, localCredRevoked, transportKeyTrust, bootstrapTrust>>

\* 7. ExpireBootstrapTrust(p, s)
\*    TTL expiry of accepted bootstrap trust.
\*    Rust: expires_at > now filter in allowed_peers_from_db().
ExpireBootstrapTrust(p, s) ==
    /\ s \in bootstrapTrust[p]
    /\ bootstrapTrust' = [bootstrapTrust EXCEPT ![p] = @ \ {s}]
    /\ UNCHANGED <<localCred, localCredHistory, localCredRevoked, transportKeyTrust, pendingBootstrapTrust>>

\* 8. ExpirePendingBootstrapTrust(p, s)
\*    TTL expiry of pending bootstrap trust.
\*    Rust: expires_at > now filter in allowed_peers_from_db().
ExpirePendingBootstrapTrust(p, s) ==
    /\ s \in pendingBootstrapTrust[p]
    /\ pendingBootstrapTrust' = [pendingBootstrapTrust EXCEPT ![p] = @ \ {s}]
    /\ UNCHANGED <<localCred, localCredHistory, localCredRevoked, transportKeyTrust, bootstrapTrust>>

\* 9. RemoveTransportKeyTrust(p, s)
\*    Removal of steady-state trust (e.g. peer_removed projection).
\*    Rust: cascading from removal projection.
RemoveTransportKeyTrust(p, s) ==
    /\ s \in transportKeyTrust[p]
    /\ transportKeyTrust' = [transportKeyTrust EXCEPT ![p] = @ \ {s}]
    /\ UNCHANGED <<localCred, localCredHistory, localCredRevoked, bootstrapTrust, pendingBootstrapTrust>>

\* ---- Next-state relation ----

Next ==
    \/ \E p \in Peers, s \in SPKIs :
        \/ GenerateCredential(p, s)
        \/ RotateCredential(p, s)
        \/ RevokeCredential(p, s)
        \/ AddTransportKeyTrust(p, s)
        \/ AddBootstrapTrust(p, s)
        \/ AddPendingBootstrapTrust(p, s)
        \/ ExpireBootstrapTrust(p, s)
        \/ ExpirePendingBootstrapTrust(p, s)
        \/ RemoveTransportKeyTrust(p, s)

\* ---- Specification ----

Spec == Init /\ [][Next]_vars

\* ---- Invariants ----

\* Inv1: Active credential is always in history.
InvActiveCredInHistory ==
    \A p \in Peers :
        localCred[p] # None => localCred[p] \in localCredHistory[p]

\* Inv2: Revoked set is a subset of history.
InvRevokedSubsetHistory ==
    \A p \in Peers :
        localCredRevoked[p] \subseteq localCredHistory[p]

\* Inv3: Active credential is never revoked.
InvActiveCredNotRevoked ==
    \A p \in Peers :
        localCred[p] # None => localCred[p] \notin localCredRevoked[p]

\* Inv4: No SPKI appears in two different peers' histories (collision resistance).
InvSPKIUniqueness ==
    \A p, q \in Peers :
        p # q => localCredHistory[p] \intersect localCredHistory[q] = {}

\* Inv5: Active SPKIs are distinct across peers (follows from Inv4 but stated explicitly).
InvActiveCredGloballyUnique ==
    \A p, q \in Peers :
        /\ p # q
        /\ localCred[p] # None
        /\ localCred[q] # None
        => localCred[p] # localCred[q]

\* Inv6: Bootstrap trust is disjoint from transport-key trust (supersession invariant).
\* Mirrors InvBootstrapTrustConsumedByTransportKey from EventGraphSchema.
InvBootstrapConsumedByTransportKey ==
    \A p \in Peers :
        bootstrapTrust[p] \intersect transportKeyTrust[p] = {}

\* Inv7: Pending bootstrap trust is disjoint from transport-key trust.
InvPendingConsumedByTransportKey ==
    \A p \in Peers :
        pendingBootstrapTrust[p] \intersect transportKeyTrust[p] = {}

\* Inv8: TrustedSPKIs is exactly the union of the three sources.
InvTrustSetIsExactUnion ==
    \A p \in Peers :
        TrustedSPKIs(p) = transportKeyTrust[p] \union bootstrapTrust[p] \union pendingBootstrapTrust[p]

\* Inv9: All trust sets contain only valid SPKIs.
InvTrustSourcesWellFormed ==
    \A p \in Peers :
        /\ transportKeyTrust[p] \subseteq SPKIs
        /\ bootstrapTrust[p] \subseteq SPKIs
        /\ pendingBootstrapTrust[p] \subseteq SPKIs

\* Inv10: Revoked SPKIs do not appear in bootstrap trust sources.
\* A revoked credential should not be trusted via temporary bootstrap paths.
InvRevokedNotInBootstrapTrust ==
    \A p \in Peers :
        /\ localCredRevoked[p] \intersect bootstrapTrust[p] = {}
        /\ localCredRevoked[p] \intersect pendingBootstrapTrust[p] = {}

\* Inv11: Mutual authentication requires both peers to have active credentials.
InvMutualAuthSymmetry ==
    \A p, q \in Peers :
        (CanAuthenticate(p, q) /\ CanAuthenticate(q, p))
        => (localCred[p] # None /\ localCred[q] # None)

====
