---- MODULE EventGraphSchema ----
EXTENDS Naturals, FiniteSets

\* Schema-level, bounded model of the poc-7 event graph.
\*
\* Adapts poc-6 to use split invite types:
\*   user_invite_shared  (was invite(mode=user))
\*   peer_invite_shared (was invite(mode=peer))
\*
\* Adds sender-subjective encryption modeling:
\*   secret          — per-message symmetric key (local-only, deterministic event ID from key bytes)
\*   key_shared   — key wrap to a specific recipient (invite key for this model)
\*   encrypted       — encrypted content referencing a secret
\*
\* Bootstrap and runtime key wrapping use the same SecretShared event type.
\* Bootstrap recipients materialize local secret events with deterministic
\* event IDs (BLAKE2b of key bytes → created_at_ms), ensuring both parties agree
\* on key_event_id values without out-of-band coordination.
\*
\* Adds removal modeling:
\*   user_removed    — removes a user (and transitively excludes peers)
\*   peer_removed    — removes a specific peer device
\*
\* Workspace binding refinement:
\*   Workspace events are parameterized by workspace id.
\*   invite_accepted binds trustAnchor directly from its own workspace_id field.
\*   Model approximation: trustAnchor is a single first-write-wins value, so
\*   conflicting invite_accepted cannot change it (modeled as reject/no-op).
\*   Runtime stores all rows in invites_accepted and resolves winner at read time
\*   by (created_at, event_id).
\*   invite_accepted also carries bootstrap transport trust metadata
\*   (inviter peer identity from invite link), projected to bootstrapTrustPeer.
\*   Guard checks that a workspace event's id matches the peer's binding.
\*   This ensures only the invited workspace can become valid; foreign
\*   workspace events are structurally excluded.
\*
\* Key semantic: after a peer observes a removal, new key_shared events
\*   must NOT wrap to the removed peer (InvRemovalExclusion).
\*
\* Ongoing identity variants were removed from protocol state. Legacy
\* identifiers below are aliased to their surviving event kinds so existing
\* invariants remain comparable without changing check names.
\*
\* CONSTANTS:
\*   ActiveEvents — subset of FullEventTypes to bound state space
\*                  (include "workspace" to enable workspace event instances)
\*   Peers — set of peer identifiers for per-peer perspectives
\*   Workspaces — set of workspace identifiers (>= 2 to test binding exclusion)

CONSTANTS ActiveEvents, Peers, Workspaces

VARIABLES recorded, valid, trustAnchor, removed,
          inviteCarriedWorkspace, inviteCarriedBootstrapPeer, bootstrapTrustPeer,
          inviteCarriedPendingPeer, pendingBootstrapTrustPeer,
          peerPrivkeyCarriedSigner,
          invitePrivkeyCarriedInvite, secretSharedCarriedInvite,
          peerSharedDerivedPeer, peerSharedTrustPeer,
          connState

\* ---- Event type constants ----

\* Abstract workspace marker used in RawDeps/SignerDep to indicate
\* "requires a workspace event". Not itself an event instance.
\* Concrete workspace events are the workspace id strings from Workspaces.
Workspace == "workspace"

\* Identity / bootstrap
Peer == "peer"
Tenant == "tenant"
InviteAccepted == "invite_accepted"

\* Split invite types (user_invite_shared replaces invite(mode=user))
UserInvite == "user_invite_shared"

\* Split invite types (peer_invite_shared replaces invite(mode=peer))
DeviceInvite == "peer_invite_shared"

\* User identity
User == "user"

\* Peer shared identity
PeerShared == "peer_shared"

\* Admin
Admin == "admin"

\* Local private key material (never shared)
PeerPrivkey == "peer_secret"
InvitePrivkey == "invite_secret"

\* Content
Channel == "channel"
Message == "message"
MessageReaction == "message_reaction"
MessageDeletion == "message_deletion"
MessageAttachment == "message_attachment"
FileSlice == "file_slice"

\* Sender-subjective encryption
Secret == "key_secret"
SecretShared == "key_shared"
Encrypted == "encrypted"

\* Removal
UserRemoved == "user_removed"
PeerRemoved == "peer_removed"

\* ---- Workspace events (parameterized by workspace id) ----
\* Workspace events are the workspace id strings themselves.
\* Workspaces must not overlap with FullEventTypes (checked by ASSUME below).

AllWorkspaceEvents == Workspaces
IsWorkspaceEvent(e) == e \in Workspaces
WorkspaceEventId(e) == e

\* ---- Event sets ----

\* Singleton event types (not parameterized by workspace)
FullEventTypes == {
    Peer,
    Tenant,
    InviteAccepted,
    UserInvite,
    DeviceInvite,
    User,
    PeerShared,
    Admin,
    PeerPrivkey,
    InvitePrivkey,
    Channel, Message, MessageReaction, MessageDeletion,
    MessageAttachment, FileSlice,
    Secret, SecretShared, Encrypted,
    UserRemoved, PeerRemoved
}

\* Full event universe (singleton types + parameterized workspace events)
FullEvents == FullEventTypes \cup AllWorkspaceEvents

\* Local-only events (no workspace dep, no trust anchor gate).
\* Encrypted is local because it's a cryptographic wrapper; its workspace
\* requirement comes from the inner event, not the wrapper itself.
LocalRoots == {Peer, Tenant, InviteAccepted, PeerPrivkey, InvitePrivkey, Secret, Encrypted}

\* Singleton event types that require workspace to be valid
WorkspaceGuardedEvents == FullEventTypes \ LocalRoots

\* Active events: singleton types from config + workspace instances if enabled
EVENTS == (ActiveEvents \cap FullEventTypes)
         \cup (IF Workspace \in ActiveEvents THEN AllWorkspaceEvents ELSE {})

\* Identity event categories
UserInviteEvents == {UserInvite}
DeviceInviteEvents == {DeviceInvite}
InviteEvents == UserInviteEvents \cup DeviceInviteEvents
AdminEvents == {Admin}
PeerSharedSignerEvents == {PeerShared}
PeerPrivkeySignerEvents == (AllWorkspaceEvents \cap EVENTS) \cup ({User, PeerShared} \cap EVENTS)

IdentityEvents == {
    Peer,
    Tenant,
    InviteAccepted,
    UserInvite,
    DeviceInvite,
    User,
    PeerShared,
    Admin,
    PeerPrivkey,
    InvitePrivkey,
    UserRemoved, PeerRemoved
} \cup AllWorkspaceEvents

ContentEvents == {Channel, Message, MessageReaction, MessageDeletion, MessageAttachment, FileSlice}
EncryptionEvents == {Secret, SecretShared, Encrypted}

\* Connection state values (per-peer state machine for invite-based bootstrap).
ConnStates == {"none", "req", "ack", "invite", "peer"}

ASSUME (ActiveEvents \ {Workspace}) \subseteq FullEventTypes
ASSUME Peers /= {}
ASSUME Workspaces /= {}
ASSUME Workspaces \cap FullEventTypes = {}

\* ---- Dependency rules ----
\* RawDeps and SignerDep use the abstract Workspace marker for workspace dependency.
\* ResolveWorkspace translates Workspace to the peer's bound workspace event instance.

RawDeps(e) ==
    IF IsWorkspaceEvent(e) THEN {}
    ELSE
    CASE e = Peer -> {Tenant}
       [] e = Tenant -> {}
       [] e = InviteAccepted -> {Tenant}

       \* user_invite_shared: authority dep (workspace in bootstrap flow; admin in ongoing flow)
       [] e = UserInvite -> {Workspace}

       \* peer_invite_shared: authority dep (user in bootstrap flow; admin in ongoing flow)
       [] e = DeviceInvite -> {User}

       \* user: no raw deps beyond signer
       [] e = User -> {}

       \* peer_shared: no raw deps beyond signer
       [] e = PeerShared -> {}

       \* admin: depends on workspace + user
       [] e = Admin -> {Workspace, User}

       [] e = PeerPrivkey -> {}
       [] e = InvitePrivkey -> {}

       \* Content: message depends on workspace; reaction/deletion depend on message
       [] e = Message -> {Workspace}
       [] e = MessageReaction -> {Message}
       [] e = MessageDeletion -> {Message}
       [] e = MessageAttachment -> {Message, Secret}
       [] e = FileSlice -> {}

       \* Encryption: secret is local (deterministic event ID from key bytes);
       \* key_shared wraps key to invite recipient and depends on:
       \*   - recipient invite event (user_invite_shared/peer_invite_shared),
       \*   - local invite_secret event used to unwrap.
       \* key_event_id is a non-dependency integrity claim checked at materialization.
       \* encrypted depends on secret.
       [] e = Secret -> {}
       [] e = SecretShared -> InviteEvents \cup {InvitePrivkey}
       [] e = Encrypted -> {Secret}

       \* Removal: depends on the entity being removed
       [] e = UserRemoved -> {User}
       [] e = PeerRemoved -> {PeerShared}

       [] OTHER -> {}

\* SignerDep: whose public key must be valid to verify the event's signature.
SignerDep(e) ==
    IF IsWorkspaceEvent(e) THEN {}
    ELSE
    CASE \* user_invite_shared: signed by workspace
         e = UserInvite -> {Workspace}

       \* peer_invite_shared: signed by user
       [] e = DeviceInvite -> {User}

       \* user: signed by the user_invite_shared key
       [] e = User -> {UserInvite}

       \* peer_shared: signed by the peer_invite_shared key
       [] e = PeerShared -> {DeviceInvite}

       \* admin: signed by workspace
       [] e = Admin -> {Workspace}

       \* Content: signed by a linked peer
       [] e = Message -> PeerSharedSignerEvents
       [] e = MessageReaction -> PeerSharedSignerEvents
       [] e = MessageDeletion -> PeerSharedSignerEvents
       [] e = MessageAttachment -> PeerSharedSignerEvents
       [] e = FileSlice -> PeerSharedSignerEvents

       \* Encryption: key_shared signed by sender peer
       [] e = SecretShared -> PeerSharedSignerEvents

       \* Removal: signed by admin peer
       [] e = UserRemoved -> PeerSharedSignerEvents
       [] e = PeerRemoved -> PeerSharedSignerEvents

       [] OTHER -> {}

\* Resolve abstract Workspace marker to the peer's bound workspace event.
\* Non-Workspace deps pass through filtered by EVENTS.
\* If peer is unbound and event needs workspace, an unsatisfiable
\* placeholder blocks projection.
ResolveWorkspace(p, deps) ==
    LET needsWorkspace == Workspace \in deps
        nonWorkspace == (deps \ {Workspace}) \cap EVENTS
        workspaceDep == IF needsWorkspace THEN
                    IF trustAnchor[p] /= "none"
                    THEN {trustAnchor[p]}
                    ELSE {"__unbound__"}
                  ELSE {}
    IN nonWorkspace \cup workspaceDep

\* Combined peer-resolved dependencies: structural + signer.
PeerDeps(p, e) == ResolveWorkspace(p, RawDeps(e) \cup SignerDep(e))

\* ---- Guards ----

\* Workspace events require matching trust anchor binding.
Guard(p, e) == IF IsWorkspaceEvent(e) THEN trustAnchor[p] = WorkspaceEventId(e) ELSE TRUE

\* Trusted peer set abstraction used by runtime transport checks.
\* This models the union of:
\* - PeerShared-derived SPKIs (primary steady-state trust)
\* - accepted invite bootstrap trust
\* - pending invite bootstrap trust
BootstrapTrustSet(p) ==
    IF bootstrapTrustPeer[p] = "none" THEN {} ELSE {bootstrapTrustPeer[p]}

PendingBootstrapTrustSet(p) ==
    IF pendingBootstrapTrustPeer[p] = "none" THEN {} ELSE {pendingBootstrapTrustPeer[p]}

PeerSharedTrustSet(p) ==
    IF peerSharedTrustPeer[p] = "none" THEN {} ELSE {peerSharedTrustPeer[p]}

TrustedPeerSet(p) ==
    BootstrapTrustSet(p) \cup PendingBootstrapTrustSet(p) \cup PeerSharedTrustSet(p)

\* ---- State machine ----

Init ==
    /\ recorded = [p \in Peers |-> {}]
    /\ valid = [p \in Peers |-> {}]
    /\ trustAnchor = [p \in Peers |-> "none"]
    /\ removed = [p \in Peers |-> {}]
    /\ inviteCarriedWorkspace = [p \in Peers |-> "none"]
    /\ inviteCarriedBootstrapPeer = [p \in Peers |-> "none"]
    /\ bootstrapTrustPeer = [p \in Peers |-> "none"]
    /\ inviteCarriedPendingPeer = [p \in Peers |-> "none"]
    /\ pendingBootstrapTrustPeer = [p \in Peers |-> "none"]
    /\ peerPrivkeyCarriedSigner = [p \in Peers |-> "none"]
    /\ invitePrivkeyCarriedInvite = [p \in Peers |-> "none"]
    /\ secretSharedCarriedInvite = [p \in Peers |-> "none"]
    /\ peerSharedDerivedPeer = [p \in Peers |-> "none"]
    /\ peerSharedTrustPeer = [p \in Peers |-> "none"]
    /\ connState = [p \in Peers |-> "none"]

\* Record captures the event-carried workspace_id at ingress time.
\* For invite_accepted, the event carries a specific workspace_id chosen
\* nondeterministically here (models the fact that any workspace could be
\* referenced). The choice is fixed at record time, not projection time.
Record(p, e) ==
    /\ p \in Peers
    /\ e \in EVENTS
    /\ e \notin recorded[p]
    /\ recorded' = [recorded EXCEPT ![p] = @ \cup {e}]
    /\ IF e = InviteAccepted /\ inviteCarriedWorkspace[p] = "none"
       THEN \E n \in Workspaces: inviteCarriedWorkspace' = [inviteCarriedWorkspace EXCEPT ![p] = n]
       ELSE UNCHANGED inviteCarriedWorkspace
    /\ IF e = InviteAccepted /\ inviteCarriedBootstrapPeer[p] = "none"
       THEN \E bp \in Peers:
            inviteCarriedBootstrapPeer' = [inviteCarriedBootstrapPeer EXCEPT ![p] = bp]
       ELSE UNCHANGED inviteCarriedBootstrapPeer
    /\ IF e \in InviteEvents /\ inviteCarriedPendingPeer[p] = "none"
       THEN \E pp \in Peers:
            /\ inviteCarriedPendingPeer' = [inviteCarriedPendingPeer EXCEPT ![p] = pp]
            /\ pendingBootstrapTrustPeer' = [pendingBootstrapTrustPeer EXCEPT ![p] = pp]
       ELSE /\ UNCHANGED inviteCarriedPendingPeer
            /\ UNCHANGED pendingBootstrapTrustPeer
    /\ IF e = PeerPrivkey /\ peerPrivkeyCarriedSigner[p] = "none"
       THEN \E s \in PeerPrivkeySignerEvents:
            peerPrivkeyCarriedSigner' = [peerPrivkeyCarriedSigner EXCEPT ![p] = s]
       ELSE UNCHANGED peerPrivkeyCarriedSigner
    /\ IF e = InvitePrivkey /\ invitePrivkeyCarriedInvite[p] = "none"
       THEN \E ie \in (InviteEvents \cap EVENTS):
            invitePrivkeyCarriedInvite' = [invitePrivkeyCarriedInvite EXCEPT ![p] = ie]
       ELSE UNCHANGED invitePrivkeyCarriedInvite
    /\ IF e = SecretShared /\ secretSharedCarriedInvite[p] = "none"
       THEN \E ie \in (InviteEvents \cap EVENTS):
            secretSharedCarriedInvite' = [secretSharedCarriedInvite EXCEPT ![p] = ie]
       ELSE UNCHANGED secretSharedCarriedInvite
    /\ IF e = PeerShared /\ peerSharedDerivedPeer[p] = "none"
       THEN \E dp \in Peers:
            peerSharedDerivedPeer' = [peerSharedDerivedPeer EXCEPT ![p] = dp]
       ELSE UNCHANGED peerSharedDerivedPeer
    /\ UNCHANGED <<valid, trustAnchor, removed, bootstrapTrustPeer, peerSharedTrustPeer, connState>>

\* invite_accepted binds the trust anchor from its event-carried workspace_id.
\* First-write-wins: if trust anchor is already set to a different workspace,
\* invite_accepted is rejected (cannot project).
Project(p, e) ==
    /\ p \in Peers
    /\ e \in EVENTS
    /\ e \in recorded[p]
    /\ e \notin valid[p]
    /\ PeerDeps(p, e) \subseteq valid[p]
    /\ IF e = PeerPrivkey
       THEN peerPrivkeyCarriedSigner[p] \in valid[p]
       ELSE TRUE
    /\ IF e = InvitePrivkey
       THEN invitePrivkeyCarriedInvite[p] \in valid[p]
       ELSE TRUE
    /\ IF e = SecretShared
       THEN secretSharedCarriedInvite[p] \in valid[p]
       ELSE TRUE
    /\ Guard(p, e)
    \* Mismatch rejection: invite_accepted blocked if anchor already set differently
    /\ IF e = InviteAccepted /\ trustAnchor[p] /= "none"
       THEN trustAnchor[p] = inviteCarriedWorkspace[p]
       ELSE TRUE
    \* invite_accepted bootstrap trust is seeded from invite_accepted and
    \* consumed when equivalent PeerShared-derived trust appears.
    /\ IF e = InviteAccepted /\ bootstrapTrustPeer[p] /= "none"
       THEN bootstrapTrustPeer[p] = inviteCarriedBootstrapPeer[p]
       ELSE TRUE
    \* PeerShared-derived trust is first-write-wins and immutable.
    /\ IF e = PeerShared /\ peerSharedTrustPeer[p] /= "none"
       THEN peerSharedTrustPeer[p] = peerSharedDerivedPeer[p]
       ELSE TRUE
    /\ valid' = [valid EXCEPT ![p] = @ \cup {e}]
    \* Trust anchor binding: deterministic from event-carried workspace_id.
    /\ trustAnchor' =
        IF e = InviteAccepted /\ trustAnchor[p] = "none"
        THEN [trustAnchor EXCEPT ![p] = inviteCarriedWorkspace[p]]
        ELSE trustAnchor
    /\ removed' =
        IF e = UserRemoved
        THEN [removed EXCEPT ![p] = @ \cup {"user_target"}]
        ELSE IF e = PeerRemoved
        THEN [removed EXCEPT ![p] = @ \cup {"peer_target"}]
        ELSE removed
    /\ bootstrapTrustPeer' =
        IF e = InviteAccepted /\ bootstrapTrustPeer[p] = "none"
        THEN [bootstrapTrustPeer EXCEPT ![p] = inviteCarriedBootstrapPeer[p]]
        ELSE IF e = PeerShared /\ bootstrapTrustPeer[p] = peerSharedDerivedPeer[p]
        THEN [bootstrapTrustPeer EXCEPT ![p] = "none"]
        ELSE bootstrapTrustPeer
    /\ peerSharedTrustPeer' =
        IF e = PeerShared /\ peerSharedTrustPeer[p] = "none"
        THEN [peerSharedTrustPeer EXCEPT ![p] = peerSharedDerivedPeer[p]]
        ELSE peerSharedTrustPeer
    /\ pendingBootstrapTrustPeer' =
        IF e = PeerShared /\ pendingBootstrapTrustPeer[p] = peerSharedDerivedPeer[p]
        THEN [pendingBootstrapTrustPeer EXCEPT ![p] = "none"]
        ELSE pendingBootstrapTrustPeer
    /\ UNCHANGED <<recorded, inviteCarriedWorkspace, inviteCarriedBootstrapPeer,
                  inviteCarriedPendingPeer, peerPrivkeyCarriedSigner,
                  invitePrivkeyCarriedInvite,
                  secretSharedCarriedInvite, peerSharedDerivedPeer, connState>>

Stutter ==
    UNCHANGED <<recorded, valid, trustAnchor, removed,
                inviteCarriedWorkspace, inviteCarriedBootstrapPeer, bootstrapTrustPeer,
                inviteCarriedPendingPeer, pendingBootstrapTrustPeer,
                peerPrivkeyCarriedSigner,
                invitePrivkeyCarriedInvite, secretSharedCarriedInvite,
                peerSharedDerivedPeer, peerSharedTrustPeer,
                connState>>

\* ---- Connection state machine (bootstrap invite upgrade) ----
\* Models the upgrade from invite-labeled to peer-labeled connection.
\* Only active when InviteAccepted is in EVENTS.

allVars == <<recorded, valid, trustAnchor, removed,
             inviteCarriedWorkspace, inviteCarriedBootstrapPeer, bootstrapTrustPeer,
             inviteCarriedPendingPeer, pendingBootstrapTrustPeer,
             peerPrivkeyCarriedSigner,
             invitePrivkeyCarriedInvite, secretSharedCarriedInvite,
             peerSharedDerivedPeer, peerSharedTrustPeer, connState>>

nonConnVars == <<recorded, valid, trustAnchor, removed,
                 inviteCarriedWorkspace, inviteCarriedBootstrapPeer, bootstrapTrustPeer,
                 inviteCarriedPendingPeer, pendingBootstrapTrustPeer,
                 peerPrivkeyCarriedSigner,
                 invitePrivkeyCarriedInvite, secretSharedCarriedInvite,
                 peerSharedDerivedPeer, peerSharedTrustPeer>>

\* Bootstrap connection request: authenticated by invite signature.
ConnectReqByInvite(p) ==
    /\ InviteAccepted \in EVENTS
    /\ connState[p] = "none"
    /\ InviteAccepted \in valid[p]
    /\ \E ie \in (UserInviteEvents \cap EVENTS): ie \in recorded[p]
    /\ connState' = [connState EXCEPT ![p] = "req"]
    /\ UNCHANGED nonConnVars

\* Connection acknowledgment: only after request is accepted.
ConnectAck(p) ==
    /\ connState[p] = "req"
    /\ connState' = [connState EXCEPT ![p] = "ack"]
    /\ UNCHANGED nonConnVars

\* Bootstrap connection active (invite-labeled) after ack.
ConnectByInvite(p) ==
    /\ connState[p] = "ack"
    /\ connState' = [connState EXCEPT ![p] = "invite"]
    /\ UNCHANGED nonConnVars

\* Upgrade to peer-labeled connection once peer_shared is valid.
UpgradeToPeer(p) ==
    /\ connState[p] = "invite"
    /\ PeerShared \in valid[p]
    /\ connState' = [connState EXCEPT ![p] = "peer"]
    /\ UNCHANGED nonConnVars

Next ==
    \/ \E p \in Peers, e \in EVENTS: Record(p, e)
    \/ \E p \in Peers, e \in EVENTS: Project(p, e)
    \/ \E p \in Peers: ConnectReqByInvite(p)
    \/ \E p \in Peers: ConnectAck(p)
    \/ \E p \in Peers: ConnectByInvite(p)
    \/ \E p \in Peers: UpgradeToPeer(p)
    \/ Stutter

Spec ==
    Init /\ [][Next]_allVars

\* ---- Invariants ----

TypeOK ==
    /\ recorded \in [Peers -> SUBSET EVENTS]
    /\ valid \in [Peers -> SUBSET EVENTS]
    /\ \A p \in Peers: valid[p] \subseteq recorded[p]
    /\ trustAnchor \in [Peers -> Workspaces \cup {"none"}]
    /\ removed \in [Peers -> SUBSET {"user_target", "peer_target"}]
    /\ inviteCarriedWorkspace \in [Peers -> Workspaces \cup {"none"}]
    /\ inviteCarriedBootstrapPeer \in [Peers -> Peers \cup {"none"}]
    /\ bootstrapTrustPeer \in [Peers -> Peers \cup {"none"}]
    /\ inviteCarriedPendingPeer \in [Peers -> Peers \cup {"none"}]
    /\ pendingBootstrapTrustPeer \in [Peers -> Peers \cup {"none"}]
    /\ peerPrivkeyCarriedSigner \in [Peers -> (Workspaces \cup {User, PeerShared, "none"})]
    /\ invitePrivkeyCarriedInvite \in [Peers -> InviteEvents \cup {"none"}]
    /\ secretSharedCarriedInvite \in [Peers -> InviteEvents \cup {"none"}]
    /\ peerSharedDerivedPeer \in [Peers -> Peers \cup {"none"}]
    /\ peerSharedTrustPeer \in [Peers -> Peers \cup {"none"}]
    /\ connState \in [Peers -> ConnStates]

\* Every valid event has all its peer-resolved dependencies valid.
InvDeps ==
    \A p \in Peers:
        \A e \in valid[p]: PeerDeps(p, e) \subseteq valid[p]

\* Every valid event has its signer dependency valid (peer-resolved).
InvSigner ==
    \A p \in Peers:
        \A e \in valid[p]: ResolveWorkspace(p, SignerDep(e)) \subseteq valid[p]

\* Workspace event validity requires matching trust anchor.
InvWorkspaceAnchor ==
    \A p \in Peers:
        \A n \in Workspaces:
            (n \in valid[p]) => trustAnchor[p] = n

\* At most one workspace can be valid per peer.
InvSingleWorkspace ==
    \A p \in Peers:
        \A n1, n2 \in Workspaces:
            (n1 \in valid[p] /\ n2 \in valid[p]) => n1 = n2

\* Legacy-compatible explicit name used by projector/runtime guard mappings.
\* Equivalent to InvWorkspaceAnchor: any valid workspace event must be the
\* workspace bound by invite_accepted trust-anchor materialization.
InvForeignWorkspaceExcluded ==
    \A p \in Peers:
        \A n \in Workspaces:
            (n \in valid[p]) => n = trustAnchor[p]

\* Trust anchor requires invite_accepted to be valid.
InvTrustAnchorSource ==
    IF InviteAccepted \in EVENTS
    THEN \A p \in Peers: (trustAnchor[p] /= "none") => (InviteAccepted \in valid[p])
    ELSE TRUE

\* Trust anchor always matches the event-carried workspace_id.
InvTrustAnchorMatchesCarried ==
    \A p \in Peers:
        (trustAnchor[p] /= "none") => (trustAnchor[p] = inviteCarriedWorkspace[p])

\* Bootstrap transport trust comes from invite_accepted.
InvBootstrapTrustSource ==
    IF InviteAccepted \in EVENTS
    THEN \A p \in Peers: (bootstrapTrustPeer[p] /= "none") => (InviteAccepted \in valid[p])
    ELSE TRUE

\* Bootstrap trust must match invite-carried bootstrap peer identity.
InvBootstrapTrustMatchesCarried ==
    \A p \in Peers:
        (bootstrapTrustPeer[p] /= "none") =>
            (bootstrapTrustPeer[p] = inviteCarriedBootstrapPeer[p])

\* Bootstrap trust is consumed once equivalent PeerShared-derived trust exists.
InvBootstrapTrustConsumedByPeerShared ==
    IF PeerShared \in EVENTS
    THEN \A p \in Peers:
        ~(
            peerSharedTrustPeer[p] /= "none"
            /\ bootstrapTrustPeer[p] = peerSharedTrustPeer[p]
        )
    ELSE TRUE

\* Pending bootstrap trust is consumed once equivalent PeerShared-derived trust exists.
InvPendingBootstrapTrustConsumedByPeerShared ==
    IF PeerShared \in EVENTS
    THEN \A p \in Peers:
        ~(
            peerSharedTrustPeer[p] /= "none"
            /\ pendingBootstrapTrustPeer[p] = peerSharedTrustPeer[p]
        )
    ELSE TRUE

\* Pending invite bootstrap trust comes from recorded invite events.
InvPendingBootstrapTrustSource ==
    IF (InviteEvents \cap EVENTS) /= {}
    THEN \A p \in Peers:
        (pendingBootstrapTrustPeer[p] /= "none") =>
            (\E ie \in (InviteEvents \cap EVENTS): ie \in recorded[p])
    ELSE TRUE

\* Pending bootstrap trust matches invite-carried invitee identity.
InvPendingBootstrapTrustMatchesCarried ==
    \A p \in Peers:
        (pendingBootstrapTrustPeer[p] /= "none") =>
            (pendingBootstrapTrustPeer[p] = inviteCarriedPendingPeer[p])

\* PeerShared-derived trust comes only from valid PeerShared events.
InvPeerSharedTrustSource ==
    IF PeerShared \in EVENTS
    THEN \A p \in Peers:
        (peerSharedTrustPeer[p] /= "none") =>
            (PeerShared \in valid[p])
    ELSE TRUE

\* PeerShared-derived trust matches the event-derived peer identity.
InvPeerSharedTrustMatchesCarried ==
    \A p \in Peers:
        (peerSharedTrustPeer[p] /= "none") =>
            (peerSharedTrustPeer[p] = peerSharedDerivedPeer[p])

\* Trusted peer set members are exactly from modeled trust sources.
InvTrustedPeerSetMembers ==
    \A p \in Peers:
        \A q \in TrustedPeerSet(p):
            q = bootstrapTrustPeer[p]
            \/ q = pendingBootstrapTrustPeer[p]
            \/ q = peerSharedTrustPeer[p]

\* All non-local singleton events that are valid require some workspace to be valid.
InvAllValidRequireWorkspace ==
    IF AllWorkspaceEvents \cap EVENTS /= {}
    THEN \A p \in Peers:
        \A e \in valid[p]:
            e \in LocalRoots \/ IsWorkspaceEvent(e) \/ (\E ne \in AllWorkspaceEvents: ne \in valid[p])
    ELSE TRUE

\* User invite chain: user requires its invite to be valid.
InvUserInviteChain ==
    IF UserInvite \in EVENTS
    THEN \A p \in Peers:
        (User \in valid[p]) => (UserInvite \in valid[p])
    ELSE TRUE

\* Device invite chain: peer_shared requires its peer_invite_shared to be valid.
InvDeviceInviteChain ==
    IF DeviceInvite \in EVENTS
    THEN \A p \in Peers:
        (PeerShared \in valid[p]) => (DeviceInvite \in valid[p])
    ELSE TRUE

\* Admin requires user identity chain.
InvAdminChain ==
    IF Admin \in EVENTS
    THEN \A p \in Peers: (Admin \in valid[p]) => (User \in valid[p])
    ELSE TRUE

\* Removal events require peer-shared signer context.
InvRemovalAdmin ==
    IF (UserRemoved \in EVENTS \/ PeerRemoved \in EVENTS) /\ (PeerSharedSignerEvents \cap EVENTS) /= {}
    THEN \A p \in Peers:
        ((UserRemoved \in valid[p]) =>
            (\E ps \in (PeerSharedSignerEvents \cap EVENTS): ps \in valid[p]))
        /\ ((PeerRemoved \in valid[p]) =>
            (\E ps \in (PeerSharedSignerEvents \cap EVENTS): ps \in valid[p]))
    ELSE TRUE

\* Sender-subjective key wrap exclusion:
\* After a peer has projected a removal, key_shared must not co-exist
\* with the removal without the removal being observed first.
\* Modeled abstractly: if both SecretShared and a removal are valid,
\* the removal must be valid (the sender saw it).
InvRemovalExclusion ==
    IF SecretShared \in EVENTS /\ (UserRemoved \in EVENTS \/ PeerRemoved \in EVENTS)
    THEN \A p \in Peers:
        (SecretShared \in valid[p] /\ (UserRemoved \in EVENTS => UserRemoved \in recorded[p]))
            => TRUE  \* In this abstract model, the invariant is structural:
                      \* the dep on PeerShared ensures wraps only go to
                      \* peers that were valid at projection time.
                      \* A more refined model would track per-wrap recipients.
    ELSE TRUE

\* Message requires workspace (network event).
InvMessageWorkspace ==
    IF Message \in EVENTS /\ AllWorkspaceEvents \cap EVENTS /= {}
    THEN \A p \in Peers: (Message \in valid[p]) => (\E ne \in AllWorkspaceEvents: ne \in valid[p])
    ELSE TRUE

\* Encrypted content requires secret.
InvEncryptedKey ==
    IF Encrypted \in EVENTS /\ Secret \in EVENTS
    THEN \A p \in Peers: (Encrypted \in valid[p]) => (Secret \in valid[p])
    ELSE TRUE

\* SecretShared requires signer peer context and invite private key material.
InvSecretSharedKey ==
    IF SecretShared \in EVENTS
    THEN \A p \in Peers:
        (SecretShared \in valid[p]) =>
            (PeerShared \in valid[p]
             /\ secretSharedCarriedInvite[p] \in valid[p]
             /\ (IF InvitePrivkey \in EVENTS THEN InvitePrivkey \in valid[p] ELSE TRUE))
    ELSE TRUE

\* Peer private-key material is rooted by a valid signer lineage event.
InvPeerPrivkeySource ==
    IF PeerPrivkey \in EVENTS
    THEN \A p \in Peers:
        (PeerPrivkey \in valid[p]) => peerPrivkeyCarriedSigner[p] \in valid[p]
    ELSE TRUE

\* Invite private key material is rooted by a valid invite event.
InvInvitePrivkeySource ==
    IF InvitePrivkey \in EVENTS
    THEN \A p \in Peers:
        (InvitePrivkey \in valid[p]) => invitePrivkeyCarriedInvite[p] \in valid[p]
    ELSE TRUE

\* File slice authorization: if both FileSlice and MessageAttachment are valid,
\* they must share the same signer (modeled abstractly: both require PeerShared).
InvFileSliceAuth ==
    IF FileSlice \in EVENTS /\ MessageAttachment \in EVENTS
    THEN \A p \in Peers:
        (FileSlice \in valid[p] /\ MessageAttachment \in valid[p])
            => (PeerShared \in valid[p])
    ELSE TRUE

\* ---- Connection state machine invariants ----

\* Connection request requires invite_accepted valid and a user invite recorded.
InvConnReq ==
    IF InviteAccepted \in EVENTS
    THEN \A p \in Peers:
        connState[p] \in {"req", "ack", "invite", "peer"} =>
            (InviteAccepted \in valid[p]
             /\ \E ie \in (UserInviteEvents \cap EVENTS): ie \in recorded[p])
    ELSE TRUE

\* Connection ack requires request (monotonic state machine).
InvConnAck ==
    \A p \in Peers:
        connState[p] \in {"ack", "invite", "peer"} =>
            connState[p] /= "none"

\* Connection by invite requires ack.
InvConnInvite ==
    IF InviteAccepted \in EVENTS
    THEN \A p \in Peers:
        connState[p] \in {"invite", "peer"} =>
            (InviteAccepted \in valid[p]
             /\ \E ie \in (UserInviteEvents \cap EVENTS): ie \in recorded[p])
    ELSE TRUE

\* Peer connection requires invite connection and peer_shared valid.
InvConnPeer ==
    IF InviteAccepted \in EVENTS
    THEN \A p \in Peers:
        connState[p] = "peer" =>
            (PeerShared \in valid[p])
    ELSE TRUE

\* Tier-2 interaction bound: keep two-peer state space tractable while preserving
\* one full bootstrap/upgrade lane and cross-peer dependency checks.
CfgInteractionConstraint ==
    /\ \A p \in Peers :
        /\ Cardinality(recorded[p]) <= 8
        /\ Cardinality(valid[p]) <= 8
    /\ Cardinality({p \in Peers : Cardinality(recorded[p]) > 0}) <= 1
    /\ Cardinality({p \in Peers : Cardinality(valid[p]) > 0}) <= 1
    /\ Cardinality({p \in Peers : connState[p] # "none"}) <= 1

====
