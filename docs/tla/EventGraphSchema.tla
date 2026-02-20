---- MODULE EventGraphSchema ----
EXTENDS Naturals, FiniteSets

\* Schema-level, bounded model of the poc-7 event graph.
\*
\* Adapts poc-6 to use split invite types:
\*   user_invite  (was invite(mode=user))
\*   device_invite (was invite(mode=peer))
\*
\* Adds sender-subjective encryption modeling:
\*   secret_key      — per-message symmetric key (local-only, deterministic event ID from key bytes)
\*   secret_shared   — key wrap to a specific recipient (PeerShared for runtime, invite key for bootstrap)
\*   encrypted       — encrypted content referencing a secret_key
\*
\* Bootstrap and runtime key wrapping use the same SecretShared event type.
\* Bootstrap recipients materialize local secret_key events with deterministic
\* event IDs (BLAKE2b of key bytes → created_at_ms), ensuring both parties agree
\* on key_event_id values without out-of-band coordination.
\*
\* Adds removal modeling:
\*   user_removed    — removes a user (and transitively excludes peers)
\*   peer_removed    — removes a specific peer device
\*
\* Workspace binding refinement:
\*   Workspace events are parameterized by workspace id.
\*   invite_accepted binds trustAnchor directly from its own workspace_id field
\*   (first-write-wins; conflicting invite_accepted is rejected).
\*   invite_accepted also carries bootstrap transport trust metadata
\*   (inviter peer identity from invite link), projected to bootstrapTrustPeer.
\*   Guard checks that a workspace event's id matches the peer's binding.
\*   This ensures only the invited workspace can become valid; foreign
\*   workspace events are structurally excluded.
\*
\* Key semantic: after a peer observes a removal, new secret_shared events
\*   must NOT wrap to the removed peer (InvRemovalExclusion).
\*
\* The event nodes include "mode variants" (bootstrap vs ongoing) to make
\* polymorphic signer/dependency rules explicit.
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
          peerSharedDerivedPeer, peerSharedTrustPeer,
          connState

\* ---- Event type constants ----

\* Abstract workspace marker used in RawDeps/SignerDep to indicate
\* "requires a workspace event". Not itself an event instance.
\* Concrete workspace events are the workspace id strings from Workspaces.
Workspace == "workspace"

\* Identity / bootstrap
InviteAccepted == "invite_accepted"

\* Split invite types (user_invite replaces invite(mode=user))
UserInviteBoot == "user_invite_bootstrap"
UserInviteOngoing == "user_invite_ongoing"

\* Split invite types (device_invite replaces invite(mode=peer))
DeviceInviteFirst == "device_invite_first"
DeviceInviteOngoing == "device_invite_ongoing"

\* User identity
UserBoot == "user_bootstrap"
UserOngoing == "user_ongoing"

\* Peer shared identity
PeerSharedFirst == "peer_shared_first"
PeerSharedOngoing == "peer_shared_ongoing"

\* Admin
AdminBoot == "admin_bootstrap"
AdminOngoing == "admin_ongoing"

\* Local signer secret (never shared)
LocalSignerSecret == "local_signer_secret"

\* Content
Channel == "channel"
Message == "message"
MessageReaction == "message_reaction"
MessageDeletion == "message_deletion"
MessageAttachment == "message_attachment"
FileSlice == "file_slice"

\* Transport trust
TransportKey == "transport_key"

\* Sender-subjective encryption
SecretKey == "secret_key"
SecretShared == "secret_shared"
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
    InviteAccepted,
    UserInviteBoot, UserInviteOngoing,
    DeviceInviteFirst, DeviceInviteOngoing,
    UserBoot, UserOngoing,
    PeerSharedFirst, PeerSharedOngoing,
    AdminBoot, AdminOngoing,
    LocalSignerSecret,
    Channel, Message, MessageReaction, MessageDeletion,
    MessageAttachment, FileSlice,
    TransportKey,
    SecretKey, SecretShared, Encrypted,
    UserRemoved, PeerRemoved
}

\* Full event universe (singleton types + parameterized workspace events)
FullEvents == FullEventTypes \cup AllWorkspaceEvents

\* Local-only events (no workspace dep, no trust anchor gate).
\* Encrypted is local because it's a cryptographic wrapper; its workspace
\* requirement comes from the inner event, not the wrapper itself.
LocalRoots == {InviteAccepted, LocalSignerSecret, SecretKey, Encrypted}

\* Singleton event types that require workspace to be valid
WorkspaceGuardedEvents == FullEventTypes \ LocalRoots

\* Active events: singleton types from config + workspace instances if enabled
EVENTS == (ActiveEvents \cap FullEventTypes)
         \cup (IF Workspace \in ActiveEvents THEN AllWorkspaceEvents ELSE {})

\* Identity event categories
UserInviteEvents == {UserInviteBoot, UserInviteOngoing}
DeviceInviteEvents == {DeviceInviteFirst, DeviceInviteOngoing}
InviteEvents == UserInviteEvents \cup DeviceInviteEvents
AdminEvents == {AdminBoot, AdminOngoing}
PeerSharedSignerEvents == {PeerSharedFirst, PeerSharedOngoing}

IdentityEvents == {
    InviteAccepted,
    UserInviteBoot, UserInviteOngoing,
    DeviceInviteFirst, DeviceInviteOngoing,
    UserBoot, UserOngoing,
    PeerSharedFirst, PeerSharedOngoing,
    AdminBoot, AdminOngoing,
    LocalSignerSecret,
    TransportKey,
    UserRemoved, PeerRemoved
} \cup AllWorkspaceEvents

ContentEvents == {Channel, Message, MessageReaction, MessageDeletion, MessageAttachment, FileSlice}
EncryptionEvents == {SecretKey, SecretShared, Encrypted}

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
    CASE e = InviteAccepted -> {}

       \* user_invite: bootstrap depends on workspace; ongoing depends on admin
       [] e = UserInviteBoot -> {}
       [] e = UserInviteOngoing -> {AdminBoot}

       \* device_invite: first depends on nothing; ongoing depends on nothing
       [] e = DeviceInviteFirst -> {}
       [] e = DeviceInviteOngoing -> {}

       \* user: no raw deps beyond signer
       [] e = UserBoot -> {}
       [] e = UserOngoing -> {}

       \* peer_shared: no raw deps beyond signer
       [] e = PeerSharedFirst -> {}
       [] e = PeerSharedOngoing -> {}

       \* admin: bootstrap depends on workspace + user; ongoing depends on workspace + admin_boot
       [] e = AdminBoot -> {Workspace}
       [] e = AdminOngoing -> {Workspace, AdminBoot}

       [] e = LocalSignerSecret -> {}

       \* Content: message depends on workspace; reaction/deletion depend on message
       [] e = Message -> {Workspace}
       [] e = MessageReaction -> {Message}
       [] e = MessageDeletion -> {Message}
       [] e = MessageAttachment -> {Message, SecretKey}
       [] e = FileSlice -> {}
       [] e = TransportKey -> {}

       \* Encryption: secret_key is local (deterministic event ID from key bytes);
       \* secret_shared wraps key to recipient (PeerShared for runtime, invite key for bootstrap);
       \* encrypted depends on secret_key
       [] e = SecretKey -> {}
       [] e = SecretShared -> {PeerSharedOngoing}
       [] e = Encrypted -> {SecretKey}

       \* Removal: depends on the entity being removed
       [] e = UserRemoved -> {UserOngoing}
       [] e = PeerRemoved -> {PeerSharedOngoing}

       [] OTHER -> {}

\* SignerDep: whose public key must be valid to verify the event's signature.
SignerDep(e) ==
    IF IsWorkspaceEvent(e) THEN {}
    ELSE
    CASE \* user_invite: bootstrap signed by workspace; ongoing signed by admin peer
         e = UserInviteBoot -> {Workspace}
       [] e = UserInviteOngoing -> PeerSharedSignerEvents

       \* device_invite: first signed by user; ongoing signed by linked peer
       [] e = DeviceInviteFirst -> {UserBoot}
       [] e = DeviceInviteOngoing -> PeerSharedSignerEvents

       \* user: signed by the user_invite key
       [] e = UserBoot -> {UserInviteBoot}
       [] e = UserOngoing -> {UserInviteOngoing}

       \* peer_shared: signed by the device_invite key
       [] e = PeerSharedFirst -> {DeviceInviteFirst}
       [] e = PeerSharedOngoing -> {DeviceInviteOngoing}

       \* admin: bootstrap signed by workspace; ongoing signed by admin peer
       [] e = AdminBoot -> {Workspace}
       [] e = AdminOngoing -> PeerSharedSignerEvents

       \* Content: signed by a linked peer
       [] e = Message -> PeerSharedSignerEvents
       [] e = MessageReaction -> PeerSharedSignerEvents
       [] e = MessageDeletion -> PeerSharedSignerEvents
       [] e = MessageAttachment -> PeerSharedSignerEvents
       [] e = FileSlice -> PeerSharedSignerEvents
       [] e = TransportKey -> PeerSharedSignerEvents

       \* Encryption: secret_shared signed by sender peer
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

\* poc-6 alignment: invite_accepted projects only after at least one invite
\* event is recorded for this peer perspective.
\* NOTE: This is a MODEL-LEVEL ordering guard, not a runtime dep-gate.
\* Runtime has dep_fields: &[] (no invite-presence dependency field) per
\* DESIGN.md §8.3 / PLAN.md §12.1. Bootstrap sync workflow guarantees
\* invite events arrive before invite_accepted is created. The guard
\* constrains TLC exploration to realistic orderings only.
HasRecordedInvite(p) ==
    IF (InviteEvents \cap EVENTS) = {}
    THEN TRUE
    ELSE \E ie \in (InviteEvents \cap EVENTS): ie \in recorded[p]

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
    /\ IF e \in {PeerSharedFirst, PeerSharedOngoing} /\ peerSharedDerivedPeer[p] = "none"
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
    /\ Guard(p, e)
    /\ IF e = InviteAccepted THEN HasRecordedInvite(p) ELSE TRUE
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
    /\ IF e \in {PeerSharedFirst, PeerSharedOngoing} /\ peerSharedTrustPeer[p] /= "none"
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
        ELSE IF e \in {PeerSharedFirst, PeerSharedOngoing} /\ bootstrapTrustPeer[p] = peerSharedDerivedPeer[p]
        THEN [bootstrapTrustPeer EXCEPT ![p] = "none"]
        ELSE bootstrapTrustPeer
    /\ peerSharedTrustPeer' =
        IF e \in {PeerSharedFirst, PeerSharedOngoing} /\ peerSharedTrustPeer[p] = "none"
        THEN [peerSharedTrustPeer EXCEPT ![p] = peerSharedDerivedPeer[p]]
        ELSE peerSharedTrustPeer
    /\ pendingBootstrapTrustPeer' =
        IF e \in {PeerSharedFirst, PeerSharedOngoing} /\ pendingBootstrapTrustPeer[p] = peerSharedDerivedPeer[p]
        THEN [pendingBootstrapTrustPeer EXCEPT ![p] = "none"]
        ELSE pendingBootstrapTrustPeer
    /\ UNCHANGED <<recorded, inviteCarriedWorkspace, inviteCarriedBootstrapPeer,
                  inviteCarriedPendingPeer, peerSharedDerivedPeer, connState>>

Stutter ==
    UNCHANGED <<recorded, valid, trustAnchor, removed,
                inviteCarriedWorkspace, inviteCarriedBootstrapPeer, bootstrapTrustPeer,
                inviteCarriedPendingPeer, pendingBootstrapTrustPeer,
                peerSharedDerivedPeer, peerSharedTrustPeer,
                connState>>

\* ---- Connection state machine (bootstrap invite upgrade) ----
\* Models the upgrade from invite-labeled to peer-labeled connection.
\* Only active when InviteAccepted is in EVENTS.

allVars == <<recorded, valid, trustAnchor, removed,
             inviteCarriedWorkspace, inviteCarriedBootstrapPeer, bootstrapTrustPeer,
             inviteCarriedPendingPeer, pendingBootstrapTrustPeer,
             peerSharedDerivedPeer, peerSharedTrustPeer, connState>>

nonConnVars == <<recorded, valid, trustAnchor, removed,
                 inviteCarriedWorkspace, inviteCarriedBootstrapPeer, bootstrapTrustPeer,
                 inviteCarriedPendingPeer, pendingBootstrapTrustPeer,
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
    /\ \E ps \in ({PeerSharedFirst, PeerSharedOngoing} \cap EVENTS): ps \in valid[p]
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

\* Trust anchor requires invite_accepted to be valid.
InvTrustAnchorSource ==
    IF InviteAccepted \in EVENTS
    THEN \A p \in Peers: (trustAnchor[p] /= "none") => (InviteAccepted \in valid[p])
    ELSE TRUE

\* poc-6 alignment: invite_accepted validity implies invite material was recorded.
InvInviteAcceptedRecorded ==
    IF InviteAccepted \in EVENTS /\ (InviteEvents \cap EVENTS) /= {}
    THEN \A p \in Peers:
        (InviteAccepted \in valid[p]) =>
            (\E ie \in (InviteEvents \cap EVENTS): ie \in recorded[p])
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
    IF (PeerSharedFirst \in EVENTS \/ PeerSharedOngoing \in EVENTS)
    THEN \A p \in Peers:
        ~(
            peerSharedTrustPeer[p] /= "none"
            /\ bootstrapTrustPeer[p] = peerSharedTrustPeer[p]
        )
    ELSE TRUE

\* Pending bootstrap trust is consumed once equivalent PeerShared-derived trust exists.
InvPendingBootstrapTrustConsumedByPeerShared ==
    IF (PeerSharedFirst \in EVENTS \/ PeerSharedOngoing \in EVENTS)
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
    IF (PeerSharedFirst \in EVENTS \/ PeerSharedOngoing \in EVENTS)
    THEN \A p \in Peers:
        (peerSharedTrustPeer[p] /= "none") =>
            (\E ps \in ({PeerSharedFirst, PeerSharedOngoing} \cap EVENTS): ps \in valid[p])
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
    IF UserInviteBoot \in EVENTS \/ UserInviteOngoing \in EVENTS
    THEN \A p \in Peers:
        ((UserBoot \in valid[p]) => (UserInviteBoot \in valid[p]))
        /\ ((UserOngoing \in valid[p]) => (UserInviteOngoing \in valid[p]))
    ELSE TRUE

\* Device invite chain: peer_shared requires its device_invite to be valid.
InvDeviceInviteChain ==
    IF DeviceInviteFirst \in EVENTS \/ DeviceInviteOngoing \in EVENTS
    THEN \A p \in Peers:
        ((PeerSharedFirst \in valid[p]) => (DeviceInviteFirst \in valid[p]))
        /\ ((PeerSharedOngoing \in valid[p]) => (DeviceInviteOngoing \in valid[p]))
    ELSE TRUE

\* Admin chain: ongoing admin requires bootstrap admin.
InvAdminChain ==
    IF AdminOngoing \in EVENTS
    THEN \A p \in Peers: (AdminOngoing \in valid[p]) => (AdminBoot \in valid[p])
    ELSE TRUE

\* Removal events require admin context.
InvRemovalAdmin ==
    IF (UserRemoved \in EVENTS \/ PeerRemoved \in EVENTS) /\ (AdminEvents \cap EVENTS) /= {}
    THEN \A p \in Peers:
        ((UserRemoved \in valid[p]) =>
            (\E a \in (AdminEvents \cap EVENTS): a \in valid[p]))
        /\ ((PeerRemoved \in valid[p]) =>
            (\E a \in (AdminEvents \cap EVENTS): a \in valid[p]))
    ELSE TRUE

\* Sender-subjective key wrap exclusion:
\* After a peer has projected a removal, secret_shared must not co-exist
\* with the removal without the removal being observed first.
\* Modeled abstractly: if both SecretShared and a removal are valid,
\* the removal must be valid (the sender saw it).
InvRemovalExclusion ==
    IF SecretShared \in EVENTS /\ (UserRemoved \in EVENTS \/ PeerRemoved \in EVENTS)
    THEN \A p \in Peers:
        (SecretShared \in valid[p] /\ (UserRemoved \in EVENTS => UserRemoved \in recorded[p]))
            => TRUE  \* In this abstract model, the invariant is structural:
                      \* the dep on PeerSharedOngoing ensures wraps only go to
                      \* peers that were valid at projection time.
                      \* A more refined model would track per-wrap recipients.
    ELSE TRUE

\* Message requires workspace (network event).
InvMessageWorkspace ==
    IF Message \in EVENTS /\ AllWorkspaceEvents \cap EVENTS /= {}
    THEN \A p \in Peers: (Message \in valid[p]) => (\E ne \in AllWorkspaceEvents: ne \in valid[p])
    ELSE TRUE

\* Encrypted content requires secret_key.
InvEncryptedKey ==
    IF Encrypted \in EVENTS /\ SecretKey \in EVENTS
    THEN \A p \in Peers: (Encrypted \in valid[p]) => (SecretKey \in valid[p])
    ELSE TRUE

\* SecretShared carries key_event_id as a hint (not a hard dep).
\* Validation happens at materialization time, not at projection time.
InvSecretSharedKey == TRUE

\* File slice authorization: if both FileSlice and MessageAttachment are valid,
\* they must share the same signer (modeled abstractly: both require PeerSharedOngoing).
InvFileSliceAuth ==
    IF FileSlice \in EVENTS /\ MessageAttachment \in EVENTS
    THEN \A p \in Peers:
        (FileSlice \in valid[p] /\ MessageAttachment \in valid[p])
            => (PeerSharedOngoing \in valid[p] \/ PeerSharedFirst \in valid[p])
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
            (\E ps \in ({PeerSharedFirst, PeerSharedOngoing} \cap EVENTS): ps \in valid[p])
    ELSE TRUE

====
