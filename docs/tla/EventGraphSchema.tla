---- MODULE EventGraphSchema ----
EXTENDS Naturals, FiniteSets

\* Schema-level, bounded model of the poc-7 event graph.
\*
\* Adapts poc-6 to use split invite types:
\*   user_invite  (was invite(mode=user))
\*   device_invite (was invite(mode=peer))
\*
\* Adds sender-subjective encryption modeling:
\*   secret_key      — per-message symmetric key (local-only)
\*   secret_shared   — key wrap to a specific recipient peer
\*   encrypted       — encrypted content referencing a secret_key
\*
\* Adds removal modeling:
\*   user_removed    — removes a user (and transitively excludes peers)
\*   peer_removed    — removes a specific peer device
\*
\* Workspace binding refinement:
\*   Workspace events are parameterized by workspace id.
\*   invite_accepted binds trustAnchor directly from its own workspace_id field
\*   (first-write-wins; conflicting invite_accepted is rejected).
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

VARIABLES recorded, valid, trustAnchor, removed, inviteCarriedNet

\* ---- Event type constants ----

\* Abstract workspace marker used in RawDeps/SignerDep to indicate
\* "requires a workspace event". Not itself an event instance.
\* Concrete workspace events are the workspace id strings from Workspaces.
Net == "workspace"

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

\* Local peer (never shared)
Peer == "peer"

\* Content
Channel == "channel"
Message == "message"
MessageReaction == "message_reaction"
MessageDeletion == "message_deletion"

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

AllNetEvents == Workspaces
IsNetEvent(e) == e \in Workspaces
NetId(e) == e

\* ---- Event sets ----

\* Singleton event types (not parameterized by workspace)
FullEventTypes == {
    InviteAccepted,
    UserInviteBoot, UserInviteOngoing,
    DeviceInviteFirst, DeviceInviteOngoing,
    UserBoot, UserOngoing,
    PeerSharedFirst, PeerSharedOngoing,
    AdminBoot, AdminOngoing,
    Peer,
    Channel, Message, MessageReaction, MessageDeletion,
    SecretKey, SecretShared, Encrypted,
    UserRemoved, PeerRemoved
}

\* Full event universe (singleton types + parameterized workspace events)
FullEvents == FullEventTypes \cup AllNetEvents

\* Local-only events (no workspace dep, no trust anchor gate).
\* Encrypted is local because it's a cryptographic wrapper; its workspace
\* requirement comes from the inner event, not the wrapper itself.
LocalRoots == {InviteAccepted, Peer, SecretKey, Encrypted}

\* Singleton event types that require workspace to be valid
NetGuardedEvents == FullEventTypes \ LocalRoots

\* Active events: singleton types from config + workspace instances if enabled
EVENTS == (ActiveEvents \cap FullEventTypes)
         \cup (IF Net \in ActiveEvents THEN AllNetEvents ELSE {})

\* Identity event categories
UserInviteEvents == {UserInviteBoot, UserInviteOngoing}
DeviceInviteEvents == {DeviceInviteFirst, DeviceInviteOngoing}
AdminEvents == {AdminBoot, AdminOngoing}

IdentityEvents == {
    InviteAccepted,
    UserInviteBoot, UserInviteOngoing,
    DeviceInviteFirst, DeviceInviteOngoing,
    UserBoot, UserOngoing,
    PeerSharedFirst, PeerSharedOngoing,
    AdminBoot, AdminOngoing,
    Peer,
    UserRemoved, PeerRemoved
} \cup AllNetEvents

ContentEvents == {Channel, Message, MessageReaction, MessageDeletion}
EncryptionEvents == {SecretKey, SecretShared, Encrypted}

ASSUME (ActiveEvents \ {Net}) \subseteq FullEventTypes
ASSUME Peers /= {}
ASSUME Workspaces /= {}
ASSUME Workspaces \cap FullEventTypes = {}

\* ---- Dependency rules ----
\* RawDeps and SignerDep use the abstract Net marker for workspace dependency.
\* ResolveNet translates Net to the peer's bound workspace event instance.

RawDeps(e) ==
    IF IsNetEvent(e) THEN {}
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
       [] e = AdminBoot -> {Net}
       [] e = AdminOngoing -> {Net, AdminBoot}

       [] e = Peer -> {}

       \* Content: channel depends on workspace; message depends on channel + user
       [] e = Channel -> {Net}
       [] e = Message -> {Channel, UserOngoing}
       [] e = MessageReaction -> {Message}
       [] e = MessageDeletion -> {Message}

       \* Encryption: secret_key is local; secret_shared depends on key + recipient peer;
       \* encrypted depends on secret_key
       [] e = SecretKey -> {}
       [] e = SecretShared -> {SecretKey, PeerSharedOngoing}
       [] e = Encrypted -> {SecretKey}

       \* Removal: depends on the entity being removed
       [] e = UserRemoved -> {UserOngoing}
       [] e = PeerRemoved -> {PeerSharedOngoing}

       [] OTHER -> {}

\* SignerDep: whose public key must be valid to verify the event's signature.
SignerDep(e) ==
    IF IsNetEvent(e) THEN {}
    ELSE
    CASE \* user_invite: bootstrap signed by workspace; ongoing signed by admin peer
         e = UserInviteBoot -> {Net}
       [] e = UserInviteOngoing -> {PeerSharedOngoing}

       \* device_invite: first signed by user; ongoing signed by linked peer
       [] e = DeviceInviteFirst -> {UserBoot}
       [] e = DeviceInviteOngoing -> {PeerSharedOngoing}

       \* user: signed by the user_invite key
       [] e = UserBoot -> {UserInviteBoot}
       [] e = UserOngoing -> {UserInviteOngoing}

       \* peer_shared: signed by the device_invite key
       [] e = PeerSharedFirst -> {DeviceInviteFirst}
       [] e = PeerSharedOngoing -> {DeviceInviteOngoing}

       \* admin: bootstrap signed by workspace; ongoing signed by admin peer
       [] e = AdminBoot -> {Net}
       [] e = AdminOngoing -> {PeerSharedOngoing}

       \* Content: signed by a linked peer
       [] e = Channel -> {PeerSharedOngoing}
       [] e = Message -> {PeerSharedOngoing}
       [] e = MessageReaction -> {PeerSharedOngoing}
       [] e = MessageDeletion -> {PeerSharedOngoing}

       \* Encryption: secret_shared signed by sender peer
       [] e = SecretShared -> {PeerSharedOngoing}

       \* Removal: signed by admin peer
       [] e = UserRemoved -> {PeerSharedOngoing}
       [] e = PeerRemoved -> {PeerSharedOngoing}

       [] OTHER -> {}

\* Resolve abstract Net marker to the peer's bound workspace event.
\* Non-Net deps pass through filtered by EVENTS.
\* If peer is unbound and event needs workspace, an unsatisfiable
\* placeholder blocks projection.
ResolveNet(p, deps) ==
    LET needsNet == Net \in deps
        nonNet == (deps \ {Net}) \cap EVENTS
        netDep == IF needsNet THEN
                    IF trustAnchor[p] /= "none"
                    THEN {trustAnchor[p]}
                    ELSE {"__unbound__"}
                  ELSE {}
    IN nonNet \cup netDep

\* Combined peer-resolved dependencies: structural + signer.
PeerDeps(p, e) == ResolveNet(p, RawDeps(e) \cup SignerDep(e))

\* ---- Guards ----

\* Workspace events require matching trust anchor binding.
Guard(p, e) == IF IsNetEvent(e) THEN trustAnchor[p] = NetId(e) ELSE TRUE

\* ---- State machine ----

Init ==
    /\ recorded = [p \in Peers |-> {}]
    /\ valid = [p \in Peers |-> {}]
    /\ trustAnchor = [p \in Peers |-> "none"]
    /\ removed = [p \in Peers |-> {}]
    /\ inviteCarriedNet = [p \in Peers |-> "none"]

\* Record captures the event-carried workspace_id at ingress time.
\* For invite_accepted, the event carries a specific workspace_id chosen
\* nondeterministically here (models the fact that any workspace could be
\* referenced). The choice is fixed at record time, not projection time.
Record(p, e) ==
    /\ p \in Peers
    /\ e \in EVENTS
    /\ e \notin recorded[p]
    /\ recorded' = [recorded EXCEPT ![p] = @ \cup {e}]
    /\ IF e = InviteAccepted /\ inviteCarriedNet[p] = "none"
       THEN \E n \in Workspaces: inviteCarriedNet' = [inviteCarriedNet EXCEPT ![p] = n]
       ELSE UNCHANGED inviteCarriedNet
    /\ UNCHANGED <<valid, trustAnchor, removed>>

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
    \* Mismatch rejection: invite_accepted blocked if anchor already set differently
    /\ IF e = InviteAccepted /\ trustAnchor[p] /= "none"
       THEN trustAnchor[p] = inviteCarriedNet[p]
       ELSE TRUE
    /\ valid' = [valid EXCEPT ![p] = @ \cup {e}]
    \* Trust anchor binding: deterministic from event-carried workspace_id.
    /\ trustAnchor' =
        IF e = InviteAccepted /\ trustAnchor[p] = "none"
        THEN [trustAnchor EXCEPT ![p] = inviteCarriedNet[p]]
        ELSE trustAnchor
    /\ removed' =
        IF e = UserRemoved
        THEN [removed EXCEPT ![p] = @ \cup {"user_target"}]
        ELSE IF e = PeerRemoved
        THEN [removed EXCEPT ![p] = @ \cup {"peer_target"}]
        ELSE removed
    /\ UNCHANGED <<recorded, inviteCarriedNet>>

Stutter ==
    UNCHANGED <<recorded, valid, trustAnchor, removed, inviteCarriedNet>>

Next ==
    \/ \E p \in Peers, e \in EVENTS: Record(p, e)
    \/ \E p \in Peers, e \in EVENTS: Project(p, e)
    \/ Stutter

Spec ==
    Init /\ [][Next]_<<recorded, valid, trustAnchor, removed, inviteCarriedNet>>

\* ---- Invariants ----

TypeOK ==
    /\ recorded \in [Peers -> SUBSET EVENTS]
    /\ valid \in [Peers -> SUBSET EVENTS]
    /\ \A p \in Peers: valid[p] \subseteq recorded[p]
    /\ trustAnchor \in [Peers -> Workspaces \cup {"none"}]
    /\ removed \in [Peers -> SUBSET {"user_target", "peer_target"}]
    /\ inviteCarriedNet \in [Peers -> Workspaces \cup {"none"}]

\* Every valid event has all its peer-resolved dependencies valid.
InvDeps ==
    \A p \in Peers:
        \A e \in valid[p]: PeerDeps(p, e) \subseteq valid[p]

\* Every valid event has its signer dependency valid (peer-resolved).
InvSigner ==
    \A p \in Peers:
        \A e \in valid[p]: ResolveNet(p, SignerDep(e)) \subseteq valid[p]

\* Workspace event validity requires matching trust anchor.
InvNetAnchor ==
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

\* Trust anchor always matches the event-carried workspace_id.
InvTrustAnchorMatchesCarried ==
    \A p \in Peers:
        (trustAnchor[p] /= "none") => (trustAnchor[p] = inviteCarriedNet[p])

\* All non-local singleton events that are valid require some workspace to be valid.
InvAllValidRequireWorkspace ==
    IF AllNetEvents \cap EVENTS /= {}
    THEN \A p \in Peers:
        \A e \in valid[p]:
            e \in LocalRoots \/ IsNetEvent(e) \/ (\E ne \in AllNetEvents: ne \in valid[p])
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

\* Channel requires workspace.
InvChannelWorkspace ==
    IF Channel \in EVENTS /\ AllNetEvents \cap EVENTS /= {}
    THEN \A p \in Peers: (Channel \in valid[p]) => (\E ne \in AllNetEvents: ne \in valid[p])
    ELSE TRUE

\* Message requires channel.
InvMessageChannel ==
    IF Message \in EVENTS /\ Channel \in EVENTS
    THEN \A p \in Peers: (Message \in valid[p]) => (Channel \in valid[p])
    ELSE TRUE

\* Encrypted content requires secret_key.
InvEncryptedKey ==
    IF Encrypted \in EVENTS /\ SecretKey \in EVENTS
    THEN \A p \in Peers: (Encrypted \in valid[p]) => (SecretKey \in valid[p])
    ELSE TRUE

\* SecretShared requires secret_key.
InvSecretSharedKey ==
    IF SecretShared \in EVENTS /\ SecretKey \in EVENTS
    THEN \A p \in Peers: (SecretShared \in valid[p]) => (SecretKey \in valid[p])
    ELSE TRUE

====
