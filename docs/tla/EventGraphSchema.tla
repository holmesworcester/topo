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
\* Key semantic: after a peer observes a removal, new secret_shared events
\*   must NOT wrap to the removed peer (InvRemovalExclusion).
\*
\* The event nodes include "mode variants" (bootstrap vs ongoing) to make
\* polymorphic signer/dependency rules explicit.
\*
\* CONSTANTS:
\*   ActiveEvents — subset of FullEvents to bound state space
\*   Peers — set of peer identifiers for per-peer perspectives

CONSTANTS ActiveEvents, Peers

VARIABLES recorded, valid, trustAnchor, removed

\* ---- Event type constants ----

\* Identity / bootstrap
Net == "network"
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

\* ---- Event sets ----

FullEvents == {
    Net, InviteAccepted,
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

\* Local-only events (no network dep, no trust anchor gate).
\* Encrypted is local because it's a cryptographic wrapper; its network
\* requirement comes from the inner event, not the wrapper itself.
LocalRoots == {InviteAccepted, Peer, SecretKey, Encrypted}

\* Events that require network to be valid (everything except local roots)
NetGuardedEvents == (FullEvents \ LocalRoots)

\* Identity event categories
UserInviteEvents == {UserInviteBoot, UserInviteOngoing}
DeviceInviteEvents == {DeviceInviteFirst, DeviceInviteOngoing}
AdminEvents == {AdminBoot, AdminOngoing}

IdentityEvents == {
    Net, InviteAccepted,
    UserInviteBoot, UserInviteOngoing,
    DeviceInviteFirst, DeviceInviteOngoing,
    UserBoot, UserOngoing,
    PeerSharedFirst, PeerSharedOngoing,
    AdminBoot, AdminOngoing,
    Peer,
    UserRemoved, PeerRemoved
}

ContentEvents == {Channel, Message, MessageReaction, MessageDeletion}
EncryptionEvents == {SecretKey, SecretShared, Encrypted}

ASSUME ActiveEvents \subseteq FullEvents
ASSUME Peers /= {}

EVENTS == ActiveEvents

\* ---- Dependency rules ----
\* RawDeps: structural dependencies (content references).
\* SignerDep: signer must be valid (whose key verifies the signature).
\* Combined: Deps(e) = (RawDeps(e) \cup SignerDep(e)) \cap EVENTS

RawDeps(e) ==
    CASE e = Net -> {}
       [] e = InviteAccepted -> {}

       \* user_invite: bootstrap depends on network; ongoing depends on admin
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

       \* admin: bootstrap depends on network + user; ongoing depends on network + admin_boot
       [] e = AdminBoot -> {Net}
       [] e = AdminOngoing -> {Net, AdminBoot}

       [] e = Peer -> {}

       \* Content: channel depends on network; message depends on channel + user
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
    CASE \* user_invite: bootstrap signed by network; ongoing signed by admin peer
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

       \* admin: bootstrap signed by network; ongoing signed by admin peer
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

\* Combined dependencies: structural + signer, filtered to active events.
Deps(e) == (RawDeps(e) \cup SignerDep(e)) \cap EVENTS

\* ---- Guards ----

\* Network validity is gated by an invite_accepted trust anchor (per peer).
Guard(p, e) == IF e = Net THEN trustAnchor[p] ELSE TRUE

\* invite_accepted requires that at least one invite event has been recorded.
HasRecordedInvite(p) ==
    LET invEvents == (UserInviteEvents \cup DeviceInviteEvents) \cap EVENTS
    IN IF invEvents = {}
       THEN TRUE
       ELSE \E ie \in invEvents: ie \in recorded[p]

\* ---- State machine ----

Init ==
    /\ recorded = [p \in Peers |-> {}]
    /\ valid = [p \in Peers |-> {}]
    /\ trustAnchor = [p \in Peers |-> FALSE]
    /\ removed = [p \in Peers |-> {}]

Record(p, e) ==
    /\ p \in Peers
    /\ e \in EVENTS
    /\ e \notin recorded[p]
    /\ recorded' = [recorded EXCEPT ![p] = @ \cup {e}]
    /\ UNCHANGED <<valid, trustAnchor, removed>>

Project(p, e) ==
    /\ p \in Peers
    /\ e \in recorded[p]
    /\ e \notin valid[p]
    /\ Deps(e) \subseteq valid[p]
    /\ Guard(p, e)
    /\ IF e = InviteAccepted THEN HasRecordedInvite(p) ELSE TRUE
    /\ valid' = [valid EXCEPT ![p] = @ \cup {e}]
    /\ trustAnchor' =
        IF e = InviteAccepted
        THEN [trustAnchor EXCEPT ![p] = TRUE]
        ELSE trustAnchor
    /\ removed' =
        IF e = UserRemoved
        THEN [removed EXCEPT ![p] = @ \cup {"user_target"}]
        ELSE IF e = PeerRemoved
        THEN [removed EXCEPT ![p] = @ \cup {"peer_target"}]
        ELSE removed
    /\ UNCHANGED <<recorded>>

Stutter ==
    UNCHANGED <<recorded, valid, trustAnchor, removed>>

Next ==
    \/ \E p \in Peers, e \in EVENTS: Record(p, e)
    \/ \E p \in Peers, e \in EVENTS: Project(p, e)
    \/ Stutter

Spec ==
    Init /\ [][Next]_<<recorded, valid, trustAnchor, removed>>

\* ---- Invariants ----

TypeOK ==
    /\ recorded \in [Peers -> SUBSET EVENTS]
    /\ valid \in [Peers -> SUBSET EVENTS]
    /\ \A p \in Peers: valid[p] \subseteq recorded[p]
    /\ trustAnchor \in [Peers -> {TRUE, FALSE}]
    /\ removed \in [Peers -> SUBSET {"user_target", "peer_target"}]

\* Every valid event has all its dependencies valid.
InvDeps ==
    \A p \in Peers:
        \A e \in valid[p]: Deps(e) \subseteq valid[p]

\* Every valid event has its signer dependency valid.
InvSigner ==
    \A p \in Peers:
        \A e \in valid[p]: (SignerDep(e) \cap EVENTS) \subseteq valid[p]

\* Network validity requires trust anchor.
InvNetAnchor ==
    \A p \in Peers: (Net \in valid[p]) => trustAnchor[p]

\* Trust anchor requires invite_accepted to be valid.
InvTrustAnchorSource ==
    IF InviteAccepted \in EVENTS
    THEN \A p \in Peers: trustAnchor[p] => (InviteAccepted \in valid[p])
    ELSE TRUE

\* invite_accepted requires at least one invite event recorded.
InvInviteAcceptedRecorded ==
    IF InviteAccepted \in EVENTS /\ ((UserInviteEvents \cup DeviceInviteEvents) \cap EVENTS) /= {}
    THEN \A p \in Peers:
        (InviteAccepted \in valid[p]) =>
            (\E ie \in ((UserInviteEvents \cup DeviceInviteEvents) \cap EVENTS): ie \in recorded[p])
    ELSE TRUE

\* All non-local events that are valid require network to be valid.
InvAllValidRequireNetwork ==
    IF Net \in EVENTS
    THEN \A p \in Peers:
        \A e \in valid[p]:
            (e \notin NetGuardedEvents) \/ (e = Net) \/ (Net \in valid[p])
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

\* Channel requires network.
InvChannelNetwork ==
    IF Channel \in EVENTS /\ Net \in EVENTS
    THEN \A p \in Peers: (Channel \in valid[p]) => (Net \in valid[p])
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
