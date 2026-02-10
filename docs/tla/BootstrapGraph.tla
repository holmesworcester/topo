---- MODULE BootstrapGraph ----
EXTENDS Naturals

\* Model of the identity bootstrap and join sequence for poc-7.
\*
\* Adapts poc-6/BootstrapGraph to use split invite types:
\*   user_invite  (was invite(mode=user))
\*   device_invite (was invite(mode=peer))
\*
\* Workspace binding refinement:
\*   A ForeignWorkspace event is included alongside Workspace. Both are workspace
\*   events, but the trust anchor binds to Workspace's id.
\*   invite_accepted binds the trust anchor directly from its own
\*   workspace_id field (first-write-wins; no pre-projection capture).
\*   The Guard mechanism checks that the workspace event's id matches
\*   the binding, structurally excluding ForeignWorkspace from ever becoming
\*   valid. InvForeignWorkspaceExcluded verifies this property.
\*
\* Focuses on:
\* - dependency ordering (dep edges)
\* - signer gating (signed_by edges)
\* - trust-anchor gating: workspace validity requires invite_accepted
\* - workspace binding: only the invited workspace can become valid
\* - bootstrap and ongoing join sequences
\* - connection upgrade from invite-labeled to peer-labeled
\*
\* Bootstrap sequence:
\*   1. invite_accepted (local, binds trust anchor from event's workspace_id)
\*   2. workspace (gated by trust anchor matching "main")
\*   3. user_invite_boot (signed_by: workspace, dep: workspace)
\*   4. user_alice (signed_by: user_invite_boot, dep: user_invite_boot)
\*   5. admin_boot (signed_by: workspace, dep: workspace + user_alice)
\*   6. device_invite_alice (signed_by: user_alice, dep: user_alice)
\*   7. peer_shared_alice (signed_by: device_invite_alice, dep: device_invite_alice)
\*
\* Ongoing join (Bob, invited by Alice):
\*   8. user_invite_ongoing (signed_by: peer_shared_alice, dep: peer_shared_alice + admin_boot)
\*   9. invite_accepted_bob (local, binds trust anchor from event's workspace_id)
\*  10. user_bob (signed_by: user_invite_ongoing, dep: user_invite_ongoing)
\*  11. device_invite_bob (signed_by: user_bob, dep: user_bob)
\*  12. peer_shared_bob (signed_by: device_invite_bob, dep: device_invite_bob)

VARIABLES recorded, valid, trustAnchor, connReq, connAck, connInvite, connPeer

\* Event constants
Workspace == "workspace"
ForeignWorkspace == "foreign_workspace"
InviteAcceptedAlice == "invite_accepted_alice"
UserInviteBoot == "user_invite_bootstrap"
UserAlice == "user_alice"
AdminBootAlice == "admin_boot_alice"
DeviceInviteAlice == "device_invite_alice"
PeerSharedAlice == "peer_shared_alice"

UserInviteOngoing == "user_invite_ongoing"
InviteAcceptedBob == "invite_accepted_bob"
UserBob == "user_bob"
DeviceInviteBob == "device_invite_bob"
PeerSharedBob == "peer_shared_bob"

EVENTS == {
    Workspace, ForeignWorkspace, InviteAcceptedAlice, UserInviteBoot, UserAlice, AdminBootAlice,
    DeviceInviteAlice, PeerSharedAlice,
    UserInviteOngoing, InviteAcceptedBob, UserBob, DeviceInviteBob, PeerSharedBob
}

\* Workspace identity: each workspace event has a distinct workspace id.
\* The trust anchor binds to a specific workspace id.
WorkspaceIdOf(e) ==
    IF e = Workspace THEN "main"
    ELSE IF e = ForeignWorkspace THEN "foreign"
    ELSE "none"

\* Combined dependency + signer edges.
\* Each event lists the set of events that must be valid before it can project.
Deps(e) ==
    CASE e = Workspace -> {}
       [] e = ForeignWorkspace -> {}
       [] e = InviteAcceptedAlice -> {}
       \* user_invite(bootstrap): signed_by workspace, dep on workspace
       [] e = UserInviteBoot -> {Workspace}
       \* user: signed_by user_invite, dep on user_invite
       [] e = UserAlice -> {UserInviteBoot}
       \* admin(bootstrap): signed_by workspace, dep on workspace + user
       [] e = AdminBootAlice -> {Workspace, UserAlice}
       \* device_invite(first): signed_by user, dep on user
       [] e = DeviceInviteAlice -> {UserAlice}
       \* peer_shared: signed_by device_invite, dep on device_invite
       [] e = PeerSharedAlice -> {DeviceInviteAlice}
       \* user_invite(ongoing): signed_by peer_shared (admin), dep on peer_shared + admin
       [] e = UserInviteOngoing -> {PeerSharedAlice, AdminBootAlice}
       [] e = InviteAcceptedBob -> {}
       \* user: signed_by user_invite, dep on user_invite
       [] e = UserBob -> {UserInviteOngoing}
       \* device_invite(first): signed_by user, dep on user
       [] e = DeviceInviteBob -> {UserBob}
       \* peer_shared: signed_by device_invite, dep on device_invite
       [] e = PeerSharedBob -> {DeviceInviteBob}
       [] OTHER -> {}

\* Guard: workspace events require matching trust anchor binding.
\* trustAnchor records the bound workspace id ("none" = unbound).
Guard(e) ==
    IF e \in {Workspace, ForeignWorkspace} THEN trustAnchor = WorkspaceIdOf(e)
    ELSE TRUE

Init ==
    /\ recorded = {}
    /\ valid = {}
    /\ trustAnchor = "none"
    /\ connReq = FALSE
    /\ connAck = FALSE
    /\ connInvite = FALSE
    /\ connPeer = FALSE

Record(e) ==
    /\ e \in EVENTS
    /\ e \notin recorded
    /\ recorded' = recorded \cup {e}
    /\ UNCHANGED <<valid, trustAnchor, connReq, connAck, connInvite, connPeer>>

\* invite_accepted binds the trust anchor directly from its own workspace_id field.
\* In this concrete model, invite_accepted always references the "main" workspace.
\* First-write-wins: if trust anchor is already set to "main", it stays.
Project(e) ==
    /\ e \in recorded
    /\ e \notin valid
    /\ Deps(e) \subseteq valid
    /\ Guard(e)
    /\ valid' = valid \cup {e}
    \* Trust anchor binding directly from invite_accepted event fields.
    /\ trustAnchor' =
        IF e \in {InviteAcceptedAlice, InviteAcceptedBob} /\ trustAnchor = "none"
        THEN "main"
        ELSE trustAnchor
    /\ UNCHANGED <<recorded, connReq, connAck, connInvite, connPeer>>

\* Bootstrap connection request: authenticated by invite signature.
ConnectReqByInvite ==
    /\ ~connReq
    /\ InviteAcceptedBob \in valid
    /\ UserInviteOngoing \in recorded
    /\ connReq' = TRUE
    /\ UNCHANGED <<recorded, valid, trustAnchor, connAck, connInvite, connPeer>>

\* Connection acknowledgment: only after request is accepted.
ConnectAck ==
    /\ connReq
    /\ ~connAck
    /\ connAck' = TRUE
    /\ UNCHANGED <<recorded, valid, trustAnchor, connReq, connInvite, connPeer>>

\* Bootstrap connection active (invite-labeled) after ack.
ConnectByInvite ==
    /\ ~connInvite
    /\ connAck
    /\ connInvite' = TRUE
    /\ UNCHANGED <<recorded, valid, trustAnchor, connReq, connAck, connPeer>>

\* Upgrade to peer_shared-labeled connection once both peers are known.
UpgradeToPeer ==
    /\ connInvite
    /\ ~connPeer
    /\ PeerSharedAlice \in valid
    /\ PeerSharedBob \in valid
    /\ connPeer' = TRUE
    /\ UNCHANGED <<recorded, valid, trustAnchor, connReq, connAck, connInvite>>

Stutter ==
    UNCHANGED <<recorded, valid, trustAnchor, connReq, connAck, connInvite, connPeer>>

Next ==
    \/ \E e \in EVENTS: Record(e)
    \/ \E e \in EVENTS: Project(e)
    \/ ConnectReqByInvite
    \/ ConnectAck
    \/ ConnectByInvite
    \/ UpgradeToPeer
    \/ Stutter

Spec ==
    Init /\ [][Next]_<<recorded, valid, trustAnchor, connReq, connAck, connInvite, connPeer>>

\* ---- Invariants ----

TypeOK ==
    /\ recorded \subseteq EVENTS
    /\ valid \subseteq EVENTS
    /\ valid \subseteq recorded
    /\ trustAnchor \in {"none", "main", "foreign"}
    /\ connReq \in {TRUE, FALSE}
    /\ connAck \in {TRUE, FALSE}
    /\ connInvite \in {TRUE, FALSE}
    /\ connPeer \in {TRUE, FALSE}

\* Every valid event has all its dependencies valid.
InvDeps ==
    \A e \in valid:
        Deps(e) \subseteq valid

\* Workspace validity requires matching trust anchor.
InvWorkspaceAnchor ==
    /\ (Workspace \in valid => trustAnchor = "main")
    /\ (ForeignWorkspace \in valid => trustAnchor = "foreign")

\* Foreign workspace event can never become valid.
\* This is the key binding property: the invite determines which
\* workspace the peer accepts, and only that workspace can project.
InvForeignWorkspaceExcluded ==
    ForeignWorkspace \notin valid

\* Connection request requires invite_accepted valid and user_invite recorded.
InvConnReq ==
    connReq => (InviteAcceptedBob \in valid /\ UserInviteOngoing \in recorded)

\* Connection ack requires request.
InvConnAck ==
    connAck => connReq

\* Connection by invite requires ack and invite material.
InvConnInvite ==
    connInvite => (connAck /\ UserInviteOngoing \in recorded /\ InviteAcceptedBob \in valid)

\* Peer connection requires invite connection and both peers valid.
InvConnPeer ==
    connPeer => (connInvite /\ PeerSharedAlice \in valid /\ PeerSharedBob \in valid)

\* user_invite chain: user requires its invite.
InvUserInviteChain ==
    /\ (UserAlice \in valid => UserInviteBoot \in valid)
    /\ (UserBob \in valid => UserInviteOngoing \in valid)

\* device_invite chain: peer_shared requires its device_invite.
InvDeviceInviteChain ==
    /\ (PeerSharedAlice \in valid => DeviceInviteAlice \in valid)
    /\ (PeerSharedBob \in valid => DeviceInviteBob \in valid)

\* Admin chain: admin_boot requires workspace and user.
InvAdminChain ==
    AdminBootAlice \in valid => (Workspace \in valid /\ UserAlice \in valid)

====
