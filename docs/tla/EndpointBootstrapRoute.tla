---- MODULE EndpointBootstrapRoute ----
EXTENDS FiniteSets, TLC

\* Focused safety model for the stricter daemon-scoped iroh auth shape.
\*
\* This is intentionally smaller than EventGraphSchema / UnifiedBridge:
\* it models only the authority edges we want to preserve when we remove the
\* current bootstrap shortcuts.
\*
\* Target runtime shape:
\* - endpoint is the transport principal (`iroh::EndpointId`)
\* - account is the workspace/session principal (today's peer/tenant scope)
\* - `endpoint_secret` is a local root and may exist before any workspace
\* - `invite_accepted` is the local accepted-workspace binding that breaks the
\*   workspace bootstrap cycle
\* - bootstrap admission is exact and proof-scoped: one invite, one local
\*   account, one remote account, one remote endpoint
\* - steady-state sessions use OpenSessionRoute only
\* - routed session admission depends on projected account/workspace +
\*   endpoint_shared binding, not on invite windows or node-global heuristics

CONSTANTS
    LocalAccounts,
    RemoteAccounts,
    Endpoints,
    Workspaces,
    Invites,
    NoAccount,
    NoEndpoint,
    NoWorkspace,
    NoInvite

Accounts == LocalAccounts \union RemoteAccounts

ASSUME /\ LocalAccounts \intersect RemoteAccounts = {}
       /\ NoAccount \notin Accounts
       /\ NoEndpoint \notin Endpoints
       /\ NoWorkspace \notin Workspaces
       /\ NoInvite \notin Invites

VARIABLES
    acceptedWorkspace,
    endpointRoot,
    endpointBinding,
    inviteWorkspace,
    inviteTarget,
    actualRemoteEndpoint,
    claimedRemoteEndpoint,
    sourceAccount,
    targetAccount,
    inviteId,
    bootstrapAdmitted,
    routeAdmitted

vars ==
    << acceptedWorkspace,
       endpointRoot,
       endpointBinding,
       inviteWorkspace,
       inviteTarget,
       actualRemoteEndpoint,
       claimedRemoteEndpoint,
       sourceAccount,
       targetAccount,
       inviteId,
       bootstrapAdmitted,
       routeAdmitted >>

TypeOK ==
    /\ acceptedWorkspace \in [Accounts -> Workspaces \union {NoWorkspace}]
    /\ endpointRoot \subseteq Endpoints
    /\ endpointBinding \in [Accounts -> Endpoints \union {NoEndpoint}]
    /\ inviteWorkspace \in [Invites -> Workspaces \union {NoWorkspace}]
    /\ inviteTarget \in [Invites -> LocalAccounts \union {NoAccount}]
    /\ actualRemoteEndpoint \in Endpoints \union {NoEndpoint}
    /\ claimedRemoteEndpoint \in Endpoints \union {NoEndpoint}
    /\ sourceAccount \in RemoteAccounts \union {NoAccount}
    /\ targetAccount \in LocalAccounts \union {NoAccount}
    /\ inviteId \in Invites \union {NoInvite}
    /\ bootstrapAdmitted \in BOOLEAN
    /\ routeAdmitted \in BOOLEAN

Init ==
    /\ acceptedWorkspace = [a \in Accounts |-> NoWorkspace]
    /\ endpointRoot = {}
    /\ endpointBinding = [a \in Accounts |-> NoEndpoint]
    /\ inviteWorkspace = [i \in Invites |-> NoWorkspace]
    /\ inviteTarget = [i \in Invites |-> NoAccount]
    /\ actualRemoteEndpoint = NoEndpoint
    /\ claimedRemoteEndpoint = NoEndpoint
    /\ sourceAccount = NoAccount
    /\ targetAccount = NoAccount
    /\ inviteId = NoInvite
    /\ bootstrapAdmitted = FALSE
    /\ routeAdmitted = FALSE

\* ---- Local graph / replay actions ----

CreateEndpointRoot(e) ==
    /\ e \in Endpoints
    /\ e \notin endpointRoot
    /\ endpointRoot' = endpointRoot \union {e}
    /\ UNCHANGED
         << acceptedWorkspace,
            endpointBinding,
            inviteWorkspace,
            inviteTarget,
            actualRemoteEndpoint,
            claimedRemoteEndpoint,
            sourceAccount,
            targetAccount,
            inviteId,
            bootstrapAdmitted,
            routeAdmitted >>

\* invite_accepted: local accepted-workspace binding. This is the local anchor
\* that breaks the workspace bootstrap cycle; it does not require the workspace
\* event itself to have projected first.
AcceptWorkspace(local, w) ==
    /\ local \in LocalAccounts
    /\ w \in Workspaces
    /\ acceptedWorkspace[local] = NoWorkspace
    /\ acceptedWorkspace' = [acceptedWorkspace EXCEPT ![local] = w]
    /\ UNCHANGED
         << endpointRoot,
            endpointBinding,
            inviteWorkspace,
            inviteTarget,
            actualRemoteEndpoint,
            claimedRemoteEndpoint,
            sourceAccount,
            targetAccount,
            inviteId,
            bootstrapAdmitted,
            routeAdmitted >>

\* Local account binds to one of this daemon's replayed endpoint roots.
BindLocalEndpoint(local, e) ==
    /\ local \in LocalAccounts
    /\ e \in endpointRoot
    /\ acceptedWorkspace[local] # NoWorkspace
    /\ endpointBinding[local] = NoEndpoint
    /\ endpointBinding' = [endpointBinding EXCEPT ![local] = e]
    /\ UNCHANGED
         << acceptedWorkspace,
            endpointRoot,
            inviteWorkspace,
            inviteTarget,
            actualRemoteEndpoint,
            claimedRemoteEndpoint,
            sourceAccount,
            targetAccount,
            inviteId,
            bootstrapAdmitted,
            routeAdmitted >>

CreateInvite(inv, local) ==
    /\ inv \in Invites
    /\ local \in LocalAccounts
    /\ acceptedWorkspace[local] # NoWorkspace
    /\ inviteWorkspace[inv] = NoWorkspace
    /\ inviteTarget[inv] = NoAccount
    /\ inviteWorkspace' = [inviteWorkspace EXCEPT ![inv] = acceptedWorkspace[local]]
    /\ inviteTarget' = [inviteTarget EXCEPT ![inv] = local]
    /\ UNCHANGED
         << acceptedWorkspace,
            endpointRoot,
            endpointBinding,
            actualRemoteEndpoint,
            claimedRemoteEndpoint,
            sourceAccount,
            targetAccount,
            inviteId,
            bootstrapAdmitted,
            routeAdmitted >>

\* ---- Bootstrap connection actions ----

StartBootstrapAttempt(remoteEndpoint, claimedEndpoint, remoteAccount, inv) ==
    /\ remoteEndpoint \in Endpoints
    /\ claimedEndpoint \in Endpoints
    /\ remoteAccount \in RemoteAccounts
    /\ inv \in Invites
    /\ inviteTarget[inv] # NoAccount
    /\ actualRemoteEndpoint' = remoteEndpoint
    /\ claimedRemoteEndpoint' = claimedEndpoint
    /\ sourceAccount' = remoteAccount
    /\ targetAccount' = inviteTarget[inv]
    /\ inviteId' = inv
    /\ bootstrapAdmitted' = FALSE
    /\ routeAdmitted' = FALSE
    /\ UNCHANGED
         << acceptedWorkspace,
            endpointRoot,
            endpointBinding,
            inviteWorkspace,
            inviteTarget >>

\* A valid invite proof admits exactly one bootstrap scope:
\* the invite's target local account, its workspace, the claimed remote account,
\* and the actual remote endpoint authenticated by iroh.
AdmitBootstrap ==
    /\ inviteId # NoInvite
    /\ targetAccount # NoAccount
    /\ sourceAccount # NoAccount
    /\ inviteWorkspace[inviteId] # NoWorkspace
    /\ acceptedWorkspace[targetAccount] = inviteWorkspace[inviteId]
    /\ claimedRemoteEndpoint = actualRemoteEndpoint
    /\ bootstrapAdmitted' = TRUE
    /\ UNCHANGED
         << acceptedWorkspace,
            endpointRoot,
            endpointBinding,
            inviteWorkspace,
            inviteTarget,
            actualRemoteEndpoint,
            claimedRemoteEndpoint,
            sourceAccount,
            targetAccount,
            inviteId,
            routeAdmitted >>

\* Canonical graph convergence after bootstrap sync.
ProjectRemoteAccountFromBootstrap ==
    /\ bootstrapAdmitted
    /\ sourceAccount \in RemoteAccounts
    /\ acceptedWorkspace[sourceAccount] = NoWorkspace
    /\ acceptedWorkspace' =
        [acceptedWorkspace EXCEPT ![sourceAccount] = inviteWorkspace[inviteId]]
    /\ UNCHANGED
         << endpointRoot,
            endpointBinding,
            inviteWorkspace,
            inviteTarget,
            actualRemoteEndpoint,
            claimedRemoteEndpoint,
            sourceAccount,
            targetAccount,
            inviteId,
            bootstrapAdmitted,
            routeAdmitted >>

\* endpoint_shared: route authority comes from projected graph state.
ProjectRemoteEndpointBinding ==
    /\ bootstrapAdmitted
    /\ sourceAccount \in RemoteAccounts
    /\ acceptedWorkspace[sourceAccount] # NoWorkspace
    /\ endpointBinding[sourceAccount] = NoEndpoint
    /\ actualRemoteEndpoint # NoEndpoint
    /\ endpointBinding' = [endpointBinding EXCEPT ![sourceAccount] = actualRemoteEndpoint]
    /\ UNCHANGED
         << acceptedWorkspace,
            endpointRoot,
            inviteWorkspace,
            inviteTarget,
            actualRemoteEndpoint,
            claimedRemoteEndpoint,
            sourceAccount,
            targetAccount,
            inviteId,
            bootstrapAdmitted,
            routeAdmitted >>

\* ---- Steady-state routed session actions ----

StartRouteAttempt(remoteEndpoint, remoteAccount, local) ==
    /\ remoteEndpoint \in Endpoints
    /\ remoteAccount \in RemoteAccounts
    /\ local \in LocalAccounts
    /\ actualRemoteEndpoint' = remoteEndpoint
    /\ claimedRemoteEndpoint' = NoEndpoint
    /\ sourceAccount' = remoteAccount
    /\ targetAccount' = local
    /\ inviteId' = NoInvite
    /\ bootstrapAdmitted' = FALSE
    /\ routeAdmitted' = FALSE
    /\ UNCHANGED
         << acceptedWorkspace,
            endpointRoot,
            endpointBinding,
            inviteWorkspace,
            inviteTarget >>

\* OpenSessionRoute is pure routed admission: same workspace, exact endpoint.
AdmitRoute ==
    /\ sourceAccount # NoAccount
    /\ targetAccount # NoAccount
    /\ acceptedWorkspace[sourceAccount] # NoWorkspace
    /\ acceptedWorkspace[sourceAccount] = acceptedWorkspace[targetAccount]
    /\ endpointBinding[sourceAccount] = actualRemoteEndpoint
    /\ routeAdmitted' = TRUE
    /\ UNCHANGED
         << acceptedWorkspace,
            endpointRoot,
            endpointBinding,
            inviteWorkspace,
            inviteTarget,
            actualRemoteEndpoint,
            claimedRemoteEndpoint,
            sourceAccount,
            targetAccount,
            inviteId,
            bootstrapAdmitted >>

ClearConnection ==
    /\ actualRemoteEndpoint' = NoEndpoint
    /\ claimedRemoteEndpoint' = NoEndpoint
    /\ sourceAccount' = NoAccount
    /\ targetAccount' = NoAccount
    /\ inviteId' = NoInvite
    /\ bootstrapAdmitted' = FALSE
    /\ routeAdmitted' = FALSE
    /\ UNCHANGED
         << acceptedWorkspace,
            endpointRoot,
            endpointBinding,
            inviteWorkspace,
            inviteTarget >>

Next ==
    \/ \E e \in Endpoints : CreateEndpointRoot(e)
    \/ \E local \in LocalAccounts, w \in Workspaces : AcceptWorkspace(local, w)
    \/ \E local \in LocalAccounts, e \in Endpoints : BindLocalEndpoint(local, e)
    \/ \E inv \in Invites, local \in LocalAccounts : CreateInvite(inv, local)
    \/ \E remoteEndpoint, claimedEndpoint \in Endpoints,
          remoteAccount \in RemoteAccounts,
          inv \in Invites :
            StartBootstrapAttempt(remoteEndpoint, claimedEndpoint, remoteAccount, inv)
    \/ AdmitBootstrap
    \/ ProjectRemoteAccountFromBootstrap
    \/ ProjectRemoteEndpointBinding
    \/ \E remoteEndpoint \in Endpoints,
          remoteAccount \in RemoteAccounts,
          local \in LocalAccounts :
            StartRouteAttempt(remoteEndpoint, remoteAccount, local)
    \/ AdmitRoute
    \/ ClearConnection

Spec == Init /\ [][Next]_vars

\* ---- Invariants ----

\* endpoint_shared is never authoritative without a workspace binding.
InvEndpointBindingRequiresWorkspace ==
    \A a \in Accounts :
        endpointBinding[a] # NoEndpoint => acceptedWorkspace[a] # NoWorkspace

\* Bootstrap proof is exact to the transport endpoint that iroh authenticated.
InvBootstrapRequiresExactEndpoint ==
    bootstrapAdmitted => claimedRemoteEndpoint = actualRemoteEndpoint

\* Bootstrap proof is exact to the invite's intended local account.
InvBootstrapRequiresInviteTarget ==
    bootstrapAdmitted =>
        /\ inviteId # NoInvite
        /\ targetAccount = inviteTarget[inviteId]

\* Bootstrap proof is exact to the invite's workspace.
InvBootstrapRequiresInviteWorkspace ==
    bootstrapAdmitted =>
        /\ inviteId # NoInvite
        /\ inviteWorkspace[inviteId] # NoWorkspace
        /\ acceptedWorkspace[targetAccount] = inviteWorkspace[inviteId]

\* Summarized bootstrap safety property: unknown endpoints are never admitted
\* by node-global heuristics; admission is always tied to one concrete proof
\* scope.
InvBootstrapAdmissionProofScoped ==
    bootstrapAdmitted =>
        /\ inviteId # NoInvite
        /\ sourceAccount # NoAccount
        /\ targetAccount = inviteTarget[inviteId]
        /\ inviteWorkspace[inviteId] # NoWorkspace
        /\ acceptedWorkspace[targetAccount] = inviteWorkspace[inviteId]
        /\ claimedRemoteEndpoint = actualRemoteEndpoint

\* Steady-state routed sessions require exact shared-workspace routing.
InvRouteRequiresSharedWorkspace ==
    routeAdmitted =>
        /\ sourceAccount # NoAccount
        /\ targetAccount # NoAccount
        /\ acceptedWorkspace[sourceAccount] # NoWorkspace
        /\ acceptedWorkspace[sourceAccount] = acceptedWorkspace[targetAccount]

\* Steady-state routed sessions require exact endpoint_shared binding.
InvRouteRequiresExactEndpointBinding ==
    routeAdmitted => endpointBinding[sourceAccount] = actualRemoteEndpoint

\* Bootstrap admission by itself is not route authority; route authority comes
\* only from projected endpoint/account graph state.
InvRouteAuthorityComesFromGraph ==
    routeAdmitted =>
        /\ acceptedWorkspace[sourceAccount] # NoWorkspace
        /\ endpointBinding[sourceAccount] # NoEndpoint

\* Summarized steady-state safety property: routed admission is graph-scoped.
InvRouteAdmissionGraphScoped ==
    routeAdmitted =>
        /\ acceptedWorkspace[sourceAccount] # NoWorkspace
        /\ acceptedWorkspace[sourceAccount] = acceptedWorkspace[targetAccount]
        /\ endpointBinding[sourceAccount] = actualRemoteEndpoint

=============================================================================
