---- MODULE EndpointSharedGraphDraft ----
EXTENDS FiniteSets, TLC

\* Draft causal model for making `endpoint` first-class in the auth graph.
\*
\* Intended shape:
\* - `endpoint_secret` is local-only, replayable, and has no deps
\* - `endpoint_shared` is a shared, self-signed transport identity event
\*   derived from `endpoint_secret`; it has no canonical deps
\* - `account_shared` (today's peer/device identity) binds workspace membership
\*   to an `endpoint_shared`, so route authority is "account in workspace W is
\*   currently on endpoint E"
\* - bootstrap exactness still comes from invite proof on the first session
\* - steady-state sessions use routed admission only
\*
\* This spec is intentionally not wired into the runtime-check matrix yet. It
\* is a draft design aid for the next auth-graph refactor.

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
    endpointSecret,
    localEndpointShared,
    publishedEndpointShared,
    accountReady,
    accountEndpoint,
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
       endpointSecret,
       localEndpointShared,
       publishedEndpointShared,
       accountReady,
       accountEndpoint,
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
    /\ endpointSecret \subseteq Endpoints
    /\ localEndpointShared \subseteq Endpoints
    /\ publishedEndpointShared \subseteq Endpoints
    /\ accountReady \subseteq Accounts
    /\ accountEndpoint \in [Accounts -> Endpoints \union {NoEndpoint}]
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
    /\ endpointSecret = {}
    /\ localEndpointShared = {}
    /\ publishedEndpointShared = {}
    /\ accountReady = {}
    /\ accountEndpoint = [a \in Accounts |-> NoEndpoint]
    /\ inviteWorkspace = [i \in Invites |-> NoWorkspace]
    /\ inviteTarget = [i \in Invites |-> NoAccount]
    /\ actualRemoteEndpoint = NoEndpoint
    /\ claimedRemoteEndpoint = NoEndpoint
    /\ sourceAccount = NoAccount
    /\ targetAccount = NoAccount
    /\ inviteId = NoInvite
    /\ bootstrapAdmitted = FALSE
    /\ routeAdmitted = FALSE

\* ---- Local replay / shared identity publication ----

CreateEndpointSecret(e) ==
    /\ e \in Endpoints
    /\ e \notin endpointSecret
    /\ endpointSecret' = endpointSecret \union {e}
    /\ UNCHANGED
         << acceptedWorkspace,
            localEndpointShared,
            publishedEndpointShared,
            accountReady,
            accountEndpoint,
            inviteWorkspace,
            inviteTarget,
            actualRemoteEndpoint,
            claimedRemoteEndpoint,
            sourceAccount,
            targetAccount,
            inviteId,
            bootstrapAdmitted,
            routeAdmitted >>

\* endpoint_shared is the shared, self-signed transport identity derived from
\* endpoint_secret. It has no canonical deps.
PublishEndpointShared(e) ==
    /\ e \in endpointSecret
    /\ e \notin localEndpointShared
    /\ localEndpointShared' = localEndpointShared \union {e}
    /\ publishedEndpointShared' = publishedEndpointShared \union {e}
    /\ UNCHANGED
         << acceptedWorkspace,
            endpointSecret,
            accountReady,
            accountEndpoint,
            inviteWorkspace,
            inviteTarget,
            actualRemoteEndpoint,
            claimedRemoteEndpoint,
            sourceAccount,
            targetAccount,
            inviteId,
            bootstrapAdmitted,
            routeAdmitted >>

\* Remote replicas may learn a published endpoint_shared without holding the
\* corresponding local endpoint_secret.
ObservePublishedEndpointShared(e) ==
    /\ e \in Endpoints
    /\ e \notin publishedEndpointShared
    /\ publishedEndpointShared' = publishedEndpointShared \union {e}
    /\ UNCHANGED
         << acceptedWorkspace,
            endpointSecret,
            localEndpointShared,
            accountReady,
            accountEndpoint,
            inviteWorkspace,
            inviteTarget,
            actualRemoteEndpoint,
            claimedRemoteEndpoint,
            sourceAccount,
            targetAccount,
            inviteId,
            bootstrapAdmitted,
            routeAdmitted >>

\* invite_accepted: local binding that breaks the bootstrap cycle.
AcceptWorkspace(local, w) ==
    /\ local \in LocalAccounts
    /\ w \in Workspaces
    /\ acceptedWorkspace[local] = NoWorkspace
    /\ acceptedWorkspace' = [acceptedWorkspace EXCEPT ![local] = w]
    /\ UNCHANGED
         << endpointSecret,
            localEndpointShared,
            publishedEndpointShared,
            accountReady,
            accountEndpoint,
            inviteWorkspace,
            inviteTarget,
            actualRemoteEndpoint,
            claimedRemoteEndpoint,
            sourceAccount,
            targetAccount,
            inviteId,
            bootstrapAdmitted,
            routeAdmitted >>

\* account_shared (today's peer/device identity) may project only after the
\* local workspace is accepted and the referenced endpoint_shared exists.
CreateLocalAccountShared(local, e) ==
    /\ local \in LocalAccounts
    /\ acceptedWorkspace[local] # NoWorkspace
    /\ e \in localEndpointShared
    /\ local \notin accountReady
    /\ accountReady' = accountReady \union {local}
    /\ accountEndpoint' = [accountEndpoint EXCEPT ![local] = e]
    /\ UNCHANGED
         << acceptedWorkspace,
            endpointSecret,
            localEndpointShared,
            publishedEndpointShared,
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
    /\ local \in accountReady
    /\ inviteWorkspace[inv] = NoWorkspace
    /\ inviteTarget[inv] = NoAccount
    /\ inviteWorkspace' = [inviteWorkspace EXCEPT ![inv] = acceptedWorkspace[local]]
    /\ inviteTarget' = [inviteTarget EXCEPT ![inv] = local]
    /\ UNCHANGED
         << acceptedWorkspace,
            endpointSecret,
            localEndpointShared,
            publishedEndpointShared,
            accountReady,
            accountEndpoint,
            actualRemoteEndpoint,
            claimedRemoteEndpoint,
            sourceAccount,
            targetAccount,
            inviteId,
            bootstrapAdmitted,
            routeAdmitted >>

\* ---- Bootstrap admission ----

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
            endpointSecret,
            localEndpointShared,
            publishedEndpointShared,
            accountReady,
            accountEndpoint,
            inviteWorkspace,
            inviteTarget >>

\* First-session bootstrap proof is exact, but it does not require
\* endpoint_shared or account_shared to have projected yet.
AdmitBootstrap ==
    /\ inviteId # NoInvite
    /\ targetAccount # NoAccount
    /\ sourceAccount # NoAccount
    /\ targetAccount \in accountReady
    /\ inviteWorkspace[inviteId] # NoWorkspace
    /\ acceptedWorkspace[targetAccount] = inviteWorkspace[inviteId]
    /\ claimedRemoteEndpoint = actualRemoteEndpoint
    /\ bootstrapAdmitted' = TRUE
    /\ UNCHANGED
         << acceptedWorkspace,
            endpointSecret,
            localEndpointShared,
            publishedEndpointShared,
            accountReady,
            accountEndpoint,
            inviteWorkspace,
            inviteTarget,
            actualRemoteEndpoint,
            claimedRemoteEndpoint,
            sourceAccount,
            targetAccount,
            inviteId,
            routeAdmitted >>

\* After bootstrap sync, the remote endpoint_shared may arrive independently.
ProjectRemoteEndpointShared ==
    /\ bootstrapAdmitted
    /\ actualRemoteEndpoint # NoEndpoint
    /\ actualRemoteEndpoint \notin publishedEndpointShared
    /\ publishedEndpointShared' = publishedEndpointShared \union {actualRemoteEndpoint}
    /\ UNCHANGED
         << acceptedWorkspace,
            endpointSecret,
            localEndpointShared,
            accountReady,
            accountEndpoint,
            inviteWorkspace,
            inviteTarget,
            actualRemoteEndpoint,
            claimedRemoteEndpoint,
            sourceAccount,
            targetAccount,
            inviteId,
            bootstrapAdmitted,
            routeAdmitted >>

\* account_shared for the remote account is only graph-authoritative after the
\* referenced endpoint_shared is present.
ProjectRemoteAccountShared ==
    /\ bootstrapAdmitted
    /\ sourceAccount \in RemoteAccounts
    /\ sourceAccount \notin accountReady
    /\ inviteId # NoInvite
    /\ inviteWorkspace[inviteId] # NoWorkspace
    /\ actualRemoteEndpoint \in publishedEndpointShared
    /\ accountReady' = accountReady \union {sourceAccount}
    /\ acceptedWorkspace' =
        [acceptedWorkspace EXCEPT ![sourceAccount] = inviteWorkspace[inviteId]]
    /\ accountEndpoint' =
        [accountEndpoint EXCEPT ![sourceAccount] = actualRemoteEndpoint]
    /\ UNCHANGED
         << endpointSecret,
            localEndpointShared,
            publishedEndpointShared,
            inviteWorkspace,
            inviteTarget,
            actualRemoteEndpoint,
            claimedRemoteEndpoint,
            sourceAccount,
            targetAccount,
            inviteId,
            bootstrapAdmitted,
            routeAdmitted >>

\* ---- Steady-state routed sessions ----

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
            endpointSecret,
            localEndpointShared,
            publishedEndpointShared,
            accountReady,
            accountEndpoint,
            inviteWorkspace,
            inviteTarget >>

\* Steady-state routed admission comes only from graph state:
\* same workspace, source account projected, exact bound endpoint.
AdmitRoute ==
    /\ sourceAccount # NoAccount
    /\ targetAccount # NoAccount
    /\ sourceAccount \in accountReady
    /\ targetAccount \in accountReady
    /\ acceptedWorkspace[sourceAccount] # NoWorkspace
    /\ acceptedWorkspace[sourceAccount] = acceptedWorkspace[targetAccount]
    /\ accountEndpoint[sourceAccount] = actualRemoteEndpoint
    /\ routeAdmitted' = TRUE
    /\ UNCHANGED
         << acceptedWorkspace,
            endpointSecret,
            localEndpointShared,
            publishedEndpointShared,
            accountReady,
            accountEndpoint,
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
            endpointSecret,
            localEndpointShared,
            publishedEndpointShared,
            accountReady,
            accountEndpoint,
            inviteWorkspace,
            inviteTarget >>

Next ==
    \/ \E e \in Endpoints : CreateEndpointSecret(e)
    \/ \E e \in Endpoints : PublishEndpointShared(e)
    \/ \E e \in Endpoints : ObservePublishedEndpointShared(e)
    \/ \E local \in LocalAccounts, w \in Workspaces : AcceptWorkspace(local, w)
    \/ \E local \in LocalAccounts, e \in Endpoints : CreateLocalAccountShared(local, e)
    \/ \E inv \in Invites, local \in LocalAccounts : CreateInvite(inv, local)
    \/ \E remoteEndpoint, claimedEndpoint \in Endpoints,
          remoteAccount \in RemoteAccounts,
          inv \in Invites :
            StartBootstrapAttempt(remoteEndpoint, claimedEndpoint, remoteAccount, inv)
    \/ AdmitBootstrap
    \/ ProjectRemoteEndpointShared
    \/ ProjectRemoteAccountShared
    \/ \E remoteEndpoint \in Endpoints,
          remoteAccount \in RemoteAccounts,
          local \in LocalAccounts :
            StartRouteAttempt(remoteEndpoint, remoteAccount, local)
    \/ AdmitRoute
    \/ ClearConnection

Spec == Init /\ [][Next]_vars

\* ---- Invariants ----

\* Shared endpoint identity must originate from a local replay root.
InvPublishedEndpointRequiresLocalRoot ==
    localEndpointShared \subseteq endpointSecret

\* Any account admitted to the graph must already belong to exactly one
\* workspace in this simplified model.
InvAccountRequiresWorkspace ==
    \A a \in accountReady : acceptedWorkspace[a] # NoWorkspace

\* account_shared cannot bind to an unpublished endpoint identity.
InvAccountEndpointRequiresPublishedEndpoint ==
    \A a \in accountReady : accountEndpoint[a] \in publishedEndpointShared

\* Bootstrap proof is always exact to the endpoint that iroh authenticated.
InvBootstrapRequiresExactEndpoint ==
    bootstrapAdmitted => claimedRemoteEndpoint = actualRemoteEndpoint

\* Bootstrap proof is always exact to the invite's local target and workspace.
InvBootstrapRequiresExactInviteScope ==
    bootstrapAdmitted =>
        /\ inviteId # NoInvite
        /\ targetAccount = inviteTarget[inviteId]
        /\ acceptedWorkspace[targetAccount] = inviteWorkspace[inviteId]

\* Route authority comes only from projected account+endpoint graph state.
InvRouteRequiresGraphScopedAccountEndpoint ==
    routeAdmitted =>
        /\ sourceAccount \in accountReady
        /\ targetAccount \in accountReady
        /\ acceptedWorkspace[sourceAccount] = acceptedWorkspace[targetAccount]
        /\ accountEndpoint[sourceAccount] = actualRemoteEndpoint

\* Same endpoint may back many accounts, but route scope remains per-account.
InvRouteCannotCrossWorkspaceOnSharedEndpoint ==
    routeAdmitted =>
        /\ acceptedWorkspace[sourceAccount] # NoWorkspace
        /\ acceptedWorkspace[sourceAccount] = acceptedWorkspace[targetAccount]

=============================================================================
