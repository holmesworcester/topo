---- MODULE LocalOperationalCausality ----
EXTENDS FiniteSets, TLC

\* Focused architecture model for the local-operational-events design.
\*
\* Core idea:
\*   causal dependencies between events are the primary thing.
\*
\* The model centers three surfaces:
\* 1) `occurred`            : the local event graph itself
\* 2) derived projection    : pure operators over `occurred`
\* 3) thin runtime shell    : actual listeners / connections / sync rounds
\*
\* Projection is modeled as a pure reduction from occurred events, not as
\* mutable imperative manager state. This makes the causality structure the
\* center of the model.
\*
\* Scope of this first-pass model:
\* - client configuration events
\* - listener reconciliation
\* - connection planning/authentication with stable `connection_id`
\* - sync-round selection/completion with stable `sync_round_id`
\* - a bug toggle for ad hoc runtime resources created without causal event basis
\*
\* Explicitly out of scope here:
\* - inbound/responder half of bilateral stitching
\* - connection/session closure paths
\* - mDNS-specific wire detail
\* - dependency fetch episodes

CONSTANTS Clients, Peers, ListenerIds, ConnectionIds, RoundIds, UseBuggyPolicyLeak

JobKinds == {"connect", "sync"}

VARIABLES occurred, actualListeners, actualConnections, actualSyncRounds

vars == <<occurred, actualListeners, actualConnections, actualSyncRounds>>

\* ---------------------------------------------------------------------------
\* Event constructors
\* ---------------------------------------------------------------------------

ClientDefined(c) == <<"client_defined", c>>
StorageBound(c) == <<"client_storage_bound", c>>
ListenerConfigured(c, l) == <<"client_listener_configured", c, l>>
JobPolicyConfigured(c, j) == <<"client_job_policy_configured", c, j>>
ClientStarted(c) == <<"client_started", c>>
JobDue(c, j) == <<"job_due", c, j>>
ListenerBound(c, l) == <<"listener_bound", c, l>>
ConnectionPlanned(c, p, cid) == <<"connection_planned", c, p, cid>>
ConnectionAuthenticated(c, p, cid) == <<"connection_authenticated", c, p, cid>>
SyncWindowSelected(c, p, cid, rid) == <<"sync_window_selected", c, p, cid, rid>>
SyncRoundCompleted(c, p, cid, rid) == <<"sync_round_completed", c, p, cid, rid>>

ClientDefinedEvents == {ClientDefined(c) : c \in Clients}
StorageBoundEvents == {StorageBound(c) : c \in Clients}
ListenerConfiguredEvents == {ListenerConfigured(c, l) : c \in Clients, l \in ListenerIds}
JobPolicyConfiguredEvents == {JobPolicyConfigured(c, j) : c \in Clients, j \in JobKinds}
ClientStartedEvents == {ClientStarted(c) : c \in Clients}
JobDueEvents == {JobDue(c, j) : c \in Clients, j \in JobKinds}
ListenerBoundEvents == {ListenerBound(c, l) : c \in Clients, l \in ListenerIds}
ConnectionPlannedEvents ==
    {ConnectionPlanned(c, p, cid) : c \in Clients, p \in Peers, cid \in ConnectionIds}
ConnectionAuthenticatedEvents ==
    {ConnectionAuthenticated(c, p, cid) : c \in Clients, p \in Peers, cid \in ConnectionIds}
SyncWindowSelectedEvents ==
    {SyncWindowSelected(c, p, cid, rid) :
        c \in Clients, p \in Peers, cid \in ConnectionIds, rid \in RoundIds}
SyncRoundCompletedEvents ==
    {SyncRoundCompleted(c, p, cid, rid) :
        c \in Clients, p \in Peers, cid \in ConnectionIds, rid \in RoundIds}

AllEvents ==
    ClientDefinedEvents
    \union StorageBoundEvents
    \union ListenerConfiguredEvents
    \union JobPolicyConfiguredEvents
    \union ClientStartedEvents
    \union JobDueEvents
    \union ListenerBoundEvents
    \union ConnectionPlannedEvents
    \union ConnectionAuthenticatedEvents
    \union SyncWindowSelectedEvents
    \union SyncRoundCompletedEvents

\* ---------------------------------------------------------------------------
\* Pure projection surfaces derived from occurred events
\* ---------------------------------------------------------------------------

ProjectedClients ==
    {c \in Clients : ClientDefined(c) \in occurred}

ProjectedStorage ==
    {c \in Clients : StorageBound(c) \in occurred}

ProjectedDesiredListeners ==
    {<<c, l>> \in (Clients \X ListenerIds) : ListenerConfigured(c, l) \in occurred}

ProjectedEnabledJobs ==
    {<<c, j>> \in (Clients \X JobKinds) : JobPolicyConfigured(c, j) \in occurred}

ProjectedStartedClients ==
    {c \in Clients : ClientStarted(c) \in occurred}

ProjectedPlannedConnections ==
    {<<c, p, cid>> \in (Clients \X Peers \X ConnectionIds) :
        ConnectionPlanned(c, p, cid) \in occurred}

ProjectedSelectedRounds ==
    {<<c, p, cid, rid>> \in (Clients \X Peers \X ConnectionIds \X RoundIds) :
        SyncWindowSelected(c, p, cid, rid) \in occurred}

HasBoundListener(c) ==
    \E l \in ListenerIds : <<c, l>> \in actualListeners

HasLiveConnection(c, p) ==
    \E cid \in ConnectionIds : <<c, p, cid>> \in actualConnections

NoPlannedOrLiveConnection(c, p) ==
    ~(\E cid \in ConnectionIds :
        <<c, p, cid>> \in ProjectedPlannedConnections
        \/ <<c, p, cid>> \in actualConnections)

NoSelectedOrCompletedRound(c, p, cid) ==
    ~(\E rid \in RoundIds :
        <<c, p, cid, rid>> \in ProjectedSelectedRounds
        \/ <<c, p, cid, rid>> \in actualSyncRounds)

\* ---------------------------------------------------------------------------
\* Causal dependency operator
\* ---------------------------------------------------------------------------

Deps(e) ==
    CASE e \in ClientDefinedEvents -> {}
      [] e \in StorageBoundEvents ->
            {ClientDefined(e[2])}
      [] e \in ListenerConfiguredEvents -> {ClientDefined(e[2])}
      [] e \in JobPolicyConfiguredEvents -> {ClientDefined(e[2])}
      [] e \in ClientStartedEvents ->
            {StorageBound(e[2])}
            \union {ListenerConfigured(e[2], l) : l \in ListenerIds}
            \union {JobPolicyConfigured(e[2], j) : j \in JobKinds}
      [] e \in JobDueEvents ->
            {ClientStarted(e[2]), JobPolicyConfigured(e[2], e[3])}
      [] e \in ListenerBoundEvents ->
            {ClientStarted(e[2]), ListenerConfigured(e[2], e[3])}
      [] e \in ConnectionPlannedEvents ->
            {JobDue(e[2], "connect")}
      [] e \in ConnectionAuthenticatedEvents ->
            {ConnectionPlanned(e[2], e[3], e[4])}
      [] e \in SyncWindowSelectedEvents ->
            {JobDue(e[2], "sync"), ConnectionAuthenticated(e[2], e[3], e[4])}
      [] e \in SyncRoundCompletedEvents ->
            {SyncWindowSelected(e[2], e[3], e[4], e[5])}
      [] OTHER -> {}

\* ---------------------------------------------------------------------------
\* Type / invariants
\* ---------------------------------------------------------------------------

TypeOK ==
    /\ UseBuggyPolicyLeak \in BOOLEAN
    /\ occurred \subseteq AllEvents
    /\ actualListeners \subseteq (Clients \X ListenerIds)
    /\ actualConnections \subseteq (Clients \X Peers \X ConnectionIds)
    /\ actualSyncRounds \subseteq (Clients \X Peers \X ConnectionIds \X RoundIds)

InvEventDepsSatisfied ==
    \A e \in occurred : Deps(e) \subseteq occurred

InvProjectedConfigHasEventCause ==
    /\ ProjectedClients = {c \in Clients : ClientDefined(c) \in occurred}
    /\ ProjectedStorage = {c \in Clients : StorageBound(c) \in occurred}
    /\ ProjectedDesiredListeners =
         {<<c, l>> \in (Clients \X ListenerIds) : ListenerConfigured(c, l) \in occurred}
    /\ ProjectedEnabledJobs =
         {<<c, j>> \in (Clients \X JobKinds) : JobPolicyConfigured(c, j) \in occurred}

InvStartedClientHasConfig ==
    \A c \in ProjectedStartedClients :
        /\ c \in ProjectedClients
        /\ c \in ProjectedStorage
        /\ \E l \in ListenerIds : <<c, l>> \in ProjectedDesiredListeners
        /\ \A j \in JobKinds : <<c, j>> \in ProjectedEnabledJobs

InvActualListenerHasCausalBasis ==
    \A c \in Clients, l \in ListenerIds :
        <<c, l>> \in actualListeners =>
            /\ ListenerBound(c, l) \in occurred
            /\ ListenerConfigured(c, l) \in occurred
            /\ ClientStarted(c) \in occurred

InvActualConnectionHasCausalBasis ==
    \A c \in Clients, p \in Peers, cid \in ConnectionIds :
        <<c, p, cid>> \in actualConnections =>
            /\ ConnectionAuthenticated(c, p, cid) \in occurred
            /\ ConnectionPlanned(c, p, cid) \in occurred
            /\ JobDue(c, "connect") \in occurred

InvActualSyncHasCausalBasis ==
    \A c \in Clients, p \in Peers, cid \in ConnectionIds, rid \in RoundIds :
        <<c, p, cid, rid>> \in actualSyncRounds =>
            /\ SyncRoundCompleted(c, p, cid, rid) \in occurred
            /\ SyncWindowSelected(c, p, cid, rid) \in occurred
            /\ ConnectionAuthenticated(c, p, cid) \in occurred
            /\ JobDue(c, "sync") \in occurred

InvNoAdHocRuntimeState ==
    /\ InvActualListenerHasCausalBasis
    /\ InvActualConnectionHasCausalBasis
    /\ InvActualSyncHasCausalBasis

InvEpisodeIdsComeFromPlanner ==
    /\ \A c \in Clients, p \in Peers, cid \in ConnectionIds :
        ConnectionAuthenticated(c, p, cid) \in occurred =>
            ConnectionPlanned(c, p, cid) \in occurred
    /\ \A c \in Clients, p \in Peers, cid \in ConnectionIds, rid \in RoundIds :
        SyncRoundCompleted(c, p, cid, rid) \in occurred =>
            SyncWindowSelected(c, p, cid, rid) \in occurred

ProgressGoal ==
    \E c \in Clients, p \in Peers, cid \in ConnectionIds, rid \in RoundIds :
        <<c, p, cid, rid>> \in actualSyncRounds

ProgressToSync == <>ProgressGoal

\* ---------------------------------------------------------------------------
\* Init
\* ---------------------------------------------------------------------------

Init ==
    /\ occurred = {}
    /\ actualListeners = {}
    /\ actualConnections = {}
    /\ actualSyncRounds = {}

\* ---------------------------------------------------------------------------
\* Event and observation actions
\* ---------------------------------------------------------------------------

EmitClientDefined_(c) ==
    /\ c \in Clients
    /\ ClientDefined(c) \notin occurred
    /\ occurred' = occurred \union {ClientDefined(c)}
    /\ UNCHANGED <<actualListeners, actualConnections, actualSyncRounds>>

EmitStorageBound_(c) ==
    /\ c \in Clients
    /\ ClientDefined(c) \in occurred
    /\ StorageBound(c) \notin occurred
    /\ occurred' = occurred \union {StorageBound(c)}
    /\ UNCHANGED <<actualListeners, actualConnections, actualSyncRounds>>

EmitListenerConfigured_(c, l) ==
    /\ c \in Clients
    /\ l \in ListenerIds
    /\ ClientDefined(c) \in occurred
    /\ ListenerConfigured(c, l) \notin occurred
    /\ occurred' = occurred \union {ListenerConfigured(c, l)}
    /\ UNCHANGED <<actualListeners, actualConnections, actualSyncRounds>>

EmitJobPolicyConfigured_(c, j) ==
    /\ c \in Clients
    /\ j \in JobKinds
    /\ ClientDefined(c) \in occurred
    /\ JobPolicyConfigured(c, j) \notin occurred
    /\ occurred' = occurred \union {JobPolicyConfigured(c, j)}
    /\ UNCHANGED <<actualListeners, actualConnections, actualSyncRounds>>

EmitClientStarted_(c) ==
    /\ c \in Clients
    /\ ClientStarted(c) \notin occurred
    /\ StorageBound(c) \in occurred
    /\ \A l \in ListenerIds : ListenerConfigured(c, l) \in occurred
    /\ \A j \in JobKinds : JobPolicyConfigured(c, j) \in occurred
    /\ occurred' = occurred \union {ClientStarted(c)}
    /\ UNCHANGED <<actualListeners, actualConnections, actualSyncRounds>>

EmitListenerBound_(c, l) ==
    /\ c \in Clients
    /\ l \in ListenerIds
    /\ ListenerBound(c, l) \notin occurred
    /\ <<c, l>> \in ProjectedDesiredListeners
    /\ c \in ProjectedStartedClients
    /\ <<c, l>> \notin actualListeners
    /\ occurred' = occurred \union {ListenerBound(c, l)}
    /\ actualListeners' = actualListeners \union {<<c, l>>}
    /\ UNCHANGED <<actualConnections, actualSyncRounds>>

EmitJobDueConnect_(c) ==
    /\ c \in Clients
    /\ JobDue(c, "connect") \notin occurred
    /\ c \in ProjectedStartedClients
    /\ <<c, "connect">> \in ProjectedEnabledJobs
    /\ \E p \in Peers : NoPlannedOrLiveConnection(c, p)
    /\ occurred' = occurred \union {JobDue(c, "connect")}
    /\ UNCHANGED <<actualListeners, actualConnections, actualSyncRounds>>

EmitConnectionPlanned_(c, p, cid) ==
    /\ c \in Clients
    /\ p \in Peers
    /\ cid \in ConnectionIds
    /\ JobDue(c, "connect") \in occurred
    /\ ConnectionPlanned(c, p, cid) \notin occurred
    /\ NoPlannedOrLiveConnection(c, p)
    /\ occurred' = occurred \union {ConnectionPlanned(c, p, cid)}
    /\ UNCHANGED <<actualListeners, actualConnections, actualSyncRounds>>

EmitConnectionAuthenticated_(c, p, cid) ==
    /\ c \in Clients
    /\ p \in Peers
    /\ cid \in ConnectionIds
    /\ ConnectionAuthenticated(c, p, cid) \notin occurred
    /\ <<c, p, cid>> \in ProjectedPlannedConnections
    /\ HasBoundListener(c)
    /\ <<c, p, cid>> \notin actualConnections
    /\ occurred' = occurred \union {ConnectionAuthenticated(c, p, cid)}
    /\ actualConnections' = actualConnections \union {<<c, p, cid>>}
    /\ UNCHANGED <<actualListeners, actualSyncRounds>>

EmitJobDueSync_(c) ==
    /\ c \in Clients
    /\ JobDue(c, "sync") \notin occurred
    /\ c \in ProjectedStartedClients
    /\ <<c, "sync">> \in ProjectedEnabledJobs
    /\ \E p \in Peers, cid \in ConnectionIds :
        <<c, p, cid>> \in actualConnections /\ NoSelectedOrCompletedRound(c, p, cid)
    /\ occurred' = occurred \union {JobDue(c, "sync")}
    /\ UNCHANGED <<actualListeners, actualConnections, actualSyncRounds>>

EmitSyncWindowSelected_(c, p, cid, rid) ==
    /\ c \in Clients
    /\ p \in Peers
    /\ cid \in ConnectionIds
    /\ rid \in RoundIds
    /\ JobDue(c, "sync") \in occurred
    /\ <<c, p, cid>> \in actualConnections
    /\ SyncWindowSelected(c, p, cid, rid) \notin occurred
    /\ NoSelectedOrCompletedRound(c, p, cid)
    /\ occurred' = occurred \union {SyncWindowSelected(c, p, cid, rid)}
    /\ UNCHANGED <<actualListeners, actualConnections, actualSyncRounds>>

EmitSyncRoundCompleted_(c, p, cid, rid) ==
    /\ c \in Clients
    /\ p \in Peers
    /\ cid \in ConnectionIds
    /\ rid \in RoundIds
    /\ SyncRoundCompleted(c, p, cid, rid) \notin occurred
    /\ <<c, p, cid, rid>> \in ProjectedSelectedRounds
    /\ <<c, p, cid>> \in actualConnections
    /\ <<c, p, cid, rid>> \notin actualSyncRounds
    /\ occurred' = occurred \union {SyncRoundCompleted(c, p, cid, rid)}
    /\ actualSyncRounds' = actualSyncRounds \union {<<c, p, cid, rid>>}
    /\ UNCHANGED <<actualListeners, actualConnections>>

\* Bug toggle: allows the runtime to create a live listener without any
\* projected desired state or causal event chain.
BuggyAdHocListenerBound_(c, l) ==
    /\ UseBuggyPolicyLeak
    /\ c \in Clients
    /\ l \in ListenerIds
    /\ ListenerBound(c, l) \notin occurred
    /\ <<c, l>> \notin actualListeners
    /\ occurred' = occurred \union {ListenerBound(c, l)}
    /\ actualListeners' = actualListeners \union {<<c, l>>}
    /\ UNCHANGED <<actualConnections, actualSyncRounds>>

\* ---------------------------------------------------------------------------
\* Aggregated action groups (useful for fairness configs)
\* ---------------------------------------------------------------------------

EmitClientDefined ==
    \E c \in Clients : EmitClientDefined_(c)

EmitStorageBound ==
    \E c \in Clients : EmitStorageBound_(c)

EmitListenerConfigured ==
    \E c \in Clients, l \in ListenerIds : EmitListenerConfigured_(c, l)

EmitJobPolicyConfigured ==
    \E c \in Clients, j \in JobKinds : EmitJobPolicyConfigured_(c, j)

EmitClientStarted ==
    \E c \in Clients : EmitClientStarted_(c)

EmitListenerBound ==
    \E c \in Clients, l \in ListenerIds : EmitListenerBound_(c, l)

EmitJobDueConnect ==
    \E c \in Clients : EmitJobDueConnect_(c)

EmitConnectionPlanned ==
    \E c \in Clients, p \in Peers, cid \in ConnectionIds :
        EmitConnectionPlanned_(c, p, cid)

EmitConnectionAuthenticated ==
    \E c \in Clients, p \in Peers, cid \in ConnectionIds :
        EmitConnectionAuthenticated_(c, p, cid)

EmitJobDueSync ==
    \E c \in Clients : EmitJobDueSync_(c)

EmitSyncWindowSelected ==
    \E c \in Clients, p \in Peers, cid \in ConnectionIds, rid \in RoundIds :
        EmitSyncWindowSelected_(c, p, cid, rid)

EmitSyncRoundCompleted ==
    \E c \in Clients, p \in Peers, cid \in ConnectionIds, rid \in RoundIds :
        EmitSyncRoundCompleted_(c, p, cid, rid)

BuggyAdHocListenerBound ==
    \E c \in Clients, l \in ListenerIds : BuggyAdHocListenerBound_(c, l)

\* ---------------------------------------------------------------------------
\* Next / specs
\* ---------------------------------------------------------------------------

Next ==
    \/ EmitClientDefined
    \/ EmitStorageBound
    \/ EmitListenerConfigured
    \/ EmitJobPolicyConfigured
    \/ EmitClientStarted
    \/ EmitListenerBound
    \/ EmitJobDueConnect
    \/ EmitConnectionPlanned
    \/ EmitConnectionAuthenticated
    \/ EmitJobDueSync
    \/ EmitSyncWindowSelected
    \/ EmitSyncRoundCompleted
    \/ BuggyAdHocListenerBound

Spec ==
    Init /\ [][Next]_vars

SpecProgress ==
    Spec
    /\ WF_vars(EmitClientDefined)
    /\ WF_vars(EmitStorageBound)
    /\ WF_vars(EmitListenerConfigured)
    /\ WF_vars(EmitJobPolicyConfigured)
    /\ WF_vars(EmitClientStarted)
    /\ WF_vars(EmitListenerBound)
    /\ WF_vars(EmitJobDueConnect)
    /\ WF_vars(EmitConnectionPlanned)
    /\ WF_vars(EmitConnectionAuthenticated)
    /\ WF_vars(EmitJobDueSync)
    /\ WF_vars(EmitSyncWindowSelected)
    /\ WF_vars(EmitSyncRoundCompleted)

=============================================================================
