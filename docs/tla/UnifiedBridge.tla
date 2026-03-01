---- MODULE UnifiedBridge ----
EXTENDS FiniteSets, TLC, Integers

\* Bridge model between EventGraphSchema-style event facts and
\* TransportCredentialLifecycle-style runtime trust/connection behavior.
\*
\* Surfaces:
\* 1) Event facts (EF_*): invite ownership, bootstrap facts, peer_shared facts, removal facts.
\* 2) Projection write intents (PW_*): abstract rows for trust and connection state.
\* 3) Runtime decisions (RT_*): derived trust/auth/dial operators from projected rows.
\*
\* This module keeps runtime materialization as a pure reduction of write-intent rows
\* (no separate mutable RT table), and proves bridge invariants over that reduction.
\*
\* Bug toggle:
\*   UseBuggyPendingGate = TRUE simulates legacy suppression of pending bootstrap trust
\*   when inviter local credential is already peer_shared-trusted.

CONSTANTS Peers, SPKIs, UseBuggyPendingGate

VARIABLES
    localCred,
    efInviteCreator,
    efBootstrapFacts,
    efPeerSharedFacts,
    efRemovedFacts,
    efPendingFacts,
    pwPeerSharedRows,
    pwBootstrapRows,
    pwPendingRows,
    pwConnState,
    syncComplete,
    fallbackAttempted,
    pendingProjectionViolation

vars ==
    << localCred,
       efInviteCreator,
       efBootstrapFacts,
       efPeerSharedFacts,
       efRemovedFacts,
       efPendingFacts,
       pwPeerSharedRows,
       pwBootstrapRows,
       pwPendingRows,
       pwConnState,
       syncComplete,
       fallbackAttempted,
       pendingProjectionViolation >>

NonePeer == "none_peer"
NoneSPKI == "none_spki"
ConnStates == {"none", "deny", "invite", "peer"}
PeerSPKIPairs == Peers \X SPKIs

ASSUME /\ NonePeer \notin Peers
       /\ NoneSPKI \notin SPKIs

Pair(p, s) == <<p, s>>
Removed(p, s) == Pair(p, s) \in efRemovedFacts
ActiveCreds == {localCred[p] : p \in Peers} \ {NoneSPKI}

\* ---- Runtime reduction (rows -> decisions) ----

RT_PeerSharedTrust(p) == {s \in SPKIs : Pair(p, s) \in pwPeerSharedRows}
RT_BootstrapTrust(p) == {s \in SPKIs : Pair(p, s) \in pwBootstrapRows}
RT_PendingTrust(p) == {s \in SPKIs : Pair(p, s) \in pwPendingRows}
RT_TrustedSPKIs(p) ==
    RT_PeerSharedTrust(p) \union RT_BootstrapTrust(p) \union RT_PendingTrust(p)

CanDialOngoing(p, q) ==
    /\ localCred[q] # NoneSPKI
    /\ localCred[q] \in RT_PeerSharedTrust(p)
    /\ ~Removed(p, localCred[q])

CanDialFallback(p, q) ==
    /\ localCred[q] # NoneSPKI
    /\ ~CanDialOngoing(p, q)
    /\ localCred[q] \in (RT_BootstrapTrust(p) \union RT_PendingTrust(p))
    /\ ~Removed(p, localCred[q])

CanAuthorize(p, q) == CanDialOngoing(p, q) \/ CanDialFallback(p, q)

DialPreference(p, q) ==
    IF CanDialOngoing(p, q) THEN "ongoing"
    ELSE IF CanDialFallback(p, q) THEN "bootstrap_fallback"
    ELSE "deny"

PendingEventCause(p, s) ==
    /\ efInviteCreator[s] = p
    /\ Pair(p, s) \notin pwPeerSharedRows

BlockedByRemoval(p, q) ==
    /\ localCred[q] # NoneSPKI
    /\ Removed(p, localCred[q])

BuggyPendingSuppressionEnabled(p, s) ==
    /\ UseBuggyPendingGate
    /\ localCred[p] # NoneSPKI
    /\ Pair(p, localCred[p]) \in pwPeerSharedRows
    /\ Pair(p, s) \notin pwPeerSharedRows

\* ---- Type invariant ----

TypeOK ==
    /\ UseBuggyPendingGate \in BOOLEAN
    /\ localCred \in [Peers -> SPKIs \union {NoneSPKI}]
    /\ efInviteCreator \in [SPKIs -> Peers \union {NonePeer}]
    /\ efBootstrapFacts \subseteq PeerSPKIPairs
    /\ efPeerSharedFacts \subseteq PeerSPKIPairs
    /\ efRemovedFacts \subseteq PeerSPKIPairs
    /\ efPendingFacts \subseteq PeerSPKIPairs
    /\ pwPeerSharedRows \subseteq PeerSPKIPairs
    /\ pwBootstrapRows \subseteq PeerSPKIPairs
    /\ pwPendingRows \subseteq PeerSPKIPairs
    /\ pwConnState \in [Peers -> [Peers -> ConnStates]]
    /\ syncComplete \in [Peers -> [Peers -> BOOLEAN]]
    /\ fallbackAttempted \in [Peers -> [Peers -> BOOLEAN]]
    /\ pendingProjectionViolation \in BOOLEAN

\* ---- Init ----

Init ==
    /\ localCred = [p \in Peers |-> NoneSPKI]
    /\ efInviteCreator = [s \in SPKIs |-> NonePeer]
    /\ efBootstrapFacts = {}
    /\ efPeerSharedFacts = {}
    /\ efRemovedFacts = {}
    /\ efPendingFacts = {}
    /\ pwPeerSharedRows = {}
    /\ pwBootstrapRows = {}
    /\ pwPendingRows = {}
    /\ pwConnState = [p \in Peers |-> [q \in Peers |-> "none"]]
    /\ syncComplete = [p \in Peers |-> [q \in Peers |-> FALSE]]
    /\ fallbackAttempted = [p \in Peers |-> [q \in Peers |-> FALSE]]
    /\ pendingProjectionViolation = FALSE

\* ---- Event-fact actions ----

InstallLocalCred(p, s) ==
    /\ localCred[p] = NoneSPKI
    /\ s \notin ActiveCreds
    /\ localCred' = [localCred EXCEPT ![p] = s]
    /\ UNCHANGED <<efInviteCreator, efBootstrapFacts, efPeerSharedFacts, efRemovedFacts, efPendingFacts,
                  pwPeerSharedRows, pwBootstrapRows, pwPendingRows, pwConnState,
                  syncComplete, fallbackAttempted, pendingProjectionViolation>>

EF_CreateInviteLocal(p, s) ==
    /\ localCred[p] # NoneSPKI
    /\ s # localCred[p]
    /\ efInviteCreator[s] = NonePeer
    /\ efInviteCreator' = [efInviteCreator EXCEPT ![s] = p]
    /\ efPendingFacts' = efPendingFacts \union {Pair(p, s)}
    /\ UNCHANGED <<localCred, efBootstrapFacts, efPeerSharedFacts, efRemovedFacts,
                  pwPeerSharedRows, pwBootstrapRows, pwPendingRows, pwConnState,
                  syncComplete, fallbackAttempted, pendingProjectionViolation>>

EF_AcceptInvite(p, s) ==
    /\ efInviteCreator[s] # NonePeer
    /\ Pair(p, s) \notin efBootstrapFacts
    /\ efBootstrapFacts' = efBootstrapFacts \union {Pair(p, s)}
    /\ UNCHANGED <<localCred, efInviteCreator, efPeerSharedFacts, efRemovedFacts, efPendingFacts,
                  pwPeerSharedRows, pwBootstrapRows, pwPendingRows, pwConnState,
                  syncComplete, fallbackAttempted, pendingProjectionViolation>>

EF_AddPeerShared(p, s) ==
    /\ Pair(p, s) \notin efPeerSharedFacts
    /\ efPeerSharedFacts' = efPeerSharedFacts \union {Pair(p, s)}
    /\ UNCHANGED <<localCred, efInviteCreator, efBootstrapFacts, efRemovedFacts, efPendingFacts,
                  pwPeerSharedRows, pwBootstrapRows, pwPendingRows, pwConnState,
                  syncComplete, fallbackAttempted, pendingProjectionViolation>>

EF_RemoveRelation(p, s) ==
    /\ Pair(p, s) \notin efRemovedFacts
    /\ efRemovedFacts' = efRemovedFacts \union {Pair(p, s)}
    /\ pwConnState' =
        [pwConnState EXCEPT
            ![p] = [q \in Peers |->
                IF localCred[q] = s THEN "deny" ELSE pwConnState[p][q]
            ]
        ]
    /\ UNCHANGED <<localCred, efInviteCreator, efBootstrapFacts, efPeerSharedFacts, efPendingFacts,
                  pwPeerSharedRows, pwBootstrapRows, pwPendingRows,
                  syncComplete, fallbackAttempted, pendingProjectionViolation>>

\* ---- Projection write-intent actions ----

PW_ProjectPendingWrite(p, s) ==
    /\ Pair(p, s) \in efPendingFacts
    /\ Pair(p, s) \notin pwPeerSharedRows
    /\ ~BuggyPendingSuppressionEnabled(p, s)
    /\ efPendingFacts' = efPendingFacts \ {Pair(p, s)}
    /\ pwPendingRows' = pwPendingRows \union {Pair(p, s)}
    /\ UNCHANGED <<localCred, efInviteCreator, efBootstrapFacts, efPeerSharedFacts, efRemovedFacts,
                  pwPeerSharedRows, pwBootstrapRows, pwConnState,
                  syncComplete, fallbackAttempted, pendingProjectionViolation>>

PW_ProjectPendingSuppressed(p, s) ==
    /\ Pair(p, s) \in efPendingFacts
    /\ Pair(p, s) \notin pwPeerSharedRows
    /\ BuggyPendingSuppressionEnabled(p, s)
    /\ efPendingFacts' = efPendingFacts \ {Pair(p, s)}
    /\ pendingProjectionViolation' = TRUE
    /\ UNCHANGED <<localCred, efInviteCreator, efBootstrapFacts, efPeerSharedFacts, efRemovedFacts,
                  pwPeerSharedRows, pwBootstrapRows, pwPendingRows, pwConnState,
                  syncComplete, fallbackAttempted>>

PW_ProjectBootstrap(p, s) ==
    /\ Pair(p, s) \in efBootstrapFacts
    /\ Pair(p, s) \notin pwPeerSharedRows
    /\ Pair(p, s) \notin pwBootstrapRows
    /\ pwBootstrapRows' = pwBootstrapRows \union {Pair(p, s)}
    /\ UNCHANGED <<localCred, efInviteCreator, efBootstrapFacts, efPeerSharedFacts, efRemovedFacts, efPendingFacts,
                  pwPeerSharedRows, pwPendingRows, pwConnState,
                  syncComplete, fallbackAttempted, pendingProjectionViolation>>

PW_ProjectPeerShared(p, s) ==
    /\ Pair(p, s) \in efPeerSharedFacts
    /\ Pair(p, s) \notin pwPeerSharedRows
    /\ pwPeerSharedRows' = pwPeerSharedRows \union {Pair(p, s)}
    /\ pwBootstrapRows' = pwBootstrapRows \ {Pair(p, s)}
    /\ pwPendingRows' = pwPendingRows \ {Pair(p, s)}
    \* Preserve ongoing-first preference by upgrading any active fallback edge for this fingerprint.
    /\ pwConnState' =
        [pwConnState EXCEPT
            ![p] = [q \in Peers |->
                IF localCred[q] = s /\ pwConnState[p][q] = "invite" THEN "peer" ELSE pwConnState[p][q]
            ]
        ]
    /\ UNCHANGED <<localCred, efInviteCreator, efBootstrapFacts, efPeerSharedFacts, efRemovedFacts, efPendingFacts,
                  syncComplete, fallbackAttempted, pendingProjectionViolation>>

\* ---- Connection-state actions ----

PW_DialOngoing(p, q) ==
    /\ p # q
    /\ CanDialOngoing(p, q)
    /\ pwConnState[p][q] # "peer"
    /\ pwConnState' = [pwConnState EXCEPT ![p][q] = "peer"]
    /\ UNCHANGED <<localCred, efInviteCreator, efBootstrapFacts, efPeerSharedFacts, efRemovedFacts, efPendingFacts,
                  pwPeerSharedRows, pwBootstrapRows, pwPendingRows,
                  syncComplete, fallbackAttempted, pendingProjectionViolation>>

PW_DialBootstrapFallback(p, q) ==
    /\ p # q
    /\ CanDialFallback(p, q)
    /\ pwConnState[p][q] # "invite"
    /\ pwConnState' = [pwConnState EXCEPT ![p][q] = "invite"]
    /\ fallbackAttempted' = [fallbackAttempted EXCEPT ![p][q] = TRUE]
    /\ UNCHANGED <<localCred, efInviteCreator, efBootstrapFacts, efPeerSharedFacts, efRemovedFacts, efPendingFacts,
                  pwPeerSharedRows, pwBootstrapRows, pwPendingRows,
                  syncComplete, pendingProjectionViolation>>

PW_UpgradeConn(p, q) ==
    /\ p # q
    /\ pwConnState[p][q] = "invite"
    /\ CanDialOngoing(p, q)
    /\ pwConnState' = [pwConnState EXCEPT ![p][q] = "peer"]
    /\ UNCHANGED <<localCred, efInviteCreator, efBootstrapFacts, efPeerSharedFacts, efRemovedFacts, efPendingFacts,
                  pwPeerSharedRows, pwBootstrapRows, pwPendingRows,
                  syncComplete, fallbackAttempted, pendingProjectionViolation>>

PW_Deny(p, q) ==
    /\ p # q
    /\ localCred[q] # NoneSPKI
    /\ Removed(p, localCred[q])
    /\ pwConnState[p][q] # "deny"
    /\ pwConnState' = [pwConnState EXCEPT ![p][q] = "deny"]
    /\ UNCHANGED <<localCred, efInviteCreator, efBootstrapFacts, efPeerSharedFacts, efRemovedFacts, efPendingFacts,
                  pwPeerSharedRows, pwBootstrapRows, pwPendingRows,
                  syncComplete, fallbackAttempted, pendingProjectionViolation>>

MarkSyncComplete(p, q) ==
    /\ p # q
    /\ pwConnState[p][q] \in {"invite", "peer"}
    /\ localCred[q] # NoneSPKI
    /\ ~Removed(p, localCred[q])
    /\ ~syncComplete[p][q]
    /\ syncComplete' = [syncComplete EXCEPT ![p][q] = TRUE]
    /\ UNCHANGED <<localCred, efInviteCreator, efBootstrapFacts, efPeerSharedFacts, efRemovedFacts, efPendingFacts,
                  pwPeerSharedRows, pwBootstrapRows, pwPendingRows, pwConnState,
                  fallbackAttempted, pendingProjectionViolation>>

\* ---- Next-state relation ----

Next ==
    \/ \E p \in Peers, s \in SPKIs :
        \/ InstallLocalCred(p, s)
        \/ EF_CreateInviteLocal(p, s)
        \/ EF_AcceptInvite(p, s)
        \/ EF_AddPeerShared(p, s)
        \/ EF_RemoveRelation(p, s)
        \/ PW_ProjectPendingWrite(p, s)
        \/ PW_ProjectPendingSuppressed(p, s)
        \/ PW_ProjectBootstrap(p, s)
        \/ PW_ProjectPeerShared(p, s)
    \/ \E p \in Peers, q \in Peers :
        \/ PW_DialOngoing(p, q)
        \/ PW_DialBootstrapFallback(p, q)
        \/ PW_UpgradeConn(p, q)
        \/ PW_Deny(p, q)
        \/ MarkSyncComplete(p, q)

FairProjection ==
    /\ \A p \in Peers, s \in SPKIs :
        WF_vars(PW_ProjectPendingWrite(p, s) \/ PW_ProjectPendingSuppressed(p, s))
    /\ \A p \in Peers, s \in SPKIs :
        WF_vars(PW_ProjectBootstrap(p, s))
    /\ \A p \in Peers, s \in SPKIs :
        WF_vars(PW_ProjectPeerShared(p, s))

FairConnection ==
    \A p \in Peers, q \in Peers :
        WF_vars(PW_DialOngoing(p, q)
                \/ PW_DialBootstrapFallback(p, q)
                \/ PW_UpgradeConn(p, q)
                \/ PW_Deny(p, q)
                \/ MarkSyncComplete(p, q))

Spec == Init /\ [][Next]_vars /\ FairProjection /\ FairConnection

\* ---- Config constraints (named for .cfg usage) ----

CfgFixConstraint ==
    /\ Cardinality(efRemovedFacts) <= 1
    /\ Cardinality(efPeerSharedFacts) <= 2
    /\ Cardinality(efBootstrapFacts) <= 2
    /\ Cardinality(efPendingFacts) <= 1
    /\ pwConnState["bob"]["alice"] = "none"
    /\ syncComplete["bob"]["alice"] = FALSE
    /\ fallbackAttempted["bob"]["alice"] = FALSE

CfgProgressFastConstraint ==
    /\ Cardinality(efRemovedFacts) <= 1
    /\ Cardinality(efPeerSharedFacts) <= 3
    /\ Cardinality(efBootstrapFacts) <= 2
    /\ Cardinality(efPendingFacts) <= 2
    /\ pwConnState["bob"]["alice"] = "none"
    /\ syncComplete["bob"]["alice"] = FALSE
    /\ fallbackAttempted["bob"]["alice"] = FALSE

CfgProgressDeepConstraint ==
    /\ Cardinality(efRemovedFacts) <= 2
    /\ Cardinality(efPeerSharedFacts) <= 4
    /\ Cardinality(efBootstrapFacts) <= 3
    /\ Cardinality(efPendingFacts) <= 3

\* ---- Core bridge invariants ----

BrInv_TrustedPeerRefinesRuntimeTrust ==
    \A p \in Peers, s \in SPKIs :
        (Pair(p, s) \in pwPeerSharedRows
         \/ Pair(p, s) \in pwBootstrapRows
         \/ Pair(p, s) \in pwPendingRows)
        => s \in RT_TrustedSPKIs(p)

BrInv_RuntimeTrustHasEventCause ==
    \A p \in Peers, s \in SPKIs :
        /\ (s \in RT_PeerSharedTrust(p) => Pair(p, s) \in efPeerSharedFacts)
        /\ (s \in RT_BootstrapTrust(p) => Pair(p, s) \in efBootstrapFacts)
        /\ (s \in RT_PendingTrust(p) => PendingEventCause(p, s))

BrInv_PendingOnlyOnInviter ==
    \A p \in Peers, s \in SPKIs :
        Pair(p, s) \in pwPendingRows => efInviteCreator[s] = p

BrInv_AllowedPeerMatchesAuthDecision ==
    \A p \in Peers, q \in Peers :
        pwConnState[p][q] \in {"invite", "peer"} => CanAuthorize(p, q)

BrInv_OngoingPreferred ==
    \A p \in Peers, q \in Peers :
        CanDialOngoing(p, q) => pwConnState[p][q] # "invite"

BrInv_BootstrapFallbackOnlyWhenNeeded ==
    \A p \in Peers, q \in Peers :
        pwConnState[p][q] = "invite" => CanDialFallback(p, q)

BrInv_RowToMaterializedExactness ==
    \A p \in Peers, s \in SPKIs :
        /\ ((s \in RT_PeerSharedTrust(p)) <=> (Pair(p, s) \in pwPeerSharedRows))
        /\ ((s \in RT_BootstrapTrust(p)) <=> (Pair(p, s) \in pwBootstrapRows))
        /\ ((s \in RT_PendingTrust(p)) <=> (Pair(p, s) \in pwPendingRows))

BrInv_LocalInviteProjectsPending ==
    ~pendingProjectionViolation

\* ---- Security bridge invariants ----

BrSec_ConnectionRequiresAuthorization ==
    BrInv_AllowedPeerMatchesAuthDecision

BrSec_NoTrustWithoutProvenance ==
    BrInv_RuntimeTrustHasEventCause

BrSec_NoPendingTrustOnJoiner ==
    BrInv_PendingOnlyOnInviter

BrSec_SourceBindingConsistency ==
    \A p \in Peers, q \in Peers :
        /\ (pwConnState[p][q] = "peer" => CanDialOngoing(p, q))
        /\ (pwConnState[p][q] = "invite" => CanDialFallback(p, q))

BrSec_RemovalDeniesConnectivity ==
    \A p \in Peers, q \in Peers :
        /\ localCred[q] # NoneSPKI
        /\ Removed(p, localCred[q])
        => ~(pwConnState[p][q] \in {"invite", "peer"})

BrSec_NoIdentityCollisionInAuthPath ==
    \A p \in Peers, q \in Peers :
        /\ p # q
        /\ localCred[p] # NoneSPKI
        /\ localCred[q] # NoneSPKI
        => localCred[p] # localCred[q]

\* ---- Liveness/progress properties ----

BrLive_BootstrapConnectEventually ==
    \A p \in Peers, q \in Peers :
        (p # q /\ (CanDialFallback(p, q) \/ CanDialOngoing(p, q)))
        ~> (pwConnState[p][q] \in {"invite", "peer"} \/ BlockedByRemoval(p, q))

BrLive_PeerUpgradeEventually ==
    \A p \in Peers, q \in Peers :
        (p # q /\ pwConnState[p][q] = "invite" /\ CanDialOngoing(p, q))
        ~> (pwConnState[p][q] = "peer" \/ BlockedByRemoval(p, q))

BrLive_BootstrapCompletionSyncEventually ==
    \A p \in Peers, q \in Peers :
        (p # q /\ pwConnState[p][q] \in {"invite", "peer"} /\ ~syncComplete[p][q])
        ~> (syncComplete[p][q] \/ BlockedByRemoval(p, q))

BrLive_FallbackAttemptEventually ==
    \A p \in Peers, q \in Peers :
        (p # q /\ CanDialFallback(p, q))
        ~> (fallbackAttempted[p][q] \/ CanDialOngoing(p, q) \/ BlockedByRemoval(p, q))

BrLive_RemovalConvergesToDeny ==
    \A p \in Peers, q \in Peers :
        (p # q /\ localCred[q] # NoneSPKI /\ Removed(p, localCred[q]))
        ~> (pwConnState[p][q] = "deny")

====
