------------------------------ MODULE ExactTransportTargeting ------------------------------
EXTENDS FiniteSets, TLC

\* Focused transport-target model layered on top of existing trust provenance
\* specs. This module does not model where authorization comes from; it models
\* how exact local-target routing and exact outbound remote matching consume a
\* tenant-scoped authorization predicate.
\
\* Rust mapping:
\*   localTarget[t]        → replay-derived local_transport_targets[t]
\*   authorized[t]         → is_authorized_for_tenant(t, remote_fp)
\*   requestedLocalFP      → parse_transport_sni(...) result on inbound
\*   presentedRemoteFP     → authenticated remote cert fingerprint
\*   expectedRemoteFP      → outbound target transport fingerprint
\*   inboundAdmitted       → session admitted after exact local-target auth
\*   outboundConnected     → outbound connection accepted after exact match

CONSTANTS
    Tenants,
    LocalFPs,
    RemoteFPs,
    NoLocalFP,
    NoRemoteFP,
    NoTenant

ASSUME /\ NoLocalFP \notin LocalFPs
       /\ NoRemoteFP \notin RemoteFPs
       /\ NoTenant \notin Tenants

VARIABLES
    localTarget,
    credSource,
    authorized,
    requestedLocalFP,
    presentedRemoteFP,
    inboundTenant,
    inboundAdmitted,
    outboundTenant,
    expectedRemoteFP,
    outboundPresentedFP,
    outboundConnected

Vars ==
    << localTarget,
       credSource,
       authorized,
       requestedLocalFP,
       presentedRemoteFP,
       inboundTenant,
       inboundAdmitted,
       outboundTenant,
       expectedRemoteFP,
       outboundPresentedFP,
       outboundConnected >>

TypeOK ==
    /\ localTarget \in [Tenants -> LocalFPs \union {NoLocalFP}]
    /\ credSource \in [Tenants -> {"none", "bootstrap", "peershared"}]
    /\ authorized \in [Tenants -> SUBSET RemoteFPs]
    /\ requestedLocalFP \in LocalFPs \union {NoLocalFP}
    /\ presentedRemoteFP \in RemoteFPs \union {NoRemoteFP}
    /\ inboundTenant \in Tenants \union {NoTenant}
    /\ inboundAdmitted \in BOOLEAN
    /\ outboundTenant \in Tenants \union {NoTenant}
    /\ expectedRemoteFP \in RemoteFPs \union {NoRemoteFP}
    /\ outboundPresentedFP \in RemoteFPs \union {NoRemoteFP}
    /\ outboundConnected \in BOOLEAN

Init ==
    /\ localTarget = [t \in Tenants |-> NoLocalFP]
    /\ credSource = [t \in Tenants |-> "none"]
    /\ authorized = [t \in Tenants |-> {}]
    /\ requestedLocalFP = NoLocalFP
    /\ presentedRemoteFP = NoRemoteFP
    /\ inboundTenant = NoTenant
    /\ inboundAdmitted = FALSE
    /\ outboundTenant = NoTenant
    /\ expectedRemoteFP = NoRemoteFP
    /\ outboundPresentedFP = NoRemoteFP
    /\ outboundConnected = FALSE

NodeAuthorizes(fp) ==
    \E t \in Tenants: fp \in authorized[t]

InstallBootstrapTarget(t, fp) ==
    /\ t \in Tenants
    /\ fp \in LocalFPs
    /\ credSource[t] # "peershared"
    /\ \A other \in Tenants \ {t}: localTarget[other] # fp
    /\ localTarget' = [localTarget EXCEPT ![t] = fp]
    /\ credSource' = [credSource EXCEPT ![t] = "bootstrap"]
    /\ UNCHANGED
         << authorized,
            requestedLocalFP,
            presentedRemoteFP,
            inboundTenant,
            inboundAdmitted,
            outboundTenant,
            expectedRemoteFP,
            outboundPresentedFP,
            outboundConnected >>

InstallPeerSharedTarget(t, fp) ==
    /\ t \in Tenants
    /\ fp \in LocalFPs
    /\ \A other \in Tenants \ {t}: localTarget[other] # fp
    /\ localTarget' = [localTarget EXCEPT ![t] = fp]
    /\ credSource' = [credSource EXCEPT ![t] = "peershared"]
    /\ UNCHANGED
         << authorized,
            requestedLocalFP,
            presentedRemoteFP,
            inboundTenant,
            inboundAdmitted,
            outboundTenant,
            expectedRemoteFP,
            outboundPresentedFP,
            outboundConnected >>

GrantAuth(t, fp) ==
    /\ t \in Tenants
    /\ fp \in RemoteFPs
    /\ authorized' = [authorized EXCEPT ![t] = @ \union {fp}]
    /\ UNCHANGED
         << localTarget,
            credSource,
            requestedLocalFP,
            presentedRemoteFP,
            inboundTenant,
            inboundAdmitted,
            outboundTenant,
            expectedRemoteFP,
            outboundPresentedFP,
            outboundConnected >>

RevokeAuth(t, fp) ==
    /\ t \in Tenants
    /\ fp \in RemoteFPs
    /\ authorized' = [authorized EXCEPT ![t] = @ \ {fp}]
    /\ UNCHANGED
         << localTarget,
            credSource,
            requestedLocalFP,
            presentedRemoteFP,
            inboundTenant,
            inboundAdmitted,
            outboundTenant,
            expectedRemoteFP,
            outboundPresentedFP,
            outboundConnected >>

StartInbound(req, remote) ==
    /\ req \in LocalFPs
    /\ remote \in RemoteFPs
    /\ requestedLocalFP' = req
    /\ presentedRemoteFP' = remote
    /\ inboundTenant' = NoTenant
    /\ inboundAdmitted' = FALSE
    /\ UNCHANGED
         << localTarget,
            credSource,
            authorized,
            outboundTenant,
            expectedRemoteFP,
            outboundPresentedFP,
            outboundConnected >>

AdmitInbound(t) ==
    /\ t \in Tenants
    /\ requestedLocalFP # NoLocalFP
    /\ presentedRemoteFP # NoRemoteFP
    /\ requestedLocalFP = localTarget[t]
    /\ presentedRemoteFP \in authorized[t]
    /\ inboundTenant' = t
    /\ inboundAdmitted' = TRUE
    /\ UNCHANGED
         << localTarget,
            credSource,
            authorized,
            requestedLocalFP,
            presentedRemoteFP,
            outboundTenant,
            expectedRemoteFP,
            outboundPresentedFP,
            outboundConnected >>

ClearInbound ==
    /\ requestedLocalFP' = NoLocalFP
    /\ presentedRemoteFP' = NoRemoteFP
    /\ inboundTenant' = NoTenant
    /\ inboundAdmitted' = FALSE
    /\ UNCHANGED
         << localTarget,
            credSource,
            authorized,
            outboundTenant,
            expectedRemoteFP,
            outboundPresentedFP,
            outboundConnected >>

StartOutbound(t, expected, presented) ==
    /\ t \in Tenants
    /\ expected \in RemoteFPs
    /\ presented \in RemoteFPs
    /\ outboundTenant' = t
    /\ expectedRemoteFP' = expected
    /\ outboundPresentedFP' = presented
    /\ outboundConnected' = FALSE
    /\ UNCHANGED
         << localTarget,
            credSource,
            authorized,
            requestedLocalFP,
            presentedRemoteFP,
            inboundTenant,
            inboundAdmitted >>

CompleteOutbound ==
    /\ outboundTenant \in Tenants
    /\ expectedRemoteFP # NoRemoteFP
    /\ outboundPresentedFP # NoRemoteFP
    /\ expectedRemoteFP = outboundPresentedFP
    /\ outboundPresentedFP \in authorized[outboundTenant]
    /\ outboundConnected' = TRUE
    /\ UNCHANGED
         << localTarget,
            credSource,
            authorized,
            requestedLocalFP,
            presentedRemoteFP,
            inboundTenant,
            inboundAdmitted,
            outboundTenant,
            expectedRemoteFP,
            outboundPresentedFP >>

ClearOutbound ==
    /\ outboundTenant' = NoTenant
    /\ expectedRemoteFP' = NoRemoteFP
    /\ outboundPresentedFP' = NoRemoteFP
    /\ outboundConnected' = FALSE
    /\ UNCHANGED
         << localTarget,
            credSource,
            authorized,
            requestedLocalFP,
            presentedRemoteFP,
            inboundTenant,
            inboundAdmitted >>

Next ==
    \/ \E t \in Tenants, fp \in LocalFPs: InstallBootstrapTarget(t, fp)
    \/ \E t \in Tenants, fp \in LocalFPs: InstallPeerSharedTarget(t, fp)
    \/ \E t \in Tenants, fp \in RemoteFPs: GrantAuth(t, fp)
    \/ \E t \in Tenants, fp \in RemoteFPs: RevokeAuth(t, fp)
    \/ \E req \in LocalFPs, remote \in RemoteFPs: StartInbound(req, remote)
    \/ \E t \in Tenants: AdmitInbound(t)
    \/ ClearInbound
    \/ \E t \in Tenants, expected \in RemoteFPs, presented \in RemoteFPs:
         StartOutbound(t, expected, presented)
    \/ CompleteOutbound
    \/ ClearOutbound

Spec ==
    Init /\ [][Next]_Vars

InvLocalTargetsUnique ==
    \A t1, t2 \in Tenants:
        /\ localTarget[t1] = localTarget[t2]
        /\ localTarget[t1] # NoLocalFP
        => t1 = t2

InvLocalTargetConsistent ==
    \A t \in Tenants:
        (credSource[t] = "none") = (localTarget[t] = NoLocalFP)

InvInboundAdmittedAuthorized ==
    inboundAdmitted =>
        /\ inboundTenant \in Tenants
        /\ requestedLocalFP = localTarget[inboundTenant]
        /\ presentedRemoteFP \in authorized[inboundTenant]

InvNoCrossTenantFallback ==
    inboundAdmitted =>
        \A t \in Tenants \ {inboundTenant}:
            requestedLocalFP # localTarget[t]

InvNodeGateSound ==
    inboundAdmitted =>
        NodeAuthorizes(presentedRemoteFP)

InvOutboundConnectedAuthorized ==
    outboundConnected =>
        /\ outboundTenant \in Tenants
        /\ expectedRemoteFP = outboundPresentedFP
        /\ outboundPresentedFP \in authorized[outboundTenant]

=============================================================================
