---- MODULE KeyEventBlockingMinimal ----
EXTENDS FiniteSets

\* Minimal model for reasoning about key materialization with these rules:
\* 1) Keys are represented only as events.
\* 2) Blocking/order/retry uses one dep-block queue mechanism.
\* 3) Projectors may emit deterministic local-only events.

VARIABLES recorded, valid, projectQueue, blockedOn
vars == <<recorded, valid, projectQueue, blockedOn>>

E_LOCAL_SIGNER_SECRET == "local_signer_secret"
E_RECIPIENT_KEY_READY == "recipient_key_ready"
E_SECRET_SHARED == "secret_shared"
E_UNWRAP_SECRET_SHARED == "unwrap_secret_shared"
E_SECRET_KEY == "secret_key"
E_ENCRYPTED == "encrypted"

EVENTS == {
    E_LOCAL_SIGNER_SECRET,
    E_RECIPIENT_KEY_READY,
    E_SECRET_SHARED,
    E_UNWRAP_SECRET_SHARED,
    E_SECRET_KEY,
    E_ENCRYPTED
}

\* External ingress is limited to root facts. Derived local events are emitted.
ExternalIngress == {
    E_LOCAL_SIGNER_SECRET,
    E_SECRET_SHARED,
    E_ENCRYPTED
}

LocalOnly == {
    E_LOCAL_SIGNER_SECRET,
    E_RECIPIENT_KEY_READY,
    E_UNWRAP_SECRET_SHARED,
    E_SECRET_KEY
}

SharedEvents == EVENTS \ LocalOnly

DeterministicUnsignedLocal == {
    E_RECIPIENT_KEY_READY,
    E_UNWRAP_SECRET_SHARED,
    E_SECRET_KEY
}

Deps(e) ==
    CASE e = E_LOCAL_SIGNER_SECRET -> {}
      [] e = E_RECIPIENT_KEY_READY -> {E_LOCAL_SIGNER_SECRET}
      [] e = E_SECRET_SHARED -> {}
      [] e = E_UNWRAP_SECRET_SHARED -> {E_SECRET_SHARED, E_RECIPIENT_KEY_READY}
      [] e = E_SECRET_KEY -> {}
      [] e = E_ENCRYPTED -> {E_SECRET_KEY}
      [] OTHER -> {}

\* Projector emission graph.
Emits(e) ==
    CASE e = E_LOCAL_SIGNER_SECRET -> {E_RECIPIENT_KEY_READY}
      [] e = E_SECRET_SHARED -> {E_UNWRAP_SECRET_SHARED}
      [] e = E_UNWRAP_SECRET_SHARED -> {E_SECRET_KEY}
      [] OTHER -> {}

Init ==
    /\ recorded = {}
    /\ valid = {}
    /\ projectQueue = {}
    /\ blockedOn = [e \in EVENTS |-> {}]

\* New canonical event bytes are persisted (recorded) and queued for projection.
Ingest(e) ==
    /\ e \in ExternalIngress
    /\ e \notin recorded
    /\ recorded' = recorded \cup {e}
    /\ projectQueue' = projectQueue \cup {e}
    /\ UNCHANGED <<valid, blockedOn>>

\* One generic projection step with dep-check + emit behavior.
Project(e) ==
    /\ e \in projectQueue
    /\ e \in recorded
    /\ e \notin valid
    /\ LET missing == Deps(e) \ valid IN
       IF missing = {} THEN
           /\ valid' = valid \cup {e}
           /\ blockedOn' = [blockedOn EXCEPT ![e] = {}]
           /\ LET emitted == Emits(e) \ recorded IN
              /\ recorded' = recorded \cup emitted
              /\ projectQueue' = (projectQueue \ {e}) \cup (emitted \ valid)
       ELSE
           /\ valid' = valid
           /\ blockedOn' = [blockedOn EXCEPT ![e] = missing]
           /\ recorded' = recorded
           /\ projectQueue' = projectQueue \ {e}

\* Existing block/unblock queue retry: when blockers become valid, requeue.
RetryUnblocked(e) ==
    /\ e \in EVENTS
    /\ e \in recorded
    /\ e \notin valid
    /\ e \notin projectQueue
    /\ blockedOn[e] # {}
    /\ blockedOn[e] \subseteq valid
    /\ projectQueue' = projectQueue \cup {e}
    /\ blockedOn' = [blockedOn EXCEPT ![e] = {}]
    /\ UNCHANGED <<recorded, valid>>

Next ==
    \/ \E e \in EVENTS: Ingest(e)
    \/ \E e \in EVENTS: Project(e)
    \/ \E e \in EVENTS: RetryUnblocked(e)
    \/ UNCHANGED vars

Spec == Init /\ [][Next]_vars

\* ----------------------
\* Safety invariants
\* ----------------------

TypeOK ==
    /\ recorded \subseteq EVENTS
    /\ valid \subseteq EVENTS
    /\ projectQueue \subseteq EVENTS
    /\ blockedOn \in [EVENTS -> SUBSET EVENTS]

InvValidSubsetRecorded == valid \subseteq recorded

InvValidEventsSatisfyDeps ==
    \A e \in valid: Deps(e) \subseteq valid

\* Core key rule: encrypted validity requires key event validity.
InvEncryptedNeedsSecretKey ==
    E_ENCRYPTED \in valid => E_SECRET_KEY \in valid

\* Emission provenance for deterministic local events.
InvKeyReadyComesFromLocalSigner ==
    E_RECIPIENT_KEY_READY \in recorded => E_LOCAL_SIGNER_SECRET \in valid

InvUnwrapEventComesFromSecretShared ==
    E_UNWRAP_SECRET_SHARED \in recorded => E_SECRET_SHARED \in valid

InvSecretKeyComesFromUnwrap ==
    E_SECRET_KEY \in recorded => E_UNWRAP_SECRET_SHARED \in valid

\* Block rows only represent deps for recorded non-valid events.
InvBlockedRowsAreForRecordedNonValid ==
    \A e \in EVENTS:
        blockedOn[e] # {} => /\ e \in recorded /\ e \notin valid /\ blockedOn[e] \subseteq Deps(e)

====
