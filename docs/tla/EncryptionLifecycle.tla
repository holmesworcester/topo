---- MODULE EncryptionLifecycle ----
EXTENDS Naturals, FiniteSets

\* Focused model of the encryption key lifecycle in poc-7:
\*   SecretKey creation, SecretShared wrapping, unwrap/materialization,
\*   Encrypted content dependency, and cascade unblocking.
\*
\* This model complements EventGraphSchema by zooming into the encryption
\* subsystem with finer-grained state tracking (per-key, per-wrap, per-encrypted).
\*
\* CONSTANTS:
\*   Peers — set of peer identifiers (2 required for key distribution)
\*   Keys — set of key identifiers (abstract secret key IDs)
\*   Contents — set of content identifiers (abstract encrypted content IDs)

CONSTANTS Peers, Keys, Contents

VARIABLES
    \* Per-peer, per-key: whether the local secret_key event exists
    localKey,           \* [Peers -> [Keys -> BOOLEAN]]
    \* Per-peer, per-key: set of peers this key has been wrapped to (SecretShared created)
    wrappedTo,          \* [Peers -> [Keys -> SUBSET Peers]]
    \* Per-peer, per-key: whether the key was materialized via unwrap
    \* (key owner sets localKey directly; recipients materialize via unwrap)
    materializedViaUnwrap, \* [Peers -> [Keys -> BOOLEAN]]
    \* Per-peer, per-content, per-key: whether encrypted content referencing this key exists
    encryptedContent,   \* [Peers -> [Contents -> Keys \cup {"none"}]]
    \* Per-peer, per-content: whether the encrypted content is decryptable (unblocked)
    decryptable,        \* [Peers -> [Contents -> BOOLEAN]]
    \* Per-peer: whether peer is "removed" (no new wraps should target them)
    peerRemoved         \* [Peers -> BOOLEAN]

vars == <<localKey, wrappedTo, materializedViaUnwrap, encryptedContent, decryptable, peerRemoved>>

Init ==
    /\ localKey = [p \in Peers |-> [k \in Keys |-> FALSE]]
    /\ wrappedTo = [p \in Peers |-> [k \in Keys |-> {}]]
    /\ materializedViaUnwrap = [p \in Peers |-> [k \in Keys |-> FALSE]]
    /\ encryptedContent = [p \in Peers |-> [c \in Contents |-> "none"]]
    /\ decryptable = [p \in Peers |-> [c \in Contents |-> FALSE]]
    /\ peerRemoved = [p \in Peers |-> FALSE]

\* ---- Actions ----

\* A peer creates a local secret key (owner-side).
\* Cascade: any encrypted content already waiting on this key becomes decryptable.
CreateKey(p, k) ==
    /\ ~localKey[p][k]
    /\ localKey' = [localKey EXCEPT ![p][k] = TRUE]
    /\ decryptable' = [decryptable EXCEPT ![p] =
        [c \in Contents |-> IF encryptedContent[p][c] = k THEN TRUE ELSE @[c]]]
    /\ UNCHANGED <<wrappedTo, materializedViaUnwrap, encryptedContent, peerRemoved>>

\* A peer wraps a key for a recipient via SecretShared.
\* Precondition: sender has the key locally, recipient is not removed.
WrapKey(sender, k, recipient) ==
    /\ sender /= recipient
    /\ localKey[sender][k]
    /\ ~peerRemoved[recipient]
    /\ recipient \notin wrappedTo[sender][k]
    /\ wrappedTo' = [wrappedTo EXCEPT ![sender][k] = @ \cup {recipient}]
    /\ UNCHANGED <<localKey, materializedViaUnwrap, encryptedContent, decryptable, peerRemoved>>

\* A recipient materializes a key from an unwrapped SecretShared event.
\* Precondition: some peer has wrapped this key to the recipient.
\* The materialized key event ID is deterministic (same key bytes -> same event ID).
UnwrapKey(recipient, k) ==
    /\ ~localKey[recipient][k]
    /\ \E sender \in Peers: recipient \in wrappedTo[sender][k]
    /\ localKey' = [localKey EXCEPT ![recipient][k] = TRUE]
    /\ materializedViaUnwrap' = [materializedViaUnwrap EXCEPT ![recipient][k] = TRUE]
    \* Cascade: any encrypted content waiting on this key becomes decryptable.
    /\ decryptable' = [decryptable EXCEPT ![recipient] =
        [c \in Contents |-> IF encryptedContent[recipient][c] = k THEN TRUE ELSE @[c]]]
    /\ UNCHANGED <<wrappedTo, encryptedContent, peerRemoved>>

\* A peer records encrypted content that depends on a specific key.
RecordEncrypted(p, c, k) ==
    /\ encryptedContent[p][c] = "none"
    /\ encryptedContent' = [encryptedContent EXCEPT ![p][c] = k]
    \* If the key is already available locally, content is immediately decryptable.
    /\ decryptable' = [decryptable EXCEPT ![p][c] = localKey[p][k]]
    /\ UNCHANGED <<localKey, wrappedTo, materializedViaUnwrap, peerRemoved>>

\* A peer is marked as removed (no further wraps to this peer).
RemovePeer(p) ==
    /\ ~peerRemoved[p]
    /\ peerRemoved' = [peerRemoved EXCEPT ![p] = TRUE]
    /\ UNCHANGED <<localKey, wrappedTo, materializedViaUnwrap, encryptedContent, decryptable>>

Next ==
    \/ \E p \in Peers, k \in Keys: CreateKey(p, k)
    \/ \E s \in Peers, k \in Keys, r \in Peers: WrapKey(s, k, r)
    \/ \E p \in Peers, k \in Keys: UnwrapKey(p, k)
    \/ \E p \in Peers, c \in Contents, k \in Keys: RecordEncrypted(p, c, k)
    \/ \E p \in Peers: RemovePeer(p)

Spec == Init /\ [][Next]_vars

\* ---- Invariants ----

\* Type correctness.
TypeOK ==
    /\ localKey \in [Peers -> [Keys -> BOOLEAN]]
    /\ wrappedTo \in [Peers -> [Keys -> SUBSET Peers]]
    /\ materializedViaUnwrap \in [Peers -> [Keys -> BOOLEAN]]
    /\ encryptedContent \in [Peers -> [Contents -> Keys \cup {"none"}]]
    /\ decryptable \in [Peers -> [Contents -> BOOLEAN]]
    /\ peerRemoved \in [Peers -> BOOLEAN]

\* InvEncryptedDependsOnMaterializedKey:
\* If encrypted content is decryptable, the corresponding local key must exist.
InvEncryptedDependsOnMaterializedKey ==
    \A p \in Peers, c \in Contents:
        decryptable[p][c] => (encryptedContent[p][c] /= "none"
                              /\ localKey[p][encryptedContent[p][c]])

\* InvUnwrapOnlyForLocalRecipient:
\* Key materialization via unwrap only occurs if the recipient was an
\* intended target of a wrap (exists in some sender's wrappedTo set).
InvUnwrapOnlyForLocalRecipient ==
    \A p \in Peers, k \in Keys:
        materializedViaUnwrap[p][k] =>
            \E sender \in Peers: p \in wrappedTo[sender][k]

\* InvDeterministicKeyIdFromUnwrap:
\* If a key is materialized via unwrap, the local key state matches
\* (deterministic event ID from key bytes). Modeled as: materializedViaUnwrap
\* implies localKey (both parties see the same key).
InvDeterministicKeyIdFromUnwrap ==
    \A p \in Peers, k \in Keys:
        materializedViaUnwrap[p][k] => localKey[p][k]

\* InvNoPhantomSecretKey:
\* Non-local (unwrapped) secret key materialization must be causally
\* explainable by a valid SecretShared unwrap path.
InvNoPhantomSecretKey ==
    \A p \in Peers, k \in Keys:
        materializedViaUnwrap[p][k] =>
            \E sender \in Peers: (sender /= p /\ p \in wrappedTo[sender][k])

\* InvBlockedEncryptedUnblocksAfterKey (safety component):
\* If encrypted content references a key and that key is locally available,
\* the content must be decryptable (not stuck in blocked state).
InvBlockedEncryptedUnblocksAfterKey ==
    \A p \in Peers, c \in Contents:
        (encryptedContent[p][c] /= "none" /\ localKey[p][encryptedContent[p][c]])
            => decryptable[p][c]

\* InvContentWritesAreEncrypted:
\* Every piece of content has a key reference (no plaintext content).
\* In this model, content either has "none" (not yet recorded) or a key.
\* This is trivially enforced by RecordEncrypted requiring a key argument.
InvContentWritesAreEncrypted ==
    \A p \in Peers, c \in Contents:
        decryptable[p][c] => encryptedContent[p][c] /= "none"

\* InvNoWrapToRemovedPeer (structural):
\* WrapKey's precondition (~peerRemoved[recipient]) ensures no wraps are
\* created for removed peers. This invariant is enforced by the action guard
\* rather than a state invariant. No explicit state-based check needed
\* because the model never produces a state where a wrap targets a
\* removed peer (the action simply doesn't fire).

\* Interaction bound for tractable model checking.
CfgInteractionConstraint ==
    /\ \A p \in Peers:
        /\ Cardinality({k \in Keys: localKey[p][k]}) <= 2
        /\ Cardinality({c \in Contents: encryptedContent[p][c] /= "none"}) <= 2
    /\ Cardinality({p \in Peers: peerRemoved[p]}) <= 1

====
