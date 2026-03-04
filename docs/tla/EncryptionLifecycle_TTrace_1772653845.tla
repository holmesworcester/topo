---- MODULE EncryptionLifecycle_TTrace_1772653845 ----
EXTENDS Sequences, TLCExt, Toolbox, EncryptionLifecycle, Naturals, TLC

_expression ==
    LET EncryptionLifecycle_TEExpression == INSTANCE EncryptionLifecycle_TEExpression
    IN EncryptionLifecycle_TEExpression!expression
----

_trace ==
    LET EncryptionLifecycle_TETrace == INSTANCE EncryptionLifecycle_TETrace
    IN EncryptionLifecycle_TETrace!trace
----

_inv ==
    ~(
        TLCGet("level") = Len(_TETrace)
        /\
        materializedViaUnwrap = ([p1 |-> [k1 |-> FALSE, k2 |-> FALSE], p2 |-> [k1 |-> FALSE, k2 |-> FALSE]])
        /\
        peerRemoved = ([p1 |-> FALSE, p2 |-> FALSE])
        /\
        encryptedContent = ([p1 |-> [c1 |-> "k1"], p2 |-> [c1 |-> "none"]])
        /\
        decryptable = ([p1 |-> [c1 |-> FALSE], p2 |-> [c1 |-> FALSE]])
        /\
        wrappedTo = ([p1 |-> [k1 |-> {}, k2 |-> {}], p2 |-> [k1 |-> {}, k2 |-> {}]])
        /\
        localKey = ([p1 |-> [k1 |-> TRUE, k2 |-> FALSE], p2 |-> [k1 |-> FALSE, k2 |-> FALSE]])
    )
----

_init ==
    /\ decryptable = _TETrace[1].decryptable
    /\ materializedViaUnwrap = _TETrace[1].materializedViaUnwrap
    /\ encryptedContent = _TETrace[1].encryptedContent
    /\ wrappedTo = _TETrace[1].wrappedTo
    /\ localKey = _TETrace[1].localKey
    /\ peerRemoved = _TETrace[1].peerRemoved
----

_next ==
    /\ \E i,j \in DOMAIN _TETrace:
        /\ \/ /\ j = i + 1
              /\ i = TLCGet("level")
        /\ decryptable  = _TETrace[i].decryptable
        /\ decryptable' = _TETrace[j].decryptable
        /\ materializedViaUnwrap  = _TETrace[i].materializedViaUnwrap
        /\ materializedViaUnwrap' = _TETrace[j].materializedViaUnwrap
        /\ encryptedContent  = _TETrace[i].encryptedContent
        /\ encryptedContent' = _TETrace[j].encryptedContent
        /\ wrappedTo  = _TETrace[i].wrappedTo
        /\ wrappedTo' = _TETrace[j].wrappedTo
        /\ localKey  = _TETrace[i].localKey
        /\ localKey' = _TETrace[j].localKey
        /\ peerRemoved  = _TETrace[i].peerRemoved
        /\ peerRemoved' = _TETrace[j].peerRemoved

\* Uncomment the ASSUME below to write the states of the error trace
\* to the given file in Json format. Note that you can pass any tuple
\* to `JsonSerialize`. For example, a sub-sequence of _TETrace.
    \* ASSUME
    \*     LET J == INSTANCE Json
    \*         IN J!JsonSerialize("EncryptionLifecycle_TTrace_1772653845.json", _TETrace)

=============================================================================

 Note that you can extract this module `EncryptionLifecycle_TEExpression`
  to a dedicated file to reuse `expression` (the module in the 
  dedicated `EncryptionLifecycle_TEExpression.tla` file takes precedence 
  over the module `EncryptionLifecycle_TEExpression` below).

---- MODULE EncryptionLifecycle_TEExpression ----
EXTENDS Sequences, TLCExt, Toolbox, EncryptionLifecycle, Naturals, TLC

expression == 
    [
        \* To hide variables of the `EncryptionLifecycle` spec from the error trace,
        \* remove the variables below.  The trace will be written in the order
        \* of the fields of this record.
        decryptable |-> decryptable
        ,materializedViaUnwrap |-> materializedViaUnwrap
        ,encryptedContent |-> encryptedContent
        ,wrappedTo |-> wrappedTo
        ,localKey |-> localKey
        ,peerRemoved |-> peerRemoved
        
        \* Put additional constant-, state-, and action-level expressions here:
        \* ,_stateNumber |-> _TEPosition
        \* ,_decryptableUnchanged |-> decryptable = decryptable'
        
        \* Format the `decryptable` variable as Json value.
        \* ,_decryptableJson |->
        \*     LET J == INSTANCE Json
        \*     IN J!ToJson(decryptable)
        
        \* Lastly, you may build expressions over arbitrary sets of states by
        \* leveraging the _TETrace operator.  For example, this is how to
        \* count the number of times a spec variable changed up to the current
        \* state in the trace.
        \* ,_decryptableModCount |->
        \*     LET F[s \in DOMAIN _TETrace] ==
        \*         IF s = 1 THEN 0
        \*         ELSE IF _TETrace[s].decryptable # _TETrace[s-1].decryptable
        \*             THEN 1 + F[s-1] ELSE F[s-1]
        \*     IN F[_TEPosition - 1]
    ]

=============================================================================



Parsing and semantic processing can take forever if the trace below is long.
 In this case, it is advised to uncomment the module below to deserialize the
 trace from a generated binary file.

\*
\*---- MODULE EncryptionLifecycle_TETrace ----
\*EXTENDS IOUtils, EncryptionLifecycle, TLC
\*
\*trace == IODeserialize("EncryptionLifecycle_TTrace_1772653845.bin", TRUE)
\*
\*=============================================================================
\*

---- MODULE EncryptionLifecycle_TETrace ----
EXTENDS EncryptionLifecycle, TLC

trace == 
    <<
    ([materializedViaUnwrap |-> [p1 |-> [k1 |-> FALSE, k2 |-> FALSE], p2 |-> [k1 |-> FALSE, k2 |-> FALSE]],peerRemoved |-> [p1 |-> FALSE, p2 |-> FALSE],encryptedContent |-> [p1 |-> [c1 |-> "none"], p2 |-> [c1 |-> "none"]],decryptable |-> [p1 |-> [c1 |-> FALSE], p2 |-> [c1 |-> FALSE]],wrappedTo |-> [p1 |-> [k1 |-> {}, k2 |-> {}], p2 |-> [k1 |-> {}, k2 |-> {}]],localKey |-> [p1 |-> [k1 |-> FALSE, k2 |-> FALSE], p2 |-> [k1 |-> FALSE, k2 |-> FALSE]]]),
    ([materializedViaUnwrap |-> [p1 |-> [k1 |-> FALSE, k2 |-> FALSE], p2 |-> [k1 |-> FALSE, k2 |-> FALSE]],peerRemoved |-> [p1 |-> FALSE, p2 |-> FALSE],encryptedContent |-> [p1 |-> [c1 |-> "k1"], p2 |-> [c1 |-> "none"]],decryptable |-> [p1 |-> [c1 |-> FALSE], p2 |-> [c1 |-> FALSE]],wrappedTo |-> [p1 |-> [k1 |-> {}, k2 |-> {}], p2 |-> [k1 |-> {}, k2 |-> {}]],localKey |-> [p1 |-> [k1 |-> FALSE, k2 |-> FALSE], p2 |-> [k1 |-> FALSE, k2 |-> FALSE]]]),
    ([materializedViaUnwrap |-> [p1 |-> [k1 |-> FALSE, k2 |-> FALSE], p2 |-> [k1 |-> FALSE, k2 |-> FALSE]],peerRemoved |-> [p1 |-> FALSE, p2 |-> FALSE],encryptedContent |-> [p1 |-> [c1 |-> "k1"], p2 |-> [c1 |-> "none"]],decryptable |-> [p1 |-> [c1 |-> FALSE], p2 |-> [c1 |-> FALSE]],wrappedTo |-> [p1 |-> [k1 |-> {}, k2 |-> {}], p2 |-> [k1 |-> {}, k2 |-> {}]],localKey |-> [p1 |-> [k1 |-> TRUE, k2 |-> FALSE], p2 |-> [k1 |-> FALSE, k2 |-> FALSE]]])
    >>
----


=============================================================================

---- CONFIG EncryptionLifecycle_TTrace_1772653845 ----
CONSTANTS
    Peers = { "p1" , "p2" }
    Keys = { "k1" , "k2" }
    Contents = { "c1" }

INVARIANT
    _inv

CHECK_DEADLOCK
    \* CHECK_DEADLOCK off because of PROPERTY or INVARIANT above.
    FALSE

INIT
    _init

NEXT
    _next

CONSTANT
    _TETrace <- _trace

ALIAS
    _expression
=============================================================================
\* Generated on Wed Mar 04 11:50:46 PST 2026