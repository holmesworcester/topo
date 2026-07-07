# Quint Models

This directory contains executable Quint models for protocol-design checks that
are not yet tied to runtime or Verus coverage gates.

## Forward-Secrecy Repair Model

`forward_secrecy_repair.qnt` models the proposed frontier-scoped repair design
at the material-authorization layer:

- `key_secret` identity is deterministic by material bytes.
- Post-accept repair requests are wildcard asks keyed by
  `(removal_frontier, recipient_wrap_pubkey)`.
- Repair responses are deterministic semantic IDs keyed by
  `(removal_frontier, recipient_wrap_pubkey, material_id)`.
- Pre-accept invite keys are separate and are not valid post-accept repair
  targets.
- Frontier authorization decides which recipients and responders are eligible.

### Success Criteria

- SC1: Post-accept requests target explicit wrap pubkeys, not invite pubkeys.
- SC2: Removed peers do not learn material excluded by the removal frontier.
- SC3: Proactive shares and late wildcard requests converge to the same
  semantic response set.
- SC4: Duplicate proactive and repair responses are idempotent when response
  identity is the semantic response key.
- SC5: The model exposes whether signed response events collapse by themselves.
  It also checks that the semantic response projection is exactly the set of
  response IDs carried by authorized signed events.

### Checks

- SC1: `inviteKeysAreNotPostAcceptRepairTargetsTest`
- SC2: `removedPeerDeniedForExcludedFrontierTest`,
  `removedPeerNeverLearnsPostRemovalMaterial`
- SC3: `lateRequestConvergesToProactiveSetTest`
- SC4: `proactivePlusLateRequestIsIdempotentTest`
- SC5: `responseEventEnvelopeDoesNotCollapseByItselfTest`,
  `responseEventSafety`, `responseProjectionMatchesEvents`

### End-To-End Validation

Run the complete local check set:

```sh
npm run quint:fs:typecheck
npm run quint:fs:test
npm run quint:fs:run
npm run quint:fs:verify
```

The important modeling caveat is SC5: if the durable DAG event ID includes a
different responder signature, duplicate response events do not collapse at the
event layer. The convergence claim is coherent only if deduplication is keyed by
the semantic response ID, or if the protocol has a deterministic response-event
identity independent of responder identity.
