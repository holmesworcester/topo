# Forged Workspace Invite Raw Exfiltration

## What happened

The runtime currently trusts the invite link's `WORKSPACE` field early enough
to let a forged link bind a newly accepted tenant to an existing local
workspace. That creates a raw exfil path:

1. attacker creates a legitimate invite for attacker workspace `A`
2. attacker rewrites only the link field `WORKSPACE.A` to `WORKSPACE.V`
   where `V` is the victim's existing local workspace id
3. victim accepts the forged link in the same DB that already contains
   workspace `V`
4. the accept path creates `InviteAccepted(... workspace_id = V ...)`
5. `same_workspace_seed` replays sibling shared events from victim workspace `V`
   into the forged tenant
6. outbound sync selects workspace `V` again and sends raw event blobs to the
   attacker

Today the attack yields raw event/blob ingress and graph pollution. Projection
on the attacker side blocks the foreign workspace, so the leak is not yet a
clean projected copy of the victim workspace, but the raw exfiltration is real.

## Why `EndpointBootstrapRoute.tla` did not catch it

The focused TLA model assumes away the vulnerable transition:

- `CreateInvite(inv, local)` sets `inviteWorkspace[inv]` directly from the
  creator's already-accepted workspace. In the model, `inviteWorkspace` is
  canonical trusted state.
- `AcceptWorkspace(local, w)` writes the accepted workspace binding directly.
  There is no model of an untrusted invite-link workspace claim being parsed
  and staged before canonical invite validation.
- `AdmitBootstrap` checks
  `acceptedWorkspace[targetAccount] = inviteWorkspace[inviteId]`, but both
  sides of that equality come from trusted modeled state.

The runtime bug lives in the gap between those assumptions:

- the link carries an untrusted workspace claim
- `prepare_invite_acceptance` records that claim into bootstrap context before
  the canonical invite/workspace relation is validated
- `accept_invite` uses the claimed workspace to create `InviteAccepted`
- local same-workspace replay and outbound sync both key off that accepted
  workspace binding

The current TLA machine also lacks a shared-DB sibling replay step. It models
bootstrap admission and later route admission, but not the local
`same_workspace_seed` fanout edge that copies existing shared events from one
tenant to another tenant in the same database.

So the invariant violation was not discovered because the violating execution
was outside the model's state space. The model checks a stronger world than the
runtime actually implements.

## Model changes needed

To catch this class of bug, the focused model needs at least:

- a distinct untrusted `linkWorkspaceClaim`
- an acceptance action that compares `linkWorkspaceClaim` against the canonical
  workspace carried by the invite event
- a local shared-DB replay/fanout action keyed by the accepted workspace
- a safety property that forbids replay or outbound sync from using a workspace
  that did not come from the canonical invite event

## Practical mitigation directions

- Make the canonical invite event the only source of truth for accepted
  workspace binding. The link can carry a hint, but mismatch must hard-fail
  before bootstrap context or `InviteAccepted` is written.
- Add a command-layer check before `append_bootstrap_context` and before
  `InviteAccepted` creation: decoded link workspace must equal the workspace
  referenced by the validated invite event.
- Add defense in depth on replay/sync selection. `same_workspace_seed` and
  outbound sync should not be authorized solely by a local accepted workspace
  string if that binding was not derived from validated invite state.
- Extend the formal models so the untrusted link field and the replay edge are
  both explicit. Otherwise the proof target stays disconnected from the actual
  attack surface.
