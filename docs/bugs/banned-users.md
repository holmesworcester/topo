# Banned Users Are Out Of Scope

## Problem

The PoC still refers to a `ban` command, but banning does not have a coherent
end-to-end implementation here. Preventing one peer from connecting is not
enough once that user has already received workspace keys and replicated state.

## Decision

Remove active documentation and migration plans that treat banning or user
removal as supported PoC functionality.

`docs/DESIGN.md` should state this explicitly: user removal is out of scope
because correct removal requires key rotation plus a concrete group key
agreement / membership-change design for the remaining members.

## Why

1. A removed user may still hold previously distributed keys.
2. Correct removal therefore needs rekeying for the remaining group.
3. Rekeying implies membership-change semantics and group key agreement work
   that this PoC intentionally does not address yet.

## Validation

1. `docs/DESIGN.md` explicitly marks user removal / banning as out of scope.
2. Active CLI migration docs no longer carry `ban` as a feature to preserve.
3. Any future removal work should be tracked as follow-on protocol design, not
   as a bugfix to the current PoC command surface.
