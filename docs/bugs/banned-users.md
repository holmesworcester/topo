# Banned users are out of scope in this PoC

The repository previously exposed a `ban` command and removal-related event plumbing, but the feature was not complete enough to be correct.

User removal requires coordinated key rotation and group key agreement so future ciphertext is no longer available to the removed user or device. This PoC does not implement that machinery, so `ban`, `user_removed`, and `peer_removed` are intentionally removed rather than treated as a supported feature.

Current resolution:

1. remove `ban` from CLI/RPC surfaces,
2. remove removal-specific event modules and trust/pipeline behavior,
3. document user removal as deferred future work instead of active PoC scope.
