# Feedback on NEGENTROPY_SQLITE_PLAN.md (v3)

## Status: APPROVED - Ready to Implement

All questions resolved by plan updates:

1. **32-byte IDs**: Core Decision #7 confirms alignment with negentropy::Id
2. **Send timing**: Section 5 clarifies "Send during reconciliation" - don't wait
3. **neg_blocks rebuild**: No OFFSET fallback - rebuild required before negentropy when `needs_rebuild=1`
4. **Projection decoupling**: Ingest worker vs projection worker architecture clear

## Implementation Order

1. Add `neg_items`, `neg_blocks`, `neg_meta` tables to schema
2. Modify ingestion to populate `neg_items` (raw 32-byte blob id)
3. Implement `NegentropyStorageSqlite` with block index
4. Add two QUIC streams (control + data)
5. Refactor sync loops with dedicated sender/receiver tasks
6. Replace `try_send` with `send().await` on ingest channel
7. Decouple projection (incoming_queue consumer runs independently)
8. Remove blob prefetch
9. Test at scale (50k, 200k, 500k)

Starting implementation.
