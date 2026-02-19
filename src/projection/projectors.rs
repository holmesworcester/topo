use crate::crypto::event_id_to_base64;
use crate::event_modules::{
    FileSliceEvent, MessageAttachmentEvent, MessageDeletionEvent, MessageEvent,
    ReactionEvent, SecretKeyEvent, SignedMemoEvent,
};
use super::result::{ContextSnapshot, EmitCommand, ProjectorResult, SqlVal, WriteOp};

/// Pure projector: Message → messages table insert.
///
/// Also checks the context snapshot for a matching deletion_intent — if the
/// message target already has a deletion intent recorded, the message is
/// projected as tombstoned on first materialization (deletion-before-create
/// convergence).
pub fn project_message_pure(
    recorded_by: &str,
    event_id_b64: &str,
    msg: &MessageEvent,
    ctx: &ContextSnapshot,
) -> ProjectorResult {
    if let Some(reason) = &ctx.signer_user_mismatch_reason {
        return ProjectorResult::reject(reason.clone());
    }

    let workspace_id_b64 = event_id_to_base64(&msg.workspace_id);
    let author_id_b64 = event_id_to_base64(&msg.author_id);

    // Check for pre-existing deletion intents (delete-before-create convergence).
    // Multiple intents may exist (different deletion events targeting this message).
    // Find the first one whose author matches the message author.
    if let Some(intent) = ctx.deletion_intents.iter().find(|i| i.author_id == author_id_b64) {
        // Message was already targeted for deletion before it arrived.
        // Record the tombstone immediately using the original deletion event ID
        // for replay invariance — the same tombstone row results regardless of
        // whether delete or create arrives first.
        let ops = vec![
            WriteOp::InsertOrIgnore {
                table: "deleted_messages",
                columns: vec!["recorded_by", "message_id", "deletion_event_id", "author_id", "deleted_at"],
                values: vec![
                    SqlVal::Text(recorded_by.to_string()),
                    SqlVal::Text(event_id_b64.to_string()),
                    SqlVal::Text(intent.deletion_event_id.clone()),
                    SqlVal::Text(intent.author_id.clone()),
                    SqlVal::Int(intent.created_at),
                ],
            },
        ];
        // Structurally valid (the event itself is fine), but tombstoned.
        return ProjectorResult::valid(ops);
    }
    // No matching-author intent found — materialize the message normally.
    // Any wrong-author intents are stale and ignored.

    let ops = vec![
        WriteOp::InsertOrIgnore {
            table: "messages",
            columns: vec!["message_id", "workspace_id", "author_id", "content", "created_at", "recorded_by"],
            values: vec![
                SqlVal::Text(event_id_b64.to_string()),
                SqlVal::Text(workspace_id_b64),
                SqlVal::Text(author_id_b64),
                SqlVal::Text(msg.content.clone()),
                SqlVal::Int(msg.created_at_ms as i64),
                SqlVal::Text(recorded_by.to_string()),
            ],
        },
    ];
    ProjectorResult::valid(ops)
}

/// Pure projector: Reaction → reactions table insert.
///
/// If the target message has been deleted, the
/// reaction is structurally valid but no row is written.
pub fn project_reaction_pure(
    recorded_by: &str,
    event_id_b64: &str,
    rxn: &ReactionEvent,
    ctx: &ContextSnapshot,
) -> ProjectorResult {
    if let Some(reason) = &ctx.signer_user_mismatch_reason {
        return ProjectorResult::reject(reason.clone());
    }

    let target_id_b64 = event_id_to_base64(&rxn.target_event_id);

    // Check deletion state — skip if target is tombstoned or has deletion intent
    if ctx.target_message_deleted {
        return ProjectorResult::valid(vec![]); // valid event, no row written
    }

    let author_id_b64 = event_id_to_base64(&rxn.author_id);
    let ops = vec![
        WriteOp::InsertOrIgnore {
            table: "reactions",
            columns: vec!["event_id", "target_event_id", "author_id", "emoji", "created_at", "recorded_by"],
            values: vec![
                SqlVal::Text(event_id_b64.to_string()),
                SqlVal::Text(target_id_b64),
                SqlVal::Text(author_id_b64),
                SqlVal::Text(rxn.emoji.clone()),
                SqlVal::Int(rxn.created_at_ms as i64),
                SqlVal::Text(recorded_by.to_string()),
            ],
        },
    ];
    ProjectorResult::valid(ops)
}

/// Pure projector: SecretKey → secret_keys table insert.
pub fn project_secret_key_pure(
    recorded_by: &str,
    event_id_b64: &str,
    sk: &SecretKeyEvent,
) -> ProjectorResult {
    let ops = vec![
        WriteOp::InsertOrIgnore {
            table: "secret_keys",
            columns: vec!["event_id", "key_bytes", "created_at", "recorded_by"],
            values: vec![
                SqlVal::Text(event_id_b64.to_string()),
                SqlVal::Blob(sk.key_bytes.to_vec()),
                SqlVal::Int(sk.created_at_ms as i64),
                SqlVal::Text(recorded_by.to_string()),
            ],
        },
    ];
    ProjectorResult::valid(ops)
}

/// Pure projector: SignedMemo → signed_memos table insert.
pub fn project_signed_memo_pure(
    recorded_by: &str,
    event_id_b64: &str,
    memo: &SignedMemoEvent,
) -> ProjectorResult {
    let signed_by_b64 = event_id_to_base64(&memo.signed_by);
    let ops = vec![
        WriteOp::InsertOrIgnore {
            table: "signed_memos",
            columns: vec!["event_id", "signed_by", "signer_type", "content", "created_at", "recorded_by"],
            values: vec![
                SqlVal::Text(event_id_b64.to_string()),
                SqlVal::Text(signed_by_b64),
                SqlVal::Int(memo.signer_type as i64),
                SqlVal::Text(memo.content.clone()),
                SqlVal::Int(memo.created_at_ms as i64),
                SqlVal::Text(recorded_by.to_string()),
            ],
        },
    ];
    ProjectorResult::valid(ops)
}

/// Pure projector: MessageDeletion → two-stage deletion intent + tombstone model.
///
/// 1. Always emits an idempotent deletion_intent write keyed by (recorded_by, "message", target_id).
/// 2. If target exists in projected state (ctx.target_message_author is Some), verifies
///    author match and emits tombstone + cascade writes.
/// 3. If target doesn't exist yet (None), only records intent — the message projector
///    will tombstone on first materialization when it checks deletion_intents.
/// 4. If already tombstoned, verifies author and returns AlreadyProcessed.
pub fn project_message_deletion_pure(
    recorded_by: &str,
    event_id_b64: &str,
    del: &MessageDeletionEvent,
    ctx: &ContextSnapshot,
) -> ProjectorResult {
    if let Some(reason) = &ctx.signer_user_mismatch_reason {
        return ProjectorResult::reject(reason.clone());
    }

    let target_b64 = event_id_to_base64(&del.target_event_id);
    let del_author_b64 = event_id_to_base64(&del.author_id);

    // Type validation: reject if target is a known non-message event.
    // (target_event_id was removed from deps for the intent-only path,
    // so we check the target type at projection time instead.)
    if ctx.target_is_non_message {
        return ProjectorResult::reject(
            "deletion target is a non-message event".to_string(),
        );
    }

    // Already tombstoned — verify author, return AlreadyProcessed
    if let Some(ref stored_author) = ctx.target_tombstone_author {
        if stored_author != &del_author_b64 {
            return ProjectorResult::reject(
                "deletion author does not match message author".to_string(),
            );
        }
        // Deletion intent should still be recorded for idempotence,
        // but it's a no-op if already exists.
        let ops = vec![
            WriteOp::InsertOrIgnore {
                table: "deletion_intents",
                columns: vec!["recorded_by", "target_kind", "target_id", "deletion_event_id", "author_id", "created_at"],
                values: vec![
                    SqlVal::Text(recorded_by.to_string()),
                    SqlVal::Text("message".to_string()),
                    SqlVal::Text(target_b64),
                    SqlVal::Text(event_id_b64.to_string()),
                    SqlVal::Text(del_author_b64),
                    SqlVal::Int(del.created_at_ms as i64),
                ],
            },
        ];
        return ProjectorResult {
            decision: super::decision::ProjectionDecision::AlreadyProcessed,
            write_ops: ops,
            emit_commands: Vec::new(),
        };
    }

    // Always record deletion intent (idempotent via INSERT OR IGNORE)
    let mut ops = vec![
        WriteOp::InsertOrIgnore {
            table: "deletion_intents",
            columns: vec!["recorded_by", "target_kind", "target_id", "deletion_event_id", "author_id", "created_at"],
            values: vec![
                SqlVal::Text(recorded_by.to_string()),
                SqlVal::Text("message".to_string()),
                SqlVal::Text(target_b64.clone()),
                SqlVal::Text(event_id_b64.to_string()),
                SqlVal::Text(del_author_b64.clone()),
                SqlVal::Int(del.created_at_ms as i64),
            ],
        },
    ];

    // Target exists — verify author, emit tombstone + cascade
    if let Some(ref msg_author) = ctx.target_message_author {
        if msg_author != &del_author_b64 {
            return ProjectorResult::reject(
                "deletion author does not match message author".to_string(),
            );
        }

        // Tombstone
        ops.push(WriteOp::InsertOrIgnore {
            table: "deleted_messages",
            columns: vec!["recorded_by", "message_id", "deletion_event_id", "author_id", "deleted_at"],
            values: vec![
                SqlVal::Text(recorded_by.to_string()),
                SqlVal::Text(target_b64.clone()),
                SqlVal::Text(event_id_b64.to_string()),
                SqlVal::Text(del_author_b64),
                SqlVal::Int(del.created_at_ms as i64),
            ],
        });

        // Cascade: delete message and its reactions (explicit write ops, not hidden side effects)
        ops.push(WriteOp::Delete {
            table: "messages",
            where_clause: vec![
                ("recorded_by", SqlVal::Text(recorded_by.to_string())),
                ("message_id", SqlVal::Text(target_b64.clone())),
            ],
        });
        ops.push(WriteOp::Delete {
            table: "reactions",
            where_clause: vec![
                ("recorded_by", SqlVal::Text(recorded_by.to_string())),
                ("target_event_id", SqlVal::Text(target_b64)),
            ],
        });

        return ProjectorResult::valid(ops);
    }

    // Target doesn't exist yet — only record intent.
    // When the message arrives, project_message_pure will check deletion_intents
    // and tombstone immediately (delete-before-create convergence).
    ProjectorResult::valid(ops)
}

/// Pure projector: MessageAttachment → message_attachments table insert.
/// Emits RetryFileSliceGuards command so pending file_slices can unblock.
pub fn project_message_attachment_pure(
    recorded_by: &str,
    event_id_b64: &str,
    att: &MessageAttachmentEvent,
) -> ProjectorResult {
    let message_id_b64 = event_id_to_base64(&att.message_id);
    let file_id_b64 = event_id_to_base64(&att.file_id);
    let key_event_id_b64 = event_id_to_base64(&att.key_event_id);
    let signer_event_id_b64 = event_id_to_base64(&att.signed_by);

    let ops = vec![
        WriteOp::InsertOrIgnore {
            table: "message_attachments",
            columns: vec![
                "recorded_by", "event_id", "message_id", "file_id",
                "blob_bytes", "total_slices", "slice_bytes", "root_hash",
                "key_event_id", "filename", "mime_type", "created_at", "signer_event_id",
            ],
            values: vec![
                SqlVal::Text(recorded_by.to_string()),
                SqlVal::Text(event_id_b64.to_string()),
                SqlVal::Text(message_id_b64),
                SqlVal::Text(file_id_b64.clone()),
                SqlVal::Int(att.blob_bytes as i64),
                SqlVal::Int(att.total_slices as i64),
                SqlVal::Int(att.slice_bytes as i64),
                SqlVal::Blob(att.root_hash.to_vec()),
                SqlVal::Text(key_event_id_b64),
                SqlVal::Text(att.filename.clone()),
                SqlVal::Text(att.mime_type.clone()),
                SqlVal::Int(att.created_at_ms as i64),
                SqlVal::Text(signer_event_id_b64),
            ],
        },
    ];

    ProjectorResult::valid_with_commands(
        ops,
        vec![EmitCommand::RetryFileSliceGuards { file_id: file_id_b64 }],
    )
}

/// Pure projector: FileSlice → file_slices table insert.
///
/// Uses ContextSnapshot.file_descriptors to determine authorization:
/// - No descriptors → guard-block (emit RecordFileSliceGuardBlock command)
/// - Multiple signers → reject
/// - Signer mismatch → reject
/// - Success → insert file_slice row
pub fn project_file_slice_pure(
    recorded_by: &str,
    event_id_b64: &str,
    fs: &FileSliceEvent,
    ctx: &ContextSnapshot,
) -> ProjectorResult {
    let file_id_b64 = event_id_to_base64(&fs.file_id);
    let slice_signer_b64 = event_id_to_base64(&fs.signed_by);

    if ctx.file_descriptors.is_empty() {
        // No descriptor yet — guard-block
        return ProjectorResult {
            decision: super::decision::ProjectionDecision::Block { missing: vec![] },
            write_ops: Vec::new(),
            emit_commands: vec![EmitCommand::RecordFileSliceGuardBlock {
                file_id: file_id_b64,
                event_id: event_id_b64.to_string(),
            }],
        };
    }

    // Check for conflicting descriptor signers
    let mut descriptor_signers = std::collections::BTreeSet::new();
    for (_, signer) in &ctx.file_descriptors {
        descriptor_signers.insert(signer.clone());
    }
    if descriptor_signers.len() > 1 {
        return ProjectorResult::reject(format!(
            "file_id {} maps to multiple attachment signers ({}), cannot authorize file_slice",
            file_id_b64,
            descriptor_signers.len()
        ));
    }

    let (descriptor_event_id, descriptor_signer) = ctx.file_descriptors[0].clone();
    if descriptor_signer != slice_signer_b64 {
        return ProjectorResult::reject(format!(
            "file_slice signer {} does not match attachment descriptor signer {}",
            slice_signer_b64, descriptor_signer
        ));
    }

    // Check for existing slice in same slot (idempotent replay or conflict)
    if let Some((ref existing_event_id, ref existing_descriptor)) = ctx.existing_file_slice {
        if existing_event_id == event_id_b64 {
            if existing_descriptor != &descriptor_event_id {
                return ProjectorResult::reject(format!(
                    "file_slice descriptor mismatch: existing {} vs authorized {}",
                    existing_descriptor, descriptor_event_id
                ));
            }
            return ProjectorResult::valid(vec![]); // idempotent replay
        } else {
            return ProjectorResult::reject(format!(
                "duplicate file_slice: slot ({}, {}, {}) already claimed by event {}",
                recorded_by, file_id_b64, fs.slice_number, existing_event_id
            ));
        }
    }

    // Insert new slice.
    // Safety: the TOCTOU window between ctx.existing_file_slice check and this
    // write is harmless because SQLite WAL is single-writer and per-peer
    // projection is serialized in the ingest runtime. InsertOrIgnore is
    // idempotent for replay, and concurrent slot claiming by different events
    // cannot occur within a single connection.
    let ops = vec![
        WriteOp::InsertOrIgnore {
            table: "file_slices",
            columns: vec!["recorded_by", "file_id", "slice_number", "event_id", "created_at", "descriptor_event_id"],
            values: vec![
                SqlVal::Text(recorded_by.to_string()),
                SqlVal::Text(file_id_b64),
                SqlVal::Int(fs.slice_number as i64),
                SqlVal::Text(event_id_b64.to_string()),
                SqlVal::Int(fs.created_at_ms as i64),
                SqlVal::Text(descriptor_event_id),
            ],
        },
    ];
    ProjectorResult::valid(ops)
}
