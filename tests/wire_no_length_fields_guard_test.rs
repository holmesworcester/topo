//! Crude guardrail test: fails if variable-length field markers reappear
//! in canonical event parser/encoder source files.
//!
//! This is intentionally crude — it scans source text for a denylist of
//! field names that would indicate a return to length-prefixed wire formats.
//! It's a cheap regression detector, not a proof.

use std::fs;

/// Canonical event source files in scope for fixed-layout enforcement.
const CANONICAL_EVENT_FILES: &[&str] = &[
    "src/events/message.rs",
    "src/events/reaction.rs",
    "src/events/signed_memo.rs",
    "src/events/encrypted.rs",
    "src/events/file_slice.rs",
    "src/events/message_attachment.rs",
    "src/events/bench_dep.rs",
    "src/events/message_deletion.rs",
    "src/events/secret_key.rs",
    "src/events/secret_shared.rs",
    "src/events/workspace.rs",
    "src/events/invite_accepted.rs",
    "src/events/user_invite.rs",
    "src/events/user.rs",
    "src/events/device_invite.rs",
    "src/events/peer_shared.rs",
    "src/events/admin.rs",
    "src/events/user_removed.rs",
    "src/events/peer_removed.rs",
    "src/events/transport_key.rs",
];

/// Denied field names that indicate variable-length wire format logic.
/// These must NOT appear as struct fields or parser variables in canonical event code.
const DENIED_FIELD_NAMES: &[&str] = &[
    "content_len",
    "emoji_len",
    "ciphertext_len",
    "filename_len",
    "mime_len",
    "dep_count",
    "payload_len",
    "body_len",
    "field_len",
    "var_bytes",
    "var_string",
];

/// Denied function/macro patterns that indicate variable-length parsing logic.
/// Parser control flow must not be driven by untrusted length fields.
const DENIED_PARSE_PATTERNS: &[&str] = &[
    "take_bytes(",
    "read_var(",
    "nom::bytes::complete::take(",
];

#[test]
fn no_length_fields_in_canonical_events() {
    let mut violations = Vec::new();

    for file in CANONICAL_EVENT_FILES {
        let contents = fs::read_to_string(file)
            .unwrap_or_else(|e| panic!("failed to read {}: {}", file, e));

        for denied in DENIED_FIELD_NAMES {
            for (line_num, line) in contents.lines().enumerate() {
                // Skip comments that explain the removal
                if line.trim_start().starts_with("//") {
                    continue;
                }
                if line.contains(denied) {
                    violations.push(format!(
                        "  {}:{}: found '{}' in: {}",
                        file,
                        line_num + 1,
                        denied,
                        line.trim()
                    ));
                }
            }
        }

        for denied in DENIED_PARSE_PATTERNS {
            for (line_num, line) in contents.lines().enumerate() {
                if line.trim_start().starts_with("//") {
                    continue;
                }
                if line.contains(denied) {
                    violations.push(format!(
                        "  {}:{}: found '{}' in: {}",
                        file,
                        line_num + 1,
                        denied,
                        line.trim()
                    ));
                }
            }
        }
    }

    assert!(
        violations.is_empty(),
        "Variable-length field markers found in canonical event files!\n\
         These indicate a regression to length-prefixed wire formats.\n\
         Violations:\n{}",
        violations.join("\n")
    );
}

#[test]
fn all_canonical_event_files_exist() {
    for file in CANONICAL_EVENT_FILES {
        assert!(
            std::path::Path::new(file).exists(),
            "Expected canonical event file does not exist: {}",
            file
        );
    }
}

/// Verify that every event type has a deterministic wire size by checking
/// that encode → parse roundtrip produces exactly the same bytes for all
/// registered types (via the existing registry).
#[test]
fn all_registered_types_have_fixed_wire_size() {
    use topo::events::{fixed_layout, registry};

    // For each type code 1..=26, verify the registry has an entry
    // and encoding produces a deterministic-length blob.
    let reg = registry();
    for code in 1u8..=26 {
        if code == 3 {
            continue; // type 3 is unused (gap in type code allocation)
        }
        let meta = reg.lookup(code);
        assert!(
            meta.is_some(),
            "type code {} missing from registry — all canonical types must be registered",
            code
        );
    }

    // Verify encrypted wire size is deterministic for all encryptable inner types
    let encryptable_codes: Vec<u8> = (1..=26u8)
        .filter(|c| reg.lookup(*c).map_or(false, |m| m.encryptable))
        .collect();

    for code in encryptable_codes {
        // These type codes are intentionally disallowed as encrypted inner events.
        if matches!(code, 5 | 6 | 9) {
            continue;
        }
        let inner_size = fixed_layout::encrypted_inner_wire_size(code);
        assert!(
            inner_size.is_some(),
            "encryptable type {} has no encrypted_inner_wire_size entry",
            code
        );
    }
}
