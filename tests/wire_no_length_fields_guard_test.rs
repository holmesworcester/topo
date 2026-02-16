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
];

#[test]
fn no_length_fields_in_canonical_events() {
    let mut violations = Vec::new();

    for file in CANONICAL_EVENT_FILES {
        let contents = fs::read_to_string(file)
            .unwrap_or_else(|e| panic!("failed to read {}: {}", file, e));

        for denied in DENIED_FIELD_NAMES {
            // Search for the denied name as a word (not inside other identifiers).
            // Simple approach: check for the denied name preceded/followed by non-alphanumeric.
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
