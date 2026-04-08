use std::fs;
use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn should_skip_file(path: &Path) -> bool {
    let file_name = path.file_name().and_then(|name| name.to_str());
    matches!(file_name, Some("repo_sql_types_guard_test.rs"))
}

fn collect_rs_files(root: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(root).unwrap_or_else(|err| {
        panic!("failed to read {}: {}", root.display(), err);
    }) {
        let entry = entry.expect("dir entry");
        let path = entry.path();
        if path.is_dir() {
            collect_rs_files(&path, out);
            continue;
        }
        if path.extension().and_then(|ext| ext.to_str()) == Some("rs") && !should_skip_file(&path) {
            out.push(path);
        }
    }
}

fn has_inferred_raw_text_or_blob_read(content: &str) -> bool {
    let lines: Vec<&str> = content.lines().collect();
    let inferred_type_hints = [
        ": String =",
        ": Option<String> =",
        ": Vec<u8> =",
        ": Option<Vec<u8>> =",
        ": (String,",
        ": Option<(String,",
        ": (Vec<u8>,",
        ": Option<(Vec<u8>,",
        "-> SqliteResult<String>",
        "-> SqliteResult<Option<String>>",
        "-> SqliteResult<Vec<u8>>",
        "-> SqliteResult<Option<Vec<u8>>>",
        "-> rusqlite::Result<String>",
        "-> rusqlite::Result<Option<String>>",
        "-> rusqlite::Result<Vec<u8>>",
        "-> rusqlite::Result<Option<Vec<u8>>>",
    ];
    for (idx, line) in lines.iter().enumerate() {
        if !line.contains("row.get(0)")
            && !line.contains("row.get(1)")
            && !line.contains("row.get(2)")
        {
            continue;
        }
        let start = idx.saturating_sub(6);
        let window = lines[start..=idx].join("\n");
        if inferred_type_hints
            .iter()
            .any(|pattern| window.contains(pattern))
        {
            return true;
        }
    }
    false
}

#[test]
fn repo_uses_typed_sql_codecs_for_text_and_blob_reads() {
    let mut files = Vec::new();
    collect_rs_files(&repo_root().join("src"), &mut files);
    collect_rs_files(&repo_root().join("tests"), &mut files);

    let banned_patterns = [
        "row.get::<_, String>",
        "row.get::<_, Option<String>>",
        "row.get::<_, Vec<u8>>",
        "row.get::<_, Option<Vec<u8>>>",
        ": String = row.get(",
        ": Option<String> = row.get(",
        ": Vec<u8> = row.get(",
        ": Option<Vec<u8>> = row.get(",
    ];

    let mut offenders = Vec::new();
    for path in files {
        let content = fs::read_to_string(&path).unwrap_or_else(|err| {
            panic!("failed to read {}: {}", path.display(), err);
        });
        let has_explicit_raw_read = banned_patterns
            .iter()
            .any(|pattern| content.contains(pattern));
        if has_explicit_raw_read || has_inferred_raw_text_or_blob_read(&content) {
            offenders.push(path);
        }
    }

    assert!(
        offenders.is_empty(),
        "repo must read SQLite TEXT/BLOB values through typed sql_types codecs, not raw String/Vec<u8>: {:?}",
        offenders
    );
}
