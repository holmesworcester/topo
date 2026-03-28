use std::fs;
use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn event_module_files_with_context_loaders(root: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    let event_modules = root.join("src/event_modules");
    let mut stack = vec![event_modules];
    while let Some(dir) = stack.pop() {
        let entries = fs::read_dir(&dir).unwrap_or_else(|err| {
            panic!("failed to read {}: {}", dir.display(), err);
        });
        for entry in entries {
            let entry = entry.expect("dir entry");
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            if path.extension().and_then(|ext| ext.to_str()) != Some("rs") {
                continue;
            }
            let content = fs::read_to_string(&path).unwrap_or_else(|err| {
                panic!("failed to read {}: {}", path.display(), err);
            });
            if content.contains("fn build_projector_context(") {
                files.push(path);
            }
        }
    }
    files.sort();
    files
}

fn projection_context_files(root: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    let event_modules = root.join("src/event_modules");
    let mut stack = vec![event_modules];
    while let Some(dir) = stack.pop() {
        let entries = fs::read_dir(&dir).unwrap_or_else(|err| {
            panic!("failed to read {}: {}", dir.display(), err);
        });
        for entry in entries {
            let entry = entry.expect("dir entry");
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            if path.file_name().and_then(|name| name.to_str()) == Some("projection_context.rs") {
                files.push(path);
            }
        }
    }
    files.sort();
    files
}

#[test]
fn event_module_context_loaders_use_projection_queries() {
    let root = repo_root();
    let files = event_module_files_with_context_loaders(&root);
    assert!(
        !files.is_empty(),
        "expected at least one context loader file"
    );

    for file in files {
        let content = fs::read_to_string(&file).expect("read context loader file");
        let function_signature = content
            .split("fn build_projector_context(")
            .nth(1)
            .and_then(|rest| rest.split(')').next())
            .unwrap_or_default();
        assert!(
            content.contains("queries: &dyn ProjectionQueries"),
            "{} should accept ProjectionQueries instead of raw SQLite connections",
            file.display()
        );
        assert!(
            !function_signature.contains("conn: &Connection"),
            "{} should not keep a raw Connection-based build_projector_context signature",
            file.display()
        );
    }
}

#[test]
fn event_module_context_loaders_live_with_projectors() {
    let root = repo_root();
    let files = projection_context_files(&root);
    assert!(
        files.is_empty(),
        "projection context loaders should live in projector.rs or the event module itself: {:?}",
        files
    );
}

#[test]
fn event_metadata_does_not_point_back_to_projection_context_modules() {
    let root = repo_root().join("src/event_modules");
    let mut stack = vec![root];
    while let Some(dir) = stack.pop() {
        let entries = fs::read_dir(&dir).unwrap_or_else(|err| {
            panic!("failed to read {}: {}", dir.display(), err);
        });
        for entry in entries {
            let entry = entry.expect("dir entry");
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            if path.file_name().and_then(|name| name.to_str()) != Some("wire.rs") {
                continue;
            }
            let content = fs::read_to_string(&path).expect("read wire.rs");
            assert!(
                !content.contains("projection_context::build_projector_context"),
                "{} should point context_loader at projector.rs or the event module itself",
                path.display()
            );
        }
    }
}

#[test]
fn sim_node_behavior_has_no_temp_sqlite_context_fallback() {
    let root = repo_root();
    let node_behavior = root.join("src/sim/node_behavior.rs");
    let content = fs::read_to_string(&node_behavior).expect("read node_behavior.rs");
    assert!(
        !content.contains("temp_sqlite_conn"),
        "sim node behavior should not reconstruct temporary SQLite state for context loading"
    );
}
