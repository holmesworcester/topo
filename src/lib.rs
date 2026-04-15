pub mod event_modules;
pub mod runtime;
pub mod shared;
pub mod sim;
pub mod state;
pub mod testutil;

pub use runtime::control::{assert, display, node, rpc, service};
pub use runtime::peering;
pub use runtime::sync_engine as sync;
pub use runtime::transport;
pub use shared::{contracts, crypto, protocol, tuning};
pub use state::db;
pub use state::pipeline as event_pipeline;
pub use state::projection;

#[cfg(test)]
mod boundary_tests {
    /// Verify that boundary import rules are not violated.
    /// This is the automated equivalent of scripts/check_boundary_imports.sh.
    #[test]
    fn test_boundary_imports_enforced() {
        let result = std::process::Command::new("bash")
            .arg("scripts/check_boundary_imports.sh")
            .output()
            .expect("failed to run boundary check script");
        if !result.status.success() {
            let stderr = String::from_utf8_lossy(&result.stderr);
            let stdout = String::from_utf8_lossy(&result.stdout);
            panic!("Boundary import check failed:\n{}\n{}", stdout, stderr);
        }
    }

    fn assert_python_script_passes(script: &str) {
        let mut command = std::process::Command::new("python3");
        command.arg(script);
        if script.ends_with("check_projector_tla_conformance.py") {
            command.env("TOPO_SKIP_CARGO_TEST_DISCOVERY", "1");
        }
        let result = command
            .output()
            .unwrap_or_else(|err| panic!("failed to run {} via python3: {}", script, err));
        if !result.status.success() {
            let stderr = String::from_utf8_lossy(&result.stderr);
            let stdout = String::from_utf8_lossy(&result.stdout);
            panic!("{} failed:\n{}\n{}", script, stdout, stderr);
        }
    }

    #[test]
    fn test_projector_tla_conformance_enforced() {
        assert_python_script_passes("scripts/check_projector_tla_conformance.py");
    }

    #[test]
    fn test_projector_tla_bijection_enforced() {
        assert_python_script_passes("scripts/check_projector_tla_bijection.py");
    }

    #[test]
    fn test_formal_seam_coverage_enforced() {
        assert_python_script_passes("scripts/check_formal_seam_coverage.py");
    }

    #[test]
    fn test_command_formal_coverage_enforced() {
        assert_python_script_passes("scripts/check_command_formal_coverage.py");
    }

    #[test]
    fn test_formal_mirror_updates_enforced() {
        assert_python_script_passes("scripts/check_formal_mirror_updates.py");
    }

    fn collect_verus_sources(dir: &std::path::Path, out: &mut Vec<String>) {
        for entry in std::fs::read_dir(dir)
            .unwrap_or_else(|err| panic!("failed to read {}: {}", dir.display(), err))
        {
            let entry = entry
                .unwrap_or_else(|err| panic!("failed to read entry in {}: {}", dir.display(), err));
            let path = entry.path();
            if path.is_dir() {
                collect_verus_sources(&path, out);
                continue;
            }
            if path.extension().and_then(|ext| ext.to_str()) != Some("rs") {
                continue;
            }
            let Some(file_name) = path.file_name().and_then(|name| name.to_str()) else {
                continue;
            };
            if matches!(file_name, "lib.rs" | "mod.rs") {
                continue;
            }
            let repo_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
            let relative = path
                .strip_prefix(repo_root)
                .unwrap_or_else(|err| panic!("failed to relativize {}: {}", path.display(), err))
                .to_string_lossy()
                .replace('\\', "/");
            out.push(relative);
        }
    }

    #[test]
    fn test_formal_seam_coverage_indexes_verus_sources() {
        let repo_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let coverage =
            std::fs::read_to_string(repo_root.join("docs/planning/FORMAL_SEAM_COVERAGE.md"))
                .expect("read formal seam coverage");
        let mut sources = Vec::new();
        collect_verus_sources(&repo_root.join("verus-proofs/src"), &mut sources);
        sources.sort();

        let missing = sources
            .into_iter()
            .filter(|source| !coverage.contains(source))
            .collect::<Vec<_>>();
        assert!(
            missing.is_empty(),
            "every non-module Verus source must be indexed as a covered seam or supporting proof module in docs/planning/FORMAL_SEAM_COVERAGE.md; missing: {missing:?}"
        );
    }
}
