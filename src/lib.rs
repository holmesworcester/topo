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
}
