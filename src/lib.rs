pub mod contracts;
pub mod crypto;
pub mod db;
pub mod db_registry;
pub mod event_modules;
pub mod event_pipeline;
pub mod identity_ops;
pub mod invite_link;
pub mod node;
pub mod peering;
pub mod projection;
pub mod protocol;
pub mod rpc;
pub mod runtime;
pub mod service;
pub mod sync;
pub mod testutil;
pub mod transport;
pub mod transport_identity;

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
            panic!(
                "Boundary import check failed:\n{}\n{}",
                stdout, stderr
            );
        }
    }
}
