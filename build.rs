use std::process::Command;

fn main() {
    // Embed git commit hash at build time for version mismatch detection.
    let output = Command::new("git")
        .args(["rev-parse", "--short=8", "HEAD"])
        .output();
    let hash = match output {
        Ok(out) if out.status.success() => {
            String::from_utf8_lossy(&out.stdout).trim().to_string()
        }
        _ => "unknown".to_string(),
    };
    println!("cargo:rustc-env=TOPO_GIT_HASH={}", hash);
    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=.git/refs/");
}
