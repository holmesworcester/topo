mod sync;
mod encryption;
mod queue;
mod deletion;
mod identity;
mod identity_sync;
mod shared_db;
mod subscription;
mod transport;

#[cfg(feature = "discovery")]
mod mdns;

/// Guard test: verify that every test function across all scenario modules uses `ScenarioHarness`.
/// This catches future tests that forget to add the harness.
#[test]
fn test_scenario_harness_guard() {
    let modules: &[(&str, &str)] = &[
        ("sync", include_str!("sync.rs")),
        ("encryption", include_str!("encryption.rs")),
        ("queue", include_str!("queue.rs")),
        ("deletion", include_str!("deletion.rs")),
        ("identity", include_str!("identity.rs")),
        ("identity_sync", include_str!("identity_sync.rs")),
        ("shared_db", include_str!("shared_db.rs")),
        ("subscription", include_str!("subscription.rs")),
        ("transport", include_str!("transport.rs")),
        ("mdns", include_str!("mdns.rs")),
    ];

    let mut uncovered = Vec::new();
    for (module_name, source) in modules {
        let lines: Vec<&str> = source.lines().collect();
        let mut test_fns: Vec<(usize, String)> = Vec::new();
        for (i, line) in lines.iter().enumerate() {
            let trimmed = line.trim();
            let is_fn_def =
                (trimmed.starts_with("fn test_") || trimmed.starts_with("async fn test_"))
                    && trimmed.contains('(');
            if !is_fn_def {
                continue;
            }
            let name = trimmed
                .trim_start_matches("async ")
                .trim_start_matches("fn ")
                .split('(')
                .next()
                .unwrap_or("")
                .to_string();
            test_fns.push((i, name));
        }

        for (idx, (start_line, ref name)) in test_fns.iter().enumerate() {
            let end_line = if idx + 1 < test_fns.len() {
                test_fns[idx + 1].0
            } else {
                lines.len()
            };
            let section = &lines[*start_line..end_line];
            let has_harness = section.iter().any(|l| l.contains("ScenarioHarness"));
            if !has_harness {
                uncovered.push(format!("{}::{}", module_name, name));
            }
        }
    }

    assert!(
        uncovered.is_empty(),
        "The following test(s) do not use ScenarioHarness: {:?}\n\
         Every scenario test must use ScenarioHarness::new(), ::skip(), or be documented.",
        uncovered,
    );
}
