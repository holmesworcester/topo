//! Test for invite bootstrap endpoint observation race condition.
//!
//! Reproduces the bug where the inviter's target planner dials the invitee
//! via endpoint observations, causing the invitee's outbound connection to
//! be repeatedly replaced before sync sessions can complete.

use std::time::Duration;

mod cli_harness;
use cli_harness::SharedWorkspaceBench;

#[tokio::test(flavor = "multi_thread")]
async fn invite_endpoint_race_prevents_bootstrap_sync() {
    let bench = SharedWorkspaceBench::new("invite-endpoint-race-test");

    // Start inviter daemon
    let inviter = bench
        .start_daemon("inviter", None, true)
        .await
        .expect("start inviter");

    // Create a device invite
    let invite_link = inviter
        .topo(&["invite"])
        .await
        .expect("create invite")
        .stdout;
    let invite_link = invite_link.trim();

    // Start invitee daemon
    let invitee = bench
        .start_daemon("invitee", None, true)
        .await
        .expect("start invitee");

    // Enable sync logging on both sides to observe the race
    inviter
        .topo(&["sync-log", "enable", "--all-runs"])
        .await
        .expect("enable inviter sync log");
    invitee
        .topo(&["sync-log", "enable", "--all-runs"])
        .await
        .expect("enable invitee sync log");

    // Accept the invite
    invitee
        .topo(&["accept-invite", invite_link])
        .await
        .expect("accept invite");

    // Give the system time to attempt bootstrap sync
    // The race should cause rapid connection cycling
    tokio::time::sleep(Duration::from_secs(5)).await;

    // Query sync runs on both sides
    let inviter_sync_runs = inviter
        .db_query::<(i64, String, i64, i64, String)>(
            "SELECT run_id, peer_id, rounds, events_sent, outcome
             FROM sync_runs
             WHERE direction = 'inbound'
             ORDER BY started_at_ms ASC",
        )
        .await
        .expect("query inviter sync runs");

    let invitee_sync_runs = invitee
        .db_query::<(i64, String, i64, i64, String)>(
            "SELECT run_id, peer_id, rounds, events_sent, outcome
             FROM sync_runs
             WHERE direction = 'outbound'
             ORDER BY started_at_ms ASC
             LIMIT 100",
        )
        .await
        .expect("query invitee sync runs");

    // Check inviter's endpoint observations
    let inviter_observations = inviter
        .db_query::<(i64,)>(
            "SELECT COUNT(*) FROM peer_endpoint_observations
             WHERE origin_ip LIKE '127.0.0.%' OR origin_ip LIKE '100.%'",
        )
        .await
        .expect("query inviter observations");

    // Expected bug behavior:
    // - Inviter has 0 sync runs from invitee
    // - Invitee has many sync runs with 0 rounds
    // - Inviter has many endpoint observations

    println!("\n=== BUG REPRODUCTION RESULTS ===");
    println!("Inviter sync_runs (inbound): {}", inviter_sync_runs.len());
    println!("Invitee sync_runs (outbound): {}", invitee_sync_runs.len());
    println!(
        "Inviter endpoint_observations: {}",
        inviter_observations.first().map(|r| r.0).unwrap_or(0)
    );

    if !invitee_sync_runs.is_empty() {
        let zero_round_runs: Vec<_> = invitee_sync_runs
            .iter()
            .filter(|(_, _, rounds, _, _)| *rounds == 0)
            .collect();
        println!("Invitee 0-round sync runs: {}", zero_round_runs.len());
    }

    // Assert the bug is present (this test documents the broken behavior)
    // When the bug is fixed, this test should be updated to assert success
    assert_eq!(
        inviter_sync_runs.len(),
        0,
        "BUG: Inviter should have 0 sync runs due to race condition"
    );
    assert!(
        invitee_sync_runs.len() > 10,
        "BUG: Invitee should have many failed sync attempts"
    );
    assert!(
        invitee_sync_runs
            .iter()
            .all(|(_, _, rounds, _, outcome)| { *rounds == 0 && outcome == "ok" }),
        "BUG: All invitee sync runs should have 0 rounds and 'ok' outcome"
    );
    assert!(
        inviter_observations.first().map(|r| r.0).unwrap_or(0) > 10,
        "BUG: Inviter should have many endpoint observations"
    );

    println!("\n✓ Bug successfully reproduced");
}

#[tokio::test(flavor = "multi_thread")]
#[ignore] // Enable after fix is applied
async fn invite_endpoint_race_fixed_allows_bootstrap_sync() {
    let bench = SharedWorkspaceBench::new("invite-endpoint-race-fixed");

    let inviter = bench
        .start_daemon("inviter", None, true)
        .await
        .expect("start inviter");

    let invite_link = inviter
        .topo(&["invite"])
        .await
        .expect("create invite")
        .stdout;
    let invite_link = invite_link.trim();

    let invitee = bench
        .start_daemon("invitee", None, true)
        .await
        .expect("start invitee");

    inviter
        .topo(&["sync-log", "enable", "--all-runs"])
        .await
        .expect("enable inviter sync log");
    invitee
        .topo(&["sync-log", "enable", "--all-runs"])
        .await
        .expect("enable invitee sync log");

    invitee
        .topo(&["accept-invite", invite_link])
        .await
        .expect("accept invite");

    // Wait for bootstrap sync to complete
    tokio::time::sleep(Duration::from_secs(3)).await;

    let inviter_sync_runs = inviter
        .db_query::<(i64, i64, i64, String)>(
            "SELECT run_id, rounds, events_sent, outcome
             FROM sync_runs
             WHERE direction = 'inbound' AND rounds > 0
             ORDER BY started_at_ms ASC",
        )
        .await
        .expect("query inviter sync runs");

    let invitee_sync_runs = invitee
        .db_query::<(i64, i64, i64, String)>(
            "SELECT run_id, rounds, events_sent, outcome
             FROM sync_runs
             WHERE direction = 'outbound' AND rounds > 0
             ORDER BY started_at_ms ASC",
        )
        .await
        .expect("query invitee sync runs");

    // With the fix:
    // - Inviter should have at least 1 successful sync run with rounds > 0
    // - Invitee should have at least 1 successful sync run with rounds > 0
    // - Both should show event exchange

    println!("\n=== FIX VERIFICATION RESULTS ===");
    println!("Inviter successful sync_runs: {}", inviter_sync_runs.len());
    println!("Invitee successful sync_runs: {}", invitee_sync_runs.len());

    if let Some((_, rounds, events_sent, outcome)) = inviter_sync_runs.first() {
        println!(
            "Inviter first run: rounds={} events_sent={} outcome={}",
            rounds, events_sent, outcome
        );
    }

    assert!(
        inviter_sync_runs.len() >= 1,
        "Inviter should have at least 1 successful sync run"
    );
    assert!(
        invitee_sync_runs.len() >= 1,
        "Invitee should have at least 1 successful sync run"
    );

    // Verify actual sync happened (rounds > 0, events exchanged)
    assert!(
        inviter_sync_runs
            .iter()
            .any(|(_, rounds, events_sent, outcome)| {
                *rounds > 0 && *events_sent > 0 && outcome == "ok"
            }),
        "Inviter should have completed sync with rounds and events"
    );

    println!("\n✓ Fix verified: Bootstrap sync completed successfully");
}
