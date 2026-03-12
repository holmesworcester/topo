//! Integration test: newest-first egress ordering ensures priority messages
//! arrive promptly even when a large backlog is queued.
//!
//! Run with: cargo test --release --test priority_test -- --nocapture

use std::time::{Duration, Instant};
use topo::db::open_connection;
use topo::testutil::{start_peers_pinned, sync_until_converged, Peer};

/// Helper: check if bob has a message with specific content.
fn has_message_with_content(db_path: &str, content_substring: &str) -> bool {
    let db = match open_connection(db_path) {
        Ok(db) => db,
        Err(_) => return false,
    };
    let count: i64 = db
        .query_row(
            "SELECT COUNT(*) FROM messages WHERE content LIKE ?1",
            rusqlite::params![format!("%{}%", content_substring)],
            |row| row.get(0),
        )
        .unwrap_or(0);
    count > 0
}

/// Core scenario: backlog + priority message. With newest-first egress,
/// the priority message should arrive at bob before the full backlog.
///
/// We use 2000 backlog messages to ensure the egress queue needs multiple
/// drain cycles (claim_batch is 500), giving us a window to observe
/// ordering. The priority message (created last, highest rowid) should
/// arrive in the first batch with DESC ordering.
#[tokio::test]
async fn priority_message_arrives_before_full_backlog() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new("warn"))
        .with_writer(std::io::stderr)
        .try_init();

    const BACKLOG: usize = 2000;
    const PRIORITY_CONTENT: &str = "PRIORITY_NEEDLE_12345";

    let alice = Peer::new_with_identity("alice");
    let bob = Peer::new_in_workspace("bob", &alice).await;

    // Create backlog messages on alice
    let gen_start = Instant::now();
    alice.batch_create_messages(BACKLOG);
    eprintln!(
        "Created {} backlog messages in {:.2}s",
        BACKLOG,
        gen_start.elapsed().as_secs_f64()
    );

    // Create the priority message LAST — it gets the highest neg_items timestamp
    // and therefore the highest egress queue rowid when enqueued during sync
    let _priority_id = alice.create_message(PRIORITY_CONTENT);
    eprintln!("Created priority message: {}", PRIORITY_CONTENT);

    // Verify alice has all messages
    let alice_count = alice.message_count();
    assert_eq!(
        alice_count,
        (BACKLOG + 1) as i64,
        "alice should have backlog + priority"
    );

    // Start sync
    let bob_db_path = bob.db_path.clone();
    let sync = start_peers_pinned(&alice, &bob);

    // Poll: wait for the priority message to arrive at bob.
    // Record how many total messages bob has when priority arrives.
    let poll_start = Instant::now();
    let timeout = Duration::from_secs(120);
    let mut bob_count_when_priority_arrived: Option<i64> = None;
    let mut snapshots: Vec<(f64, i64, bool)> = Vec::new();

    loop {
        if poll_start.elapsed() >= timeout {
            let bob_count = bob.message_count();
            let has_priority = has_message_with_content(&bob_db_path, PRIORITY_CONTENT);
            panic!(
                "Timed out waiting for priority message. bob_messages={}, has_priority={}",
                bob_count, has_priority,
            );
        }

        let bob_count = bob.message_count();
        let has_priority = has_message_with_content(&bob_db_path, PRIORITY_CONTENT);
        let elapsed = poll_start.elapsed().as_secs_f64();

        snapshots.push((elapsed, bob_count, has_priority));

        if has_priority && bob_count_when_priority_arrived.is_none() {
            bob_count_when_priority_arrived = Some(bob_count);
            eprintln!(
                "[{:.3}s] Priority arrived! bob has {}/{} messages",
                elapsed,
                bob_count,
                BACKLOG + 1,
            );
            // Don't break — continue to full convergence
        }

        if bob_count == (BACKLOG + 1) as i64 {
            if bob_count_when_priority_arrived.is_none() {
                // Edge case: all messages arrived together before we could
                // observe the priority arriving separately. This can happen
                // if the sync is extremely fast. In that case, the test is
                // inconclusive for ordering but still a valid regression test.
                bob_count_when_priority_arrived = Some(bob_count);
                eprintln!(
                    "[{:.3}s] All {} messages arrived atomically — ordering inconclusive but sync correct",
                    elapsed, bob_count,
                );
            }
            break;
        }

        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    drop(sync);

    let count_at_arrival = bob_count_when_priority_arrived.unwrap();
    let total = (BACKLOG + 1) as i64;

    // Print detailed timeline
    eprintln!();
    eprintln!("=== Priority message ordering test ===");
    eprintln!("  Backlog size:              {}", BACKLOG);
    eprintln!(
        "  Bob messages when priority arrived: {}/{}",
        count_at_arrival, total
    );
    let pct = (count_at_arrival as f64 / total as f64) * 100.0;
    eprintln!("  Priority arrived at:        {:.0}% of total", pct);

    // Print a sample of snapshots
    eprintln!("  Timeline snapshots:");
    let step = snapshots.len().max(1) / 20.min(snapshots.len()).max(1);
    for (i, (t, count, has_p)) in snapshots.iter().enumerate() {
        if i % step.max(1) == 0 || *has_p {
            eprintln!(
                "    [{:.3}s] messages={:>5} priority={}",
                t,
                count,
                if *has_p { "YES" } else { "no" }
            );
        }
    }
    eprintln!();

    // Success criteria: the priority message should arrive within the first 75%.
    // With pure FIFO ordering on 2001 events, the priority message (created last)
    // would be in the very last batch — bob would have ~2000 messages before it
    // arrives. With newest-first, it should be in the very first batch.
    //
    // We use a generous 75% threshold to account for timing granularity.
    let threshold = (total as f64 * 0.75) as i64;
    assert!(
        count_at_arrival <= threshold,
        "Priority message should arrive within first 75% of messages. \
         Got: bob had {} messages when priority arrived (out of {}). \
         This suggests FIFO ordering may still be in effect.",
        count_at_arrival,
        total,
    );
}

/// Verify that sync still completes correctly with newest-first ordering.
/// This is a basic regression test: 500 messages should all arrive.
#[tokio::test]
async fn double_send_regression_newest_first() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new("warn"))
        .with_writer(std::io::stderr)
        .try_init();

    const N: i64 = 500;

    let alice = Peer::new_with_identity("alice");
    let bob = Peer::new_in_workspace("bob", &alice).await;

    alice.batch_create_messages(N as usize);

    let metrics = sync_until_converged(
        &alice,
        &bob,
        || bob.message_count() == N,
        Duration::from_secs(120),
    )
    .await;

    assert_eq!(bob.message_count(), N);

    eprintln!();
    eprintln!("=== Newest-first regression (double_send equivalent) ===");
    eprintln!("  Messages:  {}", N);
    eprintln!("  Wall time: {:.2}s", metrics.wall_secs);
    eprintln!("  Msgs/s:    {:.0}", metrics.events_per_sec);
    eprintln!();
}
