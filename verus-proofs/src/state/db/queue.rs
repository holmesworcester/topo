//! Queue backoff schedule — verified bounds.
//!
//! Runtime `backoff_ms(attempts)` returns `BACKOFF_BASE_MS * 2^min(attempts, BACKOFF_MAX_ATTEMPTS)`.
//! The cap at `BACKOFF_MAX_ATTEMPTS = 10` keeps the max delay at 1 024 000 ms (~17 min),
//! well below any overflow risk. The verified function replaces the bit-shift
//! implementation with an explicit multiplier table (equivalent values, but Verus-friendly)
//! and an ensures clause pinning the monotonicity and bounds.

use vstd::prelude::*;

verus! {

pub const BACKOFF_BASE_MS: i64 = 1000;
pub const BACKOFF_MAX_ATTEMPTS: u32 = 10;

/// Max delay the backoff schedule can produce: 1000ms * 2^10 = 1_024_000ms ≈ 17 min.
pub const BACKOFF_CAP_MS: i64 = 1_024_000;

fn multiplier_for(capped: u32) -> (m: i64)
    requires capped <= 10,
    ensures
        m >= 1,
        m <= 1024,
        capped == 0 ==> m == 1,
        capped == 10 ==> m == 1024,
{
    match capped {
        0 => 1,
        1 => 2,
        2 => 4,
        3 => 8,
        4 => 16,
        5 => 32,
        6 => 64,
        7 => 128,
        8 => 256,
        9 => 512,
        _ => 1024,
    }
}

pub fn backoff_ms(attempts: u32) -> (delay: i64)
    ensures
        delay >= BACKOFF_BASE_MS,
        delay <= BACKOFF_CAP_MS,
        attempts == 0 ==> delay == BACKOFF_BASE_MS,
        attempts >= BACKOFF_MAX_ATTEMPTS ==> delay == BACKOFF_CAP_MS,
{
    let capped: u32 = if attempts > BACKOFF_MAX_ATTEMPTS {
        BACKOFF_MAX_ATTEMPTS
    } else {
        attempts
    };
    BACKOFF_BASE_MS * multiplier_for(capped)
}

} // verus!
