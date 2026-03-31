//! Formal verification of command creation and utility functions.

use vstd::prelude::*;

verus! {

// ═══════════════════════════════════════════════════════════════════
// Message Command
// ═══════════════════════════════════════════════════════════════════

/// Model of message creation preconditions.
pub open spec fn message_create_would_succeed(
    content_len: nat,
    has_content_key: bool,
    signer_matches_user: bool,
) -> bool {
    content_len > 0
    && has_content_key
    && signer_matches_user
}

proof fn proof_empty_content_fails()
    ensures !message_create_would_succeed(0, true, true),
{
}

proof fn proof_missing_key_fails(content_len: nat)
    requires content_len > 0
    ensures !message_create_would_succeed(content_len, false, true),
{
}

proof fn proof_signer_mismatch_fails(content_len: nat)
    requires content_len > 0
    ensures !message_create_would_succeed(content_len, true, false),
{
}

proof fn proof_all_conditions_met_succeeds(content_len: nat)
    requires content_len > 0
    ensures message_create_would_succeed(content_len, true, true),
{
}

// ═══════════════════════════════════════════════════════════════════
// File Slice Calculation
// ═══════════════════════════════════════════════════════════════════

/// Integer ceiling division.
pub open spec fn div_ceil(a: nat, b: nat) -> nat
    recommends b > 0
{
    if a % b == 0 { (a / b) as nat } else { (a / b + 1) as nat }
}

/// Calculate slices needed for a file of given size in MiB.
/// Each slice holds 65536 bytes (64 KiB).
pub open spec fn slices_for_file_size_mib(file_size_mib: nat) -> nat
    recommends file_size_mib > 0
{
    div_ceil(file_size_mib * 1024 * 1024, 65536)
}

/// Proof: 1 MiB file requires exactly 16 slices.
proof fn proof_1mib_file_needs_16_slices()
    ensures slices_for_file_size_mib(1) == 16,
{
    // 1 * 1024 * 1024 = 1048576
    // 1048576 / 65536 = 16 exactly
    assert(1nat * 1024nat * 1024nat == 1048576nat);
    assert(1048576nat % 65536nat == 0nat);
    assert(1048576nat / 65536nat == 16nat);
}

/// Proof: div_ceil for aligned sizes is just division.
proof fn proof_div_ceil_aligned(a: nat, b: nat)
    requires b > 0 && a % b == 0
    ensures div_ceil(a, b) == a / b,
{
}

/// Proof: slice count is >= 1 for non-zero files.
proof fn proof_slice_count_at_least_one(file_size_mib: nat)
    requires file_size_mib > 0
    ensures slices_for_file_size_mib(file_size_mib) >= 1,
{
    let bytes: nat = file_size_mib * 1024 * 1024;
    assert(bytes >= 1048576nat);
}

// ═══════════════════════════════════════════════════════════════════
// History Span Parsing
// ═══════════════════════════════════════════════════════════════════

/// Time unit multipliers in milliseconds.
pub open spec fn unit_multiplier_ms(unit: char) -> nat {
    if unit == 's' { 1_000 }
    else if unit == 'm' { 60_000 }
    else if unit == 'h' { 3_600_000 }
    else if unit == 'd' { 86_400_000 }
    else if unit == 'w' { 604_800_000 }
    else if unit == 'y' { 31_536_000_000 }
    else { 1 }
}

pub open spec fn parse_span(count: nat, unit: char) -> nat {
    count * unit_multiplier_ms(unit)
}

proof fn proof_3y_is_default_span()
    ensures parse_span(3, 'y') == 3 * 31_536_000_000nat,
{
}

proof fn proof_2h_is_correct()
    ensures parse_span(2, 'h') == 7_200_000nat,
{
}

proof fn proof_7d_is_one_week()
    ensures parse_span(7, 'd') == 604_800_000nat,
{
    assert(7nat * 86_400_000nat == 604_800_000nat);
}

// ═══════════════════════════════════════════════════════════════════
// Timestamp Generation
// ═══════════════════════════════════════════════════════════════════

/// Model of timestamp_for_index: evenly distributes timestamps.
pub open spec fn timestamp_for_index(
    start_at_ms: nat,
    spread_ms: nat,
    count: nat,
    index: nat,
) -> nat
    recommends count > 1 && index < count
{
    let denominator = (count - 1) as nat;
    let step = (index * spread_ms) / denominator;
    (start_at_ms + step) as nat
}

proof fn proof_first_message_at_start(start_at_ms: nat, spread_ms: nat, count: nat)
    requires count > 1
    ensures timestamp_for_index(start_at_ms, spread_ms, count, 0) == start_at_ms,
{
    assert(0nat * spread_ms == 0nat);
}

} // verus!
