//! Centralized queue tuning and low-memory configuration.
//!
//! One canonical config surface for queue capacities, claim sizes,
//! batch caps, and low-memory toggles. All values are determined by
//! the LOW_MEM_IOS / LOW_MEM environment variables at runtime.

pub fn low_mem_mode() -> bool {
    read_bool_env("LOW_MEM_IOS") || read_bool_env("LOW_MEM")
}

/// Enables periodic low-memory runtime queue/vector instrumentation logs.
pub fn low_mem_memtrace() -> bool {
    read_bool_env("LOW_MEM_MEMTRACE")
}

pub fn read_bool_env(name: &str) -> bool {
    match std::env::var(name) {
        Ok(v) => v != "0" && v.to_lowercase() != "false",
        Err(_) => false,
    }
}

// -- Ingest pipeline --
pub fn drain_batch_size() -> usize {
    if low_mem_mode() {
        50
    } else {
        100
    }
}
pub fn write_batch_cap() -> usize {
    if low_mem_mode() {
        500
    } else {
        1000
    }
}

// -- Peering --
pub fn shared_ingest_cap() -> usize {
    if low_mem_mode() {
        1000
    } else {
        10000
    }
}

// -- Sync sessions --
pub fn session_ingest_cap() -> usize {
    if low_mem_mode() {
        1000
    } else {
        5000
    }
}

// -- Transport --
pub fn max_recv_buffer() -> usize {
    if low_mem_mode() {
        512 * 1024
    } else {
        2 * 1024 * 1024
    }
}
