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

fn read_usize_env(name: &str) -> Option<usize> {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
}

// -- Ingest pipeline --
pub fn drain_batch_size() -> usize {
    if low_mem_mode() {
        10
    } else {
        100
    }
}
pub fn write_batch_cap() -> usize {
    if low_mem_mode() {
        64
    } else {
        1000
    }
}

// -- Peering --
pub fn shared_ingest_cap() -> usize {
    if low_mem_mode() {
        read_usize_env("LOW_MEM_SHARED_INGEST_CAP").unwrap_or(16)
    } else {
        10000
    }
}

// -- Sync sessions --
pub fn session_ingest_cap() -> usize {
    if low_mem_mode() {
        64
    } else {
        5000
    }
}

// -- Transport --
pub fn max_recv_buffer() -> usize {
    if low_mem_mode() {
        256 * 1024
    } else {
        2 * 1024 * 1024
    }
}

pub fn low_mem_wanted_high_watermark() -> usize {
    read_usize_env("LOW_MEM_WANTED_HIGH_WATERMARK").unwrap_or(64)
}

pub fn low_mem_wanted_low_watermark() -> usize {
    read_usize_env("LOW_MEM_WANTED_LOW_WATERMARK").unwrap_or(32)
}
