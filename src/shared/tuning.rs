//! Centralized queue tuning and low-memory configuration.
//!
//! One canonical config surface for queue capacities, batching,
//! byte-credit watermarks, and low-memory toggles. All values are determined by
//! the LOW_MEM_IOS environment variable at runtime.

pub fn low_mem_mode() -> bool {
    read_bool_env("LOW_MEM_IOS")
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

#[cfg(all(target_os = "linux", target_env = "gnu"))]
fn read_i32_env(name: &str) -> Option<i32> {
    std::env::var(name).ok().and_then(|v| v.parse::<i32>().ok())
}

/// Number of event IDs to batch-read from the DB in a single `get_shared_batch`
/// call during the data-plane drain loop.  A larger value reduces per-round
/// SQLite query overhead; keep it small in low-memory mode to limit allocation.
pub fn blob_drain_batch_size() -> usize {
    if low_mem_mode() {
        8
    } else {
        64
    }
}

// -- Ingest pipeline --
pub fn drain_batch_size() -> usize {
    if low_mem_mode() {
        4
    } else {
        100
    }
}
pub fn write_batch_cap() -> usize {
    if low_mem_mode() {
        8
    } else {
        1000
    }
}

pub fn bulk_write_batch_cap() -> usize {
    if low_mem_mode() {
        4
    } else {
        16
    }
}

pub fn response_send_quantum_bytes() -> usize {
    if let Some(v) = read_usize_env("P7_RESPONSE_SEND_QUANTUM_BYTES")
        .or_else(|| read_usize_env("P7_EGRESS_SEND_QUANTUM_BYTES"))
    {
        return v.max(1);
    }
    if low_mem_mode() {
        512 * 1024
    } else {
        1024 * 1024
    }
}

// -- Peering --
pub fn shared_ingest_cap() -> usize {
    if low_mem_mode() {
        read_usize_env("LOW_MEM_SHARED_INGEST_CAP").unwrap_or(2)
    } else {
        10000
    }
}

// -- Sync sessions --
pub fn session_ingest_cap() -> usize {
    if low_mem_mode() {
        8
    } else {
        5000
    }
}

// -- Transport --
pub fn max_recv_buffer() -> usize {
    if low_mem_mode() {
        // Must exceed one full file-slice frame (~262 KiB payload + framing),
        // otherwise low-mem receivers reject file sync traffic as oversize.
        read_usize_env("LOW_MEM_MAX_RECV_BUFFER").unwrap_or(384 * 1024)
    } else {
        2 * 1024 * 1024
    }
}

pub fn low_mem_wanted_high_watermark() -> usize {
    read_usize_env("LOW_MEM_WANTED_HIGH_WATERMARK").unwrap_or(12)
}

pub fn low_mem_wanted_low_watermark() -> usize {
    read_usize_env("LOW_MEM_WANTED_LOW_WATERMARK").unwrap_or(6)
}

pub fn wanted_high_watermark() -> usize {
    if low_mem_mode() {
        low_mem_wanted_high_watermark()
    } else {
        read_usize_env("P7_WANTED_HIGH_WATERMARK").unwrap_or(512)
    }
}

pub fn wanted_low_watermark() -> usize {
    if low_mem_mode() {
        low_mem_wanted_low_watermark()
    } else {
        read_usize_env("P7_WANTED_LOW_WATERMARK").unwrap_or(128)
    }
}

pub fn wanted_refill_quantum() -> usize {
    if low_mem_mode() {
        read_usize_env("LOW_MEM_WANTED_REFILL_QUANTUM").unwrap_or(4)
    } else {
        read_usize_env("P7_WANTED_REFILL_QUANTUM").unwrap_or(64)
    }
}

pub fn response_credit_high_watermark_bytes() -> usize {
    if low_mem_mode() {
        read_usize_env("LOW_MEM_RESPONSE_CREDIT_HIGH_WATERMARK_BYTES").unwrap_or(64 * 1024)
    } else {
        read_usize_env("P7_RESPONSE_CREDIT_HIGH_WATERMARK_BYTES").unwrap_or(512 * 1024)
    }
}

pub fn response_credit_low_watermark_bytes() -> usize {
    if low_mem_mode() {
        read_usize_env("LOW_MEM_RESPONSE_CREDIT_LOW_WATERMARK_BYTES").unwrap_or(16 * 1024)
    } else {
        read_usize_env("P7_RESPONSE_CREDIT_LOW_WATERMARK_BYTES").unwrap_or(128 * 1024)
    }
}

pub fn request_inflight_ttl_ms() -> i64 {
    if low_mem_mode() {
        read_usize_env("LOW_MEM_REQUEST_INFLIGHT_TTL_MS")
            .unwrap_or(5_000)
            .max(1) as i64
    } else {
        read_usize_env("P7_REQUEST_INFLIGHT_TTL_MS")
            .unwrap_or(60_000)
            .max(1) as i64
    }
}

#[cfg(all(target_os = "linux", target_env = "gnu"))]
pub fn apply_low_mem_allocator_tuning() {
    if !low_mem_mode() {
        return;
    }

    let arena_max = read_i32_env("LOW_MEM_MALLOC_ARENA_MAX").unwrap_or(1).max(1);
    let trim_threshold = read_i32_env("LOW_MEM_MALLOC_TRIM_THRESHOLD").unwrap_or(0);
    let mmap_threshold = read_i32_env("LOW_MEM_MALLOC_MMAP_THRESHOLD").unwrap_or(16 * 1024);
    let top_pad = read_i32_env("LOW_MEM_MALLOC_TOP_PAD").unwrap_or(0);

    // SAFETY: mallopt is process-global allocator tuning and takes primitive
    // parameters only.
    unsafe {
        let _ = libc::mallopt(libc::M_ARENA_MAX, arena_max);
        let _ = libc::mallopt(libc::M_TRIM_THRESHOLD, trim_threshold);
        let _ = libc::mallopt(libc::M_MMAP_THRESHOLD, mmap_threshold);
        let _ = libc::mallopt(libc::M_TOP_PAD, top_pad);
    }
}

#[cfg(not(all(target_os = "linux", target_env = "gnu")))]
pub fn apply_low_mem_allocator_tuning() {}
