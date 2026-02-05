pub mod protocol;
pub mod negentropy_adapter;

pub use protocol::{SyncMessage, parse_sync_message, encode_sync_message, sync_message_len};
pub use negentropy_adapter::{
    ensure_negentropy_index,
    neg_id_to_event_id,
    NegentropyBatchInserter,
    NegentropyStorageSqlite,
    reset_negentropy_profile,
    log_negentropy_profile,
    neg_block_size,
    neg_max_bytes,
    neg_rebuild_threshold,
};

use crate::wire::ENVELOPE_SIZE;

/// Sync message types
pub const MSG_TYPE_NEG_OPEN: u8 = 0x10;   // Initial negentropy message
pub const MSG_TYPE_NEG_MSG: u8 = 0x11;    // Negentropy response
pub const MSG_TYPE_HAVE_LIST: u8 = 0x12;  // List of IDs client needs from server
pub const MSG_TYPE_EVENT: u8 = 0x03;      // Event blob

/// Message sizes
/// NEG_OPEN, NEG_MSG, HAVE_LIST are variable length: type(1) + len(4) + data(len)
/// EVENT is fixed: type(1) + blob(ENVELOPE_SIZE)
pub const EVENT_SIZE: usize = 1 + ENVELOPE_SIZE; // 513 bytes
