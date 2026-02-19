pub mod wire;
pub mod bootstrap;
pub mod intro;
pub mod punch;

pub use wire::{SyncMessage, parse_sync_message, encode_sync_message};

use crate::crypto::EventId;
use negentropy::Id;

/// Convert negentropy Id to our EventId
pub fn neg_id_to_event_id(id: &Id) -> EventId {
    *id.as_bytes()
}

/// Sync message types
pub const MSG_TYPE_NEG_OPEN: u8 = 0x10;   // Initial negentropy message
pub const MSG_TYPE_NEG_MSG: u8 = 0x11;    // Negentropy response
pub const MSG_TYPE_HAVE_LIST: u8 = 0x12;  // List of IDs client needs from server
pub const MSG_TYPE_EVENT: u8 = 0x03;      // Event blob (variable length)
pub const MSG_TYPE_DONE: u8 = 0x20;      // Initiator signals all events sent
pub const MSG_TYPE_DONE_ACK: u8 = 0x21;  // Responder acknowledges done
pub const MSG_TYPE_DATA_DONE: u8 = 0x22; // Sent on data stream: no more events will follow
pub const MSG_TYPE_INTRO_OFFER: u8 = 0x30; // Intro offer for hole punching
