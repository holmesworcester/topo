//! Verified byte-level codecs for fixed-size events.
//!
//! Mirrors the runtime's `src/event_modules/layout/` which hosts the shared
//! `FieldSpec`-based encoder/decoder. The codecs here prove that each shape
//! family's encoder produces bytes that match a compositional Seq-of-bytes spec
//! and that the matching parser inverts.

pub mod shapes;
pub mod ts_id;
pub mod ts_id2;
pub mod ts_id3;
