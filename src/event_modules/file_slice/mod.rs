pub mod wire;
pub mod projector;

// Re-export stable public API so callers import from `event_modules::file_slice`.
pub use wire::{
    FileSliceEvent, FILE_SLICE_MAX_BYTES,
    parse_file_slice, encode_file_slice,
    FILE_SLICE_META,
};
pub use projector::project_pure;
