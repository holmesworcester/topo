//! Cross-layer primitives re-exported at the crate root. [`contracts`] holds the typed
//! seams between subsystems, [`crypto`] hosts hashing/signing/AEAD helpers, [`hash_graph`]
//! exposes DAG utilities, [`protocol`] defines transport frame shapes, and [`tuning`]
//! centralizes the perf/memory knobs read by the pipeline and transports.

pub mod contracts;
pub mod crypto;
pub mod hash_graph;
pub mod protocol;
pub mod tuning;
