pub mod apply;
pub mod contract;
pub mod create;
pub mod decision;
pub mod emit;
pub mod encrypted;
pub mod signer;

// Compatibility shim while call sites migrate to `projection::contract`.
pub mod result {
    pub use super::contract::*;
}
