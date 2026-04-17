//! Typed boundary contracts between major subsystems. Each submodule defines the exact
//! types that cross a seam: [`event_pipeline_contract`] between ingest callers and the
//! pipeline, [`peering_contract`] between the transport and peering loops, and
//! [`transport_identity_contract`] between transport-layer auth and the rest of the
//! daemon.

pub mod event_pipeline_contract;
pub mod peering_contract;
pub mod transport_identity_contract;
