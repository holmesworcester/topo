//! Projection engine: turns stored events into projected rows. [`projector`] defines the
//! pure projector contract types ([`projector::ProjectorResult`], [`projector::WriteOp`]);
//! [`apply`] is the engine that drives it (dep check → context load → project → write);
//! [`decision_context`] loads the typed row context that projectors see; [`create`] is the
//! event-emission API used by commands; [`encrypted`] unwraps the Encrypted envelope;
//! [`signer`] resolves and verifies signer chains; [`purge`] performs tombstone cascades.

pub mod apply;
pub mod create;
pub mod decision;
pub mod decision_context;
pub mod dep_facts;
pub mod encrypted;
pub mod projector;
pub mod purge;
pub mod signer;
