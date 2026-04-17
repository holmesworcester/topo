//! CLI and RPC control surface for the `topo` binary. Hosts the JSON-over-UDS [`rpc`]
//! protocol between CLI and daemon, the [`service`] helper shell of DB + transport
//! utilities, the multi-tenant daemon composition root [`node`], the [`assert`]
//! engine (predicate parsing + polling assertions) that backs `topo assert-*`, and
//! [`display`]/[`logging`] CLI formatting.

pub mod assert;
pub mod display;
pub mod logging;
pub mod node;
pub mod rpc;
pub mod service;
