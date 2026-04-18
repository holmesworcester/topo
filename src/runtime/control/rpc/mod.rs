//! CLI↔daemon RPC. JSON-framed requests flow over a Unix domain socket. [`protocol`]
//! defines the request/response wire types and `RpcMethod` enum, [`catalog`] enumerates
//! methods for `topo rpc describe`, [`server`] dispatches on the daemon side, and
//! [`client`] is used by CLI subcommands via `rpc_require_daemon(...)`.

pub mod catalog;
pub mod client;
pub mod protocol;
pub mod server;
