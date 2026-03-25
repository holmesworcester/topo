pub mod client_activated;
pub mod client_idle_reserved;
pub mod client_lifecycle;
pub mod client_started;
pub mod client_stopped;
pub(crate) mod common;
pub mod connection_plan_transitioned;
pub mod connection_planned;
pub mod connection_runtime;
pub mod durable_jobs;
pub mod inbound_connection_authenticated;
pub mod ingress_provenance;
pub mod inbound_connection_closed;
pub mod listener_bind_failed;
pub mod inbound_connection_rejected;
pub mod mdns_peer_observed;
pub mod outbound_connection_authenticated;
pub mod outbound_connection_closed;
pub mod outbound_connection_failed;
pub mod replay;
pub mod retention;
pub mod sync_round_completed;
pub mod sync_round_started;
pub mod sync_window_selected;

use rusqlite::Connection;

/// Operational event families are local-only event modules whose projectors
/// own replay-relevant runtime state. They live under the same event-module
/// tree and schema ownership model as canonical event modules.
pub fn ensure_schema(conn: &Connection) -> rusqlite::Result<()> {
    client_started::ensure_schema(conn)?;
    client_idle_reserved::ensure_schema(conn)?;
    inbound_connection_authenticated::ensure_schema(conn)?;
    inbound_connection_rejected::ensure_schema(conn)?;
    inbound_connection_closed::ensure_schema(conn)?;
    connection_planned::ensure_schema(conn)?;
    connection_plan_transitioned::ensure_schema(conn)?;
    durable_jobs::ensure_schema(conn)?;
    ingress_provenance::ensure_schema(conn)?;
    mdns_peer_observed::ensure_schema(conn)?;
    outbound_connection_authenticated::ensure_schema(conn)?;
    outbound_connection_failed::ensure_schema(conn)?;
    outbound_connection_closed::ensure_schema(conn)?;
    sync_round_started::ensure_schema(conn)?;
    sync_round_completed::ensure_schema(conn)?;
    sync_window_selected::ensure_schema(conn)?;
    listener_bind_failed::ensure_schema(conn)?;
    Ok(())
}
