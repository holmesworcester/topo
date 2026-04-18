//! Daemon-scoped QUIC transport. Handles connection lifecycle, SPKI-pinned daemon
//! identity, mTLS, and workspace-scoped stream multiplexing over a single daemon-level
//! connection. Exactly one backend feature (`iroh-transport` or `tor-transport`) must be
//! enabled at build time — the feature-gated `connection_lifecycle` / `peering_boundary`
//! submodules select the active backend.

pub mod cert;
pub mod connection;
pub mod daemon_identity;
pub mod identity;
pub mod identity_adapter;
pub mod multi_workspace;
pub mod session_auth;
pub mod session_factory;
pub mod transport_session_io;

#[cfg(all(feature = "iroh-transport", feature = "tor-transport"))]
compile_error!(
    "topo transport backends are mutually exclusive; build the Tor variant with --no-default-features --features tor-transport"
);

#[cfg(not(any(feature = "iroh-transport", feature = "tor-transport")))]
compile_error!("topo requires exactly one transport backend feature");

#[cfg(feature = "tor-transport")]
#[path = "connection_lifecycle_tor.rs"]
pub mod connection_lifecycle;
#[cfg(feature = "iroh-transport")]
pub mod connection_lifecycle;

#[cfg(feature = "tor-transport")]
#[path = "peering_boundary_tor.rs"]
pub mod peering_boundary;
#[cfg(feature = "iroh-transport")]
pub mod peering_boundary;

pub use cert::{
    extract_spki_fingerprint, generate_keypair, generate_self_signed_cert,
    generate_self_signed_cert_from_signing_key, validate_cert_key_match,
};
pub use connection::{DualConnection, StreamConn, StreamRecv, StreamSend};
pub use connection_lifecycle::{
    accept_daemon, dial_daemon, ConnectedDaemon, ConnectionLifecycleError,
};
pub use daemon_identity::{
    ensure_daemon_identity, ensure_daemon_identity_from_db, load_daemon_identity,
    load_daemon_identity_from_db, load_local_daemon_endpoint_id, materialize_daemon_identity,
    materialize_daemon_identity_from_db, INCONSISTENT_DAEMON_IDENTITY_ERROR,
    MISSING_DAEMON_IDENTITY_ERROR,
};
#[cfg(feature = "iroh-transport")]
pub use daemon_identity::{load_daemon_iroh_secret_key, load_daemon_iroh_secret_key_from_db};
pub use peering_boundary::{
    accept_daemon_connection, accept_daemon_peer, accept_session_peer, accept_session_provider,
    create_runtime_endpoint_for_tenants, dial_daemon_connection, dial_daemon_connection_target,
    dial_daemon_peer, dial_daemon_peer_target, dial_session_peer, dial_session_provider,
    node_trusts_peer, open_inbound_session, open_outbound_session,
    resolve_authorizing_tenant_from_db, resolve_trusting_tenant,
    shared_daemon_connection_for_connection, tenant_trusts_daemon_peer, tenant_trusts_peer,
    DaemonConnection, SessionEnvelope, SessionProvider, TransportConnection, TransportEndpoint,
    TOPO_ALPN,
};
pub(crate) use session_auth::{daemon_has_authorized_peer_route, send_inbound_session_auth_ack};
pub use session_auth::{
    read_inbound_session_auth, read_inbound_session_auth_for_connection,
    resolve_bootstrap_fallback_invite_for_daemon, resolve_bootstrap_inviter_peer_id,
    resolve_bound_daemon_peer_id, resolve_outbound_session_auth_plan, send_outbound_session_auth,
    InboundSessionAuthContext, OutboundSessionAuthPlan, OutboundSessionAuthResult,
    MAX_SESSION_AUTH_TTL_MS,
};
pub use session_factory::SessionClass;
pub use transport_session_io::{QuicTransportSessionIo, DEFAULT_SYNC_FRAME_MAX_BYTES};
