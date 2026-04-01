//! Transport-owned boundary for peering/runtime orchestration.
//!
//! Peering code should use these helpers/types rather than importing QUIC
//! concrete types or transport trust internals directly.

use std::collections::{HashMap, HashSet};
use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use iroh::address_lookup::MdnsAddressLookup;
use iroh::endpoint::VarInt;

use crate::contracts::peering_contract::TransportSessionIo;
use crate::db::open_connection;
use crate::tuning::low_mem_mode;
use crate::db::transport_trust::{
    is_authorized_for_node, is_authorized_for_tenant, resolve_authorizing_tenant,
};

use super::connection_lifecycle::{
    accept_daemon, dial_daemon, ConnectedDaemon, ConnectionLifecycleError,
};
use super::session_factory::{
    accept_session_io, open_session_io_for_class, InboundSessionState, SessionCarrier,
    SessionClass, SessionOpenError,
};
use super::{ensure_daemon_identity_from_db, load_daemon_iroh_secret_key_from_db};

pub const TOPO_ALPN: &[u8] = b"topo/p7/1";

fn env_flag(name: &str) -> bool {
    std::env::var(name)
        .ok()
        .map(|value| {
            let lowered = value.to_ascii_lowercase();
            lowered == "1" || lowered == "true" || lowered == "yes"
        })
        .unwrap_or(false)
}

#[derive(Clone, Debug)]
pub struct TransportEndpoint {
    pub(crate) inner: iroh::Endpoint,
    local_addr: SocketAddr,
    mdns: Option<MdnsAddressLookup>,
}

impl TransportEndpoint {
    pub fn new(inner: iroh::Endpoint, mdns: Option<MdnsAddressLookup>) -> io::Result<Self> {
        let local_addr = inner
            .bound_sockets()
            .into_iter()
            .find(|addr| addr.is_ipv4())
            .or_else(|| inner.bound_sockets().into_iter().next())
            .ok_or_else(|| io::Error::other("iroh endpoint has no bound sockets"))?;
        Ok(Self {
            inner,
            local_addr,
            mdns,
        })
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local_addr)
    }

    pub fn daemon_peer_id(&self) -> String {
        hex::encode(self.inner.id().as_bytes())
    }

    pub fn endpoint_addr(&self) -> iroh::EndpointAddr {
        self.inner.addr()
    }

    pub fn relay_url(&self) -> Option<String> {
        self.inner
            .addr()
            .relay_urls()
            .next()
            .cloned()
            .map(|url| url.to_string())
    }

    pub fn mdns_lookup(&self) -> Option<MdnsAddressLookup> {
        self.mdns.clone()
    }

    pub async fn warm_networking(&self) {
        let _ = self.inner.online().await;
    }

    pub async fn close_gracefully(&self) {
        self.inner.clone().close().await;
    }

    pub fn close(&self, _error_code: iroh::endpoint::VarInt, _reason: &[u8]) {
        let endpoint = self.inner.clone();
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(async move {
                endpoint.close().await;
            });
        } else {
            let _ = std::thread::spawn(move || {
                if let Ok(rt) = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    rt.block_on(endpoint.close());
                }
            });
        }
    }
}

#[derive(Clone)]
pub struct TransportConnection {
    pub(crate) inner: iroh::endpoint::Connection,
    remote_addr: Option<SocketAddr>,
}

impl TransportConnection {
    pub(crate) fn new(inner: iroh::endpoint::Connection, remote_addr: Option<SocketAddr>) -> Self {
        Self { inner, remote_addr }
    }

    pub fn stable_id(&self) -> usize {
        self.inner.stable_id()
    }

    pub fn remote_address(&self) -> Option<SocketAddr> {
        self.remote_addr
    }

    pub fn remote_label(&self) -> String {
        if let Some(remote_addr) = self.remote_addr {
            return remote_addr.to_string();
        }
        if let Some(path) = self.inner.to_info().selected_path() {
            return format!("{:?}", path.remote_addr());
        }
        hex::encode(self.inner.remote_id().as_bytes())
    }

    pub fn close(&self, error_code: iroh::endpoint::VarInt, reason: &[u8]) {
        self.inner.close(error_code, reason);
    }

    pub fn close_reason(&self) -> Option<String> {
        self.inner.close_reason().map(|reason| reason.to_string())
    }
}

#[async_trait::async_trait]
impl SessionCarrier for TransportConnection {
    type BiSend = iroh::endpoint::SendStream;
    type BiRecv = iroh::endpoint::RecvStream;

    async fn open_bi(&self) -> Result<(Self::BiSend, Self::BiRecv), String> {
        self.inner.open_bi().await.map_err(|e| e.to_string())
    }

    async fn accept_bi(&self) -> Result<(Self::BiSend, Self::BiRecv), String> {
        self.inner.accept_bi().await.map_err(|e| e.to_string())
    }

    fn close_with_reason(&self, error_code: u32, reason: &[u8]) {
        self.inner.close(error_code.into(), reason);
    }
}

/// Shared daemon-to-daemon QUIC connection that can both accept inbound
/// logical sessions and open outbound logical sessions.
///
#[derive(Clone)]
pub struct DaemonConnection {
    connection: TransportConnection,
    remote_daemon_peer_id: String,
    inbound_state: InboundSessionState<iroh::endpoint::SendStream, iroh::endpoint::RecvStream>,
    accepted_bootstrap_auth: AcceptedBootstrapAuthCache,
    admitted_session_routes: AdmittedSessionRouteCache,
}

#[derive(Clone, Default)]
struct AcceptedBootstrapAuthCache {
    inner: Arc<Mutex<HashMap<(String, String), String>>>,
}

#[derive(Clone, Default)]
struct AdmittedSessionRouteCache {
    inner: Arc<Mutex<HashSet<(String, String)>>>,
}

/// One ready-to-run logical session scope from a [`DaemonConnection`].
pub struct SessionEnvelope {
    /// Hex-encoded remote daemon certificate SPKI fingerprint.
    pub remote_daemon_peer_id: String,
    pub remote_addr: Option<SocketAddr>,
    pub remote_label: String,
    pub session_id: u64,
    pub class: SessionClass,
    pub io: Box<dyn TransportSessionIo>,
}

#[derive(Clone, Copy)]
enum SessionProviderMode {
    Initiator,
    Acceptor,
}

#[derive(Clone)]
pub struct SessionProvider {
    daemon_connection: DaemonConnection,
    mode: SessionProviderMode,
}

impl DaemonConnection {
    fn from_connected(connected: ConnectedDaemon) -> Self {
        Self {
            connection: connected.connection,
            remote_daemon_peer_id: connected.daemon_peer_id,
            inbound_state: InboundSessionState::default(),
            accepted_bootstrap_auth: AcceptedBootstrapAuthCache::default(),
            admitted_session_routes: AdmittedSessionRouteCache::default(),
        }
    }

    pub fn remote_daemon_peer_id(&self) -> &str {
        &self.remote_daemon_peer_id
    }

    pub fn peer_id(&self) -> &str {
        self.remote_daemon_peer_id()
    }

    pub fn remote_addr(&self) -> Option<SocketAddr> {
        self.connection.remote_address()
    }

    pub fn remote_label(&self) -> String {
        self.connection.remote_label()
    }

    pub fn connection(&self) -> TransportConnection {
        self.connection.clone()
    }

    pub fn remember_accepted_bootstrap_auth(
        &self,
        invite_event_id: &str,
        source_peer_id: &str,
        tenant_id: &str,
    ) {
        let mut cache = self
            .accepted_bootstrap_auth
            .inner
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        cache.insert(
            (invite_event_id.to_string(), source_peer_id.to_string()),
            tenant_id.to_string(),
        );
    }

    pub fn accepted_bootstrap_tenant(
        &self,
        invite_event_id: &str,
        source_peer_id: &str,
    ) -> Option<String> {
        let cache = self
            .accepted_bootstrap_auth
            .inner
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        cache
            .get(&(invite_event_id.to_string(), source_peer_id.to_string()))
            .cloned()
    }

    pub fn remember_admitted_session_route(&self, tenant_id: &str, remote_peer_id: &str) {
        let mut cache = self
            .admitted_session_routes
            .inner
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        cache.insert((tenant_id.to_string(), remote_peer_id.to_string()));
    }

    pub fn admits_session_route(&self, tenant_id: &str, remote_peer_id: &str) -> bool {
        let cache = self
            .admitted_session_routes
            .inner
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        cache.contains(&(tenant_id.to_string(), remote_peer_id.to_string()))
    }

    pub async fn open_outbound_session(
        &self,
        class: SessionClass,
    ) -> Result<SessionEnvelope, SessionOpenError> {
        let (session_id, io) = open_session_io_for_class(&self.connection, class).await?;
        Ok(SessionEnvelope {
            remote_daemon_peer_id: self.remote_daemon_peer_id.clone(),
            remote_addr: self.connection.remote_address(),
            remote_label: self.connection.remote_label(),
            session_id,
            class,
            io,
        })
    }

    pub async fn accept_inbound_session(&self) -> Result<SessionEnvelope, SessionOpenError> {
        let (session_id, class, io) =
            accept_session_io(&self.connection, &self.inbound_state).await?;
        Ok(SessionEnvelope {
            remote_daemon_peer_id: self.remote_daemon_peer_id.clone(),
            remote_addr: self.connection.remote_address(),
            remote_label: self.connection.remote_label(),
            session_id,
            class,
            io,
        })
    }

    pub async fn next_session(&self) -> Result<SessionEnvelope, SessionOpenError> {
        self.open_outbound_session(SessionClass::Range).await
    }
}

impl SessionProvider {
    fn new(daemon_connection: DaemonConnection, mode: SessionProviderMode) -> Self {
        Self {
            daemon_connection,
            mode,
        }
    }

    pub fn peer_id(&self) -> &str {
        self.daemon_connection.peer_id()
    }

    pub fn remote_daemon_peer_id(&self) -> &str {
        self.daemon_connection.remote_daemon_peer_id()
    }

    pub fn remote_addr(&self) -> Option<SocketAddr> {
        self.daemon_connection.remote_addr()
    }

    pub fn remote_label(&self) -> String {
        self.daemon_connection.remote_label()
    }

    pub fn connection(&self) -> TransportConnection {
        self.daemon_connection.connection()
    }

    pub async fn next_session(&self) -> Result<SessionEnvelope, SessionOpenError> {
        match self.mode {
            SessionProviderMode::Initiator => {
                self.daemon_connection
                    .open_outbound_session(SessionClass::Range)
                    .await
            }
            SessionProviderMode::Acceptor => self.daemon_connection.accept_inbound_session().await,
        }
    }
}

pub async fn create_runtime_endpoint_for_tenants(
    bind_addr: SocketAddr,
    db_path: &str,
) -> Result<TransportEndpoint, Box<dyn std::error::Error + Send + Sync>> {
    let _ = ensure_daemon_identity_from_db(db_path)?;
    let secret_key = load_daemon_iroh_secret_key_from_db(db_path)?;
    let mut builder = iroh::Endpoint::empty_builder()
        .secret_key(secret_key)
        .alpns(vec![TOPO_ALPN.to_vec()]);

    if low_mem_mode() {
        // In low-memory mode (iOS NSE, 24 MiB budget), keep a single relay
        // server for NAT traversal (adds ~1.3 MiB) but disable portmapper
        // and mDNS to stay under budget.  A single relay is essential for
        // reachability when both peers are behind NAT.
        builder = builder
            .relay_mode(low_mem_relay_mode())
            .portmapper_config(iroh::endpoint::PortmapperConfig::Disabled)
            .transport_config(low_mem_quic_transport_config());
    } else {
        builder = builder
            .relay_mode(iroh::endpoint::default_relay_mode());
    }

    let endpoint = builder
        .bind_addr(bind_addr)?
        .bind()
        .await?;

    let mdns = if env_flag("TOPO_DISABLE_DISCOVERY") || low_mem_mode() {
        None
    } else {
        let mdns = MdnsAddressLookup::builder().build(endpoint.id())?;
        endpoint.address_lookup()?.add(mdns.clone());
        Some(mdns)
    };
    TransportEndpoint::new(endpoint, mdns).map_err(Into::into)
}

/// Reduced QUIC transport configuration for low-memory mode.
///
/// Shrinks per-connection buffer allocations.  This trades peak throughput
/// for a smaller RSS footprint — acceptable for iOS NSE where we only need
/// to sync recent messages, not sustain bulk transfer rates.
///
/// Note: `receive_window` (512 KiB) is less than `max_streams *
/// stream_receive_window` (5 × 256 KiB = 1.25 MiB), so under concurrent
/// load the connection-level cap limits effective per-stream throughput.
/// This is intentional — we prefer a hard memory ceiling over peak
/// per-stream bandwidth.
fn low_mem_quic_transport_config() -> iroh::endpoint::QuicTransportConfig {
    iroh::endpoint::QuicTransportConfig::builder()
        .max_concurrent_bidi_streams(VarInt::from_u32(4))
        .max_concurrent_uni_streams(VarInt::from_u32(1))
        .stream_receive_window(VarInt::from_u32(256 * 1024)) // 256 KiB (default ~1 MiB)
        .receive_window(VarInt::from_u32(512 * 1024))        // 512 KiB connection cap
        .send_window(512 * 1024)                              // 512 KiB (default ~8 MiB)
        .build()
}

/// Single-relay mode for low-memory environments.
///
/// Uses only the first relay server from iroh's default production map
/// instead of all of them.  This adds ~1.3 MiB of RSS (vs ~4 MiB for the
/// full map) while preserving NAT traversal capability.
fn low_mem_relay_mode() -> iroh::endpoint::RelayMode {
    let default_map = iroh::endpoint::RelayMode::Default.relay_map();
    let urls: Vec<iroh::RelayUrl> = default_map.urls();
    match urls.into_iter().next() {
        Some(url) => iroh::endpoint::RelayMode::custom(std::iter::once(url)),
        None => iroh::endpoint::RelayMode::Disabled,
    }
}

pub fn tenant_trusts_peer(
    db_path: &str,
    tenant_id: &str,
    peer_fp: [u8; 32],
) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
    let db = open_connection(db_path)?;
    is_authorized_for_tenant(&db, tenant_id, &peer_fp)
}

pub fn node_trusts_peer(
    db_path: &str,
    peer_fp: [u8; 32],
) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
    let db = open_connection(db_path)?;
    is_authorized_for_node(&db, &peer_fp)
}

pub fn tenant_trusts_daemon_peer(
    db_path: &str,
    tenant_id: &str,
    daemon_fp: [u8; 32],
) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
    let db = open_connection(db_path)?;
    if is_authorized_for_tenant(&db, tenant_id, &daemon_fp)? {
        return Ok(true);
    }

    let mut stmt = db.prepare(
        "SELECT lower(hex(transport_fingerprint))
         FROM peers_shared
         WHERE recorded_by = ?1
           AND endpoint_id = ?2
           AND length(transport_fingerprint) = 32",
    )?;
    let peer_ids = stmt
        .query_map(
            rusqlite::params![tenant_id, hex::encode(daemon_fp)],
            |row| row.get::<_, String>(0),
        )?
        .collect::<Result<Vec<_>, _>>()?;

    for peer_id in peer_ids {
        let Ok(bytes) = hex::decode(&peer_id) else {
            continue;
        };
        if bytes.len() != 32 {
            continue;
        }
        let mut peer_fp = [0u8; 32];
        peer_fp.copy_from_slice(&bytes);
        if is_authorized_for_tenant(&db, tenant_id, &peer_fp)? {
            return Ok(true);
        }
    }

    Ok(false)
}

pub fn resolve_trusting_tenant(
    db_path: &str,
    tenant_ids: &[String],
    peer_fp: [u8; 32],
) -> Result<Option<String>, Box<dyn std::error::Error + Send + Sync>> {
    for tenant_id in tenant_ids {
        if tenant_trusts_peer(db_path, tenant_id, peer_fp)? {
            return Ok(Some(tenant_id.clone()));
        }
    }
    Ok(None)
}

pub fn resolve_authorizing_tenant_from_db(
    db_path: &str,
    peer_fp: [u8; 32],
) -> Result<Option<String>, Box<dyn std::error::Error + Send + Sync>> {
    let db = open_connection(db_path)?;
    resolve_authorizing_tenant(&db, &peer_fp)
}

pub async fn dial_daemon_peer_target(
    endpoint: &TransportEndpoint,
    remote: Option<SocketAddr>,
    relay_url: Option<&str>,
    sni: &str,
) -> Result<ConnectedDaemon, ConnectionLifecycleError> {
    dial_daemon(endpoint, remote, relay_url, sni).await
}

pub async fn dial_daemon_connection_target(
    endpoint: &TransportEndpoint,
    remote: Option<SocketAddr>,
    relay_url: Option<&str>,
    sni: &str,
) -> Result<DaemonConnection, ConnectionLifecycleError> {
    let connected = dial_daemon_peer_target(endpoint, remote, relay_url, sni).await?;
    Ok(DaemonConnection::from_connected(connected))
}

pub async fn dial_daemon_peer(
    endpoint: &TransportEndpoint,
    remote: SocketAddr,
    sni: &str,
) -> Result<ConnectedDaemon, ConnectionLifecycleError> {
    dial_daemon_peer_target(endpoint, Some(remote), None, sni).await
}

pub async fn dial_daemon_connection(
    endpoint: &TransportEndpoint,
    remote: SocketAddr,
    sni: &str,
) -> Result<DaemonConnection, ConnectionLifecycleError> {
    dial_daemon_connection_target(endpoint, Some(remote), None, sni).await
}

pub async fn accept_daemon_peer(
    endpoint: &TransportEndpoint,
) -> Result<Option<ConnectedDaemon>, ConnectionLifecycleError> {
    accept_daemon(endpoint).await
}

pub async fn accept_daemon_connection(
    endpoint: &TransportEndpoint,
) -> Result<Option<DaemonConnection>, ConnectionLifecycleError> {
    let connected = match accept_daemon_peer(endpoint).await? {
        Some(c) => c,
        None => return Ok(None),
    };
    Ok(Some(DaemonConnection::from_connected(connected)))
}

pub async fn dial_session_peer(
    endpoint: &TransportEndpoint,
    remote: SocketAddr,
    sni: &str,
) -> Result<ConnectedDaemon, ConnectionLifecycleError> {
    dial_daemon_peer_target(endpoint, Some(remote), None, sni).await
}

pub async fn dial_session_provider(
    endpoint: &TransportEndpoint,
    remote: SocketAddr,
    sni: &str,
) -> Result<SessionProvider, ConnectionLifecycleError> {
    dial_daemon_connection_target(endpoint, Some(remote), None, sni)
        .await
        .map(|daemon_connection| {
            SessionProvider::new(daemon_connection, SessionProviderMode::Initiator)
        })
}

pub async fn accept_session_peer(
    endpoint: &TransportEndpoint,
) -> Result<Option<ConnectedDaemon>, ConnectionLifecycleError> {
    accept_daemon_peer(endpoint).await
}

pub async fn accept_session_provider(
    endpoint: &TransportEndpoint,
) -> Result<Option<SessionProvider>, ConnectionLifecycleError> {
    accept_daemon_connection(endpoint)
        .await
        .map(|maybe_connection| {
            maybe_connection.map(|daemon_connection| {
                SessionProvider::new(daemon_connection, SessionProviderMode::Acceptor)
            })
        })
}

pub fn shared_daemon_connection_for_connection(
    connection: TransportConnection,
    remote_daemon_peer_id: String,
) -> DaemonConnection {
    DaemonConnection {
        connection,
        remote_daemon_peer_id,
        inbound_state: InboundSessionState::default(),
        accepted_bootstrap_auth: AcceptedBootstrapAuthCache::default(),
        admitted_session_routes: AdmittedSessionRouteCache::default(),
    }
}

pub async fn open_outbound_session(
    conn: &DaemonConnection,
) -> Result<(u64, Box<dyn TransportSessionIo>), SessionOpenError> {
    let session = conn.open_outbound_session(SessionClass::Range).await?;
    Ok((session.session_id, session.io))
}

pub async fn open_outbound_dependency_session(
    conn: &DaemonConnection,
) -> Result<(u64, Box<dyn TransportSessionIo>), SessionOpenError> {
    let session = conn.open_outbound_session(SessionClass::Dependency).await?;
    Ok((session.session_id, session.io))
}

pub async fn open_inbound_session(
    conn: &DaemonConnection,
) -> Result<(u64, Box<dyn TransportSessionIo>), SessionOpenError> {
    let session = conn.accept_inbound_session().await?;
    let session_id = session.session_id;
    let io = session.io;
    Ok((session_id, io))
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use crate::transport::{
        create_runtime_endpoint_for_tenants, load_daemon_identity_from_db,
        multi_workspace::transport_sni,
    };

    use super::*;

    async fn endpoint_pair() -> Result<
        (
            tempfile::TempDir,
            TransportEndpoint,
            TransportEndpoint,
            SocketAddr,
            String,
            String,
        ),
        Box<dyn std::error::Error + Send + Sync>,
    > {
        let temp = tempfile::tempdir()?;
        let server_db = temp.path().join("server.sqlite3");
        let client_db = temp.path().join("client.sqlite3");
        let server_ep = create_runtime_endpoint_for_tenants(
            "127.0.0.1:0".parse().unwrap(),
            server_db.to_str().unwrap(),
        )
        .await?;
        let client_ep = create_runtime_endpoint_for_tenants(
            "127.0.0.1:0".parse().unwrap(),
            client_db.to_str().unwrap(),
        )
        .await?;
        let server_addr = server_ep.local_addr()?;
        let server_peer_id = load_daemon_identity_from_db(server_db.to_str().unwrap())?.0;
        let client_peer_id = load_daemon_identity_from_db(client_db.to_str().unwrap())?.0;
        Ok((
            temp,
            server_ep,
            client_ep,
            server_addr,
            server_peer_id,
            client_peer_id,
        ))
    }

    #[tokio::test]
    async fn boundary_wrappers_cover_dial_and_accept() {
        let (_temp, server_ep, client_ep, server_addr, server_peer_id, client_peer_id) =
            endpoint_pair().await.expect("endpoint pair");
        let server_sni = transport_sni(&server_peer_id);

        let (accepted_res, dialed_res) = tokio::join!(
            accept_session_peer(&server_ep),
            dial_session_peer(&client_ep, server_addr, &server_sni)
        );
        let accepted = accepted_res.expect("accept").expect("accepted");
        let dialed = dialed_res.expect("dial");
        assert_eq!(accepted.daemon_peer_id, client_peer_id);
        assert_eq!(dialed.daemon_peer_id, server_peer_id);
    }
}
