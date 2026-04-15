//! Transport-owned boundary for peering/runtime orchestration.
//!
//! The Tor transport keeps the daemon/session split that the QUIC/Iroh backend
//! already expects, but each logical stream is implemented as its own Tor data
//! stream. That preserves control/data lanes without depending on QUIC.

use std::collections::{HashMap, HashSet};
use std::io;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use arti_client::config::{BoolOrAuto, TorClientConfigBuilder};
use arti_client::{StreamPrefs, TorClient};
use futures::StreamExt;
use safelog::DisplayRedacted;
use tokio::io::{split, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{mpsc, Mutex as AsyncMutex};
use tokio_util::sync::CancellationToken;
use tor_cell::relaycell::msg::Connected;
use tor_hscrypto::pk::{HsId, HsIdKeypair};
use tor_hsservice::config::OnionServiceConfigBuilder;
use tor_hsservice::HsNickname;
use tracing::warn;

use crate::contracts::peering_contract::TransportSessionIo;
use crate::db::open_connection;
use crate::db::transport_trust::{
    is_authorized_for_node, is_authorized_for_tenant, resolve_authorizing_tenant,
};

use super::connection_lifecycle::{
    accept_daemon, dial_daemon, ConnectedDaemon, ConnectionLifecycleError,
};
use super::daemon_identity::load_daemon_signing_key_from_db;
use super::ensure_daemon_identity_from_db;
use super::session_factory::{
    accept_session_io, open_session_io_for_class, InboundSessionState, SessionCarrier,
    SessionClass, SessionOpenError,
};

pub const TOPO_ALPN: &[u8] = b"topo/p7/1";

const TOPO_TOR_STREAM_PORT: u16 = 17691;
const STREAM_AUTH_MAGIC: [u8; 4] = *b"P7TA";
const STREAM_AUTH_VERSION: u8 = 1;
const STREAM_AUTH_KIND_HELLO: u8 = 0;
const STREAM_AUTH_KIND_SESSION: u8 = 1;
const STREAM_AUTH_HEADER_LEN: usize = 4 + 1 + 1 + 8 + 32 + 32 + 64;
const STREAM_AUTH_CLOCK_SKEW_MS: u64 = 5 * 60 * 1000;
const STREAM_AUTH_DOMAIN: &[u8] = b"poc7-tor-stream-auth-v1";

type TorBiSend = Box<dyn AsyncWrite + Unpin + Send + 'static>;
type TorBiRecv = Box<dyn AsyncRead + Unpin + Send + 'static>;
type TorBiStream = (TorBiSend, TorBiRecv);

fn daemon_peer_bytes(peer_id: &str) -> Result<[u8; 32], String> {
    let mut bytes = [0u8; 32];
    hex::decode_to_slice(peer_id, &mut bytes)
        .map_err(|_| format!("invalid remote daemon id '{peer_id}': expected 32-byte hex"))?;
    Ok(bytes)
}

fn onion_addr_from_peer_bytes(peer_bytes: [u8; 32]) -> String {
    let hsid = HsId::from(peer_bytes);
    let rendered = hsid.display_unredacted().to_string();
    rendered
}

fn onion_addr_from_peer_id(peer_id: &str) -> Result<String, String> {
    daemon_peer_bytes(peer_id).map(onion_addr_from_peer_bytes)
}

fn onion_service_nickname(peer_id: &str) -> Result<HsNickname, String> {
    HsNickname::try_from(format!("topo-{}", &peer_id[..16.min(peer_id.len())]))
        .map_err(|e| format!("invalid onion service nickname for daemon identity: {e}"))
}

fn tor_state_dir(db_path: &str) -> PathBuf {
    PathBuf::from(format!("{db_path}.arti-state"))
}

fn tor_cache_dir(db_path: &str) -> PathBuf {
    PathBuf::from(format!("{db_path}.arti-cache"))
}

fn current_timestamp_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn abs_diff(a: u64, b: u64) -> u64 {
    a.max(b) - a.min(b)
}

fn stream_auth_message(
    kind: u8,
    timestamp_ms: u64,
    local_daemon_peer_id: &[u8; 32],
    remote_daemon_peer_id: &[u8; 32],
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(
        STREAM_AUTH_DOMAIN.len() + STREAM_AUTH_MAGIC.len() + 1 + 1 + 8 + 32 + 32,
    );
    buf.extend_from_slice(STREAM_AUTH_DOMAIN);
    buf.extend_from_slice(&STREAM_AUTH_MAGIC);
    buf.push(STREAM_AUTH_VERSION);
    buf.push(kind);
    buf.extend_from_slice(&timestamp_ms.to_be_bytes());
    buf.extend_from_slice(local_daemon_peer_id);
    buf.extend_from_slice(remote_daemon_peer_id);
    buf
}

async fn write_stream_auth_header<W>(
    writer: &mut W,
    kind: u8,
    local_signing_key: &ed25519_dalek::SigningKey,
    local_daemon_peer_id: &[u8; 32],
    remote_daemon_peer_id: &[u8; 32],
) -> Result<(), String>
where
    W: AsyncWrite + Unpin + Send,
{
    use ed25519_dalek::Signer as _;

    let timestamp_ms = current_timestamp_ms();
    let signed = stream_auth_message(
        kind,
        timestamp_ms,
        local_daemon_peer_id,
        remote_daemon_peer_id,
    );
    let signature = local_signing_key.sign(&signed).to_bytes();

    let mut header = [0u8; STREAM_AUTH_HEADER_LEN];
    header[..4].copy_from_slice(&STREAM_AUTH_MAGIC);
    header[4] = STREAM_AUTH_VERSION;
    header[5] = kind;
    header[6..14].copy_from_slice(&timestamp_ms.to_be_bytes());
    header[14..46].copy_from_slice(local_daemon_peer_id);
    header[46..78].copy_from_slice(remote_daemon_peer_id);
    header[78..142].copy_from_slice(&signature);

    writer
        .write_all(&header)
        .await
        .map_err(|e| format!("write stream auth header: {e}"))?;
    writer
        .flush()
        .await
        .map_err(|e| format!("flush stream auth header: {e}"))?;
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AuthenticatedStreamKind {
    Hello,
    Session,
}

#[derive(Debug)]
struct AuthenticatedStreamHeader {
    kind: AuthenticatedStreamKind,
    remote_daemon_peer_id: String,
}

async fn read_stream_auth_header<R>(
    reader: &mut R,
    local_daemon_peer_id: &[u8; 32],
) -> Result<AuthenticatedStreamHeader, String>
where
    R: AsyncRead + Unpin + Send,
{
    let mut header = [0u8; STREAM_AUTH_HEADER_LEN];
    reader
        .read_exact(&mut header)
        .await
        .map_err(|e| format!("read stream auth header: {e}"))?;

    if header[..4] != STREAM_AUTH_MAGIC {
        return Err("missing Tor stream auth magic".to_string());
    }

    if header[4] != STREAM_AUTH_VERSION {
        return Err(format!("unsupported Tor stream auth version {}", header[4]));
    }

    let kind = match header[5] {
        STREAM_AUTH_KIND_HELLO => AuthenticatedStreamKind::Hello,
        STREAM_AUTH_KIND_SESSION => AuthenticatedStreamKind::Session,
        other => return Err(format!("invalid Tor stream auth kind {other}")),
    };

    let mut timestamp_bytes = [0u8; 8];
    timestamp_bytes.copy_from_slice(&header[6..14]);
    let timestamp_ms = u64::from_be_bytes(timestamp_bytes);
    if abs_diff(current_timestamp_ms(), timestamp_ms) > STREAM_AUTH_CLOCK_SKEW_MS {
        return Err("stale Tor stream auth timestamp".to_string());
    }

    let mut remote_daemon_peer_id = [0u8; 32];
    remote_daemon_peer_id.copy_from_slice(&header[14..46]);

    let mut target_daemon_peer_id = [0u8; 32];
    target_daemon_peer_id.copy_from_slice(&header[46..78]);
    if target_daemon_peer_id != *local_daemon_peer_id {
        return Err("Tor stream auth target daemon mismatch".to_string());
    }

    let mut signature_bytes = [0u8; 64];
    signature_bytes.copy_from_slice(&header[78..142]);
    let signature = ed25519_dalek::Signature::from_bytes(&signature_bytes);
    let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&remote_daemon_peer_id)
        .map_err(|_| "invalid Tor stream auth remote daemon key".to_string())?;
    let signed = stream_auth_message(
        header[5],
        timestamp_ms,
        &remote_daemon_peer_id,
        &target_daemon_peer_id,
    );
    verifying_key
        .verify_strict(&signed, &signature)
        .map_err(|_| "invalid Tor stream auth signature".to_string())?;

    Ok(AuthenticatedStreamHeader {
        kind,
        remote_daemon_peer_id: hex::encode(remote_daemon_peer_id),
    })
}

fn build_stream_prefs() -> StreamPrefs {
    let mut prefs = StreamPrefs::new();
    prefs.connect_to_onion_services(BoolOrAuto::Explicit(true));
    // Each logical stream gets its own isolation group so bulk data does not
    // force control traffic onto the same Tor circuit.
    prefs.new_isolation_group();
    prefs
}

fn tor_hsid_from_signing_key(signing_key: &ed25519_dalek::SigningKey) -> HsIdKeypair {
    let keypair = tor_llcrypto::pk::ed25519::Keypair::from_bytes(&signing_key.to_bytes());
    HsIdKeypair::from(tor_llcrypto::pk::ed25519::ExpandedKeypair::from(&keypair))
}

pub(crate) struct ConnectedDaemonNotice {
    pub(crate) remote_daemon_peer_id: String,
}

struct InboundPeerState {
    streams_tx: mpsc::UnboundedSender<TorBiStream>,
    streams_rx: AsyncMutex<mpsc::UnboundedReceiver<TorBiStream>>,
}

impl InboundPeerState {
    fn new() -> Self {
        let (streams_tx, streams_rx) = mpsc::unbounded_channel();
        Self {
            streams_tx,
            streams_rx: AsyncMutex::new(streams_rx),
        }
    }
}

struct TransportEndpointInner {
    tor_client: TorClient<tor_rtcompat::PreferredRuntime>,
    local_daemon_peer_id: String,
    local_daemon_peer_id_bytes: [u8; 32],
    local_signing_key: Arc<ed25519_dalek::SigningKey>,
    nominal_local_addr: SocketAddr,
    onion_addr: String,
    inbound_daemons_tx: mpsc::UnboundedSender<ConnectedDaemonNotice>,
    inbound_daemons_rx: AsyncMutex<mpsc::UnboundedReceiver<ConnectedDaemonNotice>>,
    peers: Mutex<HashMap<String, Arc<InboundPeerState>>>,
    shutdown: CancellationToken,
    service: Mutex<Option<Arc<tor_hsservice::RunningOnionService>>>,
    background_task: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl TransportEndpointInner {
    fn ensure_peer_state(&self, remote_daemon_peer_id: &str) -> (Arc<InboundPeerState>, bool) {
        let mut peers = self
            .peers
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let created = !peers.contains_key(remote_daemon_peer_id);
        let state = peers
            .entry(remote_daemon_peer_id.to_string())
            .or_insert_with(|| Arc::new(InboundPeerState::new()))
            .clone();
        (state, created)
    }

    fn shutdown(&self) {
        self.shutdown.cancel();
        if let Some(handle) = self
            .background_task
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .take()
        {
            handle.abort();
        }
        let _ = self
            .service
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .take();
    }
}

#[derive(Clone)]
pub struct TransportEndpoint {
    inner: Arc<TransportEndpointInner>,
}

impl std::fmt::Debug for TransportEndpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TransportEndpoint")
            .field("daemon_peer_id", &self.inner.local_daemon_peer_id)
            .field("onion_addr", &self.inner.onion_addr)
            .finish()
    }
}

impl TransportEndpoint {
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.inner.nominal_local_addr)
    }

    pub fn daemon_peer_id(&self) -> String {
        self.inner.local_daemon_peer_id.clone()
    }

    pub fn published_addrs(&self) -> Vec<String> {
        vec![format!(
            "{}:{}",
            self.inner.onion_addr, TOPO_TOR_STREAM_PORT
        )]
    }

    pub fn relay_url(&self) -> Option<String> {
        None
    }

    pub fn discovery_enabled(&self) -> bool {
        false
    }

    pub fn should_wait_for_relay_url(&self) -> bool {
        false
    }

    pub async fn warm_networking(&self) {
        let _ = self.inner.tor_client.bootstrap().await;
    }

    pub async fn close_gracefully(&self) {
        self.inner.shutdown();
    }

    pub fn close(&self, _error_code: u32, _reason: &[u8]) {
        self.inner.shutdown();
    }

    async fn open_authenticated_stream(
        &self,
        remote_daemon_peer_id: &str,
        kind: u8,
    ) -> Result<TorBiStream, String> {
        if self.inner.shutdown.is_cancelled() {
            return Err("transport endpoint closed".to_string());
        }

        let remote_daemon_peer_id_bytes = daemon_peer_bytes(remote_daemon_peer_id)?;
        let remote_onion_addr = onion_addr_from_peer_bytes(remote_daemon_peer_id_bytes);
        let target = format!("{remote_onion_addr}:{TOPO_TOR_STREAM_PORT}");
        let prefs = build_stream_prefs();
        let mut stream = self
            .inner
            .tor_client
            .connect_with_prefs(target.as_str(), &prefs)
            .await
            .map_err(|e| format!("connect to {remote_onion_addr}: {e}"))?;
        write_stream_auth_header(
            &mut stream,
            kind,
            self.inner.local_signing_key.as_ref(),
            &self.inner.local_daemon_peer_id_bytes,
            &remote_daemon_peer_id_bytes,
        )
        .await?;
        let (recv, send) = split(stream);
        Ok((Box::new(send), Box::new(recv)))
    }

    pub(crate) async fn send_hello(&self, remote_daemon_peer_id: &str) -> Result<(), String> {
        let _ = self
            .open_authenticated_stream(remote_daemon_peer_id, STREAM_AUTH_KIND_HELLO)
            .await?;
        Ok(())
    }

    async fn open_session_stream(
        &self,
        remote_daemon_peer_id: &str,
    ) -> Result<TorBiStream, String> {
        self.open_authenticated_stream(remote_daemon_peer_id, STREAM_AUTH_KIND_SESSION)
            .await
    }

    pub(crate) async fn accept_connection_notice(&self) -> Option<ConnectedDaemonNotice> {
        let mut rx = self.inner.inbound_daemons_rx.lock().await;
        tokio::select! {
            _ = self.inner.shutdown.cancelled() => None,
            notice = rx.recv() => notice,
        }
    }
}

struct TransportConnectionInner {
    endpoint: TransportEndpoint,
    remote_daemon_peer_id: String,
    remote_label: String,
    stable_id: usize,
    closed_reason: Mutex<Option<String>>,
}

#[derive(Clone)]
pub struct TransportConnection {
    inner: Arc<TransportConnectionInner>,
}

impl std::fmt::Debug for TransportConnection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TransportConnection")
            .field("remote_daemon_peer_id", &self.inner.remote_daemon_peer_id)
            .field("stable_id", &self.inner.stable_id)
            .finish()
    }
}

impl TransportConnection {
    pub(crate) fn new(endpoint: TransportEndpoint, remote_daemon_peer_id: String) -> Self {
        static NEXT_STABLE_ID: AtomicUsize = AtomicUsize::new(1);

        let remote_label = onion_addr_from_peer_id(&remote_daemon_peer_id)
            .unwrap_or_else(|_| remote_daemon_peer_id.clone());

        Self {
            inner: Arc::new(TransportConnectionInner {
                endpoint,
                remote_daemon_peer_id,
                remote_label,
                stable_id: NEXT_STABLE_ID.fetch_add(1, Ordering::Relaxed),
                closed_reason: Mutex::new(None),
            }),
        }
    }

    pub fn stable_id(&self) -> usize {
        self.inner.stable_id
    }

    pub fn remote_address(&self) -> Option<SocketAddr> {
        None
    }

    pub fn remote_label(&self) -> String {
        self.inner.remote_label.clone()
    }

    pub fn close(&self, _error_code: u32, reason: &[u8]) {
        let mut guard = self
            .inner
            .closed_reason
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        *guard = Some(String::from_utf8_lossy(reason).to_string());
    }

    pub fn close_reason(&self) -> Option<String> {
        self.inner
            .closed_reason
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .clone()
    }

    fn ensure_open(&self) -> Result<(), String> {
        if self.inner.endpoint.inner.shutdown.is_cancelled() {
            return Err("transport endpoint closed".to_string());
        }
        if let Some(reason) = self.close_reason() {
            return Err(format!("connection closed: {reason}"));
        }
        Ok(())
    }
}

#[async_trait::async_trait]
impl SessionCarrier for TransportConnection {
    type BiSend = TorBiSend;
    type BiRecv = TorBiRecv;

    async fn open_bi(&self) -> Result<(Self::BiSend, Self::BiRecv), String> {
        self.ensure_open()?;
        self.inner
            .endpoint
            .open_session_stream(&self.inner.remote_daemon_peer_id)
            .await
    }

    async fn accept_bi(&self) -> Result<(Self::BiSend, Self::BiRecv), String> {
        self.ensure_open()?;
        let (peer_state, _created) = self
            .inner
            .endpoint
            .inner
            .ensure_peer_state(&self.inner.remote_daemon_peer_id);
        let mut rx = peer_state.streams_rx.lock().await;
        tokio::select! {
            _ = self.inner.endpoint.inner.shutdown.cancelled() => {
                Err("transport endpoint closed".to_string())
            }
            stream = rx.recv() => {
                stream.ok_or_else(|| "inbound Tor peer stream queue closed".to_string())
            }
        }
    }

    fn close_with_reason(&self, _error_code: u32, reason: &[u8]) {
        self.close(0, reason);
    }
}

/// Shared daemon-to-daemon transport connection that can both accept inbound
/// logical sessions and open outbound logical sessions.
#[derive(Clone)]
pub struct DaemonConnection {
    connection: TransportConnection,
    remote_daemon_peer_id: String,
    inbound_state: InboundSessionState<TorBiSend, TorBiRecv>,
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

async fn run_inbound_stream_loop<S>(endpoint: TransportEndpoint, rend_requests: S)
where
    S: futures::Stream<Item = tor_hsservice::RendRequest> + Send + Unpin + 'static,
{
    let mut stream_requests = tor_hsservice::handle_rend_requests(rend_requests);
    while let Some(stream_request) = tokio::select! {
        _ = endpoint.inner.shutdown.cancelled() => None,
        next = stream_requests.next() => next,
    } {
        let mut stream = match stream_request.accept(Connected::new_empty()).await {
            Ok(stream) => stream,
            Err(err) => {
                warn!("failed to accept inbound Tor stream: {err}");
                continue;
            }
        };

        let auth =
            match read_stream_auth_header(&mut stream, &endpoint.inner.local_daemon_peer_id_bytes)
                .await
            {
                Ok(auth) => auth,
                Err(err) => {
                    warn!("dropping inbound Tor stream with invalid auth header: {err}");
                    continue;
                }
            };

        let (peer_state, created) = endpoint
            .inner
            .ensure_peer_state(&auth.remote_daemon_peer_id);
        let (recv, send) = split(stream);
        let stream = (Box::new(send) as TorBiSend, Box::new(recv) as TorBiRecv);

        match auth.kind {
            AuthenticatedStreamKind::Hello => {
                let _ = endpoint
                    .inner
                    .inbound_daemons_tx
                    .send(ConnectedDaemonNotice {
                        remote_daemon_peer_id: auth.remote_daemon_peer_id,
                    });
            }
            AuthenticatedStreamKind::Session => {
                let _ = peer_state.streams_tx.send(stream);
                if created {
                    let _ = endpoint
                        .inner
                        .inbound_daemons_tx
                        .send(ConnectedDaemonNotice {
                            remote_daemon_peer_id: auth.remote_daemon_peer_id,
                        });
                }
            }
        }
    }
}

pub async fn create_runtime_endpoint_for_tenants(
    bind_addr: SocketAddr,
    db_path: &str,
) -> Result<TransportEndpoint, Box<dyn std::error::Error + Send + Sync>> {
    let (daemon_peer_id, _cert, _key) = ensure_daemon_identity_from_db(db_path)?;
    let local_signing_key = Arc::new(load_daemon_signing_key_from_db(db_path)?);
    let local_daemon_peer_id_bytes = local_signing_key.verifying_key().to_bytes();
    let onion_addr = onion_addr_from_peer_bytes(local_daemon_peer_id_bytes);

    let state_dir = tor_state_dir(db_path);
    let cache_dir = tor_cache_dir(db_path);
    std::fs::create_dir_all(Path::new(&state_dir))?;
    std::fs::create_dir_all(Path::new(&cache_dir))?;

    let mut config_builder = TorClientConfigBuilder::from_directories(&state_dir, &cache_dir);
    config_builder
        .storage()
        .permissions()
        .dangerously_trust_everyone();
    let config = config_builder.build()?;
    let tor_client = TorClient::create_bootstrapped(config).await?;

    let nickname = onion_service_nickname(&daemon_peer_id).map_err(|e| io::Error::other(e))?;
    let hs_config = OnionServiceConfigBuilder::default()
        .nickname(nickname)
        .build()?;
    let hsid_keypair = tor_hsid_from_signing_key(local_signing_key.as_ref());
    let launched = tor_client.launch_onion_service_with_hsid(hs_config, hsid_keypair)?;
    let Some((service, rend_requests)) = launched else {
        return Err(io::Error::other("Tor onion service was disabled").into());
    };

    let (inbound_daemons_tx, inbound_daemons_rx) = mpsc::unbounded_channel();
    let inner = Arc::new(TransportEndpointInner {
        tor_client,
        local_daemon_peer_id: daemon_peer_id,
        local_daemon_peer_id_bytes,
        local_signing_key,
        nominal_local_addr: bind_addr,
        onion_addr,
        inbound_daemons_tx,
        inbound_daemons_rx: AsyncMutex::new(inbound_daemons_rx),
        peers: Mutex::new(HashMap::new()),
        shutdown: CancellationToken::new(),
        service: Mutex::new(Some(service)),
        background_task: Mutex::new(None),
    });
    let endpoint = TransportEndpoint { inner };

    let background = tokio::spawn(run_inbound_stream_loop(endpoint.clone(), rend_requests));
    *endpoint
        .inner
        .background_task
        .lock()
        .unwrap_or_else(|poison| poison.into_inner()) = Some(background);

    Ok(endpoint)
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
            |row| crate::db::sql_types::get_text(row, 0),
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
    use ed25519_dalek::{Signer as _, SigningKey};
    use tokio::io::{duplex, AsyncWriteExt};

    use super::*;

    fn signing_key(byte: u8) -> SigningKey {
        SigningKey::from_bytes(&[byte; 32])
    }

    fn peer_id_bytes(signing_key: &SigningKey) -> [u8; 32] {
        signing_key.verifying_key().to_bytes()
    }

    fn signed_stream_auth_header(
        kind: u8,
        remote_signing_key: &SigningKey,
        remote_daemon_peer_id: &[u8; 32],
        target_daemon_peer_id: &[u8; 32],
        timestamp_ms: u64,
    ) -> [u8; STREAM_AUTH_HEADER_LEN] {
        let signed = stream_auth_message(
            kind,
            timestamp_ms,
            remote_daemon_peer_id,
            target_daemon_peer_id,
        );
        let signature = remote_signing_key.sign(&signed).to_bytes();

        let mut header = [0u8; STREAM_AUTH_HEADER_LEN];
        header[..4].copy_from_slice(&STREAM_AUTH_MAGIC);
        header[4] = STREAM_AUTH_VERSION;
        header[5] = kind;
        header[6..14].copy_from_slice(&timestamp_ms.to_be_bytes());
        header[14..46].copy_from_slice(remote_daemon_peer_id);
        header[46..78].copy_from_slice(target_daemon_peer_id);
        header[78..142].copy_from_slice(&signature);
        header
    }

    #[test]
    fn tor_transport_onion_address_is_derived_from_daemon_keypair_identity() {
        let daemon_signing_key = signing_key(7);
        let daemon_peer_id = peer_id_bytes(&daemon_signing_key);
        let onion_from_peer_id = onion_addr_from_peer_bytes(daemon_peer_id);
        let hsid_keypair = tor_hsid_from_signing_key(&daemon_signing_key);
        let onion_from_hsid_keypair = tor_hscrypto::pk::HsIdKey::from(&hsid_keypair)
            .id()
            .display_unredacted()
            .to_string();

        assert_eq!(
            onion_from_peer_id, onion_from_hsid_keypair,
            "the daemon keypair address and onion identity must stay aligned"
        );
    }

    #[tokio::test]
    async fn tor_transport_stream_auth_header_round_trips_hello_kind() {
        let local_signing_key = signing_key(1);
        let remote_signing_key = signing_key(2);
        let local_daemon_peer_id = peer_id_bytes(&local_signing_key);
        let remote_daemon_peer_id = peer_id_bytes(&remote_signing_key);
        let (mut writer, mut reader) = duplex(256);

        write_stream_auth_header(
            &mut writer,
            STREAM_AUTH_KIND_HELLO,
            &remote_signing_key,
            &remote_daemon_peer_id,
            &local_daemon_peer_id,
        )
        .await
        .expect("write auth header");
        let parsed = read_stream_auth_header(&mut reader, &local_daemon_peer_id)
            .await
            .expect("read auth header");

        assert_eq!(parsed.kind, AuthenticatedStreamKind::Hello);
        assert_eq!(
            parsed.remote_daemon_peer_id,
            hex::encode(remote_daemon_peer_id)
        );
    }

    #[tokio::test]
    async fn tor_transport_stream_auth_header_rejects_target_daemon_mismatch() {
        let local_signing_key = signing_key(3);
        let remote_signing_key = signing_key(4);
        let local_daemon_peer_id = peer_id_bytes(&local_signing_key);
        let remote_daemon_peer_id = peer_id_bytes(&remote_signing_key);
        let wrong_target_daemon_peer_id = peer_id_bytes(&signing_key(5));
        let (mut writer, mut reader) = duplex(256);
        let header = signed_stream_auth_header(
            STREAM_AUTH_KIND_SESSION,
            &remote_signing_key,
            &remote_daemon_peer_id,
            &wrong_target_daemon_peer_id,
            current_timestamp_ms(),
        );
        writer
            .write_all(&header)
            .await
            .expect("write mismatched header");
        writer.flush().await.expect("flush mismatched header");

        let err = read_stream_auth_header(&mut reader, &local_daemon_peer_id)
            .await
            .expect_err("target mismatch should fail");
        assert!(
            err.contains("target daemon mismatch"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn tor_transport_stream_auth_header_rejects_tampered_signature() {
        let local_signing_key = signing_key(6);
        let remote_signing_key = signing_key(7);
        let local_daemon_peer_id = peer_id_bytes(&local_signing_key);
        let remote_daemon_peer_id = peer_id_bytes(&remote_signing_key);
        let (mut writer, mut reader) = duplex(256);
        let mut header = signed_stream_auth_header(
            STREAM_AUTH_KIND_SESSION,
            &remote_signing_key,
            &remote_daemon_peer_id,
            &local_daemon_peer_id,
            current_timestamp_ms(),
        );
        header[STREAM_AUTH_HEADER_LEN - 1] ^= 0x01;
        writer
            .write_all(&header)
            .await
            .expect("write tampered header");
        writer.flush().await.expect("flush tampered header");

        let err = read_stream_auth_header(&mut reader, &local_daemon_peer_id)
            .await
            .expect_err("tampered signature should fail");
        assert!(err.contains("invalid Tor stream auth signature"));
    }

    #[tokio::test]
    async fn tor_transport_stream_auth_header_rejects_stale_timestamps() {
        let local_signing_key = signing_key(8);
        let remote_signing_key = signing_key(9);
        let local_daemon_peer_id = peer_id_bytes(&local_signing_key);
        let remote_daemon_peer_id = peer_id_bytes(&remote_signing_key);
        let (mut writer, mut reader) = duplex(256);
        let header = signed_stream_auth_header(
            STREAM_AUTH_KIND_SESSION,
            &remote_signing_key,
            &remote_daemon_peer_id,
            &local_daemon_peer_id,
            0,
        );
        writer.write_all(&header).await.expect("write stale header");
        writer.flush().await.expect("flush stale header");

        let err = read_stream_auth_header(&mut reader, &local_daemon_peer_id)
            .await
            .expect_err("stale timestamp should fail");
        assert!(err.contains("stale Tor stream auth timestamp"));
    }
}
