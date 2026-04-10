//! RPC protocol types: request/response enums with serde, version field, error envelope.

use serde::{Deserialize, Serialize};

/// Current protocol version. Bump on breaking changes.
pub const PROTOCOL_VERSION: u32 = 1;

// ---------------------------------------------------------------------------
// Request
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize)]
pub struct RpcRequest {
    pub version: u32,
    pub method: RpcMethod,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum RpcMethod {
    Status,
    Messages {
        limit: usize,
    },
    Send {
        content: String,
        #[serde(default)]
        client_op_id: Option<String>,
    },
    SendFile {
        content: String,
        file_path: String,
        #[serde(default)]
        add_bad_slices: usize,
        #[serde(default)]
        client_op_id: Option<String>,
    },
    Files {
        #[serde(default = "default_view_limit")]
        limit: usize,
    },
    SaveFile {
        target: String,
        output_path: String,
    },
    GenerateFiles {
        count: usize,
        size_mib: usize,
    },
    AssertNow {
        predicate: String,
    },
    AssertEventually {
        predicate: String,
        timeout_ms: u64,
        interval_ms: u64,
    },
    TransportKeys,
    TransportAuth,
    React {
        target: String,
        emoji: String,
        #[serde(default)]
        client_op_id: Option<String>,
    },
    DeleteMessage {
        target: String,
    },
    Reactions,
    Users,
    Keys {
        summary: bool,
    },
    ContentKeys {
        summary: bool,
    },
    Workspaces,
    CreateInvite {
        #[serde(default)]
        public_addr: Option<String>,
        #[serde(default)]
        public_spki: Option<String>,
    },
    RotateKey,
    AcceptInvite {
        invite: String,
        username: String,
        devicename: String,
    },
    /// Create a device link invite for the active peer's user.
    CreateDeviceLink {
        #[serde(default)]
        public_addr: Option<String>,
        #[serde(default)]
        public_spki: Option<String>,
    },
    /// Accept a device link invite.
    AcceptLink {
        invite: String,
        devicename: String,
    },
    /// Show combined identity info for the active peer.
    Identity,
    Shutdown,
    /// List local tenants in this DB with active marker.
    Tenants,
    /// Switch active tenant by 1-based index from tenants list.
    UseTenant {
        index: usize,
    },
    /// Return the currently active tenant.
    ActiveTenant,
    /// Return the current topo log config for the running daemon.
    GetTopoLogConfig,
    /// Update topo log level for the running daemon and persist it.
    SetTopoLogLevel {
        level: String,
    },
    /// Create a new workspace + identity chain.
    CreateWorkspace {
        #[serde(default = "default_workspace_name")]
        workspace_name: String,
        #[serde(default = "default_username")]
        username: String,
        #[serde(default = "default_device_name")]
        device_name: String,
        #[serde(default)]
        message_count: usize,
        #[serde(default)]
        network_age: Option<String>,
    },
    /// List all known peers with local/remote status and endpoint info.
    Peers,
    /// Combined view: sidebar (workspace, users, tenants) + messages with inline reactions.
    View {
        #[serde(default = "default_view_limit")]
        limit: usize,
    },
    /// Create a local subscription.
    SubCreate {
        name: String,
        event_type: String,
        delivery_mode: String,
        #[serde(default)]
        spec_json: String,
    },
    /// List all subscriptions for the active peer.
    SubList,
    /// Disable a subscription.
    SubDisable {
        subscription_id: String,
    },
    /// Enable a subscription.
    SubEnable {
        subscription_id: String,
    },
    /// Poll feed items from a subscription.
    SubPoll {
        subscription_id: String,
        #[serde(default)]
        after_seq: i64,
        #[serde(default = "default_sub_poll_limit")]
        limit: usize,
    },
    /// Acknowledge feed items through a given seq.
    SubAck {
        subscription_id: String,
        through_seq: i64,
    },
    /// Get subscription state (pending count, dirty flag, cursors).
    SubState {
        subscription_id: String,
    },
    /// List all events for the active workspace with parsed fields and decryption.
    EventList,
    /// List specific events by their IDs.
    EventListByIds {
        ids: Vec<String>,
    },
    /// Show events matching an ID prefix.
    EventShow {
        prefix: String,
    },
    /// Reverse dependency tree for an event matching prefix.
    EventDeps {
        prefix: String,
        depth: usize,
    },
    /// List blocked events with their missing dependencies.
    EventBlocked,
    /// Show delivery timeline for a specific event.
    EventTimeline {
        event_id: String,
    },
    /// Trigger a negentropy round for a specific peer.
    SyncRoundPeer {
        peer: String,
    },
    /// Trigger a negentropy round for all connected peers.
    SyncRoundAll,

    /// Return all projection table counts for the active tenant.
    Stats,
    /// Run a replay pass (forward/idempotent/reverse/shuffle) and return the fingerprint.
    Replay {
        pass: String,
    },

    /// List recent/active peer connections from endpoint observations.
    Connections,

    /// Return persisted ingest observability for the active peer.
    IngestObservability {
        #[serde(default)]
        event_ids: Vec<String>,
    },

    /// Browse for peers via mDNS discovery.
    #[cfg(feature = "discovery")]
    Discover {
        #[serde(default = "default_discover_timeout_ms")]
        timeout_ms: u64,
    },
}

#[cfg(feature = "discovery")]
fn default_discover_timeout_ms() -> u64 {
    5000
}

fn default_workspace_name() -> String {
    "workspace".to_string()
}
fn default_username() -> String {
    "user".to_string()
}
fn default_device_name() -> String {
    "device".to_string()
}
fn default_view_limit() -> usize {
    50
}
fn default_sub_poll_limit() -> usize {
    50
}

// ---------------------------------------------------------------------------
// Response
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize)]
pub struct RpcResponse {
    pub version: u32,
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

impl RpcResponse {
    pub fn success(data: impl Serialize) -> Self {
        RpcResponse {
            version: PROTOCOL_VERSION,
            ok: true,
            error: None,
            data: Some(serde_json::to_value(data).unwrap_or(serde_json::Value::Null)),
        }
    }

    pub fn error(msg: impl Into<String>) -> Self {
        RpcResponse {
            version: PROTOCOL_VERSION,
            ok: false,
            error: Some(msg.into()),
            data: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Wire format: length-prefixed JSON over Unix socket
// ---------------------------------------------------------------------------

/// Encode a message as 4-byte big-endian length prefix + JSON bytes.
pub fn encode_frame(msg: &impl Serialize) -> Result<Vec<u8>, serde_json::Error> {
    let json = serde_json::to_vec(msg)?;
    let len = (json.len() as u32).to_be_bytes();
    let mut frame = Vec::with_capacity(4 + json.len());
    frame.extend_from_slice(&len);
    frame.extend_from_slice(&json);
    Ok(frame)
}

/// Read a length-prefixed JSON frame from a reader.
pub fn decode_frame<R: std::io::Read, T: serde::de::DeserializeOwned>(
    reader: &mut R,
) -> Result<T, Box<dyn std::error::Error + Send + Sync>> {
    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > 16 * 1024 * 1024 {
        return Err("frame too large (>16MB)".into());
    }
    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf)?;
    Ok(serde_json::from_slice(&buf)?)
}
