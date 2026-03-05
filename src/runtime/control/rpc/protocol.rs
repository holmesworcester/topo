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
    },
    SendFile {
        content: String,
        file_path: String,
    },
    Generate {
        count: usize,
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
    TransportIdentity,
    React {
        target: String,
        emoji: String,
    },
    DeleteMessage {
        target: String,
    },
    Reactions,
    Users,
    Keys {
        summary: bool,
    },
    Workspaces,
    IntroAttempts {
        peer: Option<String>,
    },
    CreateInvite {
        public_addr: String,
        public_spki: Option<String>,
    },
    AcceptInvite {
        invite: String,
        username: String,
        devicename: String,
    },
    /// Create a device link invite for the active peer's user.
    CreateDeviceLink {
        public_addr: String,
        public_spki: Option<String>,
    },
    /// Accept a device link invite.
    AcceptLink {
        invite: String,
        devicename: String,
    },
    /// Ban (remove) a user by number or hex event ID.
    Ban {
        target: String,
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
    /// Create a new workspace + identity chain.
    CreateWorkspace {
        #[serde(default = "default_workspace_name")]
        workspace_name: String,
        #[serde(default = "default_username")]
        username: String,
        #[serde(default = "default_device_name")]
        device_name: String,
    },
    /// List all known peers with local/remote status and endpoint info.
    Peers,
    /// Attempt UPnP port mapping for the QUIC listen port.
    Upnp,
    /// Combined view: sidebar (workspace, users, accounts) + messages with inline reactions.
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
    /// Run intro: connect peer_a and peer_b via this node.
    Intro {
        peer_a: String,
        peer_b: String,
        #[serde(default = "default_intro_ttl_ms")]
        ttl_ms: u64,
        #[serde(default = "default_intro_attempt_window_ms")]
        attempt_window_ms: u32,
    },
}

fn default_intro_ttl_ms() -> u64 {
    30000
}
fn default_intro_attempt_window_ms() -> u32 {
    4000
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
