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
    Generate {
        count: usize,
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
    /// List channels for the active peer.
    Channels,
    /// Create a new channel for the active peer.
    NewChannel {
        name: String,
    },
    /// Switch active channel by number or name.
    UseChannel {
        selector: String,
    },
    Shutdown,
    /// List peers (tenants) in this DB with active marker.
    Peers,
    /// Switch active peer by 1-based index from peers list.
    UsePeer {
        index: usize,
    },
    /// Return the currently active peer.
    ActivePeer,
    /// Create a new workspace + identity chain.
    CreateWorkspace {
        #[serde(default = "default_workspace_name")]
        workspace_name: String,
        #[serde(default = "default_username")]
        username: String,
        #[serde(default = "default_device_name")]
        device_name: String,
    },
    /// Attempt UPnP port mapping for the QUIC listen port.
    Upnp,
    /// Combined view: sidebar (workspace, users, accounts) + messages with inline reactions.
    View {
        #[serde(default = "default_view_limit")]
        limit: usize,
    },
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
