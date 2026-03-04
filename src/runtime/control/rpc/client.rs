//! RPC client: connects to daemon Unix socket and sends requests.

use std::io::Write;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

use crate::rpc::protocol::*;

/// Send an RPC request to the daemon and return the response.
pub fn rpc_call(socket_path: &Path, method: RpcMethod) -> Result<RpcResponse, RpcClientError> {
    let mut stream = connect_stream(socket_path)?;

    let req = RpcRequest {
        version: PROTOCOL_VERSION,
        method,
    };
    let frame = encode_frame(&req).map_err(RpcClientError::Json)?;
    stream.write_all(&frame)?;
    stream.flush()?;

    let resp: RpcResponse =
        decode_frame(&mut stream).map_err(|e| RpcClientError::Protocol(e.to_string()))?;
    Ok(resp)
}

/// Send a pre-built RPC request (as raw JSON value) and return the response.
/// Used by `topo rpc call` to send arbitrary JSON payloads.
pub fn rpc_call_raw(
    socket_path: &Path,
    request: &serde_json::Value,
) -> Result<RpcResponse, RpcClientError> {
    let mut stream = connect_stream(socket_path)?;

    let frame = encode_frame(request).map_err(RpcClientError::Json)?;
    stream.write_all(&frame)?;
    stream.flush()?;

    let resp: RpcResponse =
        decode_frame(&mut stream).map_err(|e| RpcClientError::Protocol(e.to_string()))?;
    Ok(resp)
}

fn connect_stream(socket_path: &Path) -> Result<UnixStream, RpcClientError> {
    let stream = UnixStream::connect(socket_path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound
            || e.kind() == std::io::ErrorKind::ConnectionRefused
        {
            RpcClientError::DaemonNotRunning(socket_path.display().to_string())
        } else {
            RpcClientError::Io(e)
        }
    })?;

    stream.set_read_timeout(Some(Duration::from_secs(120)))?;
    stream.set_write_timeout(Some(Duration::from_secs(30)))?;

    Ok(stream)
}

#[derive(Debug)]
pub enum RpcClientError {
    DaemonNotRunning(String),
    Io(std::io::Error),
    Json(serde_json::Error),
    Protocol(String),
}

impl std::fmt::Display for RpcClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RpcClientError::DaemonNotRunning(path) => {
                write!(f, "daemon not running (socket: {})", path)
            }
            RpcClientError::Io(e) => write!(f, "I/O error: {}", e),
            RpcClientError::Json(e) => write!(f, "JSON error: {}", e),
            RpcClientError::Protocol(e) => write!(f, "protocol error: {}", e),
        }
    }
}

impl std::error::Error for RpcClientError {}

impl From<std::io::Error> for RpcClientError {
    fn from(e: std::io::Error) -> Self {
        RpcClientError::Io(e)
    }
}
