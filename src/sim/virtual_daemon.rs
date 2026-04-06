use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use serde::de::DeserializeOwned;
use tokio::sync::Notify;

use crate::rpc::protocol::{RpcMethod, RpcRequest, RpcResponse, PROTOCOL_VERSION};
use crate::rpc::server::{dispatch_rpc_method, DaemonState};

/// In-process daemon harness that reuses the real structured RPC dispatcher
/// without going through the Unix socket transport.
///
/// This is the intended control seam for simulations: use real daemon RPC
/// methods for command execution and observability, and reserve simulator-only
/// controls for simulated transport/session behavior.
#[derive(Clone)]
pub struct VirtualDaemon {
    state: Arc<DaemonState>,
    shutdown: Arc<AtomicBool>,
    shutdown_notify: Arc<Notify>,
}

impl VirtualDaemon {
    pub fn new(db_path: &str) -> Self {
        Self {
            state: Arc::new(DaemonState::new(db_path)),
            shutdown: Arc::new(AtomicBool::new(false)),
            shutdown_notify: Arc::new(Notify::new()),
        }
    }

    pub fn db_path(&self) -> &str {
        &self.state.db_path
    }

    pub fn state(&self) -> Arc<DaemonState> {
        self.state.clone()
    }

    pub fn call(&self, method: RpcMethod) -> RpcResponse {
        self.call_request(RpcRequest {
            version: PROTOCOL_VERSION,
            method,
        })
    }

    pub fn call_request(&self, req: RpcRequest) -> RpcResponse {
        if req.version != PROTOCOL_VERSION {
            return RpcResponse::error(format!(
                "version mismatch: server={}, client={}",
                PROTOCOL_VERSION, req.version
            ));
        }
        let _ = (&self.shutdown, &self.shutdown_notify);
        dispatch_rpc_method(&self.state, req.method)
    }

    pub fn call_ok_value(&self, method: RpcMethod) -> Result<serde_json::Value, String> {
        let response = self.call(method);
        if response.ok {
            Ok(response.data.unwrap_or(serde_json::Value::Null))
        } else {
            Err(response
                .error
                .unwrap_or_else(|| "RPC call failed without error".to_string()))
        }
    }

    pub fn call_ok<T: DeserializeOwned>(&self, method: RpcMethod) -> Result<T, String> {
        let value = self.call_ok_value(method)?;
        serde_json::from_value(value).map_err(|err| format!("decode RPC response: {err}"))
    }
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use super::VirtualDaemon;
    use crate::rpc::protocol::RpcMethod;

    #[test]
    fn in_process_rpc_harness_reuses_real_daemon_dispatch() {
        let tmpdir = tempdir().expect("tempdir");
        let db_path = tmpdir.path().join("virtual-daemon.db");
        let daemon = VirtualDaemon::new(db_path.to_str().expect("db path utf8"));

        let created = daemon.call(RpcMethod::CreateWorkspace {
            workspace_name: "sim".to_string(),
            username: "alice".to_string(),
            device_name: "laptop".to_string(),
            message_count: 5,
            network_age: Some("1d".to_string()),
        });
        assert!(created.ok, "create workspace failed: {:?}", created.error);

        let stats = daemon
            .call_ok_value(RpcMethod::Stats)
            .expect("stats through in-process RPC");
        assert_eq!(stats["message_count"].as_i64(), Some(5));
        assert!(stats["event_count"].as_i64().unwrap_or(0) >= 5);

        let messages = daemon
            .call_ok_value(RpcMethod::Messages { limit: 3 })
            .expect("messages through in-process RPC");
        let items = messages["messages"]
            .as_array()
            .expect("messages array in response");
        assert!(!items.is_empty());
    }
}
