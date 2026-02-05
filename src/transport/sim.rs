use std::time::Duration;

use async_trait::async_trait;
use constrained_connection::{new_constrained_connection, Endpoint};
use futures::io::{AsyncReadExt, AsyncWriteExt};

use crate::sync::{encode_sync_message, parse_sync_message, SyncMessage};
use crate::sync::protocol::ParseError;
use crate::transport::connection::{ConnectionError, StreamConn};

/// Configuration for simulated link behavior
#[derive(Debug, Clone, Copy)]
pub struct SimConfig {
    /// One-way base latency in milliseconds
    pub latency_ms: u64,
    /// Link bandwidth in bytes per second (per direction)
    pub bandwidth_bytes_per_sec: u64,
}

/// Create a pair of simulated connections (full duplex)
pub fn create_sim_pair(config: SimConfig) -> (SimConnection, SimConnection) {
    let rtt = Duration::from_millis(config.latency_ms.saturating_mul(2));
    let bandwidth_bits = config.bandwidth_bytes_per_sec.saturating_mul(8).max(1);
    let (a, b) = new_constrained_connection(bandwidth_bits, rtt);
    (SimConnection::new(a), SimConnection::new(b))
}

/// Simulated connection using constrained_connection endpoints
pub struct SimConnection {
    endpoint: Endpoint,
    recv_buffer: Vec<u8>,
}

impl SimConnection {
    fn new(endpoint: Endpoint) -> Self {
        Self {
            endpoint,
            recv_buffer: Vec::with_capacity(4096),
        }
    }

    /// Send a sync message with simulated latency/bandwidth
    pub async fn send(&mut self, msg: &SyncMessage) -> Result<(), ConnectionError> {
        let data = encode_sync_message(msg);
        self.endpoint
            .write_all(&data)
            .await
            .map_err(ConnectionError::Io)?;
        Ok(())
    }

    /// Flush the endpoint
    pub async fn flush(&mut self) -> Result<(), ConnectionError> {
        self.endpoint.flush().await.map_err(ConnectionError::Io)?;
        Ok(())
    }

    /// Receive a sync message (blocking)
    pub async fn recv(&mut self) -> Result<SyncMessage, ConnectionError> {
        loop {
            if !self.recv_buffer.is_empty() {
                match parse_sync_message(&self.recv_buffer) {
                    Ok((msg, consumed)) => {
                        self.recv_buffer.drain(..consumed);
                        return Ok(msg);
                    }
                    Err(ParseError::InsufficientData) => {}
                    Err(e) => return Err(ConnectionError::Parse(e)),
                }
            }

            let mut buf = [0u8; 4096];
            let n = self.endpoint.read(&mut buf).await.map_err(ConnectionError::Io)?;
            if n == 0 {
                return Err(ConnectionError::Closed);
            }
            self.recv_buffer.extend_from_slice(&buf[..n]);
        }
    }
}

#[async_trait]
impl StreamConn for SimConnection {
    async fn send(&mut self, msg: &SyncMessage) -> Result<(), ConnectionError> {
        SimConnection::send(self, msg).await
    }

    async fn flush(&mut self) -> Result<(), ConnectionError> {
        SimConnection::flush(self).await
    }

    async fn recv(&mut self) -> Result<SyncMessage, ConnectionError> {
        SimConnection::recv(self).await
    }
}
