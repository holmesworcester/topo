use quinn::{RecvStream, SendStream};
use tokio::io::AsyncWriteExt;

use crate::sync::{parse_sync_message, encode_sync_message, SyncMessage};
use crate::sync::protocol::ParseError;
use crate::transport::sync_conn::SyncConnection;
use async_trait::async_trait;

/// Bidirectional QUIC stream wrapper for sync protocol
pub struct Connection {
    send: SendStream,
    recv: RecvStream,
    recv_buffer: Vec<u8>,
}

impl Connection {
    /// Create a new connection from quinn streams
    pub fn new(send: SendStream, recv: RecvStream) -> Self {
        Self {
            send,
            recv,
            recv_buffer: Vec::with_capacity(4096),
        }
    }

    /// Send a sync message
    pub async fn send(&mut self, msg: &SyncMessage) -> Result<(), ConnectionError> {
        let data = encode_sync_message(msg);
        self.send.write_all(&data).await?;
        Ok(())
    }

    /// Flush the send buffer
    pub async fn flush(&mut self) -> Result<(), ConnectionError> {
        self.send.flush().await?;
        Ok(())
    }

    /// Receive a sync message (blocking)
    pub async fn recv(&mut self) -> Result<SyncMessage, ConnectionError> {
        loop {
            // Try to parse from existing buffer
            if !self.recv_buffer.is_empty() {
                match parse_sync_message(&self.recv_buffer) {
                    Ok((msg, consumed)) => {
                        self.recv_buffer.drain(..consumed);
                        return Ok(msg);
                    }
                    Err(ParseError::InsufficientData) => {
                        // Need more data, continue reading
                    }
                    Err(e) => {
                        return Err(ConnectionError::Parse(e));
                    }
                }
            }

            // Read more data
            let mut buf = [0u8; 4096];
            let chunk = self.recv.read(&mut buf).await?;

            match chunk {
                Some(n) if n > 0 => {
                    self.recv_buffer.extend_from_slice(&buf[..n]);
                }
                _ => {
                    return Err(ConnectionError::Closed);
                }
            }
        }
    }

}

#[async_trait]
impl SyncConnection for Connection {
    async fn send(&mut self, msg: &SyncMessage) -> Result<(), ConnectionError> {
        Connection::send(self, msg).await
    }

    async fn send_bytes(&mut self, bytes: &[u8]) -> Result<(), ConnectionError> {
        self.send.write_all(bytes).await?;
        Ok(())
    }

    async fn flush(&mut self) -> Result<(), ConnectionError> {
        Connection::flush(self).await
    }

    async fn recv(&mut self) -> Result<SyncMessage, ConnectionError> {
        Connection::recv(self).await
    }
}

#[derive(Debug)]
pub enum ConnectionError {
    Io(std::io::Error),
    Quinn(quinn::WriteError),
    QuinnRead(quinn::ReadError),
    QuinnClose(quinn::ClosedStream),
    Parse(ParseError),
    Closed,
}

impl std::fmt::Display for ConnectionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConnectionError::Io(e) => write!(f, "IO error: {}", e),
            ConnectionError::Quinn(e) => write!(f, "Quinn write error: {}", e),
            ConnectionError::QuinnRead(e) => write!(f, "Quinn read error: {}", e),
            ConnectionError::QuinnClose(e) => write!(f, "Quinn close error: {}", e),
            ConnectionError::Parse(e) => write!(f, "Parse error: {}", e),
            ConnectionError::Closed => write!(f, "Connection closed"),
        }
    }
}

impl std::error::Error for ConnectionError {}

impl From<std::io::Error> for ConnectionError {
    fn from(e: std::io::Error) -> Self {
        ConnectionError::Io(e)
    }
}

impl From<quinn::WriteError> for ConnectionError {
    fn from(e: quinn::WriteError) -> Self {
        ConnectionError::Quinn(e)
    }
}

impl From<quinn::ReadError> for ConnectionError {
    fn from(e: quinn::ReadError) -> Self {
        ConnectionError::QuinnRead(e)
    }
}

impl From<quinn::ClosedStream> for ConnectionError {
    fn from(e: quinn::ClosedStream) -> Self {
        ConnectionError::QuinnClose(e)
    }
}

impl From<ParseError> for ConnectionError {
    fn from(e: ParseError) -> Self {
        ConnectionError::Parse(e)
    }
}

impl From<Option<std::io::Error>> for ConnectionError {
    fn from(e: Option<std::io::Error>) -> Self {
        match e {
            Some(e) => ConnectionError::Io(e),
            None => ConnectionError::Closed,
        }
    }
}
