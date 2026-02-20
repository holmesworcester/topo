use async_trait::async_trait;
use quinn::{RecvStream, SendStream};
use tokio::io::AsyncWriteExt;

use crate::protocol::{encode_frame, parse_frame, Frame};
use crate::protocol::ParseError;

use crate::tuning::max_recv_buffer;

/// Async stream connection abstraction for sync protocol.
#[async_trait]
pub trait StreamConn {
    async fn send(&mut self, msg: &Frame) -> Result<(), ConnectionError>;
    async fn flush(&mut self) -> Result<(), ConnectionError>;
    async fn recv(&mut self) -> Result<Frame, ConnectionError>;
}

/// Async send-only stream abstraction for data plane.
#[async_trait]
pub trait StreamSend {
    async fn send(&mut self, msg: &Frame) -> Result<(), ConnectionError>;
    async fn flush(&mut self) -> Result<(), ConnectionError>;
}

/// Async recv-only stream abstraction for data plane.
#[async_trait]
pub trait StreamRecv {
    async fn recv(&mut self) -> Result<Frame, ConnectionError>;
}

/// Bidirectional QUIC stream wrapper for sync protocol
pub struct Connection {
    send: SendStream,
    recv: RecvStream,
    recv_buffer: Vec<u8>,
}

/// Send-only QUIC stream wrapper
pub struct SendConnection {
    send: SendStream,
}

/// Recv-only QUIC stream wrapper
pub struct RecvConnection {
    recv: RecvStream,
    recv_buffer: Vec<u8>,
}

/// Dual-stream connection for separating control and data planes
///
/// Control stream: NegOpen, NegMsg, HaveList messages
/// Data stream: Event blobs
///
/// This prevents large event transfers from blocking control messages.
pub struct DualConnection<C: StreamConn = Connection, S: StreamSend = SendConnection, R: StreamRecv = RecvConnection> {
    pub control: C,
    pub data_send: S,
    pub data_recv: R,
}

impl DualConnection<Connection, SendConnection, RecvConnection> {
    /// Create from two bi-directional stream pairs (control first, data second)
    pub fn new(
        control_send: SendStream,
        control_recv: RecvStream,
        data_send: SendStream,
        data_recv: RecvStream,
    ) -> Self {
        Self {
            control: Connection::new(control_send, control_recv),
            data_send: SendConnection::new(data_send),
            data_recv: RecvConnection::new(data_recv),
        }
    }
}

impl<C: StreamConn, S: StreamSend, R: StreamRecv> DualConnection<C, S, R> {
    /// Flush control stream
    pub async fn flush_control(&mut self) -> Result<(), ConnectionError> {
        self.control.flush().await
    }

    /// Flush data stream
    pub async fn flush_data(&mut self) -> Result<(), ConnectionError> {
        self.data_send.flush().await
    }

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
    pub async fn send(&mut self, msg: &Frame) -> Result<(), ConnectionError> {
        let data = encode_frame(msg);
        self.send.write_all(&data).await?;
        Ok(())
    }

    /// Flush the send buffer
    pub async fn flush(&mut self) -> Result<(), ConnectionError> {
        self.send.flush().await?;
        Ok(())
    }

    /// Receive a sync message (blocking)
    pub async fn recv(&mut self) -> Result<Frame, ConnectionError> {
        loop {
            // Try to parse from existing buffer
            if !self.recv_buffer.is_empty() {
                match parse_frame(&self.recv_buffer) {
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

            if self.recv_buffer.len() > max_recv_buffer() {
                return Err(ConnectionError::Parse(ParseError::EventTooLarge(self.recv_buffer.len())));
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

impl SendConnection {
    pub fn new(send: SendStream) -> Self {
        Self { send }
    }

    pub async fn send(&mut self, msg: &Frame) -> Result<(), ConnectionError> {
        let data = encode_frame(msg);
        self.send.write_all(&data).await?;
        Ok(())
    }

    pub async fn flush(&mut self) -> Result<(), ConnectionError> {
        self.send.flush().await?;
        Ok(())
    }
}

impl RecvConnection {
    pub fn new(recv: RecvStream) -> Self {
        Self {
            recv,
            recv_buffer: Vec::with_capacity(4096),
        }
    }

    pub async fn recv(&mut self) -> Result<Frame, ConnectionError> {
        loop {
            if !self.recv_buffer.is_empty() {
                match parse_frame(&self.recv_buffer) {
                    Ok((msg, consumed)) => {
                        self.recv_buffer.drain(..consumed);
                        return Ok(msg);
                    }
                    Err(ParseError::InsufficientData) => {}
                    Err(e) => {
                        return Err(ConnectionError::Parse(e));
                    }
                }
            }

            if self.recv_buffer.len() > max_recv_buffer() {
                return Err(ConnectionError::Parse(ParseError::EventTooLarge(self.recv_buffer.len())));
            }

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
impl StreamConn for Connection {
    async fn send(&mut self, msg: &Frame) -> Result<(), ConnectionError> {
        Connection::send(self, msg).await
    }

    async fn flush(&mut self) -> Result<(), ConnectionError> {
        Connection::flush(self).await
    }

    async fn recv(&mut self) -> Result<Frame, ConnectionError> {
        Connection::recv(self).await
    }
}

#[async_trait]
impl StreamSend for SendConnection {
    async fn send(&mut self, msg: &Frame) -> Result<(), ConnectionError> {
        SendConnection::send(self, msg).await
    }

    async fn flush(&mut self) -> Result<(), ConnectionError> {
        SendConnection::flush(self).await
    }
}

#[async_trait]
impl StreamRecv for RecvConnection {
    async fn recv(&mut self) -> Result<Frame, ConnectionError> {
        RecvConnection::recv(self).await
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
