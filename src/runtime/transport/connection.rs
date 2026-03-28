use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::protocol::ParseError;
use crate::protocol::{encode_frame, parse_frame, Frame};

use crate::tuning::max_recv_buffer;

/// Async stream connection abstraction for sync protocol.
#[async_trait]
pub trait StreamConn {
    fn swap_recv_limit(&mut self, new_limit: usize) -> usize;
    async fn send(&mut self, msg: &Frame) -> Result<(), ConnectionError>;
    async fn flush(&mut self) -> Result<(), ConnectionError>;
    async fn recv(&mut self) -> Result<Frame, ConnectionError>;
}

/// Async send-only stream abstraction for data plane.
#[async_trait]
pub trait StreamSend {
    async fn send(&mut self, msg: &Frame) -> Result<(), ConnectionError>;
    async fn send_bytes(&mut self, bytes: &[u8]) -> Result<(), ConnectionError>;
    async fn flush(&mut self) -> Result<(), ConnectionError>;
}

/// Async recv-only stream abstraction for data plane.
#[async_trait]
pub trait StreamRecv {
    async fn recv(&mut self) -> Result<Frame, ConnectionError>;
    async fn recv_chunk(&mut self) -> Result<Vec<u8>, ConnectionError>;
}

/// Bidirectional stream wrapper for sync protocol.
pub struct Connection<S, R> {
    send: S,
    recv: R,
    recv_buffer: Vec<u8>,
    recv_limit: usize,
}

/// Send-only stream wrapper.
pub struct SendConnection<S> {
    send: S,
}

/// Recv-only stream wrapper.
pub struct RecvConnection<R> {
    recv: R,
    recv_buffer: Vec<u8>,
}

/// Dual-stream connection for separating control and data planes.
///
/// Control carries session protocol messages. Data carries event blobs.
/// This keeps bulk transfer from blocking session progress.
pub struct DualConnection<C: StreamConn, S: StreamSend, R: StreamRecv> {
    pub control: C,
    pub data_send: S,
    pub data_recv: R,
}

impl<C: StreamConn, S: StreamSend, R: StreamRecv> DualConnection<C, S, R> {
    pub fn from_parts(control: C, data_send: S, data_recv: R) -> Self {
        Self {
            control,
            data_send,
            data_recv,
        }
    }

    /// Flush control stream
    pub async fn flush_control(&mut self) -> Result<(), ConnectionError> {
        self.control.flush().await
    }

    /// Flush data stream
    pub async fn flush_data(&mut self) -> Result<(), ConnectionError> {
        self.data_send.flush().await
    }
}

impl<S, R> Connection<S, R> {
    pub fn new(send: S, recv: R) -> Self {
        Self {
            send,
            recv,
            recv_buffer: Vec::with_capacity(4096),
            recv_limit: max_recv_buffer(),
        }
    }
}

impl<S, R> Connection<S, R>
where
    S: AsyncWrite + Unpin + Send,
    R: AsyncRead + Unpin + Send,
{
    pub fn swap_recv_limit(&mut self, new_limit: usize) -> usize {
        let old_limit = self.recv_limit;
        self.recv_limit = new_limit;
        old_limit
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

            if self.recv_buffer.len() > self.recv_limit {
                return Err(ConnectionError::Parse(ParseError::EventTooLarge(
                    self.recv_buffer.len(),
                )));
            }

            // Read more data
            let mut buf = [0u8; 4096];
            let n = self.recv.read(&mut buf).await?;
            if n == 0 {
                return Err(ConnectionError::Closed);
            }
            self.recv_buffer.extend_from_slice(&buf[..n]);
        }
    }
}

impl<S> SendConnection<S> {
    pub fn new(send: S) -> Self {
        Self { send }
    }
}

impl<S> SendConnection<S>
where
    S: AsyncWrite + Unpin + Send,
{
    pub async fn send(&mut self, msg: &Frame) -> Result<(), ConnectionError> {
        let data = encode_frame(msg);
        self.send_bytes(&data).await
    }

    pub async fn send_bytes(&mut self, bytes: &[u8]) -> Result<(), ConnectionError> {
        self.send.write_all(bytes).await?;
        Ok(())
    }

    pub async fn flush(&mut self) -> Result<(), ConnectionError> {
        self.send.flush().await?;
        Ok(())
    }
}

impl<R> RecvConnection<R> {
    pub fn new(recv: R) -> Self {
        Self {
            recv,
            recv_buffer: Vec::with_capacity(4096),
        }
    }
}

impl<R> RecvConnection<R>
where
    R: AsyncRead + Unpin + Send,
{
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
                return Err(ConnectionError::Parse(ParseError::EventTooLarge(
                    self.recv_buffer.len(),
                )));
            }

            let mut buf = [0u8; 4096];
            let n = self.recv.read(&mut buf).await?;
            if n == 0 {
                return Err(ConnectionError::Closed);
            }
            self.recv_buffer.extend_from_slice(&buf[..n]);
        }
    }

    pub async fn recv_chunk(&mut self) -> Result<Vec<u8>, ConnectionError> {
        let mut buf = vec![0u8; 64 * 1024];
        let n = self.recv.read(&mut buf).await?;
        if n == 0 {
            Err(ConnectionError::Closed)
        } else {
            buf.truncate(n);
            Ok(buf)
        }
    }
}

#[async_trait]
impl<S, R> StreamConn for Connection<S, R>
where
    S: AsyncWrite + Unpin + Send + 'static,
    R: AsyncRead + Unpin + Send + 'static,
{
    fn swap_recv_limit(&mut self, new_limit: usize) -> usize {
        Connection::swap_recv_limit(self, new_limit)
    }

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
impl<S> StreamSend for SendConnection<S>
where
    S: AsyncWrite + Unpin + Send + 'static,
{
    async fn send(&mut self, msg: &Frame) -> Result<(), ConnectionError> {
        SendConnection::send(self, msg).await
    }

    async fn send_bytes(&mut self, bytes: &[u8]) -> Result<(), ConnectionError> {
        SendConnection::send_bytes(self, bytes).await
    }

    async fn flush(&mut self) -> Result<(), ConnectionError> {
        SendConnection::flush(self).await
    }
}

#[async_trait]
impl<R> StreamRecv for RecvConnection<R>
where
    R: AsyncRead + Unpin + Send + 'static,
{
    async fn recv(&mut self) -> Result<Frame, ConnectionError> {
        RecvConnection::recv(self).await
    }

    async fn recv_chunk(&mut self) -> Result<Vec<u8>, ConnectionError> {
        RecvConnection::recv_chunk(self).await
    }
}

#[derive(Debug)]
pub enum ConnectionError {
    Io(std::io::Error),
    Transport(String),
    Parse(ParseError),
    Closed,
}

impl std::fmt::Display for ConnectionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConnectionError::Io(e) => write!(f, "IO error: {}", e),
            ConnectionError::Transport(e) => write!(f, "Transport error: {}", e),
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
