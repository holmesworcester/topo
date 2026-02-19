use async_trait::async_trait;

use crate::contracts::network_contract::{
    ControlIo, DataRecvIo, DataSendIo, TransportSessionIo, TransportSessionIoError, TransportSessionIoParts,
};
use crate::protocol::wire::ParseError;
use crate::protocol::{encode_frame, parse_frame, Frame};
use crate::transport::connection::ConnectionError;
use crate::transport::{DualConnection, StreamConn, StreamRecv, StreamSend};

/// Largest legal sync frame today is NegOpen/NegMsg: 1 byte tag + 4 byte len + 4 MiB payload.
pub const DEFAULT_SYNC_FRAME_MAX_BYTES: usize = (4 * 1024 * 1024) + 5;

pub struct QuicTransportSessionIo<C: StreamConn, S: StreamSend, R: StreamRecv> {
    session_id: u64,
    max_frame_size: usize,
    conn: DualConnection<C, S, R>,
}

impl<C: StreamConn, S: StreamSend, R: StreamRecv> QuicTransportSessionIo<C, S, R> {
    pub fn new(session_id: u64, conn: DualConnection<C, S, R>) -> Self {
        Self {
            session_id,
            max_frame_size: DEFAULT_SYNC_FRAME_MAX_BYTES,
            conn,
        }
    }

    pub fn with_max_frame_size(
        session_id: u64,
        max_frame_size: usize,
        conn: DualConnection<C, S, R>,
    ) -> Self {
        Self {
            session_id,
            max_frame_size,
            conn,
        }
    }

    pub fn into_inner(self) -> DualConnection<C, S, R> {
        self.conn
    }
}

fn map_parse_error(err: ParseError, max_frame_size: usize) -> TransportSessionIoError {
    match err {
        ParseError::EventTooLarge(len) | ParseError::NegMessageTooLarge(len) => {
            TransportSessionIoError::FrameTooLarge {
                len,
                max: max_frame_size,
            }
        }
        other => TransportSessionIoError::PeerViolation(other.to_string()),
    }
}

fn map_connection_error(err: ConnectionError, max_frame_size: usize) -> TransportSessionIoError {
    match err {
        ConnectionError::Closed => TransportSessionIoError::ConnectionLost,
        ConnectionError::Parse(parse) => map_parse_error(parse, max_frame_size),
        ConnectionError::Io(e) => TransportSessionIoError::Internal(format!("io: {e}")),
        ConnectionError::Quinn(e) => TransportSessionIoError::Internal(format!("quinn write: {e}")),
        ConnectionError::QuinnRead(e) => TransportSessionIoError::Internal(format!("quinn read: {e}")),
        ConnectionError::QuinnClose(e) => TransportSessionIoError::Internal(format!("quinn close: {e}")),
    }
}

fn decode_exact_frame(frame: &[u8], max_frame_size: usize) -> Result<Frame, TransportSessionIoError> {
    let (msg, consumed) =
        parse_frame(frame).map_err(|e| map_parse_error(e, max_frame_size))?;

    if consumed != frame.len() {
        return Err(TransportSessionIoError::PeerViolation(format!(
            "trailing bytes in frame: consumed={consumed}, total={}",
            frame.len()
        )));
    }

    Ok(msg)
}

// ---------------------------------------------------------------------------
// Split adapters: wrap StreamConn/StreamSend/StreamRecv into contract traits
// ---------------------------------------------------------------------------

struct SyncControlIo<C: StreamConn + Send + 'static> {
    inner: C,
    max_frame_size: usize,
}

#[async_trait]
impl<C: StreamConn + Send + 'static> ControlIo for SyncControlIo<C> {
    async fn recv(&mut self) -> Result<Vec<u8>, TransportSessionIoError> {
        let msg = self
            .inner
            .recv()
            .await
            .map_err(|e| map_connection_error(e, self.max_frame_size))?;
        Ok(encode_frame(&msg))
    }

    async fn send(&mut self, frame: &[u8]) -> Result<(), TransportSessionIoError> {
        if frame.len() > self.max_frame_size {
            return Err(TransportSessionIoError::FrameTooLarge {
                len: frame.len(),
                max: self.max_frame_size,
            });
        }
        let msg = decode_exact_frame(frame, self.max_frame_size)?;
        self.inner
            .send(&msg)
            .await
            .map_err(|e| map_connection_error(e, self.max_frame_size))
    }

    async fn flush(&mut self) -> Result<(), TransportSessionIoError> {
        self.inner
            .flush()
            .await
            .map_err(|e| map_connection_error(e, self.max_frame_size))
    }
}

struct SyncDataSendIo<S: StreamSend + Send + 'static> {
    inner: S,
    max_frame_size: usize,
}

#[async_trait]
impl<S: StreamSend + Send + 'static> DataSendIo for SyncDataSendIo<S> {
    async fn send(&mut self, frame: &[u8]) -> Result<(), TransportSessionIoError> {
        if frame.len() > self.max_frame_size {
            return Err(TransportSessionIoError::FrameTooLarge {
                len: frame.len(),
                max: self.max_frame_size,
            });
        }
        let msg = decode_exact_frame(frame, self.max_frame_size)?;
        self.inner
            .send(&msg)
            .await
            .map_err(|e| map_connection_error(e, self.max_frame_size))
    }

    async fn flush(&mut self) -> Result<(), TransportSessionIoError> {
        self.inner
            .flush()
            .await
            .map_err(|e| map_connection_error(e, self.max_frame_size))
    }
}

struct SyncDataRecvIo<R: StreamRecv + Send + 'static> {
    inner: R,
    max_frame_size: usize,
}

#[async_trait]
impl<R: StreamRecv + Send + 'static> DataRecvIo for SyncDataRecvIo<R> {
    async fn recv(&mut self) -> Result<Vec<u8>, TransportSessionIoError> {
        let msg = self
            .inner
            .recv()
            .await
            .map_err(|e| map_connection_error(e, self.max_frame_size))?;
        Ok(encode_frame(&msg))
    }
}

// ---------------------------------------------------------------------------
// TransportSessionIo implementation
// ---------------------------------------------------------------------------

#[async_trait]
impl<C, S, R> TransportSessionIo for QuicTransportSessionIo<C, S, R>
where
    C: StreamConn + Send + 'static,
    S: StreamSend + Send + 'static,
    R: StreamRecv + Send + 'static,
{
    fn session_id(&self) -> u64 {
        self.session_id
    }

    fn max_frame_size(&self) -> usize {
        self.max_frame_size
    }

    fn split(self: Box<Self>) -> TransportSessionIoParts {
        let max = self.max_frame_size;
        let conn = self.conn;
        TransportSessionIoParts {
            control: Box::new(SyncControlIo {
                inner: conn.control,
                max_frame_size: max,
            }),
            data_send: Box::new(SyncDataSendIo {
                inner: conn.data_send,
                max_frame_size: max,
            }),
            data_recv: Box::new(SyncDataRecvIo {
                inner: conn.data_recv,
                max_frame_size: max,
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};

    #[derive(Default)]
    struct MockControlState {
        recv: VecDeque<Result<Frame, ConnectionError>>,
        sent: Vec<Frame>,
        flushes: usize,
    }

    #[derive(Clone)]
    struct MockControl {
        state: Arc<Mutex<MockControlState>>,
    }

    impl MockControl {
        fn with_recv(
            recv: Vec<Result<Frame, ConnectionError>>,
        ) -> (Self, Arc<Mutex<MockControlState>>) {
            let state = Arc::new(Mutex::new(MockControlState {
                recv: recv.into(),
                sent: Vec::new(),
                flushes: 0,
            }));
            (
                Self {
                    state: state.clone(),
                },
                state,
            )
        }
    }

    #[async_trait]
    impl StreamConn for MockControl {
        async fn send(&mut self, msg: &Frame) -> Result<(), ConnectionError> {
            self.state
                .lock()
                .expect("control lock")
                .sent
                .push(msg.clone());
            Ok(())
        }

        async fn flush(&mut self) -> Result<(), ConnectionError> {
            self.state.lock().expect("control lock").flushes += 1;
            Ok(())
        }

        async fn recv(&mut self) -> Result<Frame, ConnectionError> {
            self.state
                .lock()
                .expect("control lock")
                .recv
                .pop_front()
                .unwrap_or(Err(ConnectionError::Closed))
        }
    }

    #[derive(Default)]
    struct MockSendState {
        sent: Vec<Frame>,
        flushes: usize,
    }

    #[derive(Clone)]
    struct MockDataSend {
        state: Arc<Mutex<MockSendState>>,
    }

    impl MockDataSend {
        fn new() -> (Self, Arc<Mutex<MockSendState>>) {
            let state = Arc::new(Mutex::new(MockSendState::default()));
            (
                Self {
                    state: state.clone(),
                },
                state,
            )
        }
    }

    #[async_trait]
    impl StreamSend for MockDataSend {
        async fn send(&mut self, msg: &Frame) -> Result<(), ConnectionError> {
            self.state.lock().expect("send lock").sent.push(msg.clone());
            Ok(())
        }

        async fn flush(&mut self) -> Result<(), ConnectionError> {
            self.state.lock().expect("send lock").flushes += 1;
            Ok(())
        }
    }

    #[derive(Default)]
    struct MockRecvState {
        recv: VecDeque<Result<Frame, ConnectionError>>,
    }

    #[derive(Clone)]
    struct MockDataRecv {
        state: Arc<Mutex<MockRecvState>>,
    }

    impl MockDataRecv {
        fn with_recv(
            recv: Vec<Result<Frame, ConnectionError>>,
        ) -> (Self, Arc<Mutex<MockRecvState>>) {
            let state = Arc::new(Mutex::new(MockRecvState { recv: recv.into() }));
            (
                Self {
                    state: state.clone(),
                },
                state,
            )
        }
    }

    #[async_trait]
    impl StreamRecv for MockDataRecv {
        async fn recv(&mut self) -> Result<Frame, ConnectionError> {
            self.state
                .lock()
                .expect("recv lock")
                .recv
                .pop_front()
                .unwrap_or(Err(ConnectionError::Closed))
        }
    }

    fn build_io(
        control_recv: Vec<Result<Frame, ConnectionError>>,
        data_recv: Vec<Result<Frame, ConnectionError>>,
    ) -> (
        TransportSessionIoParts,
        Arc<Mutex<MockControlState>>,
        Arc<Mutex<MockSendState>>,
    ) {
        let (control, control_state) = MockControl::with_recv(control_recv);
        let (data_send, data_send_state) = MockDataSend::new();
        let (data_recv, _data_recv_state) = MockDataRecv::with_recv(data_recv);
        let conn = DualConnection {
            control,
            data_send,
            data_recv,
        };

        let io = Box::new(QuicTransportSessionIo::new(7, conn));
        let parts = io.split();
        (parts, control_state, data_send_state)
    }

    #[tokio::test]
    async fn session_io_encodes_decodes_control_and_data_frames() {
        let (mut parts, control_state, data_send_state) = build_io(
            vec![Ok(Frame::Done)],
            vec![Ok(Frame::Event {
                blob: vec![1, 2, 3],
            })],
        );

        let control_frame = parts.control.recv().await.expect("recv control");
        let (control_msg, consumed) = parse_frame(&control_frame).expect("parse control");
        assert_eq!(consumed, control_frame.len());
        assert_eq!(control_msg, Frame::Done);

        let data_frame = parts.data_recv.recv().await.expect("recv data");
        let (data_msg, consumed) = parse_frame(&data_frame).expect("parse data");
        assert_eq!(consumed, data_frame.len());
        assert_eq!(
            data_msg,
            Frame::Event {
                blob: vec![1, 2, 3]
            }
        );

        let neg_open = encode_frame(&Frame::NegOpen { msg: vec![9, 8, 7] });
        parts.control.send(&neg_open).await.expect("send control");
        let data_done = encode_frame(&Frame::DataDone);
        parts.data_send.send(&data_done).await.expect("send data");

        parts.control.flush().await.expect("control flush");
        parts.data_send.flush().await.expect("data_send flush");

        let control = control_state.lock().expect("control lock");
        assert_eq!(control.sent.len(), 1);
        assert_eq!(control.sent[0], Frame::NegOpen { msg: vec![9, 8, 7] });
        assert!(control.flushes >= 1);

        let data_send = data_send_state.lock().expect("send lock");
        assert_eq!(data_send.sent.len(), 1);
        assert_eq!(data_send.sent[0], Frame::DataDone);
        assert!(data_send.flushes >= 1);
    }

    #[tokio::test]
    async fn send_control_rejects_trailing_bytes() {
        let (mut parts, _control_state, _data_send_state) = build_io(vec![], vec![]);
        let mut frame = encode_frame(&Frame::Done);
        frame.push(0);

        let err = parts.control.send(&frame).await.expect_err("expected error");
        assert!(matches!(err, TransportSessionIoError::PeerViolation(_)));
    }

    #[tokio::test]
    async fn recv_control_maps_connection_closed_to_connection_lost() {
        let (mut parts, _control_state, _data_send_state) =
            build_io(vec![Err(ConnectionError::Closed)], vec![]);

        let err = parts.control.recv().await.expect_err("expected error");
        assert_eq!(err, TransportSessionIoError::ConnectionLost);
    }

    #[tokio::test]
    async fn recv_data_maps_parse_too_large_to_typed_error() {
        let parse_err = ConnectionError::Parse(ParseError::NegMessageTooLarge(123_456));
        let (mut parts, _control_state, _data_send_state) = build_io(vec![], vec![Err(parse_err)]);

        let err = parts.data_recv.recv().await.expect_err("expected error");
        assert_eq!(
            err,
            TransportSessionIoError::FrameTooLarge {
                len: 123_456,
                max: DEFAULT_SYNC_FRAME_MAX_BYTES,
            }
        );
    }

    #[tokio::test]
    async fn send_data_rejects_oversized_frame_before_parse() {
        let (mut parts, _control_state, _data_send_state) = build_io(vec![], vec![]);
        let oversized = vec![0u8; DEFAULT_SYNC_FRAME_MAX_BYTES + 1];

        let err = parts.data_send.send(&oversized).await.expect_err("expected error");
        assert_eq!(
            err,
            TransportSessionIoError::FrameTooLarge {
                len: DEFAULT_SYNC_FRAME_MAX_BYTES + 1,
                max: DEFAULT_SYNC_FRAME_MAX_BYTES,
            }
        );
    }
}
