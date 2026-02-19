use async_trait::async_trait;

use crate::contracts::network_contract::{
    ControlIo, DataRecvIo, DataSendIo, SessionIo, SessionIoError, SessionIoParts,
};
use crate::sync::protocol::ParseError;
use crate::sync::{encode_sync_message, parse_sync_message, SyncMessage};
use crate::transport::connection::ConnectionError;
use crate::transport::{DualConnection, StreamConn, StreamRecv, StreamSend};

/// Largest legal sync frame today is NegOpen/NegMsg: 1 byte tag + 4 byte len + 4 MiB payload.
pub const DEFAULT_SYNC_FRAME_MAX_BYTES: usize = (4 * 1024 * 1024) + 5;

pub struct SyncSessionIo<C: StreamConn, S: StreamSend, R: StreamRecv> {
    session_id: u64,
    max_frame_size: usize,
    conn: DualConnection<C, S, R>,
}

impl<C: StreamConn, S: StreamSend, R: StreamRecv> SyncSessionIo<C, S, R> {
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

fn map_parse_error(err: ParseError, max_frame_size: usize) -> SessionIoError {
    match err {
        ParseError::EventTooLarge(len) | ParseError::NegMessageTooLarge(len) => {
            SessionIoError::FrameTooLarge {
                len,
                max: max_frame_size,
            }
        }
        other => SessionIoError::PeerViolation(other.to_string()),
    }
}

fn map_connection_error(err: ConnectionError, max_frame_size: usize) -> SessionIoError {
    match err {
        ConnectionError::Closed => SessionIoError::ConnectionLost,
        ConnectionError::Parse(parse) => map_parse_error(parse, max_frame_size),
        ConnectionError::Io(e) => SessionIoError::Internal(format!("io: {e}")),
        ConnectionError::Quinn(e) => SessionIoError::Internal(format!("quinn write: {e}")),
        ConnectionError::QuinnRead(e) => SessionIoError::Internal(format!("quinn read: {e}")),
        ConnectionError::QuinnClose(e) => SessionIoError::Internal(format!("quinn close: {e}")),
    }
}

fn decode_exact_frame(frame: &[u8], max_frame_size: usize) -> Result<SyncMessage, SessionIoError> {
    let (msg, consumed) =
        parse_sync_message(frame).map_err(|e| map_parse_error(e, max_frame_size))?;

    if consumed != frame.len() {
        return Err(SessionIoError::PeerViolation(format!(
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
    async fn recv(&mut self) -> Result<Vec<u8>, SessionIoError> {
        let msg = self
            .inner
            .recv()
            .await
            .map_err(|e| map_connection_error(e, self.max_frame_size))?;
        Ok(encode_sync_message(&msg))
    }

    async fn send(&mut self, frame: &[u8]) -> Result<(), SessionIoError> {
        if frame.len() > self.max_frame_size {
            return Err(SessionIoError::FrameTooLarge {
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

    async fn flush(&mut self) -> Result<(), SessionIoError> {
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
    async fn send(&mut self, frame: &[u8]) -> Result<(), SessionIoError> {
        if frame.len() > self.max_frame_size {
            return Err(SessionIoError::FrameTooLarge {
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

    async fn flush(&mut self) -> Result<(), SessionIoError> {
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
    async fn recv(&mut self) -> Result<Vec<u8>, SessionIoError> {
        let msg = self
            .inner
            .recv()
            .await
            .map_err(|e| map_connection_error(e, self.max_frame_size))?;
        Ok(encode_sync_message(&msg))
    }
}

// ---------------------------------------------------------------------------
// SessionIo implementation
// ---------------------------------------------------------------------------

#[async_trait]
impl<C, S, R> SessionIo for SyncSessionIo<C, S, R>
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

    fn split(self: Box<Self>) -> SessionIoParts {
        let max = self.max_frame_size;
        let conn = self.conn;
        SessionIoParts {
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

    async fn poll_send_ready(&mut self) -> Result<(), SessionIoError> {
        self.conn
            .control
            .flush()
            .await
            .map_err(|e| map_connection_error(e, self.max_frame_size))?;
        self.conn
            .data_send
            .flush()
            .await
            .map_err(|e| map_connection_error(e, self.max_frame_size))?;
        Ok(())
    }

    async fn recv_control(&mut self) -> Result<Vec<u8>, SessionIoError> {
        let msg = self
            .conn
            .control
            .recv()
            .await
            .map_err(|e| map_connection_error(e, self.max_frame_size))?;
        Ok(encode_sync_message(&msg))
    }

    async fn send_control(&mut self, frame: &[u8]) -> Result<(), SessionIoError> {
        if frame.len() > self.max_frame_size {
            return Err(SessionIoError::FrameTooLarge {
                len: frame.len(),
                max: self.max_frame_size,
            });
        }
        let msg = decode_exact_frame(frame, self.max_frame_size)?;
        self.conn
            .control
            .send(&msg)
            .await
            .map_err(|e| map_connection_error(e, self.max_frame_size))
    }

    async fn recv_data(&mut self) -> Result<Vec<u8>, SessionIoError> {
        let msg = self
            .conn
            .data_recv
            .recv()
            .await
            .map_err(|e| map_connection_error(e, self.max_frame_size))?;
        Ok(encode_sync_message(&msg))
    }

    async fn send_data(&mut self, frame: &[u8]) -> Result<(), SessionIoError> {
        if frame.len() > self.max_frame_size {
            return Err(SessionIoError::FrameTooLarge {
                len: frame.len(),
                max: self.max_frame_size,
            });
        }
        let msg = decode_exact_frame(frame, self.max_frame_size)?;
        self.conn
            .data_send
            .send(&msg)
            .await
            .map_err(|e| map_connection_error(e, self.max_frame_size))
    }

    async fn close_session(&mut self, _code: u32, _reason: &[u8]) -> Result<(), SessionIoError> {
        self.conn
            .control
            .flush()
            .await
            .map_err(|e| map_connection_error(e, self.max_frame_size))?;
        self.conn
            .data_send
            .flush()
            .await
            .map_err(|e| map_connection_error(e, self.max_frame_size))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};

    #[derive(Default)]
    struct MockControlState {
        recv: VecDeque<Result<SyncMessage, ConnectionError>>,
        sent: Vec<SyncMessage>,
        flushes: usize,
    }

    #[derive(Clone)]
    struct MockControl {
        state: Arc<Mutex<MockControlState>>,
    }

    impl MockControl {
        fn with_recv(
            recv: Vec<Result<SyncMessage, ConnectionError>>,
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
        async fn send(&mut self, msg: &SyncMessage) -> Result<(), ConnectionError> {
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

        async fn recv(&mut self) -> Result<SyncMessage, ConnectionError> {
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
        sent: Vec<SyncMessage>,
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
        async fn send(&mut self, msg: &SyncMessage) -> Result<(), ConnectionError> {
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
        recv: VecDeque<Result<SyncMessage, ConnectionError>>,
    }

    #[derive(Clone)]
    struct MockDataRecv {
        state: Arc<Mutex<MockRecvState>>,
    }

    impl MockDataRecv {
        fn with_recv(
            recv: Vec<Result<SyncMessage, ConnectionError>>,
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
        async fn recv(&mut self) -> Result<SyncMessage, ConnectionError> {
            self.state
                .lock()
                .expect("recv lock")
                .recv
                .pop_front()
                .unwrap_or(Err(ConnectionError::Closed))
        }
    }

    fn build_io(
        control_recv: Vec<Result<SyncMessage, ConnectionError>>,
        data_recv: Vec<Result<SyncMessage, ConnectionError>>,
    ) -> (
        SyncSessionIo<MockControl, MockDataSend, MockDataRecv>,
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

        (SyncSessionIo::new(7, conn), control_state, data_send_state)
    }

    #[tokio::test]
    async fn session_io_encodes_decodes_control_and_data_frames() {
        let (mut io, control_state, data_send_state) = build_io(
            vec![Ok(SyncMessage::Done)],
            vec![Ok(SyncMessage::Event {
                blob: vec![1, 2, 3],
            })],
        );

        let control_frame = io.recv_control().await.expect("recv control");
        let (control_msg, consumed) = parse_sync_message(&control_frame).expect("parse control");
        assert_eq!(consumed, control_frame.len());
        assert_eq!(control_msg, SyncMessage::Done);

        let data_frame = io.recv_data().await.expect("recv data");
        let (data_msg, consumed) = parse_sync_message(&data_frame).expect("parse data");
        assert_eq!(consumed, data_frame.len());
        assert_eq!(
            data_msg,
            SyncMessage::Event {
                blob: vec![1, 2, 3]
            }
        );

        let neg_open = encode_sync_message(&SyncMessage::NegOpen { msg: vec![9, 8, 7] });
        io.send_control(&neg_open).await.expect("send control");
        let data_done = encode_sync_message(&SyncMessage::DataDone);
        io.send_data(&data_done).await.expect("send data");

        io.poll_send_ready().await.expect("poll send ready");
        io.close_session(0, b"done").await.expect("close session");

        let control = control_state.lock().expect("control lock");
        assert_eq!(control.sent.len(), 1);
        assert_eq!(control.sent[0], SyncMessage::NegOpen { msg: vec![9, 8, 7] });
        assert!(control.flushes >= 2);

        let data_send = data_send_state.lock().expect("send lock");
        assert_eq!(data_send.sent.len(), 1);
        assert_eq!(data_send.sent[0], SyncMessage::DataDone);
        assert!(data_send.flushes >= 2);
    }

    #[tokio::test]
    async fn send_control_rejects_trailing_bytes() {
        let (mut io, _control_state, _data_send_state) = build_io(vec![], vec![]);
        let mut frame = encode_sync_message(&SyncMessage::Done);
        frame.push(0);

        let err = io.send_control(&frame).await.expect_err("expected error");
        assert!(matches!(err, SessionIoError::PeerViolation(_)));
    }

    #[tokio::test]
    async fn recv_control_maps_connection_closed_to_connection_lost() {
        let (mut io, _control_state, _data_send_state) =
            build_io(vec![Err(ConnectionError::Closed)], vec![]);

        let err = io.recv_control().await.expect_err("expected error");
        assert_eq!(err, SessionIoError::ConnectionLost);
    }

    #[tokio::test]
    async fn recv_data_maps_parse_too_large_to_typed_error() {
        let parse_err = ConnectionError::Parse(ParseError::NegMessageTooLarge(123_456));
        let (mut io, _control_state, _data_send_state) = build_io(vec![], vec![Err(parse_err)]);

        let err = io.recv_data().await.expect_err("expected error");
        assert_eq!(
            err,
            SessionIoError::FrameTooLarge {
                len: 123_456,
                max: DEFAULT_SYNC_FRAME_MAX_BYTES,
            }
        );
    }

    #[tokio::test]
    async fn send_data_rejects_oversized_frame_before_parse() {
        let (mut io, _control_state, _data_send_state) = build_io(vec![], vec![]);
        let oversized = vec![0u8; DEFAULT_SYNC_FRAME_MAX_BYTES + 1];

        let err = io.send_data(&oversized).await.expect_err("expected error");
        assert_eq!(
            err,
            SessionIoError::FrameTooLarge {
                len: DEFAULT_SYNC_FRAME_MAX_BYTES + 1,
                max: DEFAULT_SYNC_FRAME_MAX_BYTES,
            }
        );
    }
}
