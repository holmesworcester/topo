use std::time::Duration;

use tokio::sync::oneshot;
use tracing::debug;

use crate::contracts::event_pipeline_contract::IngestItem;
use crate::crypto::{event_id_to_base64, hash_event, EventId};
use crate::db::queue::current_timestamp_ms;
use crate::protocol::Frame;
use crate::state::pipeline::{enqueue_direct_ingest_waiter, IngestWaiter};
use crate::sync::session::live_suppression::{
    publish_live_suppression_event, LiveSuppressionReceiveState,
};
use crate::sync::session::logging::SyncRunRxCapture;
use crate::transport::connection::ConnectionError;
use crate::transport::StreamRecv;
use crate::tuning::{
    direct_ingest_large_blob_threshold_bytes, direct_receive_batch_item_cap,
    direct_receive_large_blob_batch_max_bytes, direct_receive_small_blob_batch_max_bytes,
};

const RANGE_DATA_RECORD_PREFIX_LEN: usize = 4;

pub struct RangeReceiveResult {
    pub events_received: u64,
    pub bytes_received: u64,
    pub ingest_waiters: Vec<IngestWaiter>,
}

struct DirectReceiveBatchBuffer {
    db_path: String,
    recorded_by: String,
    source_tag: String,
    live_suppression_publish: Option<(
        crate::sync::session::live_suppression::LiveSuppressionCohortKey,
        u64,
    )>,
    batch: Vec<IngestItem>,
    batch_bytes: usize,
    batch_has_large_blob: bool,
    ingest_waiters: Vec<IngestWaiter>,
}

impl DirectReceiveBatchBuffer {
    fn open(
        db_path: String,
        recorded_by: String,
        source_tag: String,
        live_suppression_publish: Option<(
            crate::sync::session::live_suppression::LiveSuppressionCohortKey,
            u64,
        )>,
    ) -> Self {
        Self {
            db_path,
            recorded_by,
            source_tag,
            live_suppression_publish,
            batch: Vec::with_capacity(direct_receive_batch_item_cap()),
            batch_bytes: 0,
            batch_has_large_blob: false,
            ingest_waiters: Vec::new(),
        }
    }

    fn append_blob(&mut self, event_id: &EventId, blob: &[u8], created_at_ms: Option<i64>) {
        self.batch_bytes = self.batch_bytes.saturating_add(blob.len());
        self.batch_has_large_blob |= blob.len() >= direct_ingest_large_blob_threshold_bytes();
        self.batch.push((
            *event_id,
            blob.to_vec(),
            self.recorded_by.clone(),
            self.source_tag.clone(),
            current_timestamp_ms(),
            0,
        ));
        if let (Some((key, session_id)), Some(created_at_ms)) =
            (&self.live_suppression_publish, created_at_ms)
        {
            publish_live_suppression_event(key, *session_id, *event_id, created_at_ms);
        }
    }

    fn should_flush(&self) -> bool {
        self.batch.len() >= direct_receive_batch_item_cap()
            || self.batch_bytes >= self.batch_max_bytes()
    }

    fn batch_max_bytes(&self) -> usize {
        if self.batch_has_large_blob {
            direct_receive_large_blob_batch_max_bytes()
        } else {
            direct_receive_small_blob_batch_max_bytes()
        }
    }

    async fn flush(&mut self) -> Result<(), String> {
        if self.batch.is_empty() {
            return Ok(());
        }
        let batch = std::mem::take(&mut self.batch);
        self.batch_bytes = 0;
        self.batch_has_large_blob = false;
        let direct_waiter = enqueue_direct_ingest_waiter(&self.db_path, batch)
            .await
            .map_err(|e| format!("enqueue direct ingest batch: {e}"))?;
        let (completion_tx, completion_rx) = oneshot::channel();
        tokio::spawn(async move {
            let result = match direct_waiter.await {
                Ok(Ok(result)) => Ok(result.persisted_event_ids.len()),
                Ok(Err(e)) => Err(format!("direct ingest batch: {e}")),
                Err(e) => Err(format!("direct ingest waiter dropped: {e}")),
            };
            let _ = completion_tx.send(result);
        });
        self.ingest_waiters.push(completion_rx);
        Ok(())
    }

    async fn finish(mut self) -> Result<Vec<IngestWaiter>, String> {
        self.flush().await?;
        Ok(self.ingest_waiters)
    }
}

fn maybe_note_remote_done(state: &mut Option<LiveSuppressionReceiveState>) {
    let Some(state) = state.as_mut() else {
        return;
    };
    if state.remote_done_notified {
        return;
    }
    let _ = state.remote_done_tx.send(());
    state.remote_done_notified = true;
}

fn parse_next_blob_record(buffer: &[u8], offset: &mut usize) -> Result<Option<Vec<u8>>, String> {
    if *offset >= buffer.len() {
        return Ok(None);
    }
    if buffer.len() - *offset < RANGE_DATA_RECORD_PREFIX_LEN {
        return Ok(None);
    }
    let blob_len = u32::from_le_bytes(
        buffer[*offset..*offset + RANGE_DATA_RECORD_PREFIX_LEN]
            .try_into()
            .map_err(|_| "range data record length truncated".to_string())?,
    ) as usize;
    let record_len = RANGE_DATA_RECORD_PREFIX_LEN.saturating_add(blob_len);
    if buffer.len() - *offset < record_len {
        return Ok(None);
    }
    let blob_start = *offset + RANGE_DATA_RECORD_PREFIX_LEN;
    let blob_end = blob_start + blob_len;
    let blob = buffer[blob_start..blob_end].to_vec();
    *offset += record_len;
    Ok(Some(blob))
}

fn event_created_at_ms(blob: &[u8]) -> Option<i64> {
    crate::event_modules::extract_created_at_ms(blob)
        .and_then(|created_at_ms| i64::try_from(created_at_ms).ok())
}

pub fn spawn_receive_task<R>(
    data_recv: R,
    db_path: String,
    recorded_by: String,
    session_id: u64,
    source_tag: String,
    idle_timeout: Duration,
    rx_capture: Option<SyncRunRxCapture>,
    live_suppression: Option<LiveSuppressionReceiveState>,
) -> tokio::task::JoinHandle<Result<RangeReceiveResult, String>>
where
    R: StreamRecv + Send + 'static,
{
    tokio::spawn(async move {
        let mut data_recv = data_recv;
        let live_suppression_publish = live_suppression
            .as_ref()
            .map(|state| (state.key.clone(), state.session_id));
        let mut receive_buffer = DirectReceiveBatchBuffer::open(
            db_path.clone(),
            recorded_by.clone(),
            source_tag.clone(),
            live_suppression_publish,
        );
        let mut events_received = 0u64;
        let mut bytes_received = 0u64;
        let mut live_suppression = live_suppression;

        if live_suppression.is_some() {
            debug!(
                target: "topo::sync_operation",
                session_id,
                source = %source_tag,
                "live suppression receive task starting"
            );
            loop {
                let next = tokio::time::timeout(idle_timeout, data_recv.recv()).await;
                match next {
                    Ok(Ok(Frame::Event { blob })) => {
                        let event_id = hash_event(&blob);
                        let created_at_ms = event_created_at_ms(&blob);
                        if let Some(capture) = &rx_capture {
                            capture.record_event_id_b64(event_id_to_base64(&event_id));
                        }
                        receive_buffer.append_blob(&event_id, &blob, created_at_ms);
                        if receive_buffer.should_flush() {
                            receive_buffer.flush().await?;
                        }
                        bytes_received += blob.len() as u64;
                        events_received += 1;
                    }
                    Ok(Ok(Frame::SuppressIds { ids })) => {
                        if let Some(state) = &live_suppression {
                            let _ = state.inbound_suppression_tx.send(ids);
                        }
                    }
                    Ok(Ok(Frame::RangeDataDone)) => {
                        maybe_note_remote_done(&mut live_suppression);
                    }
                    Ok(Ok(_)) => {}
                    Ok(Err(ConnectionError::Closed)) | Ok(Err(_)) | Err(_) => {
                        maybe_note_remote_done(&mut live_suppression);
                        break;
                    }
                }
            }
            debug!(
                target: "topo::sync_operation",
                session_id,
                source = %source_tag,
                events_received,
                bytes_received,
                "live suppression receive task complete"
            );
        } else {
            let mut buffer = Vec::<u8>::with_capacity(64 * 1024);
            loop {
                let next = tokio::time::timeout(idle_timeout, data_recv.recv_chunk()).await;
                match next {
                    Ok(Ok(chunk)) => {
                        buffer.extend_from_slice(&chunk);
                        let mut offset = 0usize;
                        while let Some(blob) = parse_next_blob_record(&buffer, &mut offset)? {
                            let event_id = hash_event(&blob);
                            let created_at_ms = event_created_at_ms(&blob);
                            if let Some(capture) = &rx_capture {
                                capture.record_event_id_b64(event_id_to_base64(&event_id));
                            }
                            receive_buffer.append_blob(&event_id, &blob, created_at_ms);
                            if receive_buffer.should_flush() {
                                receive_buffer.flush().await?;
                            }
                            bytes_received += blob.len() as u64;
                            events_received += 1;
                        }
                        if offset > 0 {
                            buffer.drain(..offset);
                        }
                    }
                    Ok(Err(ConnectionError::Closed)) => break,
                    Ok(Err(_)) => break,
                    Err(_) => break,
                }
            }
        }

        let ingest_waiters = receive_buffer.finish().await?;
        Ok(RangeReceiveResult {
            events_received,
            bytes_received,
            ingest_waiters,
        })
    })
}
