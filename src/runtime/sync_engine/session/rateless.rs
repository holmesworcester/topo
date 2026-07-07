//! Alternative sync path: peers exchange rateless-coded snapshots instead of
//! running negentropy reconciliation.

use std::time::{Duration, Instant};

use rand::{rngs::StdRng, RngCore, SeedableRng};
use rusqlite::OptionalExtension;
use tracing::debug;

use crate::contracts::event_pipeline_contract::IngestItem;
use crate::crypto::{event_id_from_base64, event_id_to_base64, hash_event, EventId};
use crate::db::{
    open_connection,
    queue::current_timestamp_ms,
    store::Store,
    transport_creds::{resolve_tenant_transport_target, CRED_SOURCE_BOOTSTRAP},
};
use crate::protocol::Frame;
use crate::runtime::peering::loops::live_session_peer_ids;
use crate::runtime::sync_control::ManualSyncRoundCapture;
use crate::runtime::sync_engine::session::admission::resolve_sync_admission;
use crate::runtime::SyncStats;
use crate::state::pipeline::ingest_now;
use crate::sync::session::logging::SyncRunRxCapture;
use crate::sync::session::range_session::{
    build_shared_snapshot_bytes, build_shared_snapshot_bytes_for_roots, RangeReceiveResult,
};
use crate::sync::session::receive_log::{note_hot_receive_finished, note_hot_receive_started};
use crate::sync::session::windowing::{
    decode_sync_window_kind, encode_sync_window_kind, is_low_mem_allowed_window,
    is_priority_ingest_window, mark_outbound_window_completed,
    restrict_outbound_windows_to_last_week, select_outbound_window, SyncWindow, SyncWindowKind,
};
use crate::sync::session::INITIAL_CONTROL_PROGRESS_TIMEOUT;
use crate::transport::connection::ConnectionError;
use crate::transport::{DualConnection, StreamConn, StreamRecv, StreamSend};
use crate::tuning::{rateless_chunk_bytes, rateless_symbol_count};

const RATELESS_OPEN_VERSION: u8 = 1;
const RATELESS_OPEN_STEADY_STATE: u8 = 0;
const RATELESS_OPEN_BOOTSTRAP: u8 = 1;
const RATELESS_OPEN_FLAG_TS_MIN: u8 = 1 << 0;
const RATELESS_OPEN_FLAG_TS_MAX: u8 = 1 << 1;
const RATELESS_INGEST_BATCH_CAP: usize = 256;
const RATELESS_INGEST_BATCH_MAX_BYTES: usize = 8 * 1024 * 1024;
const RATELESS_POLICY_REJECT_GRACE: Duration = Duration::from_millis(100);
const RATELESS_REPAIR_SYMBOL_DEGREE: usize = 3;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RatelessSyncOpen {
    SteadyState {
        workspace_id: String,
        requested_range: SyncWindow,
    },
    Bootstrap {
        workspace_id: String,
        invite_event_id: String,
        requested_range: SyncWindow,
    },
}

impl RatelessSyncOpen {
    fn requested_range(&self) -> SyncWindow {
        match self {
            Self::SteadyState {
                requested_range, ..
            }
            | Self::Bootstrap {
                requested_range, ..
            } => *requested_range,
        }
    }

    fn workspace_id(&self) -> &str {
        match self {
            Self::SteadyState { workspace_id, .. }
            | Self::Bootstrap { workspace_id, .. } => workspace_id,
        }
    }

    fn bootstrap_invite_event_id(&self) -> Option<&str> {
        match self {
            Self::SteadyState { .. } => None,
            Self::Bootstrap {
                invite_event_id, ..
            } => Some(invite_event_id),
        }
    }
}

fn spawn_manual_round_replier(
    peer_id: &str,
    command_rx: Option<tokio::sync::mpsc::Receiver<crate::runtime::sync_control::SessionCommand>>,
) -> Option<tokio::task::JoinHandle<()>> {
    let mut command_rx = command_rx?;
    let peer_id = peer_id.to_string();
    Some(tokio::task::spawn_local(async move {
        while let Some(cmd) = command_rx.recv().await {
            match cmd {
                crate::runtime::sync_control::SessionCommand::ForceRound { reply } => {
                    let _ = reply.send(Ok(ManualSyncRoundCapture {
                        peer_id: peer_id.clone(),
                        observed_ids: Vec::new(),
                    }));
                }
            }
        }
    }))
}

async fn stop_manual_round_replier(handle: Option<tokio::task::JoinHandle<()>>) {
    if let Some(handle) = handle {
        handle.abort();
        let _ = handle.await;
    }
}

fn rateless_snapshot_range() -> SyncWindow {
    SyncWindow {
        kind: SyncWindowKind::Full,
        ts_min_inclusive_ms: None,
        ts_max_exclusive_ms: None,
    }
}

fn encode_optional_i64(payload: &mut Vec<u8>, value: Option<i64>) {
    if let Some(value) = value {
        payload.extend_from_slice(&value.to_le_bytes());
    }
}

fn encode_string_field(payload: &mut Vec<u8>, value: &str) -> Result<(), String> {
    let len = u16::try_from(value.len())
        .map_err(|_| format!("rateless open string too large: {} bytes", value.len()))?;
    payload.extend_from_slice(&len.to_le_bytes());
    Ok(())
}

pub fn encode_rateless_open(open: &RatelessSyncOpen) -> Result<Vec<u8>, String> {
    let (mode, workspace_id, invite_event_id, requested_range) = match open {
        RatelessSyncOpen::SteadyState {
            workspace_id,
            requested_range,
        } => (
            RATELESS_OPEN_STEADY_STATE,
            workspace_id.as_str(),
            None,
            *requested_range,
        ),
        RatelessSyncOpen::Bootstrap {
            workspace_id,
            invite_event_id,
            requested_range,
        } => (
            RATELESS_OPEN_BOOTSTRAP,
            workspace_id.as_str(),
            Some(invite_event_id.as_str()),
            *requested_range,
        ),
    };

    let mut flags = 0u8;
    if requested_range.ts_min_inclusive_ms.is_some() {
        flags |= RATELESS_OPEN_FLAG_TS_MIN;
    }
    if requested_range.ts_max_exclusive_ms.is_some() {
        flags |= RATELESS_OPEN_FLAG_TS_MAX;
    }

    let invite_event_id = invite_event_id.unwrap_or("");
    let mut payload = vec![
        RATELESS_OPEN_VERSION,
        mode,
        encode_sync_window_kind(requested_range.kind),
        flags,
    ];
    encode_string_field(&mut payload, workspace_id)?;
    encode_string_field(&mut payload, invite_event_id)?;
    encode_optional_i64(&mut payload, requested_range.ts_min_inclusive_ms);
    encode_optional_i64(&mut payload, requested_range.ts_max_exclusive_ms);
    payload.extend_from_slice(workspace_id.as_bytes());
    payload.extend_from_slice(invite_event_id.as_bytes());
    Ok(payload)
}

fn read_u16_le(input: &[u8], offset: &mut usize) -> Result<usize, String> {
    if input.len().saturating_sub(*offset) < 2 {
        return Err("rateless open truncated length field".to_string());
    }
    let value = u16::from_le_bytes(
        input[*offset..*offset + 2]
            .try_into()
            .map_err(|_| "rateless open truncated length field".to_string())?,
    ) as usize;
    *offset += 2;
    Ok(value)
}

fn read_i64_le(input: &[u8], offset: &mut usize) -> Result<i64, String> {
    if input.len().saturating_sub(*offset) < 8 {
        return Err("rateless open truncated timestamp field".to_string());
    }
    let value = i64::from_le_bytes(
        input[*offset..*offset + 8]
            .try_into()
            .map_err(|_| "rateless open truncated timestamp field".to_string())?,
    );
    *offset += 8;
    Ok(value)
}

fn read_string_field(input: &[u8], offset: &mut usize, len: usize) -> Result<String, String> {
    if input.len().saturating_sub(*offset) < len {
        return Err("rateless open truncated string field".to_string());
    }
    let value = std::str::from_utf8(&input[*offset..*offset + len])
        .map_err(|e| format!("rateless open contained invalid utf-8: {e}"))?
        .to_string();
    *offset += len;
    Ok(value)
}

pub fn decode_rateless_open(msg: &[u8]) -> Result<RatelessSyncOpen, String> {
    if msg.len() < 8 {
        return Err("rateless open too short".to_string());
    }
    if msg[0] != RATELESS_OPEN_VERSION {
        return Err(format!("unsupported rateless open version {}", msg[0]));
    }

    let mode = msg[1];
    let requested_range_kind = decode_sync_window_kind(msg[2])?;
    let flags = msg[3];
    let mut offset = 4usize;
    let workspace_len = read_u16_le(msg, &mut offset)?;
    let invite_len = read_u16_le(msg, &mut offset)?;
    let ts_min_inclusive_ms = if (flags & RATELESS_OPEN_FLAG_TS_MIN) != 0 {
        Some(read_i64_le(msg, &mut offset)?)
    } else {
        None
    };
    let ts_max_exclusive_ms = if (flags & RATELESS_OPEN_FLAG_TS_MAX) != 0 {
        Some(read_i64_le(msg, &mut offset)?)
    } else {
        None
    };
    let workspace_id = read_string_field(msg, &mut offset, workspace_len)?;
    let invite_event_id = read_string_field(msg, &mut offset, invite_len)?;
    if offset != msg.len() {
        return Err("rateless open had trailing bytes".to_string());
    }

    let requested_range = SyncWindow {
        kind: requested_range_kind,
        ts_min_inclusive_ms,
        ts_max_exclusive_ms,
    };
    match mode {
        RATELESS_OPEN_STEADY_STATE => {
            if !invite_event_id.is_empty() {
                return Err("steady-state rateless open must not carry invite id".to_string());
            }
            Ok(RatelessSyncOpen::SteadyState {
                workspace_id,
                requested_range,
            })
        }
        RATELESS_OPEN_BOOTSTRAP => {
            if invite_event_id.is_empty() {
                return Err("bootstrap rateless open missing invite id".to_string());
            }
            Ok(RatelessSyncOpen::Bootstrap {
                workspace_id,
                invite_event_id,
                requested_range,
            })
        }
        other => Err(format!("unsupported rateless open mode {}", other)),
    }
}

fn load_bootstrap_invite_event_id(
    conn: &rusqlite::Connection,
    recorded_by: &str,
    workspace_id: &str,
) -> Result<Option<String>, String> {
    conn.query_row(
        "SELECT invite_event_id
         FROM invites_accepted
         WHERE recorded_by = ?1
           AND workspace_id = ?2
         ORDER BY created_at DESC, event_id DESC
         LIMIT 1",
        rusqlite::params![recorded_by, workspace_id],
        |row| crate::db::sql_types::get_text(row, 0),
    )
    .optional()
    .map_err(|e| format!("load bootstrap invite event id: {e}"))
}

fn load_rateless_open(
    conn: &rusqlite::Connection,
    recorded_by: &str,
    workspace_id: &str,
    requested_range: SyncWindow,
) -> Result<RatelessSyncOpen, String> {
    let transport_target = resolve_tenant_transport_target(conn, recorded_by)
        .map_err(|e| format!("resolve rateless transport target: {e}"))?;
    if transport_target
        .as_ref()
        .map(|target| target.source == CRED_SOURCE_BOOTSTRAP)
        .unwrap_or(false)
    {
        let invite_event_id = load_bootstrap_invite_event_id(conn, recorded_by, workspace_id)?
            .ok_or_else(|| {
                format!(
                    "bootstrap rateless sync requires invite_event_id for recorded_by={} workspace_id={}",
                    recorded_by, workspace_id
                )
            })?;
        Ok(RatelessSyncOpen::Bootstrap {
            workspace_id: workspace_id.to_string(),
            invite_event_id,
            requested_range,
        })
    } else {
        Ok(RatelessSyncOpen::SteadyState {
            workspace_id: workspace_id.to_string(),
            requested_range,
        })
    }
}

fn bootstrap_root_ids(open: &RatelessSyncOpen) -> Result<Option<Vec<EventId>>, String> {
    let Some(invite_event_id) = open.bootstrap_invite_event_id() else {
        return Ok(None);
    };
    let workspace_id = event_id_from_base64(open.workspace_id()).ok_or_else(|| {
        format!(
            "decode bootstrap workspace id from rateless open: invalid event id {}",
            open.workspace_id()
        )
    })?;
    let invite_event_id = event_id_from_base64(invite_event_id).ok_or_else(|| {
        format!(
            "decode bootstrap invite id from rateless open: invalid event id {}",
            invite_event_id
        )
    })?;
    let mut root_ids = vec![workspace_id];
    if invite_event_id != workspace_id {
        root_ids.push(invite_event_id);
    }
    Ok(Some(root_ids))
}

fn build_source_blocks(snapshot: &[u8], chunk_size: usize) -> Vec<Vec<u8>> {
    if snapshot.is_empty() {
        return Vec::new();
    }
    snapshot
        .chunks(chunk_size)
        .map(|chunk| {
            let mut block = vec![0u8; chunk_size];
            block[..chunk.len()].copy_from_slice(chunk);
            block
        })
        .collect()
}

fn systematic_block_index(source_symbols: usize, symbol_index: u32) -> Option<usize> {
    let symbol_index = symbol_index as usize;
    (symbol_index < source_symbols).then_some(symbol_index)
}

fn set_coeff_bit(words: &mut [u64], bit: usize) {
    let word = bit / 64;
    let offset = bit % 64;
    if let Some(entry) = words.get_mut(word) {
        *entry |= 1u64 << offset;
    }
}

fn coefficient_words(seed: &[u8; 32], source_symbols: usize, symbol_index: u32) -> Vec<u64> {
    let word_count = source_symbols.div_ceil(64);
    let mut words = vec![0u64; word_count];
    if source_symbols == 0 {
        return words;
    }
    if let Some(block_index) = systematic_block_index(source_symbols, symbol_index) {
        set_coeff_bit(&mut words, block_index);
        return words;
    }

    let mut hasher = blake3::Hasher::new();
    hasher.update(seed);
    hasher.update(&symbol_index.to_le_bytes());
    let mut rng = StdRng::from_seed(*hasher.finalize().as_bytes());
    let degree = RATELESS_REPAIR_SYMBOL_DEGREE.min(source_symbols).max(1);
    let mut populated = 0usize;
    while populated < degree {
        let bit = (rng.next_u64() as usize) % source_symbols;
        let word = bit / 64;
        let mask = 1u64 << (bit % 64);
        if (words[word] & mask) == 0 {
            words[word] |= mask;
            populated += 1;
        }
    }
    words
}

fn bit_is_set(words: &[u64], bit: usize) -> bool {
    let word = bit / 64;
    let offset = bit % 64;
    words
        .get(word)
        .map(|entry| (entry & (1u64 << offset)) != 0)
        .unwrap_or(false)
}

fn xor_bytes(target: &mut [u8], rhs: &[u8]) {
    for (left, right) in target.iter_mut().zip(rhs.iter()) {
        *left ^= *right;
    }
}

fn encode_symbol_payload(
    source_blocks: &[Vec<u8>],
    seed: &[u8; 32],
    symbol_index: u32,
    chunk_size: usize,
) -> Vec<u8> {
    if let Some(block_index) = systematic_block_index(source_blocks.len(), symbol_index) {
        return source_blocks[block_index].clone();
    }
    let coeffs = coefficient_words(seed, source_blocks.len(), symbol_index);
    let mut payload = vec![0u8; chunk_size];
    for (idx, block) in source_blocks.iter().enumerate() {
        if bit_is_set(&coeffs, idx) {
            xor_bytes(&mut payload, block);
        }
    }
    payload
}

struct RatelessDecoder {
    source_symbols: usize,
    chunk_size: usize,
    rank: usize,
    decoded_blocks: Vec<Option<Vec<u8>>>,
}

impl RatelessDecoder {
    fn new(seed: [u8; 32], source_symbols: usize, chunk_size: usize) -> Self {
        let _ = seed;
        Self {
            source_symbols,
            chunk_size,
            rank: 0,
            decoded_blocks: std::iter::repeat_with(|| None)
                .take(source_symbols)
                .collect::<Vec<_>>(),
        }
    }

    fn absorb_symbol(&mut self, symbol_index: u32, payload: Vec<u8>) -> Result<(), String> {
        if payload.len() != self.chunk_size {
            return Err(format!(
                "rateless symbol payload length mismatch: expected {} bytes, got {}",
                self.chunk_size,
                payload.len()
            ));
        }
        if self.source_symbols == 0 {
            return Ok(());
        }
        if let Some(block_index) = systematic_block_index(self.source_symbols, symbol_index) {
            if self.decoded_blocks[block_index].is_none() {
                self.decoded_blocks[block_index] = Some(payload);
                self.rank += 1;
            }
            return Ok(());
        }
        if self.rank == self.source_symbols {
            return Ok(());
        }

        Err(format!(
            "rateless repair symbol {} arrived before systematic baseline completed: rank {} of {}",
            symbol_index, self.rank, self.source_symbols
        ))
    }

    fn finish(self, total_bytes: usize) -> Result<Vec<u8>, String> {
        if self.source_symbols == 0 {
            return Ok(Vec::new());
        }
        if self.rank != self.source_symbols {
            return Err(format!(
                "rateless snapshot decode incomplete: rank {} of {}",
                self.rank, self.source_symbols
            ));
        }

        let mut out = Vec::with_capacity(self.source_symbols.saturating_mul(self.chunk_size));
        for (pivot, payload) in self.decoded_blocks.into_iter().enumerate() {
            let Some(payload) = payload else {
                return Err(format!("missing decoded rateless row for pivot {}", pivot));
            };
            out.extend_from_slice(&payload);
        }
        out.truncate(total_bytes);
        Ok(out)
    }
}

async fn send_rateless_snapshot<S>(
    data_send: &mut S,
    session_id: u64,
    snapshot: &[u8],
    event_count: u64,
) -> Result<u64, String>
where
    S: StreamSend,
{
    let chunk_size = rateless_chunk_bytes();
    let source_blocks = build_source_blocks(snapshot, chunk_size);
    let source_symbols = source_blocks.len();
    let symbols_sent = rateless_symbol_count(source_symbols);
    let total_bytes = snapshot.len();
    let mut hasher = blake3::Hasher::new();
    hasher.update(snapshot);
    hasher.update(&session_id.to_le_bytes());
    let seed = *hasher.finalize().as_bytes();

    debug!(
        target: "topo::sync_operation",
        session_id,
        chunk_size,
        source_symbols,
        symbols_sent,
        total_bytes,
        event_count,
        "rateless sender starting"
    );

    data_send
        .send(&Frame::RatelessHeader {
            chunk_size: u32::try_from(chunk_size)
                .map_err(|_| format!("rateless chunk size out of range: {}", chunk_size))?,
            source_symbols: u32::try_from(source_symbols)
                .map_err(|_| format!("too many rateless source symbols: {}", source_symbols))?,
            symbols_sent: u32::try_from(symbols_sent)
                .map_err(|_| format!("too many rateless symbols to send: {}", symbols_sent))?,
            total_bytes: u64::try_from(total_bytes)
                .map_err(|_| format!("snapshot too large: {} bytes", total_bytes))?,
            total_events: u32::try_from(event_count)
                .map_err(|_| format!("snapshot event count out of range: {}", event_count))?,
            seed,
        })
        .await
        .map_err(|e| format!("send rateless header: {e}"))?;

    let mut bytes_sent = 0u64;
    for symbol_index in 0..symbols_sent {
        let payload = encode_symbol_payload(
            &source_blocks,
            &seed,
            u32::try_from(symbol_index).expect("symbol index fits in u32"),
            chunk_size,
        );
        bytes_sent = bytes_sent.saturating_add(payload.len() as u64);
        data_send
            .send(&Frame::RatelessSymbol {
                symbol_index: u32::try_from(symbol_index).expect("symbol index fits in u32"),
                payload,
            })
            .await
            .map_err(|e| format!("send rateless symbol: {e}"))?;
    }

    data_send
        .flush()
        .await
        .map_err(|e| format!("flush rateless snapshot: {e}"))?;

    debug!(
        target: "topo::sync_operation",
        session_id,
        chunk_size,
        source_symbols,
        symbols_sent,
        bytes_sent,
        "rateless sender complete"
    );
    Ok(bytes_sent)
}

fn parse_next_blob_record(buffer: &[u8], offset: &mut usize) -> Result<Option<Vec<u8>>, String> {
    const RECORD_PREFIX_LEN: usize = 4;
    if *offset >= buffer.len() {
        return Ok(None);
    }
    if buffer.len() - *offset < RECORD_PREFIX_LEN {
        return Err("rateless snapshot record length truncated".to_string());
    }
    let blob_len = u32::from_le_bytes(
        buffer[*offset..*offset + RECORD_PREFIX_LEN]
            .try_into()
            .map_err(|_| "rateless snapshot record length truncated".to_string())?,
    ) as usize;
    let record_len = RECORD_PREFIX_LEN.saturating_add(blob_len);
    if buffer.len() - *offset < record_len {
        return Err("rateless snapshot record body truncated".to_string());
    }
    let blob_start = *offset + RECORD_PREFIX_LEN;
    let blob_end = blob_start + blob_len;
    let blob = buffer[blob_start..blob_end].to_vec();
    *offset += record_len;
    Ok(Some(blob))
}

fn validate_rateless_header(
    chunk_size: u32,
    source_symbols: u32,
    symbols_sent: u32,
    total_bytes: u64,
) -> Result<(), String> {
    if chunk_size == 0 && (source_symbols > 0 || total_bytes > 0) {
        return Err("rateless header declared zero chunk size for non-empty snapshot".to_string());
    }
    if source_symbols == 0 {
        if total_bytes != 0 || symbols_sent != 0 {
            return Err("rateless header declared empty source set with non-empty payload".to_string());
        }
        return Ok(());
    }
    if symbols_sent < source_symbols {
        return Err(format!(
            "rateless header underspecified symbol budget: symbols_sent={} source_symbols={}",
            symbols_sent, source_symbols
        ));
    }
    Ok(())
}

fn ingest_rateless_snapshot(
    db_path: &str,
    recorded_by: &str,
    source_tag: &str,
    snapshot: &[u8],
    rx_capture: Option<&SyncRunRxCapture>,
) -> Result<u64, String> {
    let mut events_received = 0u64;
    let mut batch = Vec::<IngestItem>::with_capacity(RATELESS_INGEST_BATCH_CAP);
    let mut batch_bytes = 0usize;
    let mut offset = 0usize;

    while let Some(blob) = parse_next_blob_record(snapshot, &mut offset)? {
        let event_id = hash_event(&blob);
        if let Some(capture) = rx_capture {
            capture.record_event_id_b64(event_id_to_base64(&event_id));
        }
        let stored_at_ms = current_timestamp_ms();
        batch_bytes = batch_bytes.saturating_add(blob.len());
        batch.push((
            event_id,
            blob,
            recorded_by.to_string(),
            source_tag.to_string(),
            stored_at_ms,
            stored_at_ms,
        ));
        events_received = events_received.saturating_add(1);

        if batch.len() >= RATELESS_INGEST_BATCH_CAP
            || batch_bytes >= RATELESS_INGEST_BATCH_MAX_BYTES
        {
            ingest_now(db_path, std::mem::take(&mut batch))
                .map_err(|e| format!("ingest rateless snapshot batch: {e}"))?;
            batch_bytes = 0;
        }
    }

    if !batch.is_empty() {
        ingest_now(db_path, batch).map_err(|e| format!("ingest rateless snapshot tail: {e}"))?;
    }
    Ok(events_received)
}

fn spawn_rateless_receive_task<R>(
    data_recv: R,
    db_path: String,
    recorded_by: String,
    source_tag: String,
    idle_timeout: Duration,
    rx_capture: Option<SyncRunRxCapture>,
) -> tokio::task::JoinHandle<Result<RangeReceiveResult, String>>
where
    R: StreamRecv + Send + 'static,
{
    tokio::spawn(async move {
        let mut data_recv = data_recv;
        let mut events_received = 0u64;
        let mut bytes_received = 0u64;

        loop {
            let header = match tokio::time::timeout(idle_timeout, data_recv.recv()).await {
                Ok(Ok(Frame::RatelessHeader {
                    chunk_size,
                    source_symbols,
                    symbols_sent,
                    total_bytes,
                    total_events,
                    seed,
                })) => {
                    validate_rateless_header(chunk_size, source_symbols, symbols_sent, total_bytes)?;
                    (
                        chunk_size as usize,
                        source_symbols as usize,
                        symbols_sent as usize,
                        total_bytes as usize,
                        total_events as u64,
                        seed,
                    )
                }
                Ok(Ok(other)) => {
                    return Err(format!(
                        "expected rateless header on data stream, got {:?}",
                        other
                    ))
                }
                Ok(Err(ConnectionError::Closed)) => break,
                Ok(Err(e)) => return Err(format!("receive rateless header: {e}")),
                Err(_) => return Err("timeout waiting for rateless header".to_string()),
            };

            let (chunk_size, source_symbols, symbols_sent, total_bytes, total_events, seed) =
                header;
            let mut decoder = RatelessDecoder::new(seed, source_symbols, chunk_size);

            for _ in 0..symbols_sent {
                match tokio::time::timeout(idle_timeout, data_recv.recv()).await {
                    Ok(Ok(Frame::RatelessSymbol {
                        symbol_index,
                        payload,
                    })) => {
                        bytes_received = bytes_received.saturating_add(payload.len() as u64);
                        decoder.absorb_symbol(symbol_index, payload)?;
                    }
                    Ok(Ok(other)) => {
                        return Err(format!(
                            "expected rateless symbol on data stream, got {:?}",
                            other
                        ))
                    }
                    Ok(Err(ConnectionError::Closed)) => {
                        return Err(
                            "connection closed before rateless snapshot completed".to_string()
                        )
                    }
                    Ok(Err(e)) => return Err(format!("receive rateless symbol: {e}")),
                    Err(_) => return Err("timeout waiting for rateless symbol".to_string()),
                }
            }

            let snapshot = decoder.finish(total_bytes)?;
            let decoded_events = ingest_rateless_snapshot(
                &db_path,
                &recorded_by,
                &source_tag,
                &snapshot,
                rx_capture.as_ref(),
            )?;
            if decoded_events != total_events {
                return Err(format!(
                    "rateless snapshot decoded {} events but header declared {}",
                    decoded_events, total_events
                ));
            }
            events_received = events_received.saturating_add(decoded_events);
        }

        Ok(RangeReceiveResult {
            events_received,
            bytes_received,
            path: None,
            pending_overlay: None,
        })
    })
}

async fn run_rateless_data_exchange<S, R>(
    db: &rusqlite::Connection,
    mut data_send: S,
    data_recv: R,
    session_id: u64,
    db_path: &str,
    recorded_by: &str,
    ingress_source_tag: &str,
    workspace_id: &str,
    sync_open: &RatelessSyncOpen,
    activity_timeout: Duration,
    rx_capture: Option<SyncRunRxCapture>,
) -> Result<(u64, u64, RangeReceiveResult), Box<dyn std::error::Error + Send + Sync>>
where
    S: StreamSend,
    R: StreamRecv + Send + 'static,
{
    let snapshot_range = rateless_snapshot_range();
    let requested_range = sync_open.requested_range();
    let hot_receive = is_priority_ingest_window(requested_range.kind);
    if hot_receive {
        note_hot_receive_started(db_path);
    }

    let receive_task = spawn_rateless_receive_task(
        data_recv,
        db_path.to_string(),
        recorded_by.to_string(),
        ingress_source_tag.to_string(),
        activity_timeout,
        rx_capture,
    );
    let store = Store::new(db);
    let mut events_sent = 0u64;
    let mut bytes_sent = 0u64;

    if let Some(root_ids) = bootstrap_root_ids(sync_open)? {
        let (snapshot, event_count) = build_shared_snapshot_bytes_for_roots(
            db,
            &store,
            workspace_id,
            snapshot_range,
            &root_ids,
        )
        .map_err(|e| format!("build bootstrap rateless snapshot: {e}"))?;
        events_sent = events_sent.saturating_add(event_count);
        bytes_sent = bytes_sent.saturating_add(
            send_rateless_snapshot(&mut data_send, session_id, &snapshot, event_count)
                .await
                .map_err(|e| format!("send bootstrap rateless snapshot: {e}"))?,
        );
    }

    let (snapshot, event_count) =
        build_shared_snapshot_bytes(db, db_path, &store, workspace_id, snapshot_range)
            .map_err(|e| format!("build rateless snapshot: {e}"))?;
    events_sent = events_sent.saturating_add(event_count);
    bytes_sent = bytes_sent.saturating_add(
        send_rateless_snapshot(&mut data_send, session_id, &snapshot, event_count)
            .await
            .map_err(|e| format!("send rateless snapshot: {e}"))?,
    );
    drop(data_send);

    let received = match receive_task.await {
        Ok(result) => result.map_err(|e| format!("receive rateless snapshot: {e}"))?,
        Err(e) => {
            if hot_receive {
                note_hot_receive_finished(db_path);
            }
            return Err(format!("receive rateless snapshot join: {e}").into());
        }
    };
    if hot_receive {
        note_hot_receive_finished(db_path);
    }
    Ok((events_sent, bytes_sent, received))
}

#[allow(clippy::too_many_arguments)]
pub async fn run_rateless_sync_initiator<C, S, R>(
    conn: DualConnection<C, S, R>,
    session_id: u64,
    db_path: &str,
    timeout_secs: u64,
    peer_id: &str,
    recorded_by: &str,
    ingress_source_tag: &str,
    rx_capture: Option<SyncRunRxCapture>,
    command_rx: Option<tokio::sync::mpsc::Receiver<crate::runtime::sync_control::SessionCommand>>,
) -> Result<SyncStats, Box<dyn std::error::Error + Send + Sync>>
where
    C: StreamConn,
    S: StreamSend,
    R: StreamRecv + Send + 'static,
{
    let DualConnection {
        mut control,
        data_send,
        data_recv,
    } = conn;
    let start = Instant::now();
    let activity_timeout = Duration::from_secs(timeout_secs);
    let manual_round_replier = spawn_manual_round_replier(peer_id, command_rx);

    let db = open_connection(db_path)?;
    let ws_id = resolve_sync_admission(&db, recorded_by)?;
    let live_peer_ids = live_session_peer_ids(db_path, recorded_by);
    let range = select_outbound_window(
        db_path,
        recorded_by,
        peer_id,
        &live_peer_ids,
        crate::db::queue::current_timestamp_ms(),
    );
    let sync_open =
        load_rateless_open(&db, recorded_by, &ws_id, range).map_err(|e| format!("build rateless open: {e}"))?;

    control
        .send(&Frame::RatelessOpen {
            msg: encode_rateless_open(&sync_open)
                .map_err(|e| format!("encode rateless open: {e}"))?,
        })
        .await?;
    control.flush().await?;

    match tokio::time::timeout(RATELESS_POLICY_REJECT_GRACE, control.recv()).await {
        Ok(Ok(Frame::RangePolicyReject {
            rejected_window_kind,
            oldest_allowed_window_kind,
        })) => {
            let rejected_kind = decode_sync_window_kind(rejected_window_kind).map_err(|e| {
                format!("initiator received invalid rateless rejected window kind: {e}")
            })?;
            let oldest_allowed_kind = decode_sync_window_kind(oldest_allowed_window_kind)
                .map_err(|e| {
                    format!("initiator received invalid rateless oldest allowed window kind: {e}")
                })?;
            if rejected_kind == range.kind
                && oldest_allowed_kind == SyncWindowKind::LastWeek
                && !is_low_mem_allowed_window(range.kind)
            {
                restrict_outbound_windows_to_last_week(db_path, recorded_by, peer_id);
                stop_manual_round_replier(manual_round_replier).await;
                return Ok(SyncStats {
                    events_sent: 0,
                    events_received: 0,
                    neg_rounds: 0,
                    bytes_sent: 0,
                    bytes_received: 0,
                    duration_ms: start.elapsed().as_millis(),
                });
            }
            stop_manual_round_replier(manual_round_replier).await;
            return Err(format!(
                "initiator received unsupported rateless range policy reject: rejected={rejected_kind:?} oldest_allowed={oldest_allowed_kind:?} current={:?}",
                range.kind
            )
            .into());
        }
        Ok(Ok(other)) => {
            stop_manual_round_replier(manual_round_replier).await;
            return Err(
                format!("initiator expected rateless startup silence or policy reject, got {other:?}")
                    .into(),
            );
        }
        Ok(Err(ConnectionError::Closed)) | Err(_) => {}
        Ok(Err(e)) => {
            stop_manual_round_replier(manual_round_replier).await;
            return Err(format!("receive rateless startup control: {e}").into());
        }
    }

    let (events_sent, bytes_sent, received) = match run_rateless_data_exchange(
        &db,
        data_send,
        data_recv,
        session_id,
        db_path,
        recorded_by,
        ingress_source_tag,
        &ws_id,
        &sync_open,
        activity_timeout,
        rx_capture,
    )
    .await
    {
        Ok(result) => result,
        Err(err) => {
            stop_manual_round_replier(manual_round_replier).await;
            return Err(err);
        }
    };

    debug!(
        target: "topo::sync_operation",
        session_id,
        peer = %&peer_id[..peer_id.len().min(16)],
        range = ?range.kind,
        events_sent,
        events_received = received.events_received,
        bytes_sent,
        bytes_received = received.bytes_received,
        "initiator rateless sync session complete"
    );
    stop_manual_round_replier(manual_round_replier).await;
    let _ = mark_outbound_window_completed(
        db_path,
        recorded_by,
        peer_id,
        range,
        received.events_received,
    );

    Ok(SyncStats {
        events_sent,
        events_received: received.events_received,
        neg_rounds: 1,
        bytes_sent,
        bytes_received: received.bytes_received,
        duration_ms: start.elapsed().as_millis(),
    })
}

#[allow(clippy::too_many_arguments)]
pub async fn run_rateless_sync_responder<C, S, R>(
    conn: DualConnection<C, S, R>,
    session_id: u64,
    db_path: &str,
    timeout_secs: u64,
    peer_id: &str,
    recorded_by: &str,
    ingress_source_tag: &str,
    rx_capture: Option<SyncRunRxCapture>,
    command_rx: Option<tokio::sync::mpsc::Receiver<crate::runtime::sync_control::SessionCommand>>,
) -> Result<SyncStats, Box<dyn std::error::Error + Send + Sync>>
where
    C: StreamConn,
    S: StreamSend,
    R: StreamRecv + Send + 'static,
{
    let DualConnection {
        mut control,
        data_send,
        data_recv,
    } = conn;
    let start = Instant::now();
    let activity_timeout = Duration::from_secs(timeout_secs);
    let manual_round_replier = spawn_manual_round_replier(peer_id, command_rx);

    let initial = match tokio::time::timeout(INITIAL_CONTROL_PROGRESS_TIMEOUT, control.recv()).await
    {
        Ok(Ok(frame)) => frame,
        Ok(Err(err)) => {
            stop_manual_round_replier(manual_round_replier).await;
            return Err(err.into());
        }
        Err(err) => {
            stop_manual_round_replier(manual_round_replier).await;
            return Err(err.into());
        }
    };
    let Frame::RatelessOpen { msg } = initial else {
        stop_manual_round_replier(manual_round_replier).await;
        return Err(format!("responder expected RatelessOpen, got {initial:?}").into());
    };
    let sync_open = decode_rateless_open(&msg)?;
    let range = sync_open.requested_range();
    if crate::tuning::low_mem_mode() && !is_low_mem_allowed_window(range.kind) {
        control
            .send(&Frame::RangePolicyReject {
                rejected_window_kind: encode_sync_window_kind(range.kind),
                oldest_allowed_window_kind: encode_sync_window_kind(SyncWindowKind::LastWeek),
            })
            .await?;
        control.flush().await?;
        stop_manual_round_replier(manual_round_replier).await;
        return Ok(SyncStats {
            events_sent: 0,
            events_received: 0,
            neg_rounds: 0,
            bytes_sent: 0,
            bytes_received: 0,
            duration_ms: start.elapsed().as_millis(),
        });
    }

    let db = open_connection(db_path)?;
    let ws_id = resolve_sync_admission(&db, recorded_by)?;
    if sync_open.workspace_id() != ws_id {
        stop_manual_round_replier(manual_round_replier).await;
        return Err(format!(
            "rateless open workspace mismatch: remote={} local={}",
            sync_open.workspace_id(),
            ws_id
        )
        .into());
    }

    let (events_sent, bytes_sent, received) = match run_rateless_data_exchange(
        &db,
        data_send,
        data_recv,
        session_id,
        db_path,
        recorded_by,
        ingress_source_tag,
        &ws_id,
        &sync_open,
        activity_timeout,
        rx_capture,
    )
    .await
    {
        Ok(result) => result,
        Err(err) => {
            stop_manual_round_replier(manual_round_replier).await;
            return Err(err);
        }
    };

    debug!(
        target: "topo::sync_operation",
        session_id,
        peer = %&peer_id[..peer_id.len().min(16)],
        range = ?range.kind,
        events_sent,
        events_received = received.events_received,
        bytes_sent,
        bytes_received = received.bytes_received,
        "responder rateless sync session complete"
    );
    stop_manual_round_replier(manual_round_replier).await;

    Ok(SyncStats {
        events_sent,
        events_received: received.events_received,
        neg_rounds: 1,
        bytes_sent,
        bytes_received: received.bytes_received,
        duration_ms: start.elapsed().as_millis(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encode_all_symbols(snapshot: &[u8], chunk_size: usize) -> (Vec<Vec<u8>>, [u8; 32]) {
        let source_blocks = build_source_blocks(snapshot, chunk_size);
        let symbols_sent = rateless_symbol_count(source_blocks.len());
        let mut hasher = blake3::Hasher::new();
        hasher.update(snapshot);
        let seed = *hasher.finalize().as_bytes();
        let symbols = (0..symbols_sent)
            .map(|symbol_index| {
                encode_symbol_payload(
                    &source_blocks,
                    &seed,
                    u32::try_from(symbol_index).unwrap(),
                    chunk_size,
                )
            })
            .collect::<Vec<_>>();
        (symbols, seed)
    }

    #[test]
    fn rateless_decoder_roundtrips_snapshot() {
        let snapshot = (0..150_000).map(|idx| (idx % 251) as u8).collect::<Vec<_>>();
        let chunk_size = 4096;
        let source_symbols = build_source_blocks(&snapshot, chunk_size).len();
        let (symbols, seed) = encode_all_symbols(&snapshot, chunk_size);
        let mut decoder = RatelessDecoder::new(seed, source_symbols, chunk_size);
        for (symbol_index, symbol) in symbols.into_iter().enumerate() {
            decoder
                .absorb_symbol(u32::try_from(symbol_index).unwrap(), symbol)
                .unwrap();
        }
        let decoded = decoder.finish(snapshot.len()).unwrap();
        assert_eq!(decoded, snapshot);
    }

    #[test]
    fn rateless_decoder_breaks_on_insufficient_symbols() {
        let snapshot = (0..48_000).map(|idx| (idx % 97) as u8).collect::<Vec<_>>();
        let chunk_size = 2048;
        let source_symbols = build_source_blocks(&snapshot, chunk_size).len();
        let (symbols, seed) = encode_all_symbols(&snapshot, chunk_size);
        let mut decoder = RatelessDecoder::new(seed, source_symbols, chunk_size);
        for (symbol_index, symbol) in symbols
            .into_iter()
            .take(source_symbols.saturating_sub(1))
            .enumerate()
        {
            decoder
                .absorb_symbol(u32::try_from(symbol_index).unwrap(), symbol)
                .unwrap();
        }
        let err = decoder.finish(snapshot.len()).unwrap_err();
        assert!(
            err.contains("decode incomplete"),
            "expected insufficient-symbol failure, got {err}"
        );
    }
}
