use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use serde::Serialize;
use serde_json::json;
use tracing::warn;

use crate::contracts::peering_contract::{SessionDirection, SessionMeta};
use crate::crypto::hash_event;
use crate::db::open_connection;
use crate::db::sync_log::{
    ensure_schema, finalize_run, insert_run_event, insert_run_received_event, insert_run_start,
    load_config, NewSyncRun, NewSyncRunEvent,
};
use crate::protocol::Frame;
use crate::runtime::SyncStats;
use crate::tuning::low_mem_mode;

const NEG_FINGERPRINT_SIZE: usize = 16;
const NEG_ID_SIZE: usize = 32;
const MAX_CAPTURE_IDS: usize = 32;

#[derive(Clone, Copy)]
pub enum LogLane {
    Control,
    Data,
}

#[derive(Clone, Copy)]
pub enum LogDir {
    Tx,
    Rx,
}

impl LogLane {
    fn as_str(self) -> &'static str {
        match self {
            Self::Control => "control",
            Self::Data => "data",
        }
    }
}

impl LogDir {
    fn as_str(self) -> &'static str {
        match self {
            Self::Tx => "tx",
            Self::Rx => "rx",
        }
    }
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

fn short_peer(peer_hex: &str) -> String {
    peer_hex.chars().take(16).collect()
}

#[derive(Serialize)]
struct NegEntry {
    bound_ts: String,
    bound_id_prefix: String,
    mode: String,
    fingerprint_hex: Option<String>,
    id_count: Option<usize>,
    ids: Option<Vec<String>>,
    ids_truncated: bool,
}

#[derive(Serialize)]
struct NegPayloadSummary {
    protocol: Option<u64>,
    entry_count: usize,
    skip_count: usize,
    fingerprint_count: usize,
    idlist_count: usize,
    entries: Vec<NegEntry>,
    parse_error: Option<String>,
}

fn decode_var_int(encoded: &mut &[u8]) -> Result<u64, String> {
    if encoded.is_empty() {
        return Err("unexpected EOF while decoding varint".to_string());
    }

    let mut res = 0u64;
    let mut consumed = 0usize;
    for byte in encoded.iter() {
        consumed += 1;
        res = (res << 7) | (*byte as u64 & 0b0111_1111);
        if (byte & 0b1000_0000) == 0 {
            *encoded = &encoded[consumed..];
            return Ok(res);
        }
        if consumed >= 10 {
            return Err("varint too long".to_string());
        }
    }

    Err("unterminated varint".to_string())
}

fn take_bytes<'a>(encoded: &'a mut &[u8], n: usize) -> Result<&'a [u8], String> {
    if encoded.len() < n {
        return Err(format!(
            "unexpected EOF while decoding payload (need {}, have {})",
            n,
            encoded.len()
        ));
    }
    let out = &encoded[..n];
    *encoded = &encoded[n..];
    Ok(out)
}

fn parse_neg_payload(msg: &[u8], capture_full_ids: bool) -> NegPayloadSummary {
    let mut payload = msg;
    let mut entries = Vec::new();
    let mut skip_count = 0usize;
    let mut fingerprint_count = 0usize;
    let mut idlist_count = 0usize;
    let mut parse_error = None;
    let mut protocol = None;

    if !payload.is_empty() {
        protocol = Some(payload[0] as u64);
        payload = &payload[1..];
    } else {
        parse_error = Some("empty negentropy payload".to_string());
    }

    let mut last_ts = 0u64;

    while parse_error.is_none() && !payload.is_empty() {
        let ts_enc = match decode_var_int(&mut payload) {
            Ok(v) => v,
            Err(e) => {
                parse_error = Some(e);
                break;
            }
        };
        let mut ts = if ts_enc == 0 { u64::MAX } else { ts_enc - 1 };
        ts = ts.saturating_add(last_ts);
        last_ts = ts;

        let id_len = match decode_var_int(&mut payload) {
            Ok(v) => v as usize,
            Err(e) => {
                parse_error = Some(e);
                break;
            }
        };
        let id_prefix = match take_bytes(&mut payload, id_len) {
            Ok(v) => hex::encode(v),
            Err(e) => {
                parse_error = Some(e);
                break;
            }
        };

        let mode = match decode_var_int(&mut payload) {
            Ok(v) => v,
            Err(e) => {
                parse_error = Some(e);
                break;
            }
        };

        match mode {
            0 => {
                skip_count += 1;
                entries.push(NegEntry {
                    bound_ts: if ts == u64::MAX {
                        "MAX".to_string()
                    } else {
                        ts.to_string()
                    },
                    bound_id_prefix: id_prefix,
                    mode: "Skip".to_string(),
                    fingerprint_hex: None,
                    id_count: None,
                    ids: None,
                    ids_truncated: false,
                });
            }
            1 => {
                let fp = match take_bytes(&mut payload, NEG_FINGERPRINT_SIZE) {
                    Ok(v) => hex::encode(v),
                    Err(e) => {
                        parse_error = Some(e);
                        break;
                    }
                };
                fingerprint_count += 1;
                entries.push(NegEntry {
                    bound_ts: if ts == u64::MAX {
                        "MAX".to_string()
                    } else {
                        ts.to_string()
                    },
                    bound_id_prefix: id_prefix,
                    mode: "Fingerprint".to_string(),
                    fingerprint_hex: Some(fp),
                    id_count: None,
                    ids: None,
                    ids_truncated: false,
                });
            }
            2 => {
                let total = match decode_var_int(&mut payload) {
                    Ok(v) => v as usize,
                    Err(e) => {
                        parse_error = Some(e);
                        break;
                    }
                };
                let mut ids = Vec::new();
                let keep = if capture_full_ids {
                    total
                } else {
                    total.min(MAX_CAPTURE_IDS)
                };
                for idx in 0..total {
                    let id = match take_bytes(&mut payload, NEG_ID_SIZE) {
                        Ok(v) => v,
                        Err(e) => {
                            parse_error = Some(e);
                            break;
                        }
                    };
                    if idx < keep {
                        ids.push(hex::encode(id));
                    }
                }
                if parse_error.is_some() {
                    break;
                }
                idlist_count += 1;
                entries.push(NegEntry {
                    bound_ts: if ts == u64::MAX {
                        "MAX".to_string()
                    } else {
                        ts.to_string()
                    },
                    bound_id_prefix: id_prefix,
                    mode: "IdList".to_string(),
                    fingerprint_hex: None,
                    id_count: Some(total),
                    ids: Some(ids),
                    ids_truncated: !capture_full_ids && total > MAX_CAPTURE_IDS,
                });
            }
            other => {
                parse_error = Some(format!("unexpected mode {}", other));
            }
        }
    }

    NegPayloadSummary {
        protocol,
        entry_count: entries.len(),
        skip_count,
        fingerprint_count,
        idlist_count,
        entries,
        parse_error,
    }
}

fn frame_detail_json(frame: &Frame, capture_full_ids: bool) -> Option<String> {
    match frame {
        Frame::NegOpen { msg } | Frame::NegMsg { msg } => {
            serde_json::to_string(&parse_neg_payload(msg, capture_full_ids)).ok()
        }
        Frame::RequestIds { ids } => {
            let keep = if capture_full_ids {
                ids.len()
            } else {
                ids.len().min(MAX_CAPTURE_IDS)
            };
            let ids_hex: Vec<String> = ids.iter().take(keep).map(hex::encode).collect();
            serde_json::to_string(&json!({
                "id_count": ids.len(),
                "ids": ids_hex,
                "ids_truncated": !capture_full_ids && ids.len() > MAX_CAPTURE_IDS
            }))
            .ok()
        }
        Frame::DiscoveryHints {
            priority_lane,
            hints,
        } => {
            let keep = if capture_full_ids {
                hints.len()
            } else {
                hints.len().min(MAX_CAPTURE_IDS)
            };
            let ids_hex: Vec<String> = hints
                .iter()
                .take(keep)
                .map(|hint| hex::encode(hint.event_id))
                .collect();
            let semantic_types: Vec<u8> = hints
                .iter()
                .take(keep)
                .map(|hint| hint.semantic_type_code)
                .collect();
            let encoded_sizes: Vec<u32> = hints
                .iter()
                .take(keep)
                .map(|hint| hint.encoded_size_bytes)
                .collect();
            let created_at_ms: Vec<u64> = hints
                .iter()
                .take(keep)
                .map(|hint| hint.created_at_ms)
                .collect();
            serde_json::to_string(&json!({
                "priority_lane": priority_lane,
                "hint_count": hints.len(),
                "ids": ids_hex,
                "semantic_type_codes": semantic_types,
                "encoded_size_bytes": encoded_sizes,
                "created_at_ms": created_at_ms,
                "hints_truncated": !capture_full_ids && hints.len() > MAX_CAPTURE_IDS
            }))
            .ok()
        }
        Frame::Event { blob } => {
            let event_id = hash_event(blob);
            serde_json::to_string(&json!({
                "event_id": hex::encode(event_id),
                "blob_len": blob.len()
            }))
            .ok()
        }
        Frame::IntroOffer { .. }
        | Frame::OpenSessionAuthPeerShared { .. }
        | Frame::OpenSessionAuthInvite { .. }
        | Frame::OpenSessionAuthAck { .. } => None,
    }
}

fn frame_type(frame: &Frame) -> &'static str {
    match frame {
        Frame::NegOpen { .. } => "NegOpen",
        Frame::NegMsg { .. } => "NegMsg",
        Frame::RequestIds { .. } => "RequestIds",
        Frame::DiscoveryHints { .. } => "DiscoveryHints",
        Frame::Event { .. } => "Event",
        Frame::IntroOffer { .. } => "IntroOffer",
        Frame::OpenSessionAuthPeerShared { .. } => "OpenSessionAuthPeerShared",
        Frame::OpenSessionAuthInvite { .. } => "OpenSessionAuthInvite",
        Frame::OpenSessionAuthAck { .. } => "OpenSessionAuthAck",
    }
}

enum WorkerMsg {
    Trace(NewSyncRunEvent),
    ReceivedEvent(String),
    Finalize(NewSyncRun),
}

#[derive(Clone)]
pub struct SyncRunCapture {
    tx: std::sync::mpsc::Sender<WorkerMsg>,
    seq: Arc<AtomicU64>,
    capture_full_ids: bool,
}

impl SyncRunCapture {
    fn new(
        tx: std::sync::mpsc::Sender<WorkerMsg>,
        seq: Arc<AtomicU64>,
        capture_full_ids: bool,
    ) -> Self {
        Self {
            tx,
            seq,
            capture_full_ids,
        }
    }

    pub fn record_frame(&self, lane: LogLane, dir: LogDir, frame: &Frame, msg_len: usize) {
        let detail_json = frame_detail_json(frame, self.capture_full_ids);
        let seq = self.seq.fetch_add(1, Ordering::Relaxed).saturating_add(1);
        let event = NewSyncRunEvent {
            seq,
            ts_ms: now_ms(),
            lane: lane.as_str().to_string(),
            direction: dir.as_str().to_string(),
            frame_type: frame_type(frame).to_string(),
            msg_len,
            detail_json,
        };
        let _ = self.tx.send(WorkerMsg::Trace(event));
    }

    pub fn record_marker(
        &self,
        lane: &str,
        direction: &str,
        frame_type: &str,
        detail_json: Option<String>,
    ) {
        let seq = self.seq.fetch_add(1, Ordering::Relaxed).saturating_add(1);
        let event = NewSyncRunEvent {
            seq,
            ts_ms: now_ms(),
            lane: lane.to_string(),
            direction: direction.to_string(),
            frame_type: frame_type.to_string(),
            msg_len: 0,
            detail_json,
        };
        let _ = self.tx.send(WorkerMsg::Trace(event));
    }
}

#[derive(Clone)]
pub struct SyncRunRxCapture {
    tx: std::sync::mpsc::Sender<WorkerMsg>,
}

impl SyncRunRxCapture {
    fn new(tx: std::sync::mpsc::Sender<WorkerMsg>) -> Self {
        Self { tx }
    }

    pub fn record_event_id_b64(&self, event_id_b64: String) {
        let _ = self.tx.send(WorkerMsg::ReceivedEvent(event_id_b64));
    }
}

fn should_enable_rx_capture(low_mem: bool) -> bool {
    !low_mem
}

pub struct SessionRunLogger {
    started_at_ms: i64,
    session_id: u64,
    tenant_id: String,
    peer_id: String,
    direction: String,
    remote_addr: String,
    role: String,
    tx: Option<std::sync::mpsc::Sender<WorkerMsg>>,
    capture: Option<SyncRunCapture>,
    rx_capture: Option<SyncRunRxCapture>,
    worker: Option<std::thread::JoinHandle<Option<i64>>>,
}

impl SessionRunLogger {
    pub fn maybe_new(db_path: &str, meta: &SessionMeta, role: &str) -> Option<Self> {
        let db = open_connection(db_path).ok()?;
        ensure_schema(&db).ok()?;
        let cfg = load_config(&db).ok()?;

        let direction = match meta.direction {
            SessionDirection::Inbound => "inbound",
            SessionDirection::Outbound => "outbound",
        };

        let started_at_ms = now_ms();
        let initial_run = NewSyncRun {
            started_at_ms,
            ended_at_ms: started_at_ms,
            session_id: meta.session_id,
            tenant_id: meta.tenant.0.clone(),
            peer_id: hex::encode(meta.peer.0),
            direction: direction.to_string(),
            remote_addr: meta.remote_addr.to_string(),
            role: role.to_string(),
            rounds: 0,
            events_sent: 0,
            events_received: 0,
            bytes_sent: 0,
            bytes_received: 0,
            changed: false,
            outcome: "in_progress".to_string(),
            error: None,
        };
        let run_id = insert_run_start(&db, &initial_run).ok()?;

        let (tx, rx) = std::sync::mpsc::channel::<WorkerMsg>();
        let seq = Arc::new(AtomicU64::new(0));
        let capture = if cfg.enabled {
            Some(SyncRunCapture::new(tx.clone(), seq, cfg.capture_full_ids))
        } else {
            None
        };
        // Low-memory mode keeps sync summary logging but skips the unbounded
        // file-slice receive-link queue used for effective download-rate math.
        let rx_capture = if should_enable_rx_capture(low_mem_mode()) {
            Some(SyncRunRxCapture::new(tx.clone()))
        } else {
            None
        };
        let db_path = db_path.to_string();
        let worker = std::thread::spawn(move || {
            let db = match open_connection(&db_path) {
                Ok(db) => db,
                Err(e) => {
                    warn!("sync_log: failed to open db for run {}: {}", run_id, e);
                    return None;
                }
            };

            while let Ok(msg) = rx.recv() {
                match msg {
                    WorkerMsg::Trace(event) => {
                        if let Err(e) = insert_run_event(&db, run_id, &event) {
                            warn!(
                                "sync_log: failed to persist trace event for run {}: {}",
                                run_id, e
                            );
                        }
                    }
                    WorkerMsg::ReceivedEvent(event_id) => {
                        if let Err(e) = insert_run_received_event(&db, run_id, &event_id) {
                            warn!(
                                "sync_log: failed to persist received event for run {}: {}",
                                run_id, e
                            );
                        }
                    }
                    WorkerMsg::Finalize(run) => {
                        return match finalize_run(&db, run_id, &run, &cfg) {
                            Ok(id) => id,
                            Err(e) => {
                                warn!(
                                    "sync_log: failed to finalize run {} (peer={}): {}",
                                    run.session_id,
                                    short_peer(&run.peer_id),
                                    e
                                );
                                None
                            }
                        };
                    }
                }
            }

            None
        });

        Some(Self {
            started_at_ms,
            session_id: meta.session_id,
            tenant_id: meta.tenant.0.clone(),
            peer_id: initial_run.peer_id,
            direction: direction.to_string(),
            remote_addr: meta.remote_addr.to_string(),
            role: role.to_string(),
            tx: Some(tx),
            capture,
            rx_capture,
            worker: Some(worker),
        })
    }

    pub fn capture(&self) -> Option<SyncRunCapture> {
        self.capture.clone()
    }

    pub fn rx_capture(&self) -> Option<SyncRunRxCapture> {
        self.rx_capture.clone()
    }

    pub fn finalize(
        mut self,
        stats: Option<&SyncStats>,
        outcome: &str,
        error: Option<String>,
    ) -> Option<i64> {
        let rounds = stats.map(|s| s.neg_rounds).unwrap_or(0);
        let events_sent = stats.map(|s| s.events_sent).unwrap_or(0);
        let events_received = stats.map(|s| s.events_received).unwrap_or(0);
        let bytes_sent = stats.map(|s| s.bytes_sent).unwrap_or(0);
        let bytes_received = stats.map(|s| s.bytes_received).unwrap_or(0);
        let changed = events_sent > 0 || events_received > 0;

        let run = NewSyncRun {
            started_at_ms: self.started_at_ms,
            ended_at_ms: now_ms(),
            session_id: self.session_id,
            tenant_id: self.tenant_id,
            peer_id: self.peer_id,
            direction: self.direction,
            remote_addr: self.remote_addr,
            role: self.role,
            rounds,
            events_sent,
            events_received,
            bytes_sent,
            bytes_received,
            changed,
            outcome: outcome.to_string(),
            error,
        };

        self.capture.take();
        let tx = self.tx.take()?;
        let _ = tx.send(WorkerMsg::Finalize(run));
        drop(tx);

        self.worker.take().and_then(|h| h.join().ok()).flatten()
    }
}

#[cfg(test)]
mod tests {
    use super::should_enable_rx_capture;

    #[test]
    fn rx_capture_enabled_outside_lowmem() {
        assert!(should_enable_rx_capture(false));
    }

    #[test]
    fn rx_capture_disabled_in_lowmem() {
        assert!(!should_enable_rx_capture(true));
    }
}
