use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::time::Duration;

use negentropy::{Id, NegentropyStorageVector};
use rusqlite::Connection;

use crate::crypto::{event_id_to_base64, hash_event, EventId};
use crate::db::store::Store;
use crate::protocol::neg_id_to_event_id;
use crate::sync::session::logging::SyncRunRxCapture;
use crate::sync::session::receive_log::ReceiveLogWriter;
use crate::sync::session::windowing::{SyncWindow, SyncWindowKind};
use crate::transport::connection::ConnectionError;
use crate::transport::{StreamRecv, StreamSend};

const RANGE_DATA_RECORD_PREFIX_LEN: usize = 4;
const CLOSURE_QUERY_BATCH: usize = 256;

pub struct RangeReceiveResult {
    pub events_received: u64,
    pub bytes_received: u64,
    pub path: Option<PathBuf>,
}

fn load_range_root_entries(
    conn: &Connection,
    workspace_id: &str,
    range: SyncWindow,
) -> Result<Vec<(i64, EventId)>, String> {
    let mut stmt = conn
        .prepare(
            "SELECT ts, id
             FROM shared_event_index
             WHERE workspace_id = ?1
               AND (?2 IS NULL OR ts >= ?2)
               AND (?3 IS NULL OR ts < ?3)
             ORDER BY ts, id",
        )
        .map_err(|e| format!("prepare shared index query: {e}"))?;
    let mut rows = stmt
        .query(rusqlite::params![
            workspace_id,
            range.ts_min(),
            range.ts_max_exclusive()
        ])
        .map_err(|e| format!("query shared index rows: {e}"))?;
    let mut entries = Vec::new();
    while let Some(row) = rows
        .next()
        .map_err(|e| format!("iterate shared index rows: {e}"))?
    {
        let ts: i64 = row
            .get(0)
            .map_err(|e| format!("read shared index ts: {e}"))?;
        let id_blob: Vec<u8> = row
            .get(1)
            .map_err(|e| format!("read shared index id: {e}"))?;
        if id_blob.len() != 32 {
            continue;
        }
        let mut event_id = [0u8; 32];
        event_id.copy_from_slice(&id_blob);
        entries.push((ts, event_id));
    }
    Ok(entries)
}

fn expand_transitive_shared_deps(
    conn: &Connection,
    seed_ids: &[EventId],
) -> Result<Vec<(i64, EventId)>, String> {
    if seed_ids.is_empty() {
        return Ok(Vec::new());
    }

    let mut discovered = Vec::new();
    let mut visited: HashSet<EventId> = seed_ids.iter().copied().collect();
    let mut frontier: Vec<EventId> = seed_ids.to_vec();

    while !frontier.is_empty() {
        let batch: Vec<EventId> = frontier
            .drain(..frontier.len().min(CLOSURE_QUERY_BATCH))
            .collect();
        let placeholders = batch.iter().map(|_| "?").collect::<Vec<_>>().join(",");
        let batch_ids: Vec<String> = batch.iter().map(event_id_to_base64).collect();

        let sql = format!(
            "SELECT d.dep_event_id, e.created_at
             FROM event_deps d
             JOIN events e ON e.event_id = d.dep_event_id
             WHERE d.event_id IN ({})
               AND e.share_scope = 'shared'
             ORDER BY e.created_at ASC, d.dep_event_id ASC",
            placeholders
        );
        let mut stmt = conn
            .prepare(&sql)
            .map_err(|e| format!("prepare dep closure query: {e}"))?;
        let mut rows = stmt
            .query(rusqlite::params_from_iter(batch_ids.iter()))
            .map_err(|e| format!("query dep closure rows: {e}"))?;
        while let Some(row) = rows
            .next()
            .map_err(|e| format!("iterate dep closure rows: {e}"))?
        {
            let dep_b64: String = row
                .get(0)
                .map_err(|e| format!("read dep closure dep_event_id: {e}"))?;
            let created_at: i64 = row
                .get(1)
                .map_err(|e| format!("read dep closure created_at: {e}"))?;
            let Some(dep_id) = crate::crypto::event_id_from_base64(&dep_b64) else {
                continue;
            };
            if visited.insert(dep_id) {
                frontier.push(dep_id);
                discovered.push((created_at, dep_id));
            }
        }

        let carrier_sql = format!(
            "SELECT DISTINCT ks.event_id, carrier.created_at
             FROM event_deps d
             JOIN key_shared ks ON ks.key_event_id = d.dep_event_id
             JOIN events carrier ON carrier.event_id = ks.event_id
             WHERE d.event_id IN ({})
               AND d.dep_field_name = 'key_event_id'
               AND carrier.share_scope = 'shared'
             ORDER BY carrier.created_at ASC, ks.event_id ASC",
            placeholders
        );
        let mut carrier_stmt = conn
            .prepare(&carrier_sql)
            .map_err(|e| format!("prepare key carrier closure query: {e}"))?;
        let mut carrier_rows = carrier_stmt
            .query(rusqlite::params_from_iter(batch_ids.iter()))
            .map_err(|e| format!("query key carrier closure rows: {e}"))?;
        while let Some(row) = carrier_rows
            .next()
            .map_err(|e| format!("iterate key carrier closure rows: {e}"))?
        {
            let carrier_b64: String = row
                .get(0)
                .map_err(|e| format!("read key carrier event_id: {e}"))?;
            let created_at: i64 = row
                .get(1)
                .map_err(|e| format!("read key carrier created_at: {e}"))?;
            let Some(carrier_id) = crate::crypto::event_id_from_base64(&carrier_b64) else {
                continue;
            };
            if visited.insert(carrier_id) {
                frontier.push(carrier_id);
                discovered.push((created_at, carrier_id));
            }
        }
    }

    Ok(discovered)
}

fn load_shared_window_entries(
    conn: &Connection,
    workspace_id: &str,
    range: SyncWindow,
) -> Result<Vec<(i64, EventId)>, String> {
    let roots = load_range_root_entries(conn, workspace_id, range)?;
    let root_ids: Vec<EventId> = roots.iter().map(|(_, id)| *id).collect();
    let deps = expand_transitive_shared_deps(conn, &root_ids)?;
    let mut all_by_id: HashMap<EventId, i64> = HashMap::with_capacity(roots.len() + deps.len());
    for (ts, event_id) in roots.into_iter().chain(deps.into_iter()) {
        all_by_id.entry(event_id).or_insert(ts);
    }
    let mut entries: Vec<(i64, EventId)> = all_by_id.into_iter().map(|(id, ts)| (ts, id)).collect();
    entries.sort_by(|(left_ts, left_id), (right_ts, right_id)| {
        left_ts.cmp(right_ts).then_with(|| left_id.cmp(right_id))
    });
    Ok(entries)
}

pub fn load_shared_event_index_slice(
    conn: &Connection,
    workspace_id: &str,
    range: SyncWindow,
) -> Result<NegentropyStorageVector, String> {
    let mut storage = NegentropyStorageVector::new();
    for (ts, event_id) in load_shared_window_entries(conn, workspace_id, range)? {
        storage
            .insert(ts.max(0) as u64, Id::from_byte_array(event_id))
            .map_err(|e| format!("insert negentropy vector item: {e}"))?;
    }
    storage
        .seal()
        .map_err(|e| format!("seal negentropy vector storage: {e}"))?;
    Ok(storage)
}

pub fn load_shared_send_batch(
    store: &Store<'_>,
    ids: &[EventId],
) -> Result<Vec<(EventId, Vec<u8>)>, String> {
    if ids.is_empty() {
        return Ok(Vec::new());
    }

    let base_blobs = store
        .get_shared_batch(ids)
        .map_err(|e| format!("load shared batch: {e}"))?;
    let mut ordered = Vec::with_capacity(ids.len());

    for event_id in ids {
        let Some(blob) = base_blobs.get(event_id) else {
            continue;
        };
        ordered.push((*event_id, blob.clone()));
    }

    Ok(ordered)
}

fn dependency_rank(
    event_id: EventId,
    ids_in_batch: &HashSet<EventId>,
    edges: &HashMap<EventId, Vec<EventId>>,
    memo: &mut HashMap<EventId, usize>,
    visiting: &mut HashSet<EventId>,
) -> usize {
    if let Some(rank) = memo.get(&event_id) {
        return *rank;
    }
    if !visiting.insert(event_id) {
        return 0;
    }
    let mut rank = 0usize;
    if let Some(deps) = edges.get(&event_id) {
        for dep_id in deps {
            if !ids_in_batch.contains(dep_id) {
                continue;
            }
            rank = rank.max(1 + dependency_rank(*dep_id, ids_in_batch, edges, memo, visiting));
        }
    }
    visiting.remove(&event_id);
    memo.insert(event_id, rank);
    rank
}

fn prioritize_send_order(
    store: &Store<'_>,
    range: SyncWindow,
    ids: &[EventId],
) -> Result<Vec<EventId>, String> {
    if ids.is_empty() {
        return Ok(Vec::new());
    }

    let created_at_by_id = store
        .get_shared_created_at_batch(ids)
        .map_err(|e| format!("load shared created_at batch: {e}"))?;
    let edges = store
        .get_shared_dep_edges_batch(ids)
        .map_err(|e| format!("load shared dep edges batch: {e}"))?;
    let ids_in_batch: HashSet<EventId> = ids.iter().copied().collect();
    let mut memo = HashMap::new();
    let mut ordered: Vec<EventId> = ids
        .iter()
        .filter(|event_id| created_at_by_id.contains_key(*event_id))
        .copied()
        .collect();
    ordered.sort_by(|left, right| {
        let left_rank = dependency_rank(*left, &ids_in_batch, &edges, &mut memo, &mut HashSet::new());
        let right_rank = dependency_rank(*right, &ids_in_batch, &edges, &mut memo, &mut HashSet::new());
        let left_ts = created_at_by_id.get(left).copied().unwrap_or_default();
        let right_ts = created_at_by_id.get(right).copied().unwrap_or_default();
        left_rank
            .cmp(&right_rank)
            .then_with(|| match range.kind {
                SyncWindowKind::LastDay => right_ts.cmp(&left_ts).then_with(|| right.cmp(left)),
                SyncWindowKind::Full | SyncWindowKind::LastWeek | SyncWindowKind::LastTwelveWeeks => {
                    left_ts.cmp(&right_ts).then_with(|| left.cmp(right))
                }
            })
    });
    Ok(ordered)
}

pub async fn send_have_events<S>(
    store: &Store<'_>,
    data_send: &mut S,
    have_ids: &[Id],
    range: SyncWindow,
) -> Result<(u64, u64), String>
where
    S: StreamSend,
{
    if have_ids.is_empty() {
        return Ok((0, 0));
    }

    let mut events_sent = 0u64;
    let mut bytes_sent = 0u64;
    let event_ids: Vec<EventId> = have_ids.iter().map(neg_id_to_event_id).collect();
    let event_ids = prioritize_send_order(store, range, &event_ids)?;
    for chunk in event_ids.chunks(64) {
        let ordered = load_shared_send_batch(store, chunk)?;
        let mut payload = Vec::new();
        for (_event_id, blob) in ordered {
            let blob_len = u32::try_from(blob.len())
                .map_err(|_| format!("range event too large: {} bytes", blob.len()))?;
            payload.extend_from_slice(&blob_len.to_le_bytes());
            payload.extend_from_slice(&blob);
            events_sent += 1;
            bytes_sent += blob.len() as u64;
        }
        if payload.is_empty() {
            continue;
        }
        data_send
            .send_bytes(&payload)
            .await
            .map_err(|e| format!("send range data chunk: {e}"))?;
    }
    data_send
        .flush()
        .await
        .map_err(|e| format!("flush range data stream: {e}"))?;
    Ok((events_sent, bytes_sent))
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

pub fn spawn_receive_log_task<R>(
    data_recv: R,
    db_path: String,
    recorded_by: String,
    session_id: u64,
    source_tag: String,
    idle_timeout: Duration,
    rx_capture: Option<SyncRunRxCapture>,
) -> tokio::task::JoinHandle<Result<RangeReceiveResult, String>>
where
    R: StreamRecv + Send + 'static,
{
    tokio::spawn(async move {
        let mut data_recv = data_recv;
        let mut writer = ReceiveLogWriter::open(&db_path, &recorded_by, session_id, &source_tag)?;
        let mut events_received = 0u64;
        let mut bytes_received = 0u64;
        let mut buffer = Vec::<u8>::with_capacity(64 * 1024);

        loop {
            let next = tokio::time::timeout(idle_timeout, data_recv.recv_chunk()).await;
            match next {
                Ok(Ok(chunk)) => {
                    buffer.extend_from_slice(&chunk);
                    let mut offset = 0usize;
                    while let Some(blob) = parse_next_blob_record(&buffer, &mut offset)? {
                        if let Some(capture) = &rx_capture {
                            capture.record_event_id_b64(event_id_to_base64(&hash_event(&blob)));
                        }
                        bytes_received += blob.len() as u64;
                        events_received += 1;
                        writer.append_blob(&blob)?;
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

        Ok(RangeReceiveResult {
            events_received,
            bytes_received,
            path: writer.finish()?,
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{hash_event, spki_fingerprint_from_ed25519_pubkey};
    use crate::db::open_in_memory;
    use crate::db::schema::create_tables;
    use crate::db::store::{insert_event, insert_shared_event_index_entry_if_shared};
    use crate::event_modules::message::{create as create_message, CreateMessageCmd};
    use crate::event_modules::workspace::{
        commands::{create_workspace_with_options, CreateWorkspaceOptions},
        identity_ops::{create_user_invite_events_as_admin_at, ensure_content_key_for_peer},
        load_local_authoring_context,
    };
    use crate::event_modules::{encode_event, BenchDepEvent, ParsedEvent, ShareScope};

    fn insert_shared_bench_dep(
        conn: &Connection,
        workspace_id: &str,
        created_at_ms: i64,
        dep_ids: Vec<EventId>,
        payload_byte: u8,
    ) -> EventId {
        let event = ParsedEvent::BenchDep(BenchDepEvent {
            created_at_ms: created_at_ms as u64,
            dep_ids,
            payload: [payload_byte; 16],
        });
        let blob = encode_event(&event).unwrap();
        let event_id = hash_event(&blob);
        insert_event(
            conn,
            &event_id,
            "bench_dep_perf_testing",
            &blob,
            ShareScope::Shared,
            created_at_ms,
            created_at_ms,
        )
        .unwrap();
        insert_shared_event_index_entry_if_shared(
            conn,
            ShareScope::Shared,
            created_at_ms,
            &event_id,
            workspace_id,
            &blob,
        )
        .unwrap();
        event_id
    }
    const DAY_MS: i64 = 24 * 60 * 60 * 1000;

    struct HotMessageFixture {
        workspace_id_b64: String,
        message_event_id: EventId,
        signer_event_id: EventId,
        author_event_id: EventId,
        key_event_id: EventId,
        key_shared_event_id: EventId,
        message_created_at_ms: i64,
    }

    fn event_created_at(conn: &Connection, event_id: &EventId) -> i64 {
        conn.query_row(
            "SELECT created_at FROM events WHERE event_id = ?1",
            rusqlite::params![crate::crypto::event_id_to_base64(event_id)],
            |row| row.get(0),
        )
        .unwrap()
    }

    fn first_admin_event_id(conn: &Connection, recorded_by: &str) -> EventId {
        let event_id_b64: String = conn
            .query_row(
                "SELECT a.event_id
                 FROM admins a
                 JOIN events e ON e.event_id = a.event_id
                 WHERE a.recorded_by = ?1
                 ORDER BY e.created_at ASC, a.event_id ASC
                 LIMIT 1",
                rusqlite::params![recorded_by],
                |row| row.get(0),
            )
            .unwrap();
        crate::crypto::event_id_from_base64(&event_id_b64).unwrap()
    }

    fn first_key_shared_for_key(conn: &Connection, recorded_by: &str, key_event_id: &EventId) -> EventId {
        let event_id_b64: String = conn
            .query_row(
                "SELECT ks.event_id
                 FROM key_shared ks
                 JOIN events e ON e.event_id = ks.event_id
                 WHERE ks.recorded_by = ?1
                   AND ks.key_event_id = ?2
                 ORDER BY e.created_at ASC, ks.event_id ASC
                 LIMIT 1",
                rusqlite::params![
                    recorded_by,
                    crate::crypto::event_id_to_base64(key_event_id),
                ],
                |row| row.get(0),
            )
            .unwrap();
        crate::crypto::event_id_from_base64(&event_id_b64).unwrap()
    }

    fn seed_hot_message_with_old_key_share(conn: &Connection) -> HotMessageFixture {
        let end_at_ms = crate::db::queue::current_timestamp_ms().max(31 * DAY_MS) as u64;
        let create = create_workspace_with_options(
            conn,
            "bootstrap",
            "workspace",
            "alice",
            "laptop",
            CreateWorkspaceOptions {
                message_count: 0,
                network_age_ms: Some((30 * DAY_MS) as u64),
                end_at_ms: Some(end_at_ms),
            },
        )
        .unwrap();
        let recorded_by = hex::encode(spki_fingerprint_from_ed25519_pubkey(
            &create.peer_shared_key.verifying_key().to_bytes(),
        ));
        let ctx = load_local_authoring_context(conn, &recorded_by).unwrap();
        let key_event_id = ensure_content_key_for_peer(conn, &recorded_by).unwrap();
        let admin_event_id = first_admin_event_id(conn, &recorded_by);
        let invite_created_at_ms = end_at_ms.saturating_sub((20 * DAY_MS) as u64);
        let _invite = create_user_invite_events_as_admin_at(
            conn,
            &recorded_by,
            &create.peer_shared_key,
            &create.peer_shared_event_id,
            &admin_event_id,
            &create.workspace_id,
            invite_created_at_ms,
            None,
        )
        .unwrap();
        let key_shared_event_id = first_key_shared_for_key(conn, &recorded_by, &key_event_id);
        let message_event_id = create_message(
            conn,
            &recorded_by,
            &ctx.signer_event_id,
            &ctx.signing_key,
            end_at_ms,
            CreateMessageCmd {
                workspace_id: ctx.workspace_id,
                author_id: ctx.author_id,
                content: "fresh hot message".to_string(),
            },
        )
        .unwrap();

        HotMessageFixture {
            workspace_id_b64: crate::crypto::event_id_to_base64(&create.workspace_id),
            message_event_id,
            signer_event_id: ctx.signer_event_id,
            author_event_id: ctx.author_id,
            key_event_id,
            key_shared_event_id,
            message_created_at_ms: end_at_ms as i64,
        }
    }

    #[test]
    fn load_shared_send_batch_returns_requested_events_only() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();
        let store = Store::new(&conn);
        let workspace_id = "ws-1";

        let dep_id = insert_shared_bench_dep(&conn, workspace_id, 10, vec![], 0x11);
        let root_id = insert_shared_bench_dep(&conn, workspace_id, 20, vec![dep_id], 0x22);

        let ordered = load_shared_send_batch(&store, &[root_id]).unwrap();
        assert_eq!(ordered.len(), 1);
        assert_eq!(ordered[0].0, root_id);
    }

    #[test]
    fn load_shared_window_entries_include_transitive_deps_outside_root_range() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();
        let workspace_id = "ws-1";

        let dep_id = insert_shared_bench_dep(&conn, workspace_id, 10, vec![], 0x11);
        let mid_id = insert_shared_bench_dep(&conn, workspace_id, 20, vec![dep_id], 0x22);
        let root_id = insert_shared_bench_dep(&conn, workspace_id, 100, vec![mid_id], 0x33);

        let entries = load_shared_window_entries(
            &conn,
            workspace_id,
            SyncWindow {
                kind: SyncWindowKind::LastDay,
                ts_min_inclusive_ms: Some(90),
                ts_max_exclusive_ms: None,
            },
        )
        .unwrap();
        let ids: HashSet<EventId> = entries.into_iter().map(|(_, id)| id).collect();
        assert!(ids.contains(&root_id));
        assert!(ids.contains(&mid_id));
        assert!(ids.contains(&dep_id));
    }

    #[test]
    fn prioritize_send_order_puts_deps_before_dependents() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();
        let workspace_id = "ws-1";
        let store = Store::new(&conn);

        let dep_id = insert_shared_bench_dep(&conn, workspace_id, 10, vec![], 0x11);
        let root_id = insert_shared_bench_dep(&conn, workspace_id, 100, vec![dep_id], 0x22);

        let ordered = prioritize_send_order(
            &store,
            SyncWindow {
                kind: SyncWindowKind::LastDay,
                ts_min_inclusive_ms: Some(90),
                ts_max_exclusive_ms: None,
            },
            &[root_id, dep_id],
        )
        .unwrap();
        assert_eq!(ordered, vec![dep_id, root_id]);
    }

    #[test]
    fn last_day_range_includes_old_auth_and_key_share_deps_for_hot_message() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();
        let fixture = seed_hot_message_with_old_key_share(&conn);
        let cutoff = fixture.message_created_at_ms - DAY_MS;

        assert!(event_created_at(&conn, &fixture.message_event_id) >= cutoff);
        assert!(event_created_at(&conn, &fixture.signer_event_id) < cutoff);
        assert!(event_created_at(&conn, &fixture.author_event_id) < cutoff);
        assert!(event_created_at(&conn, &fixture.key_shared_event_id) < cutoff);

        let range = SyncWindow {
            kind: SyncWindowKind::LastDay,
            ts_min_inclusive_ms: Some(cutoff),
            ts_max_exclusive_ms: None,
        };
        let entries = load_shared_window_entries(&conn, &fixture.workspace_id_b64, range).unwrap();
        let ids: Vec<EventId> = entries.iter().map(|(_, id)| *id).collect();
        let id_set: HashSet<EventId> = ids.iter().copied().collect();

        assert!(id_set.contains(&fixture.message_event_id));
        assert!(id_set.contains(&fixture.signer_event_id));
        assert!(id_set.contains(&fixture.author_event_id));
        assert!(id_set.contains(&fixture.key_shared_event_id));
        assert!(!id_set.contains(&fixture.key_event_id));

        let store = Store::new(&conn);
        let ordered = prioritize_send_order(&store, range, &ids).unwrap();
        let pos = |event_id: EventId| {
            ordered
                .iter()
                .position(|candidate| *candidate == event_id)
                .unwrap()
        };

        assert!(pos(fixture.author_event_id) < pos(fixture.signer_event_id));
        assert!(pos(fixture.signer_event_id) < pos(fixture.message_event_id));
        assert!(pos(fixture.key_shared_event_id) < pos(fixture.message_event_id));
    }
}
