use std::collections::{BTreeSet, HashMap};

use rusqlite::OptionalExtension;
use serde::Serialize;

use crate::contracts::event_pipeline_contract::IngestItem;
use crate::crypto::hash_event;
use crate::db::open_connection;
use crate::event_modules::{self as events, ParsedEvent};
use crate::event_pipeline::ingest_now;
use crate::sim::key_repair::{key_request_target, key_shared_target, response_rank, RepairTarget};
use crate::sim::query_snapshot::{ImportedConnectTarget, ImportedPeerState};
use crate::state::db::transport_creds::resolve_tenant_transport_target;

type PairSyncResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[derive(Clone, Debug)]
struct TransferableSharedEvent {
    event_id: String,
    created_at_ms: i64,
    blob: Vec<u8>,
}

#[derive(Clone, Debug)]
pub(crate) struct PreparedPairSyncDirection {
    pub(crate) stats: PairSyncDirectionStats,
    pub(crate) dest_db_path: String,
    pub(crate) batch: Vec<IngestItem>,
}

#[derive(Clone, Debug)]
pub(crate) struct PreparedPairSyncSession {
    pub(crate) left_to_right: PreparedPairSyncDirection,
    pub(crate) right_to_left: PreparedPairSyncDirection,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SimPeerNode {
    pub db_path: String,
    pub recorded_by: String,
    pub daemon_peer_id: Option<String>,
    pub local_transport_peer_id: Option<String>,
    pub connect_targets: Vec<ImportedConnectTarget>,
}

impl SimPeerNode {
    pub fn from_imported(db_path: &str, imported: &ImportedPeerState) -> Self {
        Self {
            db_path: db_path.to_string(),
            recorded_by: imported.recorded_by.clone(),
            daemon_peer_id: imported.daemon_peer_id.clone(),
            local_transport_peer_id: imported.local_transport_peer_id.clone(),
            connect_targets: imported.connect_targets.clone(),
        }
    }

    fn identity_keys(&self) -> BTreeSet<String> {
        let mut out = BTreeSet::new();
        out.insert(self.recorded_by.clone());
        if let Some(daemon_peer_id) = &self.daemon_peer_id {
            out.insert(daemon_peer_id.clone());
        }
        if let Some(local_transport_peer_id) = &self.local_transport_peer_id {
            out.insert(local_transport_peer_id.clone());
        }
        out
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PairSyncIntent {
    pub initiator_db_path: String,
    pub initiator_recorded_by: String,
    pub target_db_path: String,
    pub target_recorded_by: String,
    pub target_transport_peer_id: String,
    pub source: String,
    pub invite_event_id: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct PairSyncDirectionStats {
    pub source_db_path: String,
    pub source_recorded_by: String,
    pub dest_db_path: String,
    pub dest_recorded_by: String,
    pub transferred_events: usize,
    pub transferred_bytes: u64,
    pub transferred_key_request_events: usize,
    pub suppressed_key_request_events: usize,
    pub transferred_key_shared_events: usize,
    pub suppressed_key_shared_events: usize,
    pub transferred_event_ids: Vec<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct PairSyncSessionStats {
    pub left_to_right: PairSyncDirectionStats,
    pub right_to_left: PairSyncDirectionStats,
}

pub fn plan_pair_sync_intents(peers: &[SimPeerNode]) -> Vec<PairSyncIntent> {
    let mut identities: HashMap<String, Vec<usize>> = HashMap::new();
    for (idx, peer) in peers.iter().enumerate() {
        for key in peer.identity_keys() {
            identities.entry(key).or_default().push(idx);
        }
    }

    let mut intents = Vec::new();
    let mut seen = BTreeSet::new();
    for initiator in peers {
        for target in &initiator.connect_targets {
            let Some(matches) = identities.get(&target.transport_peer_id) else {
                continue;
            };
            for target_idx in matches {
                let target_peer = &peers[*target_idx];
                if initiator.db_path == target_peer.db_path
                    && initiator.recorded_by == target_peer.recorded_by
                {
                    continue;
                }
                let key = (
                    initiator.db_path.clone(),
                    initiator.recorded_by.clone(),
                    target_peer.db_path.clone(),
                    target_peer.recorded_by.clone(),
                    target.transport_peer_id.clone(),
                    target.source.clone(),
                    target.invite_event_id.clone(),
                );
                if !seen.insert(key) {
                    continue;
                }
                intents.push(PairSyncIntent {
                    initiator_db_path: initiator.db_path.clone(),
                    initiator_recorded_by: initiator.recorded_by.clone(),
                    target_db_path: target_peer.db_path.clone(),
                    target_recorded_by: target_peer.recorded_by.clone(),
                    target_transport_peer_id: target.transport_peer_id.clone(),
                    source: target.source.clone(),
                    invite_event_id: target.invite_event_id.clone(),
                });
            }
        }
    }

    intents.sort_by(|left, right| {
        (
            &left.initiator_recorded_by,
            &left.target_recorded_by,
            &left.source,
        )
            .cmp(&(
                &right.initiator_recorded_by,
                &right.target_recorded_by,
                &right.source,
            ))
    });
    intents
}

pub fn run_pair_sync_session(
    left_db_path: &str,
    left_recorded_by: &str,
    right_db_path: &str,
    right_recorded_by: &str,
) -> PairSyncResult<PairSyncSessionStats> {
    let prepared = prepare_pair_sync_session(
        left_db_path,
        left_recorded_by,
        right_db_path,
        right_recorded_by,
    )?;
    apply_prepared_pair_sync_session(prepared)
}

pub(crate) fn prepare_pair_sync_session(
    left_db_path: &str,
    left_recorded_by: &str,
    right_db_path: &str,
    right_recorded_by: &str,
) -> PairSyncResult<PreparedPairSyncSession> {
    Ok(PreparedPairSyncSession {
        left_to_right: collect_shared_events_one_way(
            left_db_path,
            left_recorded_by,
            right_db_path,
            right_recorded_by,
        )?,
        right_to_left: collect_shared_events_one_way(
            right_db_path,
            right_recorded_by,
            left_db_path,
            left_recorded_by,
        )?,
    })
}

pub(crate) fn apply_prepared_pair_sync_session(
    prepared: PreparedPairSyncSession,
) -> PairSyncResult<PairSyncSessionStats> {
    apply_prepared_direction(&prepared.left_to_right)?;
    apply_prepared_direction(&prepared.right_to_left)?;
    Ok(PairSyncSessionStats {
        left_to_right: prepared.left_to_right.stats,
        right_to_left: prepared.right_to_left.stats,
    })
}

fn collect_shared_events_one_way(
    source_db_path: &str,
    source_recorded_by: &str,
    dest_db_path: &str,
    dest_recorded_by: &str,
) -> PairSyncResult<PreparedPairSyncDirection> {
    let source = open_connection(source_db_path)?;
    crate::db::schema::create_tables(&source)?;
    let dest = open_connection(dest_db_path)?;
    crate::db::schema::create_tables(&dest)?;

    let known_dest_events = stored_event_ids(&dest)?;
    let winning_key_shared_events = winning_key_shared_event_ids(&source, source_recorded_by)?;
    let observed_key_shared_targets = observed_key_shared_targets(&source, source_recorded_by)?;
    let source_tag = format!(
        "quic_recv:{}@sim",
        source_transport_peer_id(&source, source_recorded_by)?
    );
    let now_ms = crate::db::queue::current_timestamp_ms();

    let mut primary_event_ids = Vec::new();
    let mut transferred_key_request_events = 0usize;
    let mut suppressed_key_request_events = 0usize;
    let mut transferred_key_shared_events = 0usize;
    let mut suppressed_key_shared_events = 0usize;
    let mut primary_events = Vec::<TransferableSharedEvent>::new();

    let mut stmt = source.prepare(
        "SELECT e.event_id, e.event_type, e.blob
         FROM recorded_events re
         JOIN events e ON e.event_id = re.event_id
         WHERE re.peer_id = ?1
           AND e.share_scope = 'shared'
         ORDER BY e.created_at ASC, e.event_id ASC",
    )?;
    let rows = stmt.query_map(rusqlite::params![source_recorded_by], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, Vec<u8>>(2)?,
        ))
    })?;

    for row in rows {
        let (event_id, _event_type, blob) = row?;
        if known_dest_events.contains(&event_id) {
            continue;
        }
        match semantic_parsed_event(&blob) {
            Ok(ParsedEvent::KeyRequest(event)) => {
                if observed_key_shared_targets.contains(&key_request_target(&event)) {
                    suppressed_key_request_events = suppressed_key_request_events.saturating_add(1);
                    continue;
                }
                transferred_key_request_events = transferred_key_request_events.saturating_add(1);
            }
            Ok(ParsedEvent::KeyShared(_)) => {
                if !winning_key_shared_events.contains(&event_id) {
                    suppressed_key_shared_events = suppressed_key_shared_events.saturating_add(1);
                    continue;
                }
                transferred_key_shared_events = transferred_key_shared_events.saturating_add(1);
            }
            _ => {}
        }
        primary_event_ids.push(event_id.clone());
        primary_events.push(TransferableSharedEvent {
            event_id,
            created_at_ms: events::extract_created_at_ms(&blob).unwrap_or(0) as i64,
            blob,
        });
    }

    let transferable_events =
        expand_transferable_shared_closure(&source, &known_dest_events, primary_events)?;
    let transferred_event_ids = transferable_events
        .iter()
        .map(|event| event.event_id.clone())
        .collect::<Vec<_>>();
    let transferred_bytes = transferable_events
        .iter()
        .map(|event| event.blob.len() as u64)
        .sum::<u64>();
    let batch = transferable_events
        .into_iter()
        .map(|event| {
            (
                hash_event(&event.blob),
                event.blob,
                dest_recorded_by.to_string(),
                source_tag.clone(),
                now_ms,
                now_ms,
            )
        })
        .collect::<Vec<IngestItem>>();

    Ok(PreparedPairSyncDirection {
        stats: PairSyncDirectionStats {
            source_db_path: source_db_path.to_string(),
            source_recorded_by: source_recorded_by.to_string(),
            dest_db_path: dest_db_path.to_string(),
            dest_recorded_by: dest_recorded_by.to_string(),
            transferred_events: transferred_event_ids.len(),
            transferred_bytes,
            transferred_key_request_events,
            suppressed_key_request_events,
            transferred_key_shared_events,
            suppressed_key_shared_events,
            transferred_event_ids,
        },
        dest_db_path: dest_db_path.to_string(),
        batch,
    })
}

fn expand_transferable_shared_closure(
    source: &rusqlite::Connection,
    known_dest_events: &BTreeSet<String>,
    primary_events: Vec<TransferableSharedEvent>,
) -> PairSyncResult<Vec<TransferableSharedEvent>> {
    let mut by_event_id = BTreeSet::<String>::new();
    let mut out = Vec::<TransferableSharedEvent>::new();
    let mut pending = primary_events;

    while let Some(event) = pending.pop() {
        if known_dest_events.contains(&event.event_id)
            || !by_event_id.insert(event.event_id.clone())
        {
            continue;
        }
        let parsed = match events::parse_event(&event.blob) {
            Ok(parsed) => parsed,
            Err(_) => {
                out.push(event);
                continue;
            }
        };

        for (_field_name, dep_id) in recursive_dep_field_values(&parsed) {
            let dep_id_b64 = crate::crypto::event_id_to_base64(&dep_id);
            if known_dest_events.contains(&dep_id_b64) || by_event_id.contains(&dep_id_b64) {
                continue;
            }
            let Some(dep_event) = load_transferable_shared_event(source, &dep_id_b64)? else {
                continue;
            };
            pending.push(dep_event);
        }

        out.push(event);
    }

    out.sort_by(|left, right| {
        (left.created_at_ms, &left.event_id).cmp(&(right.created_at_ms, &right.event_id))
    });
    Ok(out)
}

fn load_transferable_shared_event(
    source: &rusqlite::Connection,
    event_id_b64: &str,
) -> PairSyncResult<Option<TransferableSharedEvent>> {
    let row: Option<(String, Vec<u8>, i64)> = source
        .query_row(
            "SELECT event_type, blob, created_at
             FROM events
             WHERE event_id = ?1
             LIMIT 1",
            rusqlite::params![event_id_b64],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?;
    let Some((_event_type, blob, created_at_ms)) = row else {
        return Ok(None);
    };
    let Some(type_code) = events::extract_event_type(&blob) else {
        return Ok(None);
    };
    let Some(meta) = events::registry().lookup(type_code) else {
        return Ok(None);
    };
    if meta.share_scope != events::ShareScope::Shared {
        return Ok(None);
    }
    Ok(Some(TransferableSharedEvent {
        event_id: event_id_b64.to_string(),
        created_at_ms,
        blob,
    }))
}

fn semantic_parsed_event(blob: &[u8]) -> PairSyncResult<ParsedEvent> {
    let parsed = events::parse_event(blob)?;
    match parsed {
        ParsedEvent::Signed(signed) => semantic_parsed_event(&signed.payload),
        other => Ok(other),
    }
}

fn recursive_dep_field_values(parsed: &ParsedEvent) -> Vec<(&'static str, [u8; 32])> {
    let mut deps = parsed.dep_field_values();
    if let ParsedEvent::Signed(signed) = parsed {
        deps.push(("signer_event_id", signed.signer_event_id));
        if let Ok(inner) = semantic_parsed_event(&signed.payload) {
            deps.extend(recursive_dep_field_values(&inner));
        }
    }
    deps
}

fn winning_key_shared_event_ids(
    conn: &rusqlite::Connection,
    recorded_by: &str,
) -> PairSyncResult<BTreeSet<String>> {
    let mut stmt = conn.prepare(
        "SELECT e.event_id, e.blob
         FROM recorded_events re
         JOIN events e ON e.event_id = re.event_id
         WHERE re.peer_id = ?1
         ORDER BY re.id ASC",
    )?;
    let rows = stmt.query_map(rusqlite::params![recorded_by], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?))
    })?;

    let mut best_by_target = HashMap::<RepairTarget, ([u8; 32], [u8; 32], String)>::new();
    for row in rows {
        let (event_id, blob) = row?;
        let Ok(ParsedEvent::KeyShared(event)) = semantic_parsed_event(&blob) else {
            continue;
        };
        let Some(signer_event_id) = crate::event_modules::signed::outer_signer_event_id(&blob)
        else {
            continue;
        };
        let target = key_shared_target(&event);
        let rank = response_rank(target, signer_event_id);
        best_by_target
            .entry(target)
            .and_modify(|best| {
                if (rank, signer_event_id, event_id.as_str()) < (best.0, best.1, best.2.as_str()) {
                    *best = (rank, signer_event_id, event_id.clone());
                }
            })
            .or_insert((rank, signer_event_id, event_id));
    }

    Ok(best_by_target
        .into_values()
        .map(|(_, _, event_id)| event_id)
        .collect())
}

fn observed_key_shared_targets(
    conn: &rusqlite::Connection,
    recorded_by: &str,
) -> PairSyncResult<BTreeSet<RepairTarget>> {
    let mut stmt = conn.prepare(
        "SELECT e.blob
         FROM recorded_events re
         JOIN events e ON e.event_id = re.event_id
         WHERE re.peer_id = ?1
         ORDER BY re.id ASC",
    )?;
    let rows = stmt.query_map(rusqlite::params![recorded_by], |row| {
        row.get::<_, Vec<u8>>(0)
    })?;

    let mut out = BTreeSet::new();
    for row in rows {
        let blob = row?;
        let Ok(ParsedEvent::KeyShared(event)) = semantic_parsed_event(&blob) else {
            continue;
        };
        out.insert(key_shared_target(&event));
    }
    Ok(out)
}

fn apply_prepared_direction(direction: &PreparedPairSyncDirection) -> PairSyncResult<()> {
    if !direction.batch.is_empty() {
        let _ = ingest_now(&direction.dest_db_path, direction.batch.clone())?;
        const MAX_DRAIN_PASSES: usize = 64;
        for _ in 0..MAX_DRAIN_PASSES {
            let drained = crate::event_pipeline::drain_project_queue(
                &direction.dest_db_path,
                &direction.stats.dest_recorded_by,
                1000,
            );
            if drained == 0 {
                return Ok(());
            }
        }
        return Err(format!(
            "projection queue did not drain for simulated tenant `{}`",
            direction.stats.dest_recorded_by
        )
        .into());
    }
    Ok(())
}

fn stored_event_ids(conn: &rusqlite::Connection) -> Result<BTreeSet<String>, rusqlite::Error> {
    let mut stmt = conn.prepare("SELECT event_id FROM events")?;
    let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
    rows.collect::<Result<BTreeSet<_>, _>>()
}

fn source_transport_peer_id(
    conn: &rusqlite::Connection,
    recorded_by: &str,
) -> PairSyncResult<String> {
    if let Some(target) = resolve_tenant_transport_target(conn, recorded_by)? {
        return Ok(target.transport_peer_id);
    }
    if let Some(row) = crate::db::daemon_identity::load(conn)? {
        return Ok(row.peer_id);
    }
    Ok(recorded_by.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn imported(
        recorded_by: &str,
        daemon_peer_id: Option<&str>,
        connect_to: &[&str],
    ) -> SimPeerNode {
        SimPeerNode {
            db_path: format!("/tmp/{recorded_by}.db"),
            recorded_by: recorded_by.to_string(),
            daemon_peer_id: daemon_peer_id.map(ToString::to_string),
            local_transport_peer_id: Some(recorded_by.to_string()),
            connect_targets: connect_to
                .iter()
                .map(|peer_id| ImportedConnectTarget {
                    source: "bootstrap".into(),
                    transport_peer_id: (*peer_id).to_string(),
                    remote: "127.0.0.1:4242".into(),
                    invite_event_id: Some("invite".into()),
                })
                .collect(),
        }
    }

    #[test]
    fn planner_matches_connect_targets_against_multiple_peer_identity_keys() {
        let alice = imported("alice-tenant", Some("alice-daemon"), &[]);
        let bob = imported("bob-tenant", Some("bob-daemon"), &["alice-daemon"]);
        let carol = imported("carol-tenant", Some("carol-daemon"), &["bob-tenant"]);

        let intents = plan_pair_sync_intents(&[alice, bob, carol]);

        assert_eq!(intents.len(), 2);
        assert_eq!(intents[0].initiator_recorded_by, "bob-tenant");
        assert_eq!(intents[0].target_recorded_by, "alice-tenant");
        assert_eq!(intents[1].initiator_recorded_by, "carol-tenant");
        assert_eq!(intents[1].target_recorded_by, "bob-tenant");
    }
}
