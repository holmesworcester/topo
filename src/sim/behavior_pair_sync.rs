use std::collections::{BTreeSet, HashMap};

use serde::Serialize;

use crate::event_modules::{self as events, ParsedEvent};
use crate::sim::key_repair::{key_request_target, key_shared_target, response_rank, RepairTarget};

use super::node_behavior::{EventProjectionFilter, NodeBehaviorEngine};
use super::pair_sync::{PairSyncDirectionStats, PairSyncSessionStats};
use super::query_snapshot::{ImportedConnectTarget, ImportedPeerState};
use super::sqlite_behavior_summary;

type BehaviorPairSyncResult<T> = Result<T, Box<dyn std::error::Error>>;

#[derive(Clone, Debug)]
struct TransferableSharedEvent {
    event_id: String,
    created_at_ms: i64,
    blob: Vec<u8>,
}

pub struct BehaviorSimPeerNode {
    pub db_path: String,
    pub recorded_by: String,
    pub daemon_peer_id: Option<String>,
    pub local_transport_peer_id: Option<String>,
    pub connect_targets: Vec<ImportedConnectTarget>,
    pub behavior: NodeBehaviorEngine,
}

impl BehaviorSimPeerNode {
    pub fn from_imported(
        imported: &ImportedPeerState,
        filter: EventProjectionFilter,
    ) -> BehaviorPairSyncResult<Self> {
        let summary = sqlite_behavior_summary(&imported.db_path, &imported.recorded_by)?;
        Ok(Self {
            db_path: imported.db_path.clone(),
            recorded_by: imported.recorded_by.clone(),
            daemon_peer_id: imported.daemon_peer_id.clone(),
            local_transport_peer_id: imported.local_transport_peer_id.clone(),
            connect_targets: imported.connect_targets.clone(),
            behavior: NodeBehaviorEngine::seed_imported(imported, filter, &summary)?,
        })
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
pub struct BehaviorPairSyncIntent {
    pub initiator_recorded_by: String,
    pub target_recorded_by: String,
    pub target_transport_peer_id: String,
    pub source: String,
    pub invite_event_id: Option<String>,
}

#[derive(Clone, Debug)]
struct PreparedBehaviorDirection {
    stats: PairSyncDirectionStats,
    source_tag: String,
    blobs: Vec<Vec<u8>>,
}

#[derive(Clone, Debug)]
struct PreparedBehaviorSession {
    left_to_right: PreparedBehaviorDirection,
    right_to_left: PreparedBehaviorDirection,
}

pub fn plan_behavior_pair_sync_intents(
    peers: &[BehaviorSimPeerNode],
) -> Vec<BehaviorPairSyncIntent> {
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
                if initiator.recorded_by == target_peer.recorded_by {
                    continue;
                }
                let key = (
                    initiator.recorded_by.clone(),
                    target_peer.recorded_by.clone(),
                    target.transport_peer_id.clone(),
                    target.source.clone(),
                    target.invite_event_id.clone(),
                );
                if !seen.insert(key) {
                    continue;
                }
                intents.push(BehaviorPairSyncIntent {
                    initiator_recorded_by: initiator.recorded_by.clone(),
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

pub fn run_behavior_pair_sync_session(
    left: &BehaviorSimPeerNode,
    right: &BehaviorSimPeerNode,
) -> BehaviorPairSyncResult<PairSyncSessionStats> {
    let prepared = PreparedBehaviorSession {
        left_to_right: collect_behavior_shared_events_one_way(left, right)?,
        right_to_left: collect_behavior_shared_events_one_way(right, left)?,
    };
    apply_prepared_behavior_direction(right, &prepared.left_to_right)?;
    apply_prepared_behavior_direction(left, &prepared.right_to_left)?;
    Ok(PairSyncSessionStats {
        left_to_right: prepared.left_to_right.stats,
        right_to_left: prepared.right_to_left.stats,
    })
}

fn collect_behavior_shared_events_one_way(
    source: &BehaviorSimPeerNode,
    dest: &BehaviorSimPeerNode,
) -> BehaviorPairSyncResult<PreparedBehaviorDirection> {
    let known_dest_events = dest.behavior.recorded_event_ids();
    let shared_events = source.behavior.shared_recorded_events()?;
    let winning_key_shared_events = winning_key_shared_event_ids(&source.behavior)?;
    let observed_key_shared_targets = observed_key_shared_targets(&source.behavior)?;
    let source_tag = format!("quic_recv:{}@sim", source.behavior.transport_peer_id());

    let mut primary_events = Vec::<TransferableSharedEvent>::new();
    let mut transferred_key_request_events = 0usize;
    let mut suppressed_key_request_events = 0usize;
    let mut transferred_key_shared_events = 0usize;
    let mut suppressed_key_shared_events = 0usize;

    for (event_id, event_type, _created_at_ms, blob) in shared_events {
        if known_dest_events.contains(&event_id) {
            continue;
        }
        if event_type == "key_request" {
            let Ok(ParsedEvent::KeyRequest(event)) = events::parse_event(&blob) else {
                continue;
            };
            if observed_key_shared_targets.contains(&key_request_target(&event)) {
                suppressed_key_request_events = suppressed_key_request_events.saturating_add(1);
                continue;
            }
            transferred_key_request_events = transferred_key_request_events.saturating_add(1);
        } else if event_type == "key_shared" {
            if !winning_key_shared_events.contains(&event_id) {
                suppressed_key_shared_events = suppressed_key_shared_events.saturating_add(1);
                continue;
            }
            transferred_key_shared_events = transferred_key_shared_events.saturating_add(1);
        }
        primary_events.push(TransferableSharedEvent {
            event_id,
            created_at_ms: events::extract_created_at_ms(&blob).unwrap_or(0) as i64,
            blob,
        });
    }

    let transferable_events =
        expand_transferable_shared_closure(source, &known_dest_events, primary_events)?;
    let transferred_event_ids = transferable_events
        .iter()
        .map(|event| event.event_id.clone())
        .collect::<Vec<_>>();
    let transferred_bytes = transferable_events
        .iter()
        .map(|event| event.blob.len() as u64)
        .sum::<u64>();
    let blobs = transferable_events
        .into_iter()
        .map(|event| event.blob)
        .collect::<Vec<_>>();

    Ok(PreparedBehaviorDirection {
        stats: PairSyncDirectionStats {
            source_db_path: source.db_path.clone(),
            source_recorded_by: source.recorded_by.clone(),
            dest_db_path: dest.db_path.clone(),
            dest_recorded_by: dest.recorded_by.clone(),
            transferred_events: transferred_event_ids.len(),
            transferred_bytes,
            transferred_key_request_events,
            suppressed_key_request_events,
            transferred_key_shared_events,
            suppressed_key_shared_events,
            transferred_event_ids,
        },
        source_tag,
        blobs,
    })
}

fn expand_transferable_shared_closure(
    source: &BehaviorSimPeerNode,
    known_dest_events: &BTreeSet<String>,
    primary_events: Vec<TransferableSharedEvent>,
) -> BehaviorPairSyncResult<Vec<TransferableSharedEvent>> {
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
            let Some(dep_event) = source.behavior.transferable_shared_event(&dep_id_b64)? else {
                continue;
            };
            pending.push(TransferableSharedEvent {
                event_id: dep_event.0,
                created_at_ms: dep_event.2,
                blob: dep_event.3,
            });
        }
        out.push(event);
    }

    out.sort_by(|left, right| {
        (left.created_at_ms, &left.event_id).cmp(&(right.created_at_ms, &right.event_id))
    });
    Ok(out)
}

fn semantic_parsed_event(blob: &[u8]) -> Result<ParsedEvent, Box<dyn std::error::Error>> {
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

fn apply_prepared_behavior_direction(
    dest: &BehaviorSimPeerNode,
    direction: &PreparedBehaviorDirection,
) -> BehaviorPairSyncResult<()> {
    if !direction.blobs.is_empty() {
        let _ = dest
            .behavior
            .apply_transferred_batch(&direction.source_tag, direction.blobs.clone())?;
    }
    Ok(())
}

fn winning_key_shared_event_ids(
    behavior: &NodeBehaviorEngine,
) -> BehaviorPairSyncResult<BTreeSet<String>> {
    let mut best_by_target = HashMap::<RepairTarget, ([u8; 32], [u8; 32], String)>::new();
    for (event_id, _event_type, _created_at_ms, blob) in behavior.shared_recorded_events()? {
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
    behavior: &NodeBehaviorEngine,
) -> BehaviorPairSyncResult<BTreeSet<RepairTarget>> {
    let mut out = BTreeSet::new();
    for (_event_id, _event_type, _created_at_ms, blob) in behavior.shared_recorded_events()? {
        let Ok(ParsedEvent::KeyShared(event)) = semantic_parsed_event(&blob) else {
            continue;
        };
        out.insert(key_shared_target(&event));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event_modules::workspace::commands::CreateInviteResponse;
    use crate::rpc::protocol::RpcMethod;
    use crate::sim::{
        import_peer_state, run_pair_sync_session, sqlite_behavior_summary, VirtualDaemon,
    };

    fn active_peer_id(daemon: &VirtualDaemon) -> String {
        daemon
            .call_ok_value(RpcMethod::ActiveTenant)
            .expect("active tenant")["peer_id"]
            .as_str()
            .expect("peer id")
            .to_string()
    }

    fn subset_summary(
        summary: &crate::sim::NodeBehaviorSummary,
        tables: &[&str],
    ) -> crate::sim::NodeBehaviorSummary {
        let wanted = tables
            .iter()
            .map(|table| (*table).to_string())
            .collect::<BTreeSet<_>>();
        crate::sim::NodeBehaviorSummary {
            recorded_by: summary.recorded_by.clone(),
            tables: summary
                .tables
                .iter()
                .filter(|(table, _)| wanted.contains(*table))
                .map(|(table, rows)| (table.clone(), rows.clone()))
                .collect(),
        }
    }

    fn summary_delta(
        before: &crate::sim::NodeBehaviorSummary,
        after: &crate::sim::NodeBehaviorSummary,
        tables: &[&str],
    ) -> crate::sim::NodeBehaviorSummary {
        let before_subset = subset_summary(before, tables);
        let after_subset = subset_summary(after, tables);
        let mut out = std::collections::BTreeMap::new();
        for (table, after_rows) in &after_subset.tables {
            let before_rows = before_subset.tables.get(table).cloned().unwrap_or_default();
            let before_set = before_rows.into_iter().collect::<BTreeSet<_>>();
            let delta_rows = after_rows
                .iter()
                .filter(|row| !before_set.contains(*row))
                .cloned()
                .collect::<Vec<_>>();
            if !delta_rows.is_empty() {
                out.insert(table.clone(), delta_rows);
            }
        }
        crate::sim::NodeBehaviorSummary {
            recorded_by: after.recorded_by.clone(),
            tables: out,
        }
    }

    #[test]
    fn behavior_pair_sync_matches_sqlite_pair_sync_for_invite_and_rotation() {
        let tmpdir = tempfile::tempdir().expect("tempdir");
        let creator = VirtualDaemon::new(tmpdir.path().join("creator.db").to_str().unwrap());
        let joiner = VirtualDaemon::new(tmpdir.path().join("joiner.db").to_str().unwrap());

        creator
            .call_ok_value(RpcMethod::CreateWorkspace {
                workspace_name: "sim".into(),
                username: "alice".into(),
                device_name: "laptop".into(),
            })
            .expect("create workspace");
        creator
            .call_ok_value(RpcMethod::RotateKey)
            .expect("rotate key");
        let invite: CreateInviteResponse = creator
            .call_ok(RpcMethod::CreateInvite {
                public_addr: Some("127.0.0.1:9001".into()),
                public_spki: None,
            })
            .expect("create invite");
        joiner
            .call_ok_value(RpcMethod::AcceptInvite {
                invite: invite.invite_link,
                username: "bob".into(),
                devicename: "phone".into(),
            })
            .expect("accept invite");

        let creator_peer = active_peer_id(&creator);
        let joiner_peer = active_peer_id(&joiner);
        run_pair_sync_session(
            creator.db_path(),
            &creator_peer,
            joiner.db_path(),
            &joiner_peer,
        )
        .expect("bootstrap sqlite sync");
        creator
            .call_ok_value(RpcMethod::RotateKey)
            .expect("second rotate key");

        let creator_import =
            import_peer_state(creator.db_path(), &creator_peer).expect("import creator");
        let joiner_import =
            import_peer_state(joiner.db_path(), &joiner_peer).expect("import joiner");
        let creator_behavior =
            BehaviorSimPeerNode::from_imported(&creator_import, EventProjectionFilter::default())
                .expect("creator behavior");
        let joiner_behavior =
            BehaviorSimPeerNode::from_imported(&joiner_import, EventProjectionFilter::default())
                .expect("joiner behavior");
        let sqlite_before =
            sqlite_behavior_summary(joiner.db_path(), &joiner_peer).expect("sqlite joiner before");
        let behavior_before = joiner_behavior.behavior.summary();

        let sqlite_stats = run_pair_sync_session(
            creator.db_path(),
            &creator_peer,
            joiner.db_path(),
            &joiner_peer,
        )
        .expect("sqlite pair sync");
        let behavior_stats = run_behavior_pair_sync_session(&creator_behavior, &joiner_behavior)
            .expect("memory pair sync");

        assert_eq!(
            behavior_stats.left_to_right.transferred_event_ids,
            sqlite_stats.left_to_right.transferred_event_ids
        );
        assert_eq!(
            behavior_stats.right_to_left.transferred_event_ids,
            sqlite_stats.right_to_left.transferred_event_ids
        );

        let modeled_tables = ["key_rotations", "key_shared", "key_secrets", "valid_events"];
        let expected_joiner =
            sqlite_behavior_summary(joiner.db_path(), &joiner_peer).expect("sqlite joiner");
        assert_eq!(
            summary_delta(
                &behavior_before,
                &joiner_behavior.behavior.summary(),
                &modeled_tables
            ),
            summary_delta(&sqlite_before, &expected_joiner, &modeled_tables),
            "behavior_stats={:?} sqlite_stats={:?} behavior_after={:?} sqlite_after={:?}",
            behavior_stats,
            sqlite_stats,
            joiner_behavior.behavior.summary(),
            expected_joiner,
        );
    }

    #[test]
    fn behavior_pair_sync_matches_sqlite_pair_sync_for_message_flow() {
        let tmpdir = tempfile::tempdir().expect("tempdir");
        let creator = VirtualDaemon::new(tmpdir.path().join("creator.db").to_str().unwrap());
        let joiner = VirtualDaemon::new(tmpdir.path().join("joiner.db").to_str().unwrap());

        creator
            .call_ok_value(RpcMethod::CreateWorkspace {
                workspace_name: "sim".into(),
                username: "alice".into(),
                device_name: "laptop".into(),
            })
            .expect("create workspace");
        let invite: CreateInviteResponse = creator
            .call_ok(RpcMethod::CreateInvite {
                public_addr: Some("127.0.0.1:9002".into()),
                public_spki: None,
            })
            .expect("create invite");
        joiner
            .call_ok_value(RpcMethod::AcceptInvite {
                invite: invite.invite_link,
                username: "bob".into(),
                devicename: "phone".into(),
            })
            .expect("accept invite");

        let creator_peer = active_peer_id(&creator);
        let joiner_peer = active_peer_id(&joiner);
        run_pair_sync_session(
            creator.db_path(),
            &creator_peer,
            joiner.db_path(),
            &joiner_peer,
        )
        .expect("bootstrap sqlite sync");
        creator
            .call_ok_value(RpcMethod::RotateKey)
            .expect("rotate key before message");
        run_pair_sync_session(
            creator.db_path(),
            &creator_peer,
            joiner.db_path(),
            &joiner_peer,
        )
        .expect("rotation sqlite sync");

        creator
            .call_ok_value(RpcMethod::Send {
                content: "hello from behavior sync".into(),
                client_op_id: None,
            })
            .expect("send message");

        let creator_import =
            import_peer_state(creator.db_path(), &creator_peer).expect("import creator");
        let joiner_import =
            import_peer_state(joiner.db_path(), &joiner_peer).expect("import joiner");
        let creator_behavior =
            BehaviorSimPeerNode::from_imported(&creator_import, EventProjectionFilter::default())
                .expect("creator behavior");
        let joiner_behavior =
            BehaviorSimPeerNode::from_imported(&joiner_import, EventProjectionFilter::default())
                .expect("joiner behavior");
        let sqlite_before =
            sqlite_behavior_summary(joiner.db_path(), &joiner_peer).expect("sqlite joiner before");
        let behavior_before = joiner_behavior.behavior.summary();

        let sqlite_stats = run_pair_sync_session(
            creator.db_path(),
            &creator_peer,
            joiner.db_path(),
            &joiner_peer,
        )
        .expect("sqlite pair sync");
        let behavior_stats = run_behavior_pair_sync_session(&creator_behavior, &joiner_behavior)
            .expect("memory pair sync");

        assert_eq!(
            behavior_stats.left_to_right.transferred_event_ids,
            sqlite_stats.left_to_right.transferred_event_ids
        );
        assert_eq!(
            behavior_stats.right_to_left.transferred_event_ids,
            sqlite_stats.right_to_left.transferred_event_ids
        );

        let modeled_tables = ["key_secrets", "messages", "valid_events"];
        let expected_joiner =
            sqlite_behavior_summary(joiner.db_path(), &joiner_peer).expect("sqlite joiner");
        assert_eq!(
            summary_delta(
                &behavior_before,
                &joiner_behavior.behavior.summary(),
                &modeled_tables
            ),
            summary_delta(&sqlite_before, &expected_joiner, &modeled_tables),
            "behavior_stats={:?} sqlite_stats={:?} behavior_after={:?} sqlite_after={:?}",
            behavior_stats,
            sqlite_stats,
            joiner_behavior.behavior.summary(),
            expected_joiner,
        );
    }
}
