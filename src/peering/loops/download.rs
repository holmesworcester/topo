//! Download loop: fetch events from multiple sources concurrently using
//! coordinated round-based assignment.

use std::net::SocketAddr;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;

use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::contracts::event_pipeline_contract::{BatchWriterFn, IngestItem};
use crate::contracts::peering_contract::{
    PeerFingerprint, SessionDirection, SessionHandler, SessionMeta, TenantId,
};
use crate::crypto::EventId;
use crate::db::open_connection;
use crate::db::schema::create_tables;
use crate::db::store::lookup_workspace_id;
use crate::sync::session::run_coordinator;
use crate::sync::PeerCoord;
use crate::sync::SyncSessionHandler;
use crate::transport::{dial_session_peer, open_outbound_session, TransportEndpoint};

use super::{
    peer_fingerprint_from_hex, shared_ingest_cap, CONNECT_RETRY_DELAY, SESSION_GAP,
    SYNC_SESSION_TIMEOUT_SECS,
};

// ---------------------------------------------------------------------------
// Download from multiple sources
// ---------------------------------------------------------------------------

/// Download from multiple sources concurrently (sink as initiator).
///
/// Uses coordinated round-based assignment: each sync round, peers report
/// their discovered need_ids to a coordinator thread, which assigns events
/// to peers using greedy load balancing (least-loaded peer that has the event).
/// Undelivered events re-appear as need_ids in the next round and get
/// reassigned -- slow peers don't block downloads permanently.
///
/// A shared batch_writer handles all incoming events from all sources.
pub async fn download_from_sources(
    db_path: &str,
    recorded_by: &str,
    endpoints: Vec<(TransportEndpoint, SocketAddr)>,
    batch_writer_fn: BatchWriterFn,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    {
        let db = open_connection(db_path)?;
        create_tables(&db)?;
    }

    let total = endpoints.len();

    // Shared batch_writer: single writer for all source connections
    let ingest_cap = shared_ingest_cap();
    let (shared_tx, shared_rx) = mpsc::channel::<IngestItem>(ingest_cap);
    let shared_events = Arc::new(AtomicU64::new(0));
    let writer_events = shared_events.clone();
    let writer_db_path = db_path.to_string();
    let bw = batch_writer_fn;
    let _writer_handle = std::thread::spawn(move || {
        bw(writer_db_path, shared_rx, writer_events);
    });

    // Create per-peer coordination channels
    let mut peer_coords = Vec::new();
    let mut report_rxs = Vec::new();
    let mut assign_txs = Vec::new();

    for i in 0..total {
        let (report_tx, report_rx) = std::sync::mpsc::channel::<Vec<EventId>>();
        let (assign_tx, assign_rx) = std::sync::mpsc::channel::<Vec<EventId>>();
        peer_coords.push(PeerCoord {
            peer_idx: i,
            report_tx,
            assign_rx: std::sync::Mutex::new(assign_rx),
        });
        report_rxs.push(report_rx);
        assign_txs.push(assign_tx);
    }

    // Spawn coordinator thread
    let _coord_handle = std::thread::spawn(move || {
        run_coordinator(report_rxs, assign_txs);
    });

    let mut handles = Vec::new();

    // Look up workspace SNI once for all peers
    let download_sni = {
        let db = open_connection(db_path)?;
        let ws_id = lookup_workspace_id(&db, recorded_by);
        if ws_id.is_empty() {
            "localhost".to_string()
        } else {
            crate::transport::multi_workspace::workspace_sni(&ws_id)
        }
    };

    for (peer_coord, (endpoint, remote)) in peer_coords.into_iter().zip(endpoints.into_iter()) {
        let peer_coord: Arc<PeerCoord> = std::sync::Arc::new(peer_coord);
        let db_path = db_path.to_string();
        let recorded_by = recorded_by.to_string();
        let ingest_tx = shared_tx.clone();
        let sni = download_sni.clone();
        let handler = SyncSessionHandler::initiator_with_coordination(
            db_path.clone(),
            SYNC_SESSION_TIMEOUT_SECS,
            peer_coord.clone(),
            ingest_tx.clone(),
        );

        handles.push(std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async move {
                loop {
                    let connected = match dial_session_peer(&endpoint, remote, &sni, None).await {
                        Ok(c) => c,
                        Err(e) => {
                            warn!("Failed to connect to {}: {}", remote, e);
                            tokio::time::sleep(CONNECT_RETRY_DELAY).await;
                            continue;
                        }
                    };
                    let connection = connected.connection;
                    let peer_id = connected.peer_id;
                    let peer_fp = match peer_fingerprint_from_hex(&peer_id) {
                        Some(fp) => fp,
                        None => {
                            warn!(
                                "Invalid peer fingerprint {}, retrying",
                                &peer_id[..16.min(peer_id.len())]
                            );
                            tokio::time::sleep(CONNECT_RETRY_DELAY).await;
                            continue;
                        }
                    };
                    info!("Connected to {} for download", peer_id);

                    // Inner loop: repeated sync sessions
                    loop {
                        let (session_id, io) = match open_outbound_session(&connection).await {
                            Ok(r) => r,
                            Err(e) => {
                                info!("Connection dropped: {}", e);
                                break;
                            }
                        };

                        let meta = SessionMeta {
                            session_id,
                            tenant: TenantId(recorded_by.clone()),
                            peer: PeerFingerprint(peer_fp),
                            remote_addr: connection.remote_address(),
                            direction: SessionDirection::Outbound,
                        };

                        if let Err(e) = handler.on_session(meta, io, CancellationToken::new()).await
                        {
                            warn!("Download session error: {}", e);
                        }

                        tokio::time::sleep(SESSION_GAP).await;
                    }
                }
            });
        }));
    }

    // Drop our copy so writer exits when all sessions drop theirs
    drop(shared_tx);

    for handle in handles {
        let _ = handle.join();
    }
    Ok(())
}
