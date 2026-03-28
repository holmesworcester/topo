use serde::Serialize;

use super::topology::Topology;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
pub struct PeerId(pub u32);

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub enum ActivityProfile {
    AlwaysOnline,
    Intermittent {
        online_for_ms: u64,
        offline_for_ms: u64,
        phase_ms: u64,
    },
    Offline,
}

impl ActivityProfile {
    pub fn is_online_at(&self, at_ms: u64) -> bool {
        match self {
            Self::AlwaysOnline => true,
            Self::Offline => false,
            Self::Intermittent {
                online_for_ms,
                offline_for_ms,
                phase_ms,
            } => {
                let cycle = online_for_ms.saturating_add(*offline_for_ms);
                if cycle == 0 {
                    return true;
                }
                let offset = at_ms.saturating_add(*phase_ms) % cycle;
                offset < *online_for_ms
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub enum MessageAuthoring {
    Fixed { peer_id: PeerId },
    RoundRobin,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PeerSpec {
    pub id: PeerId,
    pub activity: ActivityProfile,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SyncPolicy {
    pub interval_ms: u64,
    pub link_rtt_ms: u64,
    pub bandwidth_bytes_per_ms: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub enum IngestPolicy {
    EagerAll,
    HotMessageWindow { recent_message_count: u32 },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Scenario {
    pub peers: Vec<PeerSpec>,
    pub topology: Topology,
    pub message_count: u32,
    pub message_interval_ms: u64,
    pub message_bytes: u32,
    pub key_need_bytes: u32,
    pub key_repair_bytes: u32,
    pub repair_ttl_ms: u64,
    pub ingest: IngestPolicy,
    pub sync_rounds: u32,
    pub authoring: MessageAuthoring,
    pub sync: SyncPolicy,
}

impl Scenario {
    pub fn tiny_demo(topology: Topology) -> Self {
        let peers = vec![
            PeerSpec {
                id: PeerId(0),
                activity: ActivityProfile::AlwaysOnline,
            },
            PeerSpec {
                id: PeerId(1),
                activity: ActivityProfile::AlwaysOnline,
            },
            PeerSpec {
                id: PeerId(2),
                activity: ActivityProfile::Intermittent {
                    online_for_ms: 10,
                    offline_for_ms: 10,
                    phase_ms: 0,
                },
            },
            PeerSpec {
                id: PeerId(3),
                activity: ActivityProfile::Offline,
            },
        ];

        Self {
            peers,
            topology,
            message_count: 8,
            message_interval_ms: 5,
            message_bytes: 512,
            key_need_bytes: 160,
            key_repair_bytes: 170,
            repair_ttl_ms: 50,
            ingest: IngestPolicy::EagerAll,
            sync_rounds: 4,
            authoring: MessageAuthoring::Fixed { peer_id: PeerId(0) },
            sync: SyncPolicy {
                interval_ms: 10,
                link_rtt_ms: 2,
                bandwidth_bytes_per_ms: 64,
            },
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.peers.is_empty() {
            return Err("scenario must include at least one peer".into());
        }
        if self.message_count == 0 {
            return Err("scenario must include at least one message".into());
        }
        if self.sync.interval_ms == 0 {
            return Err("sync interval must be non-zero".into());
        }
        if self.sync.bandwidth_bytes_per_ms == 0 {
            return Err("bandwidth_bytes_per_ms must be non-zero".into());
        }
        Ok(())
    }

    pub fn horizon_ms(&self) -> u64 {
        self.message_interval_ms
            .saturating_mul(self.message_count as u64)
            .saturating_add(self.repair_ttl_ms)
            .saturating_add(
                self.sync
                    .interval_ms
                    .saturating_mul(self.sync_rounds as u64 + 1),
            )
    }

    pub fn author_for(&self, message_id: u32) -> PeerId {
        match self.authoring {
            MessageAuthoring::Fixed { peer_id } => peer_id,
            MessageAuthoring::RoundRobin => {
                let idx = (message_id as usize) % self.peers.len();
                self.peers[idx].id
            }
        }
    }
}
