#![allow(dead_code)]

use std::collections::VecDeque;
use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

const SOCKET_POLL_INTERVAL: Duration = Duration::from_millis(50);

#[derive(Clone, Copy, Debug)]
pub struct NetworkProfile {
    pub slug: &'static str,
    pub title: &'static str,
    pub note: &'static str,
    pub bandwidth_mbps_per_direction: f64,
    pub rtt_ms: u64,
    pub jitter_ms: u64,
    pub loss_percent: f64,
}

impl NetworkProfile {
    pub fn one_way_latency(&self) -> Duration {
        Duration::from_secs_f64(self.rtt_ms as f64 / 2_000.0)
    }

    pub fn jitter(&self) -> Duration {
        Duration::from_millis(self.jitter_ms)
    }
}

#[derive(Clone, Default)]
struct DirectionStats {
    inner: Arc<Mutex<DirectionStatsInner>>,
}

#[derive(Default)]
struct DirectionStatsInner {
    packets_sent: u64,
    bytes_sent: u64,
    packets_dropped: u64,
    bytes_dropped: u64,
    first_send_at: Option<Instant>,
    last_send_at: Option<Instant>,
}

struct DirectionStatsSnapshot {
    packets_sent: u64,
    bytes_sent: u64,
    packets_dropped: u64,
    bytes_dropped: u64,
    active_secs: f64,
}

impl DirectionStats {
    fn record_sent(&self, bytes: usize) {
        let now = Instant::now();
        let mut inner = self.inner.lock().expect("lock direction stats");
        inner.packets_sent = inner.packets_sent.saturating_add(1);
        inner.bytes_sent = inner.bytes_sent.saturating_add(bytes as u64);
        inner.first_send_at.get_or_insert(now);
        inner.last_send_at = Some(now);
    }

    fn record_drop(&self, bytes: usize) {
        let mut inner = self.inner.lock().expect("lock direction stats");
        inner.packets_dropped = inner.packets_dropped.saturating_add(1);
        inner.bytes_dropped = inner.bytes_dropped.saturating_add(bytes as u64);
    }

    fn snapshot(&self) -> DirectionStatsSnapshot {
        let inner = self.inner.lock().expect("lock direction stats");
        let active_secs = match (inner.first_send_at, inner.last_send_at) {
            (Some(first), Some(last)) if last > first => (last - first).as_secs_f64(),
            _ => 0.0,
        };
        DirectionStatsSnapshot {
            packets_sent: inner.packets_sent,
            bytes_sent: inner.bytes_sent,
            packets_dropped: inner.packets_dropped,
            bytes_dropped: inner.bytes_dropped,
            active_secs,
        }
    }
}

pub const REALISTIC_NETWORK_PROFILES: &[NetworkProfile] = &[
    NetworkProfile {
        slug: "wifi-max",
        title: "Wi-Fi Max",
        note: "Optimistic short-range Wi-Fi ceiling profile for local peer-to-peer sync on a strong link",
        bandwidth_mbps_per_direction: 150.0,
        rtt_ms: 8,
        jitter_ms: 1,
        loss_percent: 0.1,
    },
    NetworkProfile {
        slug: "bluetooth-max",
        title: "Bluetooth Max",
        note: "Optimistic Bluetooth Classic ceiling profile for nearby peers on a clean link",
        bandwidth_mbps_per_direction: 2.1,
        rtt_ms: 20,
        jitter_ms: 3,
        loss_percent: 0.2,
    },
    NetworkProfile {
        slug: "ble-max",
        title: "BLE Max",
        note: "Optimistic BLE 2M-style ceiling profile for metadata-heavy but low-throughput local sync",
        bandwidth_mbps_per_direction: 1.4,
        rtt_ms: 18,
        jitter_ms: 2,
        loss_percent: 0.1,
    },
    NetworkProfile {
        slug: "cable",
        title: "Cable",
        note: "Low-latency residential cable bottlenecked by practical peer-to-peer uplink",
        bandwidth_mbps_per_direction: 35.0,
        rtt_ms: 24,
        jitter_ms: 2,
        loss_percent: 0.2,
    },
    NetworkProfile {
        slug: "dsl",
        title: "DSL",
        note: "Older fixed-line access with modest throughput and higher base latency",
        bandwidth_mbps_per_direction: 3.0,
        rtt_ms: 44,
        jitter_ms: 4,
        loss_percent: 0.3,
    },
    NetworkProfile {
        slug: "mobile",
        title: "Mobile",
        note: "Typical good cellular path with higher jitter and mild loss",
        bandwidth_mbps_per_direction: 15.0,
        rtt_ms: 80,
        jitter_ms: 12,
        loss_percent: 0.8,
    },
    NetworkProfile {
        slug: "slow-mobile",
        title: "Slow Mobile",
        note: "Congested or edge-of-cell coverage with degraded throughput and stability",
        bandwidth_mbps_per_direction: 2.0,
        rtt_ms: 140,
        jitter_ms: 20,
        loss_percent: 1.5,
    },
    NetworkProfile {
        slug: "starlink",
        title: "Starlink",
        note: "Low-earth-orbit satellite path with moderate throughput and elevated jitter",
        bandwidth_mbps_per_direction: 15.0,
        rtt_ms: 70,
        jitter_ms: 15,
        loss_percent: 0.5,
    },
];

pub fn selected_profiles_from_env() -> Vec<NetworkProfile> {
    match std::env::var("PERF_REALISTIC_NETWORK_PROFILES") {
        Ok(raw) => raw
            .split(',')
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(|slug| {
                resolve_profile(*profile_by_slug(slug).unwrap_or_else(|| {
                    panic!(
                        "unknown PERF_REALISTIC_NETWORK_PROFILES entry `{slug}`; supported={}",
                        supported_profile_slugs()
                    )
                }))
            })
            .collect(),
        Err(_) => REALISTIC_NETWORK_PROFILES
            .iter()
            .copied()
            .map(resolve_profile)
            .collect(),
    }
}

pub fn repeat_count_from_env() -> usize {
    match std::env::var("PERF_REALISTIC_NETWORK_REPEATS") {
        Ok(raw) => {
            let repeats = raw
                .parse::<usize>()
                .unwrap_or_else(|_| panic!("invalid PERF_REALISTIC_NETWORK_REPEATS `{raw}`"));
            assert!(repeats >= 1, "PERF_REALISTIC_NETWORK_REPEATS must be >= 1");
            repeats
        }
        Err(_) => 1,
    }
}

pub fn clear_realistic_network_env() {
    for name in [
        "PERF_REALISTIC_NETWORK_PROFILES",
        "PERF_REALISTIC_NETWORK_REPEATS",
        "PERF_REALISTIC_NETWORK_BANDWIDTH_MBPS",
        "PERF_REALISTIC_NETWORK_RTT_MS",
        "PERF_REALISTIC_NETWORK_JITTER_MS",
        "PERF_REALISTIC_NETWORK_LOSS_PERCENT",
    ] {
        std::env::remove_var(name);
    }
}

fn profile_by_slug(slug: &str) -> Option<&'static NetworkProfile> {
    REALISTIC_NETWORK_PROFILES
        .iter()
        .find(|profile| profile.slug == slug)
}

fn supported_profile_slugs() -> String {
    REALISTIC_NETWORK_PROFILES
        .iter()
        .map(|profile| profile.slug)
        .collect::<Vec<_>>()
        .join(",")
}

fn resolve_profile(profile: NetworkProfile) -> NetworkProfile {
    NetworkProfile {
        bandwidth_mbps_per_direction: env_override_f64(
            "PERF_REALISTIC_NETWORK_BANDWIDTH_MBPS",
            profile.bandwidth_mbps_per_direction,
        ),
        rtt_ms: env_override_u64("PERF_REALISTIC_NETWORK_RTT_MS", profile.rtt_ms),
        jitter_ms: env_override_u64("PERF_REALISTIC_NETWORK_JITTER_MS", profile.jitter_ms),
        loss_percent: env_override_f64("PERF_REALISTIC_NETWORK_LOSS_PERCENT", profile.loss_percent),
        ..profile
    }
}

fn env_override_u64(name: &str, default: u64) -> u64 {
    match std::env::var(name) {
        Ok(raw) => raw
            .parse::<u64>()
            .unwrap_or_else(|_| panic!("invalid {name} `{raw}`")),
        Err(_) => default,
    }
}

fn env_override_f64(name: &str, default: f64) -> f64 {
    match std::env::var(name) {
        Ok(raw) => raw
            .parse::<f64>()
            .unwrap_or_else(|_| panic!("invalid {name} `{raw}`")),
        Err(_) => default,
    }
}

#[derive(Debug)]
struct QueuedPacket {
    dest: SocketAddr,
    payload: Vec<u8>,
}

pub struct UdpTrafficShaper {
    left_addr: SocketAddr,
    right_addr: SocketAddr,
    profile_state: Arc<Mutex<NetworkProfile>>,
    stop: Arc<AtomicBool>,
    left_to_right_stats: DirectionStats,
    right_to_left_stats: DirectionStats,
    handles: Vec<JoinHandle<()>>,
}

#[derive(Clone)]
pub struct UdpTrafficShaperControl {
    profile_state: Arc<Mutex<NetworkProfile>>,
}

impl UdpTrafficShaperControl {
    pub fn set_profile(&self, profile: NetworkProfile) {
        *self.profile_state.lock().expect("lock shaper profile") = profile;
    }
}

impl UdpTrafficShaper {
    pub fn new(
        left_real_addr: SocketAddr,
        right_real_addr: SocketAddr,
        profile: NetworkProfile,
    ) -> Self {
        let left_socket = UdpSocket::bind(("127.0.0.1", 0)).expect("bind left shaper socket");
        left_socket
            .set_read_timeout(Some(SOCKET_POLL_INTERVAL))
            .expect("set left shaper timeout");
        let right_socket = UdpSocket::bind(("127.0.0.1", 0)).expect("bind right shaper socket");
        right_socket
            .set_read_timeout(Some(SOCKET_POLL_INTERVAL))
            .expect("set right shaper timeout");

        let left_addr = left_socket.local_addr().expect("read left shaper addr");
        let right_addr = right_socket.local_addr().expect("read right shaper addr");

        let profile_state = Arc::new(Mutex::new(profile));
        let stop = Arc::new(AtomicBool::new(false));
        let left_to_right_stats = DirectionStats::default();
        let right_to_left_stats = DirectionStats::default();
        let (to_left_tx, to_left_rx) = mpsc::channel::<QueuedPacket>();
        let (to_right_tx, to_right_rx) = mpsc::channel::<QueuedPacket>();
        let mut handles = Vec::new();
        let left_send_socket = left_socket
            .try_clone()
            .expect("clone left shaper socket for send");
        let right_send_socket = right_socket
            .try_clone()
            .expect("clone right shaper socket for send");

        handles.push(spawn_receiver(
            left_socket,
            right_real_addr,
            left_real_addr,
            to_left_tx,
            Arc::clone(&stop),
        ));
        handles.push(spawn_receiver(
            right_socket,
            left_real_addr,
            right_real_addr,
            to_right_tx,
            Arc::clone(&stop),
        ));
        handles.push(spawn_sender(
            right_send_socket,
            to_left_rx,
            Arc::clone(&profile_state),
            Arc::clone(&stop),
            right_to_left_stats.clone(),
            0xC0A1E_u64,
        ));
        handles.push(spawn_sender(
            left_send_socket,
            to_right_rx,
            Arc::clone(&profile_state),
            Arc::clone(&stop),
            left_to_right_stats.clone(),
            0xB0B_u64,
        ));

        Self {
            left_addr,
            right_addr,
            profile_state,
            stop,
            left_to_right_stats,
            right_to_left_stats,
            handles,
        }
    }

    pub fn left_addr(&self) -> SocketAddr {
        self.left_addr
    }

    pub fn right_addr(&self) -> SocketAddr {
        self.right_addr
    }

    pub fn controller(&self) -> UdpTrafficShaperControl {
        UdpTrafficShaperControl {
            profile_state: Arc::clone(&self.profile_state),
        }
    }
}

impl Drop for UdpTrafficShaper {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        wake_socket(self.left_addr);
        wake_socket(self.right_addr);
        while let Some(handle) = self.handles.pop() {
            let _ = handle.join();
        }
        if shaper_stats_enabled() {
            let profile = *self.profile_state.lock().expect("lock shaper profile");
            log_direction_stats(
                profile.slug,
                "left->right",
                &self.left_to_right_stats.snapshot(),
            );
            log_direction_stats(
                profile.slug,
                "right->left",
                &self.right_to_left_stats.snapshot(),
            );
        }
    }
}

fn spawn_receiver(
    recv_socket: UdpSocket,
    expected_source: SocketAddr,
    dest: SocketAddr,
    queue_tx: mpsc::Sender<QueuedPacket>,
    stop: Arc<AtomicBool>,
) -> JoinHandle<()> {
    thread::spawn(move || {
        let mut buf = [0u8; 65_536];
        loop {
            match recv_socket.recv_from(&mut buf) {
                Ok((_, _)) if stop.load(Ordering::Relaxed) => break,
                Ok((len, source_addr)) => {
                    if source_addr != expected_source {
                        continue;
                    }
                    if queue_tx
                        .send(QueuedPacket {
                            dest,
                            payload: buf[..len].to_vec(),
                        })
                        .is_err()
                    {
                        break;
                    }
                }
                Err(err)
                    if err.kind() == std::io::ErrorKind::WouldBlock
                        || err.kind() == std::io::ErrorKind::TimedOut =>
                {
                    if stop.load(Ordering::Relaxed) {
                        break;
                    }
                }
                Err(_) if stop.load(Ordering::Relaxed) => break,
                Err(err) => panic!("UDP shaper recv failed: {err}"),
            }
        }
    })
}

/// Spawn a sender thread that models both bandwidth (serialization delay) and
/// latency (propagation delay) without confounding the two.
///
/// Previous implementation slept for serialization + propagation per packet,
/// which reset the bandwidth clock every iteration and limited throughput to
/// `packet_size / (serialization + propagation)` instead of the intended
/// `packet_size / serialization`. The fix uses a delay line: packets are
/// scheduled based on when the wire finishes serializing them, held in a
/// VecDeque until their arrival time, then delivered to the socket.
fn spawn_sender(
    send_socket: UdpSocket,
    queue_rx: mpsc::Receiver<QueuedPacket>,
    profile_state: Arc<Mutex<NetworkProfile>>,
    stop: Arc<AtomicBool>,
    stats: DirectionStats,
    seed: u64,
) -> JoinHandle<()> {
    thread::spawn(move || {
        let mut next_tx_finish = Instant::now();
        let mut last_arrival = Instant::now();
        let mut rng = StdRng::seed_from_u64(seed);
        let mut delay_line: VecDeque<(Instant, QueuedPacket)> = VecDeque::new();

        loop {
            // Deliver packets whose arrival time has passed.
            let now = Instant::now();
            while let Some((arrival, _)) = delay_line.front() {
                if now >= *arrival {
                    let (_, pkt) = delay_line.pop_front().unwrap();
                    if send_socket.send_to(&pkt.payload, pkt.dest).is_ok() {
                        stats.record_sent(pkt.payload.len());
                    }
                } else {
                    break;
                }
            }

            if stop.load(Ordering::Relaxed) {
                break;
            }

            // Wait for the next delay-line delivery or a new inbound packet.
            let recv_timeout = match delay_line.front() {
                Some((arrival, _)) => {
                    let remaining = arrival.saturating_duration_since(Instant::now());
                    if remaining.is_zero() {
                        Duration::from_micros(1)
                    } else {
                        remaining.min(SOCKET_POLL_INTERVAL)
                    }
                }
                None => SOCKET_POLL_INTERVAL,
            };

            match queue_rx.recv_timeout(recv_timeout) {
                Ok(packet) => {
                    let profile = *profile_state.lock().expect("lock shaper profile");
                    if should_drop(&mut rng, profile.loss_percent) {
                        stats.record_drop(packet.payload.len());
                        continue;
                    }
                    let now = Instant::now();
                    let start_tx = next_tx_finish.max(now);
                    let serialization = serialization_delay(&profile, packet.payload.len());
                    next_tx_finish = start_tx + serialization;
                    // Arrival = when this packet reaches the destination.
                    // .max(last_arrival) preserves in-order delivery.
                    let arrival =
                        (next_tx_finish + propagation_delay(&mut rng, &profile)).max(last_arrival);
                    last_arrival = arrival;
                    delay_line.push_back((arrival, packet));
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
            }
        }
    })
}

fn should_drop(rng: &mut StdRng, loss_percent: f64) -> bool {
    loss_percent > 0.0 && rng.gen_bool((loss_percent / 100.0).clamp(0.0, 1.0))
}

fn serialization_delay(profile: &NetworkProfile, bytes: usize) -> Duration {
    let bytes_per_second = (profile.bandwidth_mbps_per_direction * 1_000_000.0) / 8.0;
    Duration::from_secs_f64((bytes as f64) / bytes_per_second.max(1.0))
}

fn propagation_delay(rng: &mut StdRng, profile: &NetworkProfile) -> Duration {
    let base_ms = profile.one_way_latency().as_secs_f64() * 1_000.0;
    let jitter_ms = profile.jitter().as_secs_f64() * 1_000.0;
    let offset_ms = if jitter_ms > 0.0 {
        rng.gen_range(-jitter_ms..=jitter_ms)
    } else {
        0.0
    };
    Duration::from_secs_f64(((base_ms + offset_ms).max(0.0)) / 1_000.0)
}

fn wake_socket(addr: SocketAddr) {
    if let Ok(socket) = UdpSocket::bind(("127.0.0.1", 0)) {
        let _ = socket.send_to(&[0u8], addr);
    }
}

fn shaper_stats_enabled() -> bool {
    std::env::var("PERF_REALISTIC_NETWORK_SHAPER_STATS")
        .map(|value| value != "0" && value.to_lowercase() != "false")
        .unwrap_or(false)
}

fn log_direction_stats(profile_slug: &str, direction: &str, stats: &DirectionStatsSnapshot) {
    let mib_sent = stats.bytes_sent as f64 / (1024.0 * 1024.0);
    let effective_mbps = if stats.active_secs > 0.0 {
        (stats.bytes_sent as f64 * 8.0) / stats.active_secs / 1_000_000.0
    } else {
        0.0
    };
    eprintln!(
        "[shaper-stats] profile={} direction={} packets_sent={} bytes_sent={} ({:.2} MiB) packets_dropped={} bytes_dropped={} active_secs={:.3} effective_mbps={:.2}",
        profile_slug,
        direction,
        stats.packets_sent,
        stats.bytes_sent,
        mib_sent,
        stats.packets_dropped,
        stats.bytes_dropped,
        stats.active_secs,
        effective_mbps,
    );
}
