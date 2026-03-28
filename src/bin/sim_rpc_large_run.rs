use std::time::Instant;

use serde::Serialize;
use tempfile::tempdir;
use topo::rpc::protocol::RpcMethod;
use topo::sim::{
    ActivityProfile, IngestPolicy, MessageAuthoring, PeerId, PeerSpec, Scenario, Simulation,
    SyncPolicy, Topology, VirtualDaemon,
};

#[derive(Debug, Clone, Copy)]
enum TopologyArg {
    Star,
    Graph,
}

impl TopologyArg {
    fn parse(s: &str) -> Result<Self, String> {
        match s {
            "star" => Ok(Self::Star),
            "graph" => Ok(Self::Graph),
            other => Err(format!(
                "unsupported topology `{other}`; use `star` or `graph`"
            )),
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct RunConfig {
    users: u32,
    messages: usize,
    topology: TopologyArg,
    graph_degree: usize,
    sync_rounds: u32,
}

impl Default for RunConfig {
    fn default() -> Self {
        Self {
            users: 100_000,
            messages: 100_000,
            topology: TopologyArg::Star,
            graph_degree: 2,
            sync_rounds: 1,
        }
    }
}

#[derive(Debug, Serialize)]
struct RunReport {
    config: ReportConfig,
    daemon: serde_json::Value,
    simulation: topo::sim::SimulationSummary,
    timings: serde_json::Value,
}

#[derive(Debug, Serialize)]
struct ReportConfig {
    users: u32,
    messages_requested: usize,
    topology: &'static str,
    graph_degree: usize,
    sync_rounds: u32,
}

fn parse_config() -> Result<RunConfig, String> {
    let mut config = RunConfig::default();
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--users" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--users requires a value".to_string())?;
                config.users = value
                    .parse::<u32>()
                    .map_err(|err| format!("parse --users: {err}"))?;
            }
            "--messages" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--messages requires a value".to_string())?;
                config.messages = value
                    .parse::<usize>()
                    .map_err(|err| format!("parse --messages: {err}"))?;
            }
            "--topology" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--topology requires a value".to_string())?;
                config.topology = TopologyArg::parse(&value)?;
            }
            "--graph-degree" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--graph-degree requires a value".to_string())?;
                config.graph_degree = value
                    .parse::<usize>()
                    .map_err(|err| format!("parse --graph-degree: {err}"))?;
            }
            "--sync-rounds" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--sync-rounds requires a value".to_string())?;
                config.sync_rounds = value
                    .parse::<u32>()
                    .map_err(|err| format!("parse --sync-rounds: {err}"))?;
            }
            other => return Err(format!("unknown arg `{other}`")),
        }
    }
    Ok(config)
}

fn build_scenario(config: RunConfig, message_count: u32) -> Scenario {
    let peers = (0..config.users)
        .map(|peer| PeerSpec {
            id: PeerId(peer),
            activity: ActivityProfile::AlwaysOnline,
        })
        .collect();

    let topology = match config.topology {
        TopologyArg::Star => Topology::Star { hub: PeerId(0) },
        TopologyArg::Graph => Topology::Graph {
            degree: config.graph_degree,
        },
    };

    Scenario {
        peers,
        topology,
        message_count,
        message_interval_ms: 0,
        message_bytes: 512,
        key_need_bytes: 160,
        key_repair_bytes: 170,
        repair_ttl_ms: 60_000,
        ingest: IngestPolicy::EagerAll,
        sync_rounds: config.sync_rounds,
        authoring: MessageAuthoring::Fixed { peer_id: PeerId(0) },
        sync: SyncPolicy {
            interval_ms: 1,
            link_rtt_ms: 2,
            bandwidth_bytes_per_ms: 64_000,
        },
    }
}

fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let config = parse_config()?;

    let total_started = Instant::now();
    let tmpdir = tempdir()?;
    let db_path = tmpdir.path().join("sim-rpc-large-run.db");
    let daemon = VirtualDaemon::new(db_path.to_str().ok_or("db path utf8")?);
    let setup_ms = total_started.elapsed().as_millis();

    let create_started = Instant::now();
    let create_workspace = daemon.call(RpcMethod::CreateWorkspace {
        workspace_name: "sim-large".to_string(),
        username: "alice".to_string(),
        device_name: "sim-daemon".to_string(),
    });
    let create_workspace_ms = create_started.elapsed().as_millis();
    if !create_workspace.ok {
        return Err(format!(
            "CreateWorkspace failed: {}",
            create_workspace
                .error
                .unwrap_or_else(|| "unknown error".to_string())
        )
        .into());
    }

    let generate_started = Instant::now();
    let generate = daemon.call(RpcMethod::Generate {
        count: config.messages,
        history_span: Some("365d".to_string()),
    });
    let generate_ms = generate_started.elapsed().as_millis();
    if !generate.ok {
        return Err(format!(
            "Generate failed: {}",
            generate
                .error
                .unwrap_or_else(|| "unknown error".to_string())
        )
        .into());
    }

    let stats = daemon.call_ok_value(RpcMethod::Stats)?;
    let observed_messages = stats["message_count"]
        .as_u64()
        .ok_or("Stats.message_count missing")? as u32;
    let messages_preview = daemon.call_ok_value(RpcMethod::Messages { limit: 1 })?;

    let simulation_started = Instant::now();
    let scenario = build_scenario(config, observed_messages);
    let summary = Simulation::new(scenario)?.run();
    let simulation_ms = simulation_started.elapsed().as_millis();

    let report = RunReport {
        config: ReportConfig {
            users: config.users,
            messages_requested: config.messages,
            topology: match config.topology {
                TopologyArg::Star => "star",
                TopologyArg::Graph => "graph",
            },
            graph_degree: config.graph_degree,
            sync_rounds: config.sync_rounds,
        },
        daemon: serde_json::json!({
            "db_path": daemon.db_path(),
            "create_workspace_ok": create_workspace.ok,
            "generate_ok": generate.ok,
            "stats": stats,
            "messages_preview": messages_preview,
        }),
        simulation: summary,
        timings: serde_json::json!({
            "setup_ms": setup_ms,
            "create_workspace_ms": create_workspace_ms,
            "generate_ms": generate_ms,
            "simulation_ms": simulation_ms,
            "total_ms": total_started.elapsed().as_millis(),
        }),
    };

    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}
