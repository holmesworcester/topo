use topo::sim::{
    emit_key_requests_for_dbs, emit_key_shared_responses_for_dbs, FakeTopologyPreference,
    KeyResponsePolicy, PlannerMode, PlannerSimulation,
};

#[derive(Debug, Clone, Copy)]
enum ModeArg {
    Planner,
    NearestNeighborNoAuth,
}

impl ModeArg {
    fn parse(s: &str) -> Result<Self, String> {
        match s {
            "planner" => Ok(Self::Planner),
            "nearest-neighbor-no-auth" => Ok(Self::NearestNeighborNoAuth),
            other => Err(format!(
                "unsupported --mode `{other}`; use `planner` or `nearest-neighbor-no-auth`"
            )),
        }
    }

    fn as_planner_mode(self) -> PlannerMode {
        match self {
            Self::Planner => PlannerMode::RealConnectTargets,
            Self::NearestNeighborNoAuth => PlannerMode::NearestNeighborNoAuth,
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum TopologyArg {
    Graph,
    Star,
}

impl TopologyArg {
    fn parse(s: &str) -> Result<Self, String> {
        match s {
            "graph" => Ok(Self::Graph),
            "star" => Ok(Self::Star),
            other => Err(format!(
                "unsupported --topology `{other}`; use `graph` or `star`"
            )),
        }
    }

    fn as_fake_topology(self) -> FakeTopologyPreference {
        match self {
            Self::Graph => FakeTopologyPreference::Graph,
            Self::Star => FakeTopologyPreference::Star,
        }
    }
}

#[derive(Debug, Clone)]
struct Config {
    dbs: Vec<String>,
    rounds: u32,
    mode: ModeArg,
    topology: TopologyArg,
    repair_run: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            dbs: Vec::new(),
            rounds: 1,
            mode: ModeArg::Planner,
            topology: TopologyArg::Graph,
            repair_run: false,
        }
    }
}

fn parse_args() -> Result<Config, String> {
    let mut config = Config::default();
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--db" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--db requires a value".to_string())?;
                config.dbs.push(value);
            }
            "--rounds" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--rounds requires a value".to_string())?;
                config.rounds = value
                    .parse::<u32>()
                    .map_err(|err| format!("parse --rounds: {err}"))?;
            }
            "--mode" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--mode requires a value".to_string())?;
                config.mode = ModeArg::parse(&value)?;
            }
            "--topology" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--topology requires a value".to_string())?;
                config.topology = TopologyArg::parse(&value)?;
            }
            "--repair-run" => {
                config.repair_run = true;
            }
            other => return Err(format!("unknown arg `{other}`")),
        }
    }
    if config.dbs.is_empty() {
        return Err("provide at least one --db PATH".to_string());
    }
    Ok(config)
}

fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let config = parse_args()?;
    let repair_stats = if config.repair_run {
        let request_stats = emit_key_requests_for_dbs(&config.dbs)?;
        let response_stats =
            emit_key_shared_responses_for_dbs(&config.dbs, KeyResponsePolicy::BestObservedOnly)?;
        Some(serde_json::json!({
            "request_stats": request_stats,
            "response_stats": response_stats,
        }))
    } else {
        None
    };
    let report = PlannerSimulation::with_mode_and_topology(
        config.dbs,
        config.mode.as_planner_mode(),
        config.topology.as_fake_topology(),
    )
    .run_rounds(config.rounds)?;
    let mut value = serde_json::to_value(&report)?;
    if let Some(repair_stats) = repair_stats {
        value["repair_stats"] = repair_stats;
    }
    println!("{}", serde_json::to_string_pretty(&value)?);
    Ok(())
}
