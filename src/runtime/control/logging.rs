use std::sync::OnceLock;

use tracing::info;
use tracing_subscriber::{
    filter::{Directive, LevelFilter},
    layer::SubscriberExt,
    reload, EnvFilter, Registry,
};

use crate::state::db::{iroh_log::IrohLogMode, topo_log::TopoLogLevel};

pub const IROH_LOG_SUPPRESSION_DIRECTIVES: &[&str] = &[
    "iroh=off",
    "iroh_blobs=off",
    "iroh_gossip=off",
    "iroh_net_report=off",
    "iroh_relay=off",
    "netwatch=off",
    "n0_dns=off",
    "n0_future=off",
    "noq_proto=off",
    "noq_udp=off",
    "quinn=off",
    "swarm_discovery=off",
];

type TopoLogReloadHandle = reload::Handle<EnvFilter, Registry>;

static TOPO_LOG_RELOAD_HANDLE: OnceLock<TopoLogReloadHandle> = OnceLock::new();

pub(crate) fn build_env_filter_from_spec(
    rust_log: Option<&str>,
    topo_log_level: TopoLogLevel,
    iroh_log_mode: IrohLogMode,
) -> EnvFilter {
    let builder = EnvFilter::builder().with_default_directive(LevelFilter::WARN.into());
    let mut filter = match rust_log {
        Some(spec) => builder.parse_lossy(spec),
        None => builder.from_env_lossy(),
    };
    let topo_directive = format!("topo={}", topo_log_level.as_str())
        .parse::<Directive>()
        .expect("hard-coded topo log directive must be valid");
    filter = filter.add_directive(topo_directive);
    if iroh_log_mode == IrohLogMode::Suppress {
        for directive in IROH_LOG_SUPPRESSION_DIRECTIVES {
            let parsed = directive
                .parse::<Directive>()
                .expect("hard-coded iroh log suppression directive must be valid");
            filter = filter.add_directive(parsed);
        }
    }
    filter
}

pub fn build_start_subscriber(
    iroh_log_mode: IrohLogMode,
    topo_log_level: TopoLogLevel,
) -> impl tracing::Subscriber + Send + Sync {
    let filter = build_env_filter_from_spec(None, topo_log_level, iroh_log_mode);
    let (filter_layer, reload_handle) = reload::Layer::new(filter);
    let _ = TOPO_LOG_RELOAD_HANDLE.set(reload_handle);
    tracing_subscriber::registry()
        .with(filter_layer)
        .with(tracing_subscriber::fmt::layer())
}

pub fn reload_topo_log_level(
    topo_log_level: TopoLogLevel,
    iroh_log_mode: IrohLogMode,
) -> Result<(), String> {
    let Some(handle) = TOPO_LOG_RELOAD_HANDLE.get() else {
        return Err("topo log reload handle not initialized".to_string());
    };
    let rust_log = std::env::var("RUST_LOG").ok();
    handle
        .reload(build_env_filter_from_spec(
            rust_log.as_deref(),
            topo_log_level,
            iroh_log_mode,
        ))
        .map_err(|e| format!("reload topo log filter: {e}"))?;
    info!("topo log level updated to {}", topo_log_level.as_str());
    Ok(())
}

pub fn topo_log_reload_is_active() -> bool {
    TOPO_LOG_RELOAD_HANDLE.get().is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_show_mode_leaves_explicit_filter_unchanged() {
        let filter = build_env_filter_from_spec(
            Some("info,topo::runtime::peering=debug"),
            TopoLogLevel::Warn,
            IrohLogMode::Show,
        );
        let rendered = format!("{}", filter);
        assert!(rendered.contains("info"));
        assert!(rendered.contains("topo::runtime::peering=debug"));
        assert!(rendered.contains("topo=warn"));
        assert!(!rendered.contains("noq_proto=off"));
    }

    #[test]
    fn test_suppress_mode_adds_iroh_target_directives() {
        let filter =
            build_env_filter_from_spec(Some("info"), TopoLogLevel::Info, IrohLogMode::Suppress);
        let rendered = format!("{}", filter);
        assert!(rendered.contains("info"));
        assert!(rendered.contains("topo=info"));
        for directive in IROH_LOG_SUPPRESSION_DIRECTIVES {
            assert!(
                rendered.contains(directive),
                "missing suppression directive in rendered filter: {}",
                directive
            );
        }
    }
}
