use topo::db::iroh_log::IrohLogMode;

use tracing_subscriber::{
    filter::{Directive, LevelFilter},
    EnvFilter, FmtSubscriber,
};

pub(crate) const IROH_LOG_SUPPRESSION_DIRECTIVES: &[&str] = &[
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

pub(crate) fn build_env_filter_from_spec(
    rust_log: Option<&str>,
    iroh_log_mode: IrohLogMode,
) -> EnvFilter {
    let builder = EnvFilter::builder().with_default_directive(LevelFilter::WARN.into());
    let mut filter = match rust_log {
        Some(spec) => builder.parse_lossy(spec),
        None => builder.from_env_lossy(),
    };
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

pub(crate) fn build_start_subscriber(
    iroh_log_mode: IrohLogMode,
) -> impl tracing::Subscriber + Send + Sync {
    let filter = build_env_filter_from_spec(None, iroh_log_mode);
    FmtSubscriber::builder().with_env_filter(filter).finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_show_mode_leaves_explicit_filter_unchanged() {
        let filter = build_env_filter_from_spec(Some("info,topo=debug"), IrohLogMode::Show);
        let rendered = format!("{}", filter);
        assert!(rendered.contains("info"));
        assert!(rendered.contains("topo=debug"));
        assert!(!rendered.contains("noq_proto=off"));
    }

    #[test]
    fn test_suppress_mode_adds_iroh_target_directives() {
        let filter = build_env_filter_from_spec(Some("info"), IrohLogMode::Suppress);
        let rendered = format!("{}", filter);
        assert!(rendered.contains("info"));
        for directive in IROH_LOG_SUPPRESSION_DIRECTIVES {
            assert!(
                rendered.contains(directive),
                "missing suppression directive in rendered filter: {}",
                directive
            );
        }
    }
}
