use clap::Parser;

use topo::sim::{
    run_large_graph_sampled_decrypt_trial, KeyResponsePolicy, LargeGraphSampleDecryptConfig,
};

#[derive(Parser, Debug)]
struct Args {
    #[arg(long, default_value_t = 100_000)]
    users: usize,
    #[arg(long, default_value_t = 6)]
    degree: usize,
    #[arg(long, default_value_t = 16)]
    samples: usize,
    #[arg(long, default_value_t = 7)]
    seed: u64,
}

fn main() {
    let args = Args::parse();
    let report = run_large_graph_sampled_decrypt_trial(LargeGraphSampleDecryptConfig {
        logical_users: args.users,
        degree: args.degree,
        sample_count: args.samples,
        seed: args.seed,
        response_policy: KeyResponsePolicy::BestObservedOnly,
        message_content: format!(
            "large-graph sampled decrypt u{} s{} seed{}",
            args.users, args.samples, args.seed
        ),
    })
    .expect("large graph sampled decrypt trial");
    println!(
        "{}",
        serde_json::to_string_pretty(&report).expect("serialize decrypt report")
    );
}
