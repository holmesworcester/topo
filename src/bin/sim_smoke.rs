use topo::sim::{Simulation, Topology};

fn main() {
    let topology = match std::env::args().nth(1).as_deref() {
        Some("graph") => Topology::Graph { degree: 2 },
        _ => Topology::Star {
            hub: topo::sim::PeerId(0),
        },
    };

    let scenario = topo::sim::Scenario::tiny_demo(topology);
    let summary = Simulation::new(scenario)
        .expect("build tiny simulator")
        .run();
    println!(
        "{}",
        serde_json::to_string_pretty(&summary).expect("serialize summary")
    );
}
