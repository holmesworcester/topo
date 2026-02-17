//! p7d — poc-7 daemon process.
//!
//! Owns the database, runs sync, and listens on a local Unix socket for RPC commands.
//! One daemon per profile/peer.
//!
//! With `--node`: multi-tenant mode. Discovers all local identities from the DB
//! and starts a per-tenant QUIC endpoint sharing a single batch writer.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use clap::Parser;
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;

use poc_7::db::{open_connection, schema::create_tables};
use poc_7::rpc::server::run_rpc_server;
use poc_7::service;

#[derive(Parser)]
#[command(name = "p7d")]
#[command(about = "poc-7 daemon — owns DB, runs sync, serves RPC")]
struct Args {
    /// Database path (defines profile)
    #[arg(short, long, default_value = "server.db")]
    db: String,

    /// Listen address for QUIC sync
    #[arg(short, long, default_value = "127.0.0.1:4433")]
    bind: SocketAddr,

    /// Peer to connect to (if omitted, just listens)
    #[arg(short = 'r', long)]
    connect: Option<SocketAddr>,

    /// Custom RPC socket path (default: <db>.p7d.sock)
    #[arg(long)]
    socket: Option<String>,

    /// Multi-tenant node mode: discover all local identities and start
    /// per-tenant QUIC endpoints with a shared batch writer.
    #[arg(long)]
    node: bool,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let args = Args::parse();

    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .finish();
    let _ = tracing::subscriber::set_global_default(subscriber);

    // Initialize DB eagerly.
    {
        let db = open_connection(&args.db)?;
        create_tables(&db)?;
    }

    let socket_path = args
        .socket
        .as_ref()
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| service::socket_path_for_db(&args.db));

    let shutdown = Arc::new(AtomicBool::new(false));
    let db_path = Arc::new(args.db.clone());

    // Start RPC server in a background thread.
    let rpc_shutdown = shutdown.clone();
    let rpc_socket = socket_path.clone();
    let rpc_db = db_path.clone();
    let rpc_handle = std::thread::spawn(move || {
        if let Err(e) = run_rpc_server(&rpc_socket, rpc_db, rpc_shutdown) {
            tracing::error!("RPC server error: {}", e);
        }
    });

    info!("p7d started (db={}, socket={})", args.db, socket_path.display());

    if args.node {
        // Multi-tenant node mode
        let bind_ip = args.bind.ip();
        poc_7::node::run_node(&args.db, bind_ip).await?;
    } else {
        // Single-tenant sync mode: always run accept_loop for incoming
        // connections. connect_loop only runs when --connect is provided.
        service::svc_sync(args.bind, args.connect, &args.db).await?;
    }

    // Signal RPC server to stop.
    shutdown.store(true, Ordering::Relaxed);
    let _ = rpc_handle.join();

    // Clean up socket file.
    let _ = std::fs::remove_file(&socket_path);

    info!("p7d shut down cleanly");
    Ok(())
}
