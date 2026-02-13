//! p7d — poc-7 daemon process.
//!
//! Owns the database, runs sync, and listens on a local Unix socket for RPC commands.
//! One daemon per profile/peer.

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

    /// Peer fingerprints to trust (hex, repeatable)
    #[arg(long = "pin-peer")]
    pin_peer: Vec<String>,

    /// Custom RPC socket path (default: <db>.p7d.sock)
    #[arg(long)]
    socket: Option<String>,
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

    // Run sync as the main task (or just wait for Ctrl-C if no peers).
    if !args.pin_peer.is_empty() || args.connect.is_some() {
        service::svc_sync(args.bind, args.connect, &args.db, &args.pin_peer).await?;
    } else {
        // No peers configured — just serve RPC and wait for shutdown.
        info!("No peers configured, running RPC-only mode. Ctrl-C to stop.");
        tokio::signal::ctrl_c().await?;
    }

    // Signal RPC server to stop.
    shutdown.store(true, Ordering::Relaxed);
    let _ = rpc_handle.join();

    // Clean up socket file.
    let _ = std::fs::remove_file(&socket_path);

    info!("p7d shut down cleanly");
    Ok(())
}
