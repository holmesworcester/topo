use clap::{Parser, Subcommand};
use std::net::SocketAddr;
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;

use poc_7::db::{open_connection, schema::create_tables};
use poc_7::sync::SyncMessage;
use poc_7::sync::engine::{run_sync_initiator_dual, run_sync_responder_dual};
use poc_7::transport::{
    DualConnection,
    create_client_endpoint,
    create_server_endpoint,
    generate_keypair,
    generate_self_signed_cert,
};

#[derive(Parser)]
#[command(name = "poc-7")]
#[command(about = "High-performance QUIC sync system")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run as a listening server
    Listen {
        /// Address to bind to
        #[arg(short, long, default_value = "127.0.0.1:4433")]
        bind: SocketAddr,

        /// Database path
        #[arg(short, long, default_value = "server.db")]
        db: String,

        /// Run duration in seconds
        #[arg(short, long, default_value = "30")]
        timeout: u64,
    },

    /// Connect to a remote peer
    Connect {
        /// Remote address to connect to
        #[arg(short, long)]
        remote: SocketAddr,

        /// Database path
        #[arg(short, long, default_value = "client.db")]
        db: String,

        /// Run duration in seconds
        #[arg(short, long, default_value = "30")]
        timeout: u64,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    let cli = Cli::parse();

    match cli.command {
        Commands::Listen { bind, db, timeout } => {
            run_listen(bind, &db, timeout).await?;
        }
        Commands::Connect { remote, db, timeout } => {
            run_connect(remote, &db, timeout).await?;
        }
    }

    Ok(())
}

async fn run_listen(
    bind: SocketAddr,
    db_path: &str,
    timeout_secs: u64,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    info!("Starting server on {}", bind);

    let (signing_key, _) = generate_keypair();
    let (cert, key) = generate_self_signed_cert(&signing_key)?;

    let endpoint = create_server_endpoint(bind, cert, key)?;
    info!("Server listening on {}", endpoint.local_addr()?);

    {
        let db = open_connection(db_path)?;
        create_tables(&db)?;
    }

    let incoming = endpoint.accept().await.ok_or("No connection")?;
    let connection = incoming.await?;
    let peer_id = connection.remote_address().to_string();
    info!("Accepted connection from {}", peer_id);

    let (control_send, control_recv) = connection.accept_bi().await?;
    let (data_send, data_recv) = connection.accept_bi().await?;
    let conn = DualConnection::new(control_send, control_recv, data_send, data_recv);
    info!("Accepted control and data streams");

    run_sync_responder_dual(conn, db_path, timeout_secs, &peer_id).await?;

    connection.close(0u32.into(), b"done");

    Ok(())
}

async fn run_connect(
    remote: SocketAddr,
    db_path: &str,
    timeout_secs: u64,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    info!("Connecting to {}", remote);

    let endpoint = create_client_endpoint("0.0.0.0:0".parse()?)?;

    let connection = endpoint.connect(remote, "localhost")?.await?;
    let peer_id = connection.remote_address().to_string();
    info!("Connected to {}", peer_id);

    {
        let db = open_connection(db_path)?;
        create_tables(&db)?;
    }

    let (control_send, control_recv) = connection.open_bi().await?;
    let (data_send, data_recv) = connection.open_bi().await?;
    let mut conn = DualConnection::new(control_send, control_recv, data_send, data_recv);

    conn.control.send(&SyncMessage::HaveList { ids: vec![] }).await?;
    conn.data_send.send(&SyncMessage::HaveList { ids: vec![] }).await?;
    conn.flush_control().await?;
    conn.flush_data().await?;
    info!("Opened and established control and data streams");

    run_sync_initiator_dual(conn, db_path, timeout_secs, &peer_id).await?;

    connection.close(0u32.into(), b"done");

    Ok(())
}
