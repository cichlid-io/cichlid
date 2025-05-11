mod config_store;
mod handlers;
mod select_stream_or_shutdown;
mod server_loop;
mod tls_accept_stream;
mod types;

use clap::Parser;
use config_store::{ConfigStore, new_store};
use handlers::handle_tls_connection;
use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod};
use std::sync::Arc;
use tokio::{net::{TcpListener, TcpStream}, signal, task};
use tokio_openssl::SslStream;
use server_loop::serve_tls_stream;
use tls_accept_stream::tls_accept_stream;
use tracing::{info, error};
use crate::types::GenericBoxedStream;

#[derive(Parser, Debug, Clone)]
#[command(author, version, about)]
struct Args {
    #[arg(long)]
    cert_path: String,
    #[arg(long)]
    key_path: String,
    #[arg(long, default_value = "127.0.0.1")]
    host: String,
    #[arg(long, default_value = "8443")]
    port: u16,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    let args = Args::parse();

    let store = new_store();
    let shutdown_notify = Arc::new(tokio::sync::Notify::new());

    let shutdown_handle = shutdown_notify.clone();
    task::spawn(async move {
        signal::ctrl_c().await.expect("failed to listen for ctrl_c");
        info!("Shutdown requested.");
        shutdown_handle.notify_waiters();
    });

    if let Err(e) = run_web_server(args, store, shutdown_notify).await {
        error!("Server error: {}", e);
    }
}

async fn run_web_server(
    args: Args,
    store: ConfigStore,
    shutdown_notify: Arc<tokio::sync::Notify>,
) -> Result<(), Box<dyn std::error::Error>> {
    let addr = format!("{}:{}", args.host, args.port);
    let tcp = TcpListener::bind(&addr).await?;
    info!("Listening on https://{}", addr);

    let mut builder = SslAcceptor::mozilla_intermediate(SslMethod::tls())?;
    builder.set_certificate_chain_file(&args.cert_path)?;
    builder.set_private_key_file(&args.key_path, SslFiletype::PEM)?;
    let ssl_acceptor = Arc::new(builder.build());

    //let stream: Pin<Box<dyn Stream<Item = Result<SslStream<TcpStream>, std::io::Error>> + Send>> = Box::pin(tls_accept_stream(tcp, ssl_acceptor.clone()));
    let stream: GenericBoxedStream<Result<SslStream<TcpStream>, std::io::Error>> = Box::pin(tls_accept_stream(tcp, ssl_acceptor.clone()));

    serve_tls_stream(
        stream,
        shutdown_notify.clone(),
        move |stream_result| {
            let store = store.clone();
            task::spawn(async move {
                match stream_result {
                    Ok(stream) => {
                        handle_tls_connection(stream, store).await;
                    }
                    Err(e) => {
                        tracing::error!("TLS stream error during connection: {}", e);
                    }
                }
            })
        },
    ).await?;

    Ok(())
}
