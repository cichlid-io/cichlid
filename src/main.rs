mod certs;
mod config_store;
mod handlers;
mod pq;
mod select_stream_or_shutdown;
mod server_loop;
mod tls_accept_stream;
mod types;
mod workers;

use clap::{Parser, Subcommand};
use config_store::{ConfigStore, new_store};
use handlers::handle_tls_connection;
use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod};
use std::fs;
use std::path::PathBuf;
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
    #[arg(long, help = "Path to TLS certificate file")]
    cert_path: Option<PathBuf>,
    #[arg(long, help = "Path to TLS private key file")]
    key_path: Option<PathBuf>,
    #[arg(long, default_value = "127.0.0.1")]
    host: String,
    #[arg(long, default_value = "8443")]
    port: u16,

    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Subcommand, Debug, Clone)]
pub enum Command {
    /// Generate legacy TLS certificates
    GenCerts {

        /// Path to write the certificate file
        #[arg(long)]
        cert_out: String,

        /// Path to write the private key file
        #[arg(long)]
        key_out: String,
    },

    /// Generate post-quantum TLS certificates (e.g., Dilithium3)
    GenPqCerts {
        #[arg(long)]
        cert_out: PathBuf,
        #[arg(long)]
        key_out: PathBuf,

        #[arg(long, value_parser = validate_pq_alg)]
        alg: Option<String>,
    },

    /// List PQ algorithms supported by the linked OpenSSL+OQS provider
    ListPqAlgs,

    // More subcommands could be added here later
}

fn validate_pq_alg(s: &str) -> Result<String, String> {
    match pq::list_pq_signature_algorithms() {
        Ok(list) if list.contains(&s.to_string()) => Ok(s.to_string()),
        Ok(list) => Err(format!(
            "Invalid algorithm '{}'. Valid options are:\n  {}",
            s,
            list.join("\n  ")
        )),
        Err(_) => Err("Could not retrieve PQ algorithms from OpenSSL".into()),
    }
}


#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();

    match &args.command {
        Some(Command::GenCerts { cert_out, key_out }) => {
            // reject --cert-path or --key-path if present
            if args.cert_path.is_some() || args.key_path.is_some() {
                eprintln!("Error: --cert-path and --key-path must not be used with 'gen-certs'");
                std::process::exit(1);
            }
            certs::generate_self_signed_cert(cert_out, key_out)?;
            println!("Certificates generated at:\n  cert: {}\n  key: {}", cert_out, key_out);
            return Ok(());
        }
        Some(Command::GenPqCerts { cert_out, key_out, alg }) => {
            let alg = match alg {
                Some(a) => a,
                None => {
                    eprintln!("Missing --alg. Available PQ algorithms:\n");
                    for a in pq::list_pq_signature_algorithms()? {
                        println!("  {}", a);
                    }
                    std::process::exit(1);
                }
            };
            let status = std::process::Command::new("openssl")
                .args([
                    "req", "-new", "-x509",
                    "-newkey", alg,
                    "-keyout", key_out.to_str().unwrap(),
                    "-out", cert_out.to_str().unwrap(),
                    "-nodes",
                    "-subj", "/CN=localhost",
                    "-provider", "default",
                    "-provider", "oqsprovider",
                ])
                .status()?;

            if !status.success() {
                eprintln!("OpenSSL failed to generate PQ certs with algorithm '{}'", alg);
                std::process::exit(1);
            }

            println!("PQ certificate written to:\n  cert: {}\n  key: {}", cert_out.display(), key_out.display());
            return Ok(());
        }
        Some(Command::ListPqAlgs) => {
            let output = std::process::Command::new("openssl")
                .args(["list", "-signature-algorithms", "-provider", "default", "-provider", "oqsprovider"])
                .output()
                .expect("Failed to run openssl");

            if !output.status.success() {
                eprintln!("Error: OpenSSL did not complete successfully");
                std::process::exit(1);
            }

            for line in String::from_utf8_lossy(&output.stdout).lines() {
                if let Some(algo) = line.strip_suffix(" @ oqsprovider") {
                    println!("{}", algo.trim());
                }
            }

            return Ok(());
        }
        None => {
            // require cert path
            let cert_path = args.cert_path.as_ref().unwrap_or_else(|| {
                eprintln!("Error: --cert-path is required when no subcommand is given");
                std::process::exit(1);
            });
            if !cert_path.exists() {
                eprintln!("Error: cert file not found at '{}'", cert_path.display());
                std::process::exit(1);
            }
            if fs::metadata(cert_path)?.permissions().readonly() {
                eprintln!("Error: cert file '{}' is not readable", cert_path.display());
                std::process::exit(1);
            }

            // require key path
            let key_path = args.key_path.as_ref().unwrap_or_else(|| {
                eprintln!("Error: --key-path is required when no subcommand is given");
                std::process::exit(1);
            });
            if !key_path.exists() {
                eprintln!("Error: key file not found at '{}'", key_path.display());
                std::process::exit(1);
            }
            if fs::metadata(key_path)?.permissions().readonly() {
                eprintln!("Error: key file '{}' is not readable", key_path.display());
                std::process::exit(1);
            }
        }
    }

    let store = new_store();
    let shutdown_notify = Arc::new(tokio::sync::Notify::new());

    // Set up shutdown handler
    let shutdown_handle = shutdown_notify.clone();
    tokio::spawn({
        let interrupt_handle = shutdown_handle.clone();
        async move {
            if let Err(e) = signal::ctrl_c().await {
                error!("Failed to listen for shutdown signal: {}", e);
            }
            interrupt_handle.notify_waiters();
        }
    });

    // Spawn web server as a task
    let server_handle = tokio::spawn({
        let args_clone = args.clone();
        let store_clone = store.clone();
        let server_shutdown = shutdown_notify.clone();
        async move {
            if let Err(e) = run_web_server(args_clone, store_clone, server_shutdown).await {
                error!("Server error: {}", e);
            }
        }
    });

    // Spawn workers as a task
    let worker_handle = tokio::spawn({
        let worker_shutdown_handle = shutdown_notify.clone();
        async move {
            workers::run_workers(worker_shutdown_handle).await;
        }
    });

    // Wait for both the server and workers to exit
    let _ = tokio::try_join!(server_handle, worker_handle);

    Ok(())
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
    let cert_path = args.cert_path.as_ref().expect("cert_path required");
    let key_path = args.key_path.as_ref().expect("key_path required");
    builder.set_certificate_chain_file(cert_path)?;
    builder.set_private_key_file(key_path, SslFiletype::PEM)?;
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
