mod certs;
mod config_store;
mod handlers;
mod install;
mod pq;
mod select_stream_or_shutdown;
mod server_loop;
mod tls_accept_stream;
mod types;
mod workers;

use crate::types::GenericBoxedStream;
use clap::{Parser, Subcommand};
use config_store::{ConfigStore, new_store};
use handlers::handle_tls_connection;
use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod};
use server_loop::serve_tls_stream;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use tls_accept_stream::tls_accept_stream;
use tokio::{
    net::{TcpListener, TcpStream},
    signal, task,
};
use tokio_openssl::SslStream;
use tracing::{error, info};

#[derive(Parser, Debug, Clone)]
#[command(author, version, about)]
struct Args {
    #[arg(
        long,
        default_value = "/etc/cichlid/tls/default/cert.pem",
        help = "Path to TLS certificate file"
    )]
    cert_path: PathBuf,
    #[arg(
        long,
        default_value = "/etc/cichlid/tls/default/key.pem",
        help = "Path to TLS private key file"
    )]
    key_path: PathBuf,
    #[arg(
        long,
        default_value = "/etc/cichlid/tls/default/ca-cert.pem",
        help = "Path to CA certificate file (for peer verification)"
    )]
    ca_cert_path: PathBuf,
    #[arg(long, default_value = "0.0.0.0")]
    host: String,
    #[arg(long, default_value = "29170")]
    port: u16,
    /// Peer discovery interval in seconds
    #[arg(
        long,
        default_value = "5",
        help = "Peer discovery interval, in seconds"
    )]
    discovery_interval: u64,

    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Subcommand, Debug, Clone)]
pub enum Command {
    /// Install cichlid systemd service and user
    Install {
        /// Overwrite existing systemd service file and certs if they exist
        #[arg(long)]
        overwrite: bool,
        /// Path to TLS certificate file for service (default: /etc/cichlid/tls/default/cert.pem)
        #[arg(
            long,
            default_value = "/etc/cichlid/tls/default/cert.pem",
            help = "Path to TLS certificate file"
        )]
        cert_path: PathBuf,
        /// Path to TLS private key file for service (default: /etc/cichlid/tls/default/key.pem)
        #[arg(
            long,
            default_value = "/etc/cichlid/tls/default/key.pem",
            help = "Path to TLS private key file"
        )]
        key_path: PathBuf,
    },

    /// Uninstall cichlid: stop service, optionally remove all files and user
    Uninstall {
        /// Remove system user, service, binary, and config
        #[arg(long)]
        purge: bool,
    },

    /// Generate TLS certificates. If --alg is given and matches a PQ algorithm, generate a PQ certificate.
    GenCerts {
        /// Path to write the certificate file
        #[arg(
            long,
            default_value = "/etc/cichlid/tls/default/cert.pem",
            help = "Path to TLS certificate file"
        )]
        cert_path: PathBuf,

        /// Path to write the private key file
        #[arg(
            long,
            default_value = "/etc/cichlid/tls/default/key.pem",
            help = "Path to TLS private key file"
        )]
        key_path: PathBuf,

        /// Path to CA certificate for signing
        #[arg(
            long,
            default_value = "/etc/cichlid/tls/default/ca-cert.pem",
            help = "Path to signing CA certificate"
        )]
        ca_cert_path: PathBuf,

        /// Path to CA private key for signing
        #[arg(
            long,
            default_value = "/etc/cichlid/tls/default/ca-key.pem",
            help = "Path to signing CA private key"
        )]
        ca_key_path: PathBuf,

        /// Algorithm (PQ or classic) for key/cert generation. If omitted, use normal algorithm.
        #[arg(long)]
        alg: Option<String>,

        /// Subject names for the certificate SAN (DNS/IP). Multiple allowed: --subject-name name1 --subject-name name2
        #[arg(long = "subject-name", action = clap::ArgAction::Append)]
        subject_names: Vec<String>,
    },

    /// List PQ algorithms supported by the linked OpenSSL+OQS provider
    ListPqAlgs,

    /// Generate a cichlid CA certificate and private key (errors if file exists). If --alg is given and matches a PQ algorithm, use PQ.
    GenCa {
        /// Path to write the CA certificate file
        #[arg(
            long,
            default_value = "/etc/cichlid/tls/default/ca-cert.pem",
            help = "Path to CA certificate file"
        )]
        ca_cert_path: PathBuf,
        /// Path to write the CA private key file
        #[arg(
            long,
            default_value = "/etc/cichlid/tls/default/ca-key.pem",
            help = "Path to CA private key file"
        )]
        ca_key_path: PathBuf,
        /// Algorithm (PQ or classic) for CA key/cert generation. If omitted, use normal algorithm.
        #[arg(long)]
        alg: Option<String>,
    },
    // More subcommands could be added here later
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();

    match &args.command {
        Some(Command::Install {
            overwrite,
            cert_path,
            key_path,
        }) => {
            install::install(*overwrite, cert_path.clone(), key_path.clone())?;
            return Ok(());
        }
        Some(Command::Uninstall { purge }) => {
            install::uninstall(*purge)?;
            return Ok(());
        }
        Some(Command::GenCerts {
            cert_path,
            key_path,
            ca_cert_path,
            ca_key_path,
            alg,
            subject_names,
        }) => {
            // CA cert/key must exist
            if !ca_cert_path.exists() {
                tracing::error!(
                    "CA certificate file does not exist: {}",
                    ca_cert_path.display()
                );
                std::process::exit(1);
            }
            if !ca_key_path.exists() {
                tracing::error!(
                    "CA private key file does not exist: {}",
                    ca_key_path.display()
                );
                std::process::exit(1);
            }

            // Fallback to generic names if none supplied.
            let names: Vec<String> = if subject_names.is_empty() {
                vec!["localhost".to_string(), "127.0.0.1".to_string()]
            } else {
                subject_names.clone()
            };
            let subject_refs: Vec<&str> = names.iter().map(|s| s.as_str()).collect();

            if let Some(alg) = alg.as_ref() {
                // Is it a PQ algorithm?
                let is_pq = pq::list_pq_signature_algorithms()?.contains(alg);
                if is_pq {
                    certs::generate_pq_cert_signed_by_ca(
                        cert_path
                            .to_str()
                            .expect("Failed to convert cert_path to str"),
                        key_path
                            .to_str()
                            .expect("Failed to convert key_path to str"),
                        ca_cert_path
                            .to_str()
                            .expect("Failed to convert ca_cert_path to str"),
                        ca_key_path
                            .to_str()
                            .expect("Failed to convert ca_key_path to str"),
                        alg,
                        &subject_refs,
                    )?;
                    tracing::info!(
                        "PQ certificate signed by CA and written to:\n  cert: {}\n  key: {}",
                        cert_path.display(),
                        key_path.display()
                    );
                    return Ok(());
                }
            }
            // Normal (non-PQ) path
            certs::generate_cert_signed_by_ca(
                cert_path
                    .to_str()
                    .expect("Failed to convert cert_path to str"),
                key_path
                    .to_str()
                    .expect("Failed to convert key_path to str"),
                ca_cert_path
                    .to_str()
                    .expect("Failed to convert ca_cert_path to str"),
                ca_key_path
                    .to_str()
                    .expect("Failed to convert ca_key_path to str"),
                &subject_refs,
            )?;
            tracing::info!(
                "Certificate signed by CA and written to:\n  cert: {}\n  key: {}",
                cert_path.display(),
                key_path.display()
            );
            return Ok(());
        }
        Some(Command::ListPqAlgs) => {
            let output = std::process::Command::new("openssl")
                .args([
                    "list",
                    "-signature-algorithms",
                    "-provider",
                    "default",
                    "-provider",
                    "oqsprovider",
                ])
                .output()
                .expect("Failed to run openssl");

            if !output.status.success() {
                tracing::error!("Error: OpenSSL did not complete successfully");
                std::process::exit(1);
            }

            for line in String::from_utf8_lossy(&output.stdout).lines() {
                if let Some(algo) = line.strip_suffix(" @ oqsprovider") {
                    tracing::info!("{}", algo.trim());
                }
            }

            return Ok(());
        }
        Some(Command::GenCa {
            ca_cert_path,
            ca_key_path,
            alg,
        }) => {
            // Error if either file exists
            if ca_cert_path.exists() || ca_key_path.exists() {
                tracing::error!(
                    "CA cert or key already exists ({} or {}). Aborting.",
                    ca_cert_path.display(),
                    ca_key_path.display()
                );
                std::process::exit(1);
            }
            if let Some(alg) = alg.as_ref() {
                // Is it a PQ algorithm?
                let is_pq = pq::list_pq_signature_algorithms()?.contains(alg);
                if is_pq {
                    certs::generate_pq_ca_cert(
                        ca_cert_path.to_str().unwrap(),
                        ca_key_path.to_str().unwrap(),
                        alg,
                    )?;
                    tracing::info!(
                        "PQ CA certificate and key written to:\n  cert: {}\n  key: {}",
                        ca_cert_path.display(),
                        ca_key_path.display()
                    );
                    return Ok(());
                }
            }
            // Otherwise, generate a normal (non-PQ) CA
            certs::generate_normal_ca_cert(
                ca_cert_path.to_str().unwrap(),
                ca_key_path.to_str().unwrap(),
            )?;
            tracing::info!(
                "Generated cichlid CA:\n  cert: {}\n  key: {}",
                ca_cert_path.display(),
                ca_key_path.display()
            );
            return Ok(());
        }
        None => {
            // require cert path
            let cert_path = &args.cert_path;
            if !cert_path.exists() {
                tracing::error!("Error: cert file not found at '{}'", cert_path.display());
                std::process::exit(1);
            }
            if fs::metadata(cert_path)?.permissions().readonly() {
                tracing::error!("Error: cert file '{}' is not readable", cert_path.display());
                std::process::exit(1);
            }

            // require key path
            let key_path = &args.key_path;
            if !key_path.exists() {
                tracing::error!("Error: key file not found at '{}'", key_path.display());
                std::process::exit(1);
            }
            if fs::metadata(key_path)?.permissions().readonly() {
                tracing::error!("Error: key file '{}' is not readable", key_path.display());
                std::process::exit(1);
            }
        }
    }

    let store = new_store();
    let shutdown_notify = Arc::new(tokio::sync::Notify::new());

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

    let worker_handle = tokio::spawn({
        let worker_shutdown_handle = shutdown_notify.clone();
        let worker_port = args.port;
        let discovery_interval = args.discovery_interval;
        let cert_path = args.cert_path.clone();
        let key_path = args.key_path.clone();
        let ca_cert_path = args.ca_cert_path.clone();
        async move {
            workers::run_workers(
                worker_shutdown_handle,
                worker_port,
                discovery_interval,
                cert_path,
                key_path,
                ca_cert_path,
            ).await;
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
    let cert_path = &args.cert_path;
    let key_path = &args.key_path;
    let ca_cert_path = &args.ca_cert_path;
    builder.set_certificate_chain_file(cert_path)?;
    builder.set_private_key_file(key_path, SslFiletype::PEM)?;
    // Set CA cert for peer cert verification
    builder.set_ca_file(ca_cert_path)?;
    use openssl::ssl::SslVerifyMode;
    builder.set_verify(SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT);
    let ssl_acceptor = Arc::new(builder.build());

    //let stream: Pin<Box<dyn Stream<Item = Result<SslStream<TcpStream>, std::io::Error>> + Send>> = Box::pin(tls_accept_stream(tcp, ssl_acceptor.clone()));
    let stream: GenericBoxedStream<Result<SslStream<TcpStream>, std::io::Error>> =
        Box::pin(tls_accept_stream(tcp, ssl_acceptor.clone()));

    serve_tls_stream(stream, shutdown_notify.clone(), move |stream_result| {
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
    })
    .await?;

    Ok(())
}
