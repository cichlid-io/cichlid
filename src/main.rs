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
    #[arg(long, help = "Path to TLS certificate file")]
    cert_path: Option<PathBuf>,
    #[arg(long, help = "Path to TLS private key file")]
    key_path: Option<PathBuf>,
    #[arg(long, default_value = "0.0.0.0")]
    host: String,
    #[arg(long, default_value = "29170")]
    port: u16,
    /// Peer discovery interval in seconds
    #[arg(
        long,
        default_value = "300",
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
    },

    /// Uninstall cichlid: stop service, optionally remove all files and user
    Uninstall {
        /// Remove system user, service, binary, and config
        #[arg(long)]
        purge: bool,
    },

    /// Generate legacy TLS certificates
    GenCerts {
        /// Path to write the certificate file
        #[arg(long, help = "Path to TLS certificate file")]
        cert_path: String,

        /// Path to write the private key file
        #[arg(long, help = "Path to TLS private key file")]
        key_path: String,
    },

    /// Generate post-quantum TLS certificates (e.g., Dilithium3)
    GenPqCerts {
        #[arg(long, help = "Path to TLS certificate file")]
        cert_path: PathBuf,
        #[arg(long, help = "Path to TLS private key file")]
        key_path: PathBuf,

        #[arg(long, value_parser = validate_pq_alg)]
        alg: Option<String>,
    },

    /// List PQ algorithms supported by the linked OpenSSL+OQS provider
    ListPqAlgs,

    /// Generate a cichlid self-signed CA certificate and private key (errors if file exists)
    GenCa {
        /// Path to write the CA certificate file
        #[arg(long, help = "Path to CA certificate file")]
        ca_cert_path: String,
        /// Path to write the CA private key file
        #[arg(long, help = "Path to CA private key file")]
        ca_key_path: String,
    },
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
        Some(Command::Install { overwrite }) => {
            install::install(*overwrite)?;
            return Ok(());
        }
        Some(Command::Uninstall { purge }) => {
            install::uninstall(*purge)?;
            return Ok(());
        }
        Some(Command::GenCerts {
            cert_path,
            key_path,
        }) => {
            // reject --cert-path or --key-path if present
            if args.cert_path.is_some() || args.key_path.is_some() {
                tracing::error!(
                    "Error: --cert-path and --key-path must not be used with 'gen-certs'"
                );
                std::process::exit(1);
            }
            certs::generate_self_signed_cert(cert_path.as_str(), key_path.as_str())?;
            tracing::info!(
                "Certificates generated at:\n  cert: {}\n  key: {}",
                cert_path,
                key_path
            );
            return Ok(());
        }
        Some(Command::GenPqCerts {
            cert_path,
            key_path,
            alg,
        }) => {
            let alg = match alg {
                Some(a) => a,
                None => {
                    tracing::error!("Missing --alg. Available PQ algorithms:");
                    for a in pq::list_pq_signature_algorithms()? {
                        tracing::info!("  {}", a);
                    }
                    std::process::exit(1);
                }
            };
            let status = std::process::Command::new("openssl")
                .args([
                    "req",
                    "-new",
                    "-x509",
                    "-newkey",
                    alg.as_str(),
                    "-keyout",
                    key_path.to_str().unwrap(),
                    "-out",
                    cert_path.to_str().unwrap(),
                    "-nodes",
                    "-subj",
                    "/CN=localhost",
                    "-provider",
                    "default",
                    "-provider",
                    "oqsprovider",
                ])
                .status()?;

            if !status.success() {
                tracing::error!(
                    "OpenSSL failed to generate PQ certs with algorithm '{}'",
                    alg
                );
                std::process::exit(1);
            }

            tracing::info!(
                "PQ certificate written to:\n  cert: {}\n  key: {}",
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
        Some(Command::GenCa { ca_cert_path, ca_key_path }) => {
            use std::path::Path;
            use openssl::rsa::Rsa;
            use openssl::x509::X509NameBuilder;
            use openssl::pkey::PKey;
            use openssl::x509::X509Builder;
            use openssl::asn1::Asn1Time;
            use openssl::x509::extension::BasicConstraints;
            use openssl::x509::extension::KeyUsage;

            // Error if either file exists
            if Path::new(&ca_cert_path).exists() || Path::new(&ca_key_path).exists() {
                tracing::error!("CA cert or key already exists ({} or {}). Aborting.", ca_cert_path, ca_key_path);
                std::process::exit(1);
            }

            // Generate RSA CA keypair
            let rsa = Rsa::generate(4096).expect("Failed to generate RSA");
            let pkey = PKey::from_rsa(rsa).expect("Failed to create CA PKey");

            // Subject/issuer name
            let mut name = X509NameBuilder::new().unwrap();
            name.append_entry_by_text("CN", "cichlid-ca").unwrap();
            let name = name.build();

            // Build self-signed X509 cert
            let mut builder = X509Builder::new().unwrap();
            builder.set_version(2).unwrap();
            builder.set_subject_name(&name).unwrap();
            builder.set_issuer_name(&name).unwrap();
            builder.set_pubkey(&pkey).unwrap();
            builder.set_not_before(&Asn1Time::days_from_now(0).unwrap()).unwrap();
            builder.set_not_after(&Asn1Time::days_from_now(3650).unwrap()).unwrap(); // 10 years
            let basic_constraints = BasicConstraints::new().critical().ca().build().unwrap();
            builder.append_extension(basic_constraints).unwrap();
            let key_usage = KeyUsage::new().key_cert_sign().crl_sign().build().unwrap();
            builder.append_extension(key_usage).unwrap();
            builder.sign(&pkey, openssl::hash::MessageDigest::sha256()).unwrap();
            let ca_cert = builder.build();

            // Write key and cert to files
            std::fs::write(&ca_cert_path, ca_cert.to_pem().unwrap()).expect("Failed to write CA cert");
            std::fs::write(&ca_key_path, pkey.private_key_to_pem_pkcs8().unwrap()).expect("Failed to write CA key");

            tracing::info!(
                "Generated cichlid CA:\n  cert: {}\n  key: {}",
                ca_cert_path,
                ca_key_path
            );
            return Ok(());
        }
        None => {
            // require cert path
            let cert_path = args.cert_path.as_ref().unwrap_or_else(|| {
                tracing::error!("Error: --cert-path is required when no subcommand is given");
                std::process::exit(1);
            });
            if !cert_path.exists() {
                tracing::error!("Error: cert file not found at '{}'", cert_path.display());
                std::process::exit(1);
            }
            if fs::metadata(cert_path)?.permissions().readonly() {
                tracing::error!("Error: cert file '{}' is not readable", cert_path.display());
                std::process::exit(1);
            }

            // require key path
            let key_path = args.key_path.as_ref().unwrap_or_else(|| {
                tracing::error!("Error: --key-path is required when no subcommand is given");
                std::process::exit(1);
            });
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
        async move {
            workers::run_workers(worker_shutdown_handle, worker_port, discovery_interval).await;
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
