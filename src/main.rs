mod certs;
mod config_store;
mod handlers;
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
    #[arg(long, default_value = "127.0.0.1")]
    host: String,
    #[arg(long, default_value = "8443")]
    port: u16,

    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Subcommand, Debug, Clone)]
pub enum Command {
    /// Install cichlid systemd service and user
    /// Install cichlid systemd service and user
    Install {
        /// Overwrite service or certs if already present
        #[arg(long, help = "Overwrite existing systemd service file and certs if they exist")]
        overwrite: bool,
    },

    /// Uninstall cichlid: stop service, optionally remove all files and user
    Uninstall {
        /// Remove all files and user, not just disable service
        #[arg(long, help = "Remove system user, service, binary, and config")]
        purge: bool,
    },

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
        Some(Command::Install { overwrite }) => {
            use std::fs::{self, File};
            use std::io::Write;
            use std::process::Command;
            use std::path::Path;
            // Root check: If not EUID 0, print error and exit
            if unsafe { libc::geteuid() } != 0 {
                eprintln!("Install must be run as root (e.g., with sudo)");
                std::process::exit(1);
            }
            // 1. Create system user cichlid
            let output = Command::new("id").arg("-u").arg("cichlid").output();
            if let Ok(out) = &output {
                if !out.status.success() {
                    // useradd if doesn't exist
                    let status = Command::new("useradd")
                        .args(&[
                            "-r",
                            "-m",
                            "-d",
                            "/var/lib/cichlid",
                            "-G",
                            "wheel",
                            "cichlid",
                        ])
                        .status()
                        .expect("failed to create user cichlid");
                    if !status.success() {
                        eprintln!("Failed to create cichlid user");
                        std::process::exit(1);
                    }
                }
            } else {
                eprintln!("User lookup failed.");
                std::process::exit(1);
            }

            // 2. Add passwordless sudo for cichlid under /etc/sudoers.d/cichlid
            let sudoers_content = "cichlid ALL=(ALL) NOPASSWD:ALL\n";
            let mut file = File::create("/etc/sudoers.d/cichlid")
                .expect("Failed to write /etc/sudoers.d/cichlid -- need root?");
            file.write_all(sudoers_content.as_bytes())
                .expect("Failed to write sudoers line");
            // set correct permissions
            let _ = Command::new("chmod")
                .args(&["0440", "/etc/sudoers.d/cichlid"])
                .status();

            // 3. Copy invoked binary to /usr/local/bin/cichlid if not exists or overwrite requested
            let bin_dest = "/usr/local/bin/cichlid";
            let exe_path = std::fs::read_link("/proc/self/exe")
                .expect("Failed to determine running binary location");
            if Path::new(bin_dest).exists() && !*overwrite {
                eprintln!("Binary {} already exists. Use --overwrite to replace.", bin_dest);
                std::process::exit(1);
            }
            // If overwrite requested AND service is active, stop it first
            if *overwrite {
                let status = Command::new("systemctl")
                    .args(&["is-active", "--quiet", "cichlid.service"])
                    .status();
                if let Ok(st) = status {
                    if st.success() {
                        // Service is active, stop it
                        let _ = Command::new("systemctl").args(&["stop", "cichlid.service"]).status();
                    }
                }
            }
            fs::copy(&exe_path, bin_dest)
                .expect("Failed to copy binary to /usr/local/bin/cichlid -- need root?");

            // 4. Make /etc/cichlid/cert and generate default cert/key
            let cert_dir = "/etc/cichlid/cert";
            let default_cert = "/etc/cichlid/cert/default-cert.pem";
            let default_key = "/etc/cichlid/cert/default-key.pem";
            if let Err(e) = fs::create_dir_all(cert_dir) {
                eprintln!("Failed to create cert directory {}: {}", cert_dir, e);
                std::process::exit(1);
            }
            let cert_exists = Path::new(default_cert).exists();
            let key_exists = Path::new(default_key).exists();
            if (cert_exists || key_exists) && !*overwrite {
                eprintln!("Default cert or key already exists in {}. Use --overwrite to replace.", cert_dir);
                std::process::exit(1);
            }
            match certs::generate_self_signed_cert(default_cert, default_key) {
                Ok(_) => println!("Default cert and key generated at {}/", cert_dir),
                Err(e) => {
                    eprintln!("Failed to generate default TLS cert/key: {}", e);
                    std::process::exit(1);
                }
            }

            // 5. Create a systemd unit file referencing the cert/key
            let systemd_unit = format!(
                r#"[Unit]
Description=Cichlid Service
After=network.target

[Service]
User=cichlid
ExecStart=/usr/local/bin/cichlid \
    --cert-path {} \
    --key-path {}
WorkingDirectory=/var/lib/cichlid
Restart=on-failure
LimitNOFILE=4096

[Install]
WantedBy=multi-user.target
"#,
                default_cert, default_key
            );
            let mut unit = File::create("/etc/systemd/system/cichlid.service")
                .expect("Failed to write /etc/systemd/system/cichlid.service -- need root?");
            unit.write_all(systemd_unit.as_bytes())
                .expect("Failed to write systemd file");

            // 6. Reload systemd and enable service
            let _ = Command::new("systemctl").args(&["daemon-reload"]).status();
            let _ = Command::new("systemctl")
                .args(&["enable", "--now", "cichlid.service"])
                .status();

            println!(
                "Cichlid installed, system user, sudoers, binary, cert/key, and service set up."
            );
            return Ok(());
        }
        Some(Command::Uninstall { purge }) => {
            use std::process::Command;
            use std::fs;
            // Check root
            if unsafe { libc::geteuid() } != 0 {
                eprintln!("Uninstall must be run as root (e.g., with sudo)");
                std::process::exit(1);
            }

            // Stop and disable the service
            let _ = Command::new("systemctl").args(&["stop", "cichlid.service"]).status();
            let _ = Command::new("systemctl").args(&["disable", "cichlid.service"]).status();

            if *purge {
                // Remove systemd service unit
                let _ = fs::remove_file("/etc/systemd/system/cichlid.service");
                let _ = Command::new("systemctl").args(&["daemon-reload"]).status();

                // Remove sudoer file
                let _ = fs::remove_file("/etc/sudoers.d/cichlid");

                // Remove binary
                let _ = fs::remove_file("/usr/local/bin/cichlid");

                // Remove config folder and certs
                let _ = fs::remove_dir_all("/etc/cichlid");

                // Delete user
                let _ = Command::new("userdel").args(&["-r", "cichlid"]).status();

                println!("Cichlid service, files, user, and config purged.");
            } else {
                println!("Cichlid service stopped and disabled. (user, binary, and config left intact)");
            }
            return Ok(());
        }
        Some(Command::GenCerts { cert_out, key_out }) => {
            // reject --cert-path or --key-path if present
            if args.cert_path.is_some() || args.key_path.is_some() {
                eprintln!("Error: --cert-path and --key-path must not be used with 'gen-certs'");
                std::process::exit(1);
            }
            certs::generate_self_signed_cert(cert_out, key_out)?;
            println!(
                "Certificates generated at:\n  cert: {}\n  key: {}",
                cert_out, key_out
            );
            return Ok(());
        }
        Some(Command::GenPqCerts {
            cert_out,
            key_out,
            alg,
        }) => {
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
                    "req",
                    "-new",
                    "-x509",
                    "-newkey",
                    alg,
                    "-keyout",
                    key_out.to_str().unwrap(),
                    "-out",
                    cert_out.to_str().unwrap(),
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
                eprintln!(
                    "OpenSSL failed to generate PQ certs with algorithm '{}'",
                    alg
                );
                std::process::exit(1);
            }

            println!(
                "PQ certificate written to:\n  cert: {}\n  key: {}",
                cert_out.display(),
                key_out.display()
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
