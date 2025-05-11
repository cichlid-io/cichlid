use clap::Parser;
use hyper::{service::{make_service_fn, service_fn}, Body, Method, Request, Response, Server, StatusCode};
use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod};
use serde::{Deserialize, Serialize};
use std::{net::SocketAddr, sync::{Arc, Mutex}};
use tokio::task;
use tracing::{info, error};
use tracing_subscriber;

mod tls_accept_stream;
use tls_accept_stream::tls_accept_stream;

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

#[derive(Debug, Serialize, Deserialize, Clone)]
struct ConfigItem {
    id: String,
    server_ip: String,
    ssh_user: String,
    ssh_port: u16,
    commands: Vec<String>,
}

type ConfigStore = Arc<Mutex<Vec<ConfigItem>>>;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    let args = Args::parse();

    let config_store: ConfigStore = Arc::new(Mutex::new(vec![]));

    let web_handle = task::spawn(run_web_server(args.clone(), config_store.clone()));
    let worker_handle = task::spawn(run_workers(config_store.clone()));

    if let Err(e) = tokio::try_join!(web_handle, worker_handle) {
        error!("Runtime failed: {:?}", e);
    }
}

async fn run_web_server(args: Args, config_store: ConfigStore) {
    let addr: SocketAddr = format!("{}:{}", args.host, args.port)
        .parse()
        .expect("Invalid host or port");

    let mut builder = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();
    builder.set_private_key_file(&args.key_path, SslFiletype::PEM).unwrap();
    builder.set_certificate_chain_file(&args.cert_path).unwrap();
    let ssl_acceptor = Arc::new(builder.build());

    let tcp_listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("bind failed");

    info!("Web server listening on https://{}", addr);

    let make_svc = make_service_fn(move |_conn| {
        let store = config_store.clone();
        async move {
            Ok::<_, hyper::Error>(service_fn(move |req| {
                route_request(req, store.clone())
            }))
        }
    });

    let tls_stream = tls_accept_stream(tcp_listener, ssl_acceptor);

    let server = Server::builder(hyper::server::accept::from_stream(tls_stream))
        .serve(make_svc);

    // Setup graceful shutdown (Ctrl+C or systemd SIGINT)
    let shutdown_signal = async {
        tokio::signal::ctrl_c().await.expect("failed to install Ctrl+C handler");
        info!("Shutdown signal received");
    };

    if let Err(e) = server.with_graceful_shutdown(shutdown_signal).await {
        error!("Server error: {}", e);
    }
}

async fn route_request(req: Request<Body>, config_store: ConfigStore) -> Result<Response<Body>, hyper::Error> {
    match (req.method(), req.uri().path()) {
        (&Method::GET, "/configs") => {
            let configs = config_store.lock().unwrap();
            let json = serde_json::to_string(&*configs).unwrap();
            Ok(Response::new(Body::from(json)))
        }

        (&Method::POST, "/config") => {
            let whole_body = hyper::body::to_bytes(req.into_body()).await?;
            match serde_json::from_slice::<ConfigItem>(&whole_body) {
                Ok(config) => {
                    config_store.lock().unwrap().push(config);
                    Ok(Response::builder()
                        .status(StatusCode::CREATED)
                        .body(Body::from("{\"status\": \"stored\"}"))
                        .unwrap())
                }
                Err(_) => Ok(Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .body(Body::from("{\"error\": \"invalid JSON\"}"))
                    .unwrap()),
            }
        }

        _ => Ok(Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Body::from("{\"error\": \"not found\"}"))
            .unwrap()),
    }
}

async fn run_workers(config_store: ConfigStore) {
    info!("Worker runtime started.");
    loop {
        // simulate periodic worker task
        {
            let configs = config_store.lock().unwrap();
            info!("Worker sees {} configs", configs.len());
        }

        tokio::time::sleep(std::time::Duration::from_secs(10)).await;
    }
}
