use crate::config_store::ConfigStore;
use crate::types::ConfigItem;
use hyper::server::conn::Http;
use hyper::service::service_fn;
use hyper::{Body, Request, Response, StatusCode};
use tokio::net::TcpStream;
//use tokio::io::AsyncWriteExt;
use tokio_openssl::SslStream;
use tracing::error;

pub async fn handle_tls_connection(mut stream: SslStream<TcpStream>, config_store: ConfigStore) {
    let service = service_fn(move |req| {
        let store = config_store.clone();
        async move { route_request(req, store).await }
    });

    let remote_addr = stream.get_ref().peer_addr().ok();

    let result = Http::new().serve_connection(&mut stream, service).await;
    if let Err(e) = result {
        error!("TLS connection error: {}", e);
    }
    // Ensure shutdown and closure
    if let Err(e) = tokio::io::AsyncWriteExt::shutdown(stream.get_mut()).await {
        error!("TLS/TCP shutdown error: {:?}", e);
    }
    drop(stream);
    if let Some(addr) = remote_addr {
        tracing::info!("TLS connection with {} closed and resources dropped.", addr);
    }
}

pub async fn route_request(
    req: Request<Body>,
    config_store: ConfigStore,
) -> Result<Response<Body>, hyper::Error> {
    use hyper::Method;

    match (req.method(), req.uri().path()) {
        (&Method::GET, "/health") => {
            // Compile-time version and build hash, set with env! or option_env!
            let version = env!("CARGO_PKG_VERSION");
            let build = option_env!("GIT_COMMIT_HASH").unwrap_or("unknown");
            let json = format!(r#"{{ "version": "{}", "build": "{}" }}"#, version, build);
            Ok(Response::builder()
                .header("Content-Type", "application/json")
                .body(Body::from(json))
                .unwrap())
        }
        (&Method::GET, "/configs") => {
            let store = config_store.lock().unwrap();
            let json = serde_json::to_string(&*store).unwrap();
            Ok(Response::new(Body::from(json)))
        }

        (&Method::POST, "/config") => {
            let body = hyper::body::to_bytes(req.into_body()).await?;
            match serde_json::from_slice::<ConfigItem>(&body) {
                Ok(item) => {
                    config_store.lock().unwrap().push(item);
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

        (&Method::GET, "/peers") => match sled::open("peers_db") {
            Ok(db) => {
                let mut peers = vec![];
                for res in db.iter() {
                    if let Ok((_, v)) = res {
                        if let Ok(rec) = serde_json::from_slice::<crate::workers::PeerRecord>(&v) {
                            peers.push(rec);
                        }
                    }
                }
                let json = serde_json::to_string(&peers).unwrap_or_else(|_| "[]".to_string());
                Ok(Response::builder()
                    .header("Content-Type", "application/json")
                    .body(Body::from(json))
                    .unwrap())
            }
            Err(_) => Ok(Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Body::from("{\"error\": \"db not available\"}"))
                .unwrap()),
        },

        _ => Ok(Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Body::from("{\"error\": \"not found\"}"))
            .unwrap()),
    }
}
