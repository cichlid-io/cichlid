use crate::config_store::ConfigStore;
use crate::types::ConfigItem;
use hyper::{Body, Request, Response, StatusCode};
use hyper::server::conn::Http;
use hyper::service::service_fn;
use tokio::net::TcpStream;
use tokio_openssl::SslStream;
use tracing::error;

pub async fn handle_tls_connection(
    stream: SslStream<TcpStream>,
    config_store: ConfigStore,
) {
    let service = service_fn(move |req| {
        let store = config_store.clone();
        async move { route_request(req, store).await }
    });

    if let Err(e) = Http::new().serve_connection(stream, service).await {
        error!("TLS connection error: {}", e);
    }
}

pub async fn route_request(
    req: Request<Body>,
    config_store: ConfigStore,
) -> Result<Response<Body>, hyper::Error> {
    use hyper::Method;

    match (req.method(), req.uri().path()) {
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

        _ => Ok(Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Body::from("{\"error\": \"not found\"}"))
            .unwrap()),
    }
}
