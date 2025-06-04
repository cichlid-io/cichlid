use crate::config_store::ConfigStore;
use crate::types::ConfigItem;
use hyper::{Body, Request, Response, StatusCode};

use std::sync::Arc;

pub async fn route_request(
    req: Request<Body>,
    config_store: ConfigStore,
    peer_db: Arc<sled::Db>,
) -> Result<Response<Body>, hyper::Error> {
    use hyper::Method;

    // Determine mTLS status of the CURRENT request
    let current_request_mtls_ok = req.extensions()
        .get::<crate::types::ClientAuthStatus>() // Ensure correct path
        .map_or(false, |status| status.cert_presented && status.cert_verified_ok);

    match (req.method(), req.uri().path()) {
        (&Method::GET, "/health") => {
            let version = env!("CARGO_PKG_VERSION");
            let build = option_env!("GIT_COMMIT_HASH").unwrap_or("unknown");
            let mut health_data = serde_json::json!({
                "version": version,
                "build": build,
            });

            // Check for client certificate from SslStream in request extensions
            // Check for client certificate from ClientAuthStatus in request extensions
            if let Some(auth_status) = req.extensions().get::<crate::types::ClientAuthStatus>() {
                if auth_status.cert_presented && auth_status.cert_verified_ok {
                // In a real system, fetch this from /etc/machine-id or similar
                let system_uuid = std::fs::read_to_string("/etc/machine-id")
                    .unwrap_or_else(|_| "unknown-uuid".to_string())
                    .trim()
                    .to_string();
                health_data["uuid"] = serde_json::json!(system_uuid);
                }
            }

            let json_body = serde_json::to_string(&health_data).unwrap();
            Ok(Response::builder()
                .header("Content-Type", "application/json")
                .body(Body::from(json_body))
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

        (&Method::GET, "/peers") => {
            use serde_json::Value;
            let mut peers_response_list = vec![]; // Build a list of JSON Values for the response

            for res in peer_db.iter() {
                if let Ok((_key, sled_value)) = res {
                    if let Ok(peer_record) = serde_json::from_slice::<crate::peers::PeerRecord>(&sled_value) {
                        // Try to parse the persisted health string into a JSON Value
                        match serde_json::from_str::<Value>(&peer_record.health) {
                            Ok(mut health_obj) => { // health_obj is now a mutable Value, likely an Object
                                if !current_request_mtls_ok {
                                    // If current request is not mTLS authenticated, remove uuid from this peer's health
                                    if let Some(obj_map) = health_obj.as_object_mut() {
                                        obj_map.remove("uuid");
                                    }
                                }
                                // Construct the peer object for the response list
                                let mut response_peer_map = serde_json::Map::new();
                                response_peer_map.insert("ip".to_string(), Value::String(peer_record.ip));
                                response_peer_map.insert("port".to_string(), Value::Number(peer_record.port.into()));
                                response_peer_map.insert("health".to_string(), health_obj); // health_obj might have had uuid removed
                                response_peer_map.insert("last_observed".to_string(), Value::Number(peer_record.last_observed.into()));
                                peers_response_list.push(Value::Object(response_peer_map));
                            }
                            Err(_) => {
                                // Health string wasn't valid JSON, include it as a string, or handle error
                                // For simplicity, let's just create a basic representation
                                let mut response_peer_map = serde_json::Map::new();
                                response_peer_map.insert("ip".to_string(), Value::String(peer_record.ip));
                                response_peer_map.insert("port".to_string(), Value::Number(peer_record.port.into()));
                                response_peer_map.insert("health".to_string(), Value::String("Error parsing health data".to_string())); // Or include raw string
                                response_peer_map.insert("last_observed".to_string(), Value::Number(peer_record.last_observed.into()));
                                peers_response_list.push(Value::Object(response_peer_map));
                            }
                        }
                    }
                }
            }
            let json_body = serde_json::to_string(&peers_response_list).unwrap_or_else(|_| "[]".to_string());
            Ok(Response::builder()
                .header("Content-Type", "application/json")
                .body(Body::from(json_body))
                .unwrap())
        }

        _ => Ok(Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Body::from("{\"error\": \"not found\"}"))
            .unwrap()),
    }
}
