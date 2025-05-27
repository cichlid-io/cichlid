use hyper::{Body, Client};
use hyper_openssl::HttpsConnector;
use serde::{Deserialize, Serialize};
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};
use tokio::{sync::Notify, time};
use tracing::{info, trace};
use get_if_addrs::get_if_addrs;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct PeerRecord {
    pub ip: String,
    pub port: u16,
    pub health: String, // raw JSON from /health
    pub last_observed: i64,
}

pub async fn run_workers(shutdown: Arc<Notify>, port: u16, discovery_interval: u64) {
    info!("Worker runtime started");

    // Open sled db for peers
    let peer_db = sled::open("peers_db").expect("Failed to open sled DB");

    // Spawn network discovery worker
    let _build = option_env!("GIT_COMMIT_HASH").unwrap_or("unknown");
    let _version = env!("CARGO_PKG_VERSION");

    // Spawn peer discovery as a detached background task
    tokio::spawn({
        let shutdown = shutdown.clone();
        async move {
            loop {
                tokio::select! {
                    _ = tokio::time::sleep(Duration::from_secs(discovery_interval)) => {
                        info!("Worker: performing background peer discovery...");
                        // Run peer discovery every cycle using get_if_addrs for subnet detection
                        let mut peer_scan_tasks = Vec::new();
                        match get_if_addrs() {
                            Ok(addrs) => {
                                for iface in addrs.into_iter() {
                                    if let get_if_addrs::IfAddr::V4(ifv4) = iface.addr {
                                        let ipv4 = ifv4.ip;
                                        // Skip loopback networks (starting with 127)
                                        if ipv4.octets()[0] == 127 {
                                            continue;
                                        }
                                        let mask = ifv4.netmask;
                                        let prefix_len = mask.octets()
                                            .iter()
                                            .map(|b| b.count_ones())
                                            .sum::<u32>();
                                        let base_u32 = u32::from_be_bytes(ipv4.octets()) & u32::from_be_bytes(mask.octets());
                                        let host_bits = 32 - prefix_len;
                                        let max_hosts = if host_bits > 0 { (1u32 << host_bits) - 2 } else { 0 };
                                        info!(
                                            "Peer discovery: interface {}  {}/{}  mask={} prefix={} scanning {} IPs",
                                            iface.name, ipv4, prefix_len, mask, prefix_len, max_hosts
                                        );
                                        for i in 1..=max_hosts {
                                            let candidate = base_u32 + i;
                                            let candidate_ip = Ipv4Addr::from(candidate);
                                            // Avoid self
                                            if candidate_ip == ipv4 { continue; }
                                            let addr = SocketAddr::new(IpAddr::V4(candidate_ip), port);
                                            let peer_db = peer_db.clone();
                                            peer_scan_tasks.push(tokio::spawn(discover_and_track_cichlid(addr, peer_db)));
                                        }
                                    }
                                }
                            }
                            Err(e) => {
                                info!("if-addrs error: {}", e);
                            }
                        }
                        futures_util::future::join_all(peer_scan_tasks).await;
                    }
                    _ = shutdown.notified() => {
                        info!("Worker: shutdown signal received (discovery)");
                        break;
                    }
                }
            }
        }
    });

    // Wait forever for shutdown so discovery runs continuously
    shutdown.notified().await;
    info!("Worker runtime exited");
}

async fn discover_and_track_cichlid(addr: SocketAddr, peer_db: sled::Db) {
    info!("ping {}:{}", addr.ip(), addr.port());
    let url = format!("https://{}:{}/health", addr.ip(), addr.port());
    let https = match HttpsConnector::new() {
        Ok(conn) => conn,
        Err(_) => {
            trace!("Failed to create HTTPS connector");
            return;
        }
    };
    let client: Client<_, Body> = Client::builder().build(https);

    let req = match hyper::Request::get(&url).body(Body::empty()) {
        Ok(r) => r,
        Err(_) => return,
    };
    let res = time::timeout(Duration::from_secs(2), client.request(req)).await;
    let now = chrono::Utc::now().timestamp();
    match res {
        Ok(Ok(mut resp)) if resp.status().is_success() => {
            let health_bytes = match hyper::body::to_bytes(resp.body_mut()).await {
                Ok(b) => b,
                Err(_) => {
                    trace!("No response from {} (body read fail)", addr.ip());
                    return;
                }
            };
            let health_json: String = String::from_utf8_lossy(&health_bytes).to_string();
            let key = format!("{}:{}", addr.ip(), addr.port());
            let new_record = PeerRecord {
                ip: addr.ip().to_string(),
                port: addr.port(),
                health: health_json.clone(),
                last_observed: now,
            };

            let prev: Option<PeerRecord> = peer_db
                .get(&key)
                .ok()
                .and_then(|iv| iv.and_then(|v| serde_json::from_slice(&v).ok()));
            if let Some(mut prev_rec) = prev {
                if prev_rec.health == new_record.health {
                    prev_rec.last_observed = now;
                    if let Ok(val) = serde_json::to_vec(&prev_rec) {
                        let _ = peer_db.insert(&key, val);
                    }
                } else {
                    if let Ok(val) = serde_json::to_vec(&new_record) {
                        let _ = peer_db.insert(&key, val);
                    }
                    info!(
                        "Discovered UPDATED cichlid at {}:{} -- new health: {}",
                        addr.ip(),
                        addr.port(),
                        new_record.health
                    );
                }
            } else {
                if let Ok(val) = serde_json::to_vec(&new_record) {
                    let _ = peer_db.insert(&key, val);
                }
                info!(
                    "Discovered NEW cichlid at {}:{} -- health: {}",
                    addr.ip(),
                    addr.port(),
                    new_record.health
                );
            }
        }
        _ => {
            trace!("No response from {}", addr.ip());
        }
    }
}
