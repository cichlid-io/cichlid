use crate::peers::PeerRecord;
use get_if_addrs::get_if_addrs;
use openssl::ssl::{SslConnector, SslFiletype, SslMethod, SslVerifyMode};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::sync::Notify;
use tokio_openssl::SslStream;
use tracing::info;

pub async fn run_workers(
    shutdown: Arc<Notify>,
    port: u16,
    discovery_interval: u64,
    peer_db: Arc<sled::Db>,
    cert_path: std::path::PathBuf,
    key_path: std::path::PathBuf,
    ca_cert_path: std::path::PathBuf,
) {
    info!("Worker runtime started");
    tracing::info!("cichlid worker started, PID={}", std::process::id());

    // Build SslConnector ONCE for all peer scans
    let mut builder = SslConnector::builder(SslMethod::tls()).unwrap();
    builder.set_certificate_chain_file(&cert_path).unwrap();
    builder
        .set_private_key_file(&key_path, SslFiletype::PEM)
        .unwrap();
    builder.set_ca_file(&ca_cert_path).unwrap();
    builder.set_verify(SslVerifyMode::PEER);
    let ssl = Arc::new(builder.build());

    use tokio::sync::Semaphore;
    let concurrency = Arc::new(Semaphore::new(32)); // Limit concurrent probes (tune as needed)
    tokio::spawn({
        let ssl = ssl.clone();
        let peer_db = peer_db.clone();
        let shutdown = shutdown.clone();
        let concurrency = concurrency.clone();
        async move {
            loop {
                tokio::select! {
                    _ = tokio::time::sleep(std::time::Duration::from_secs(discovery_interval)) => {
                        let mut tasks = Vec::new();
                        if let Ok(addrs) = get_if_addrs() {
                            for iface in addrs {
                                if let get_if_addrs::IfAddr::V4(ifv4) = iface.addr {
                                    let ipv4 = ifv4.ip;
                                    if ipv4.octets()[0] == 127 { continue; }
                                    let mask = ifv4.netmask;
                                    let prefix_len = mask.octets().iter().map(|b| b.count_ones()).sum::<u32>();
                                    let base_u32 = u32::from_be_bytes(ipv4.octets()) & u32::from_be_bytes(mask.octets());
                                    let host_bits = 32 - prefix_len;
                                    let max_hosts = if host_bits > 0 { (1u32 << host_bits) - 2 } else { 0 };
                                    for i in 1..=max_hosts {
                                        let candidate_ip = Ipv4Addr::from(base_u32 + i);
                                        if candidate_ip == ipv4 { continue; }
                                        let addr = SocketAddr::new(IpAddr::V4(candidate_ip), port);
                                        let peer_db = peer_db.clone();
                                        let ssl = ssl.clone();
                                        let semaphore = concurrency.clone();
                                        tasks.push(tokio::spawn(async move {
                                            let _permit = semaphore.acquire_owned().await.unwrap();
                                            discover_and_track_cichlid(addr, peer_db, ssl).await;
                                        }));
                                    }
                                }
                            }
                        }
                        futures_util::future::join_all(tasks).await;
                    }
                    _ = shutdown.notified() => break,
                }
            }
        }
    });
    shutdown.notified().await;
}

async fn discover_and_track_cichlid(
    addr: SocketAddr,
    peer_db: Arc<sled::Db>,
    ssl: Arc<SslConnector>,
) {
    if addr.ip().to_string() == "10.49.0.10" {
        println!("WORKER ENTRY: {:?}", addr);
    }
    use std::pin::Pin;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let tcp = match TcpStream::connect(addr).await {
        Ok(s) => s,
        Err(e) => {
            match e.kind() {
                std::io::ErrorKind::HostUnreachable => {
                    // do nothing. this address is unreachable.
                    //tracing::trace!("Peer {}: Host unreachable", addr);
                }
                std::io::ErrorKind::ConnectionRefused => {
                    // found something here, but it's not a cichlid
                    tracing::info!("Peer {}: Connection refused", addr);
                }
                _ => {
                    tracing::warn!("Peer {}: Connection error: {}", addr, e);
                }
            }
            //tracing::trace!("Peer {}: TCP connect failed: {}", addr, e);
            return;
        }
    };

    let ssl = match openssl::ssl::Ssl::new(ssl.context()) {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!("Peer {}: SSL context failed: {}", addr, e);
            return;
        }
    };
    let mut tls = match SslStream::new(ssl, tcp) {
        Ok(stream) => stream,
        Err(e) => {
            tracing::warn!("Peer {}: SslStream construct fail: {}", addr, e);
            return;
        }
    };
    if let Err(e) = Pin::new(&mut tls).connect().await {
        tracing::warn!("Peer {}: TLS handshake failed: {}", addr, e);
        return;
    }

    // Write: GET /health HTTP/1.1 ...
    let http_req = format!(
        "GET /health HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
        addr.ip()
    );
    if let Err(e) = tls.write_all(http_req.as_bytes()).await {
        tracing::warn!("Peer {}: write_all failed: {}", addr, e);
        return;
    }
    let mut buf = Vec::new();
    if let Err(e) = tls.read_to_end(&mut buf).await {
        tracing::warn!("Peer {}: read_to_end failed: {}", addr, e);
        return;
    }
    let response = String::from_utf8_lossy(&buf);

    info!("Peer {}: full HTTP response: {}", addr, response);

    // New robust HTTP parsing for /health
    let now = chrono::Utc::now().timestamp();
    let mut found_200 = false;
    // let mut found_version = false; // removed to silence unused assignment
    let mut json_start = None;

    for (i, line) in response.lines().enumerate() {
        if i == 0 && line.contains("200 OK") {
            found_200 = true;
        }
        if line.contains('{') && json_start.is_none() {
            json_start = Some(response.find('{').unwrap());
        }
    }
    if let Some(start) = json_start {
        let json = &response[start..];
        let found_version = json.contains("version");
        if found_200 && found_version {
            let key = format!("{}:{}", addr.ip(), addr.port());
            let health_json = json.to_string();
            info!("Peer {}: will persist health record: {}", addr, health_json);

            let new_record = PeerRecord {
                ip: addr.ip().to_string(),
                port: addr.port(),
                health: health_json.clone(),
                last_observed: now,
            };

            match serde_json::to_vec(&new_record) {
                Ok(val) => match peer_db.insert(&key, val) {
                    Ok(Some(prev_val)) => {
                        if let Ok(old_rec) = serde_json::from_slice::<PeerRecord>(&prev_val) {
                            if old_rec.health == new_record.health {
                                info!(
                                    "Discovered UPDATED cichlid at {}:{} -- health: {}",
                                    addr.ip(),
                                    addr.port(),
                                    new_record.health
                                );
                            } else {
                                info!(
                                    "Discovered CHANGED cichlid at {}:{} -- old health: {} -- new health: {}",
                                    addr.ip(),
                                    addr.port(),
                                    old_rec.health,
                                    new_record.health
                                );
                            }
                        } else {
                            info!(
                                "Discovered UPDATED cichlid at {}:{} (could not decode previous value)",
                                addr.ip(),
                                addr.port()
                            );
                        }
                    }
                    Ok(None) => {
                        info!(
                            "Discovered NEW cichlid at {}:{} -- health: {}",
                            addr.ip(),
                            addr.port(),
                            new_record.health
                        );
                    }
                    Err(e) => {
                        tracing::error!(
                            "Failed to persist peer (sled insert) {}:{}: {}",
                            addr.ip(),
                            addr.port(),
                            e
                        );
                    }
                },
                Err(e) => {
                    tracing::error!(
                        "Failed to serialize PeerRecord for {}:{}: {}",
                        addr.ip(),
                        addr.port(),
                        e
                    );
                }
            }
        } else {
            info!(
                "Peer {}: 200 OK but could not locate version or valid JSON body. Found_200={:?}, Found_version={:?}",
                addr, found_200, found_version
            );
        }
    } else {
        info!(
            "Peer {}: HTTP response missing JSON body. Full: {}",
            addr, response
        );
    }
}
