use std::{net::{IpAddr, Ipv4Addr, SocketAddr}, time::Duration, sync::Arc};
use tokio::{sync::Notify, task, time};
use tracing::{info, trace};
use hyper::{Client, Body};
use hyper_openssl::HttpsConnector;

pub async fn run_workers(shutdown: Arc<Notify>, port: u16) {
    info!("Worker runtime started");

    // Spawn network discovery worker
    let discovery_shutdown = shutdown.clone();

    let build = option_env!("GIT_COMMIT_HASH").unwrap_or("unknown");
    let version = env!("CARGO_PKG_VERSION");

    let handle = task::spawn(async move {
        // Only scan local IPv4 network for brevity (assume /24)
        let our_ip = local_ip_address::local_ip()
            .map(|ip| ip.to_string())
            .unwrap_or_else(|_| "127.0.0.1".to_string());
        let base = match our_ip.parse::<Ipv4Addr>() {
            Ok(ip) => Ipv4Addr::new(ip.octets()[0], ip.octets()[1], ip.octets()[2], 0),
            Err(_) => Ipv4Addr::new(127, 0, 0, 0),
        };
        let mut tasks = vec![];

        for i in 1u8..=254 {
            let shutdown = discovery_shutdown.clone();
            let target = Ipv4Addr::new(base.octets()[0], base.octets()[1], base.octets()[2], i);

            // Avoid self
            if our_ip == target.to_string() {
                continue;
            }

            let addr = SocketAddr::new(IpAddr::V4(target), port);
            tasks.push(tokio::spawn(discover_cichlid(addr, version, build, shutdown.clone())));
        }

        futures_util::future::join_all(tasks).await;
    });

    // Spawn dummy worker
    let main_worker = task::spawn({
        let shutdown = shutdown.clone();
        async move {
            loop {
                tokio::select! {
                    _ = tokio::time::sleep(Duration::from_secs(5)) => {
                        info!("Worker: performing background task...");
                    }
                    _ = shutdown.notified() => {
                        info!("Worker: shutdown signal received");
                        break;
                    }
                }
            }
        }
    });

    let _ = futures_util::future::join_all(vec![handle, main_worker]).await;

    info!("Worker runtime exited");
}

async fn discover_cichlid(addr: SocketAddr, _version: &str, _build: &str, _shutdown: Arc<Notify>) {
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
    match res {
        Ok(Ok(resp)) => {
            if resp.status().is_success() {
                info!("Discovered cichlid at {}", addr.ip());
            } else {
                trace!("No response from {} (HTTP {})", addr.ip(), resp.status());
            }
        }
        _ => {
            trace!("No response from {}", addr.ip());
        }
    }
}
