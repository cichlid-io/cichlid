use std::time::Duration;
use std::sync::Arc;
use tokio::sync::Notify;
use tokio::task;
use tracing::{info, error};

pub async fn run_workers(shutdown: Arc<Notify>) {
    info!("Worker runtime started");

    let handle = task::spawn(async move {
        loop {
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_secs(5)) => {
                    info!("Worker: performing background task...");
                    // insert actual worker logic here
                }
                _ = shutdown.notified() => {
                    info!("Worker: shutdown signal received");
                    break;
                }
            }
        }
    });

    if let Err(e) = handle.await {
        error!("Worker task exited with error: {:?}", e);
    }

    info!("Worker runtime exited");
}
