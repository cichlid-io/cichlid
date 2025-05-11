use crate::select_stream_or_shutdown::select_stream_or_shutdown;
use crate::types::GenericBoxedStream;

use tokio::sync::Notify;
use tracing::info;
use std::sync::Arc;

/// Run a TLS stream listener with graceful shutdown
pub async fn serve_tls_stream<T>(
    mut stream: GenericBoxedStream<T>,
    shutdown_notify: Arc<Notify>,
    handler: impl Fn(T) -> tokio::task::JoinHandle<()> + Send + Sync + 'static,
) -> Result<(), Box<dyn std::error::Error>> {
    loop {
        match select_stream_or_shutdown(stream.as_mut(), shutdown_notify.clone()).await {
            Ok(Some(item)) => {
                handler(item);
            }
            Ok(None) => {
                info!("Stream ended");
                break;
            }
            Err(()) => {
                info!("Shutdown requested");
                break;
            }
        }
    }

    Ok(())
}
