use std::pin::Pin;
use std::sync::Arc;
use tokio::sync::Notify;
use futures_util::Stream;
use futures_util::StreamExt;

/// Await the next item from a stream or a shutdown signal.
///
/// - Returns `Ok(Some(item))` when the stream yields
/// - Returns `Ok(None)` when the stream ends
/// - Returns `Err(())` on shutdown
pub async fn select_stream_or_shutdown<T>(
    mut stream: Pin<&mut (dyn Stream<Item = T> + Send)>,
    shutdown_notify: Arc<Notify>,
) -> Result<Option<T>, ()> {
    tokio::select! {
        item = stream.next() => Ok(item),
        _ = shutdown_notify.notified() => Err(()),
    }
}
