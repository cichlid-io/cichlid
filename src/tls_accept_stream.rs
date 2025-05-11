use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;

use async_stream::stream;
use futures_util::Stream;
use openssl::ssl::{Ssl, SslAcceptor};
use tokio::net::{TcpListener, TcpStream};
use tokio_openssl::SslStream;
use tracing::{error, info};

pub fn tls_accept_stream(
    listener: TcpListener,
    acceptor: Arc<SslAcceptor>,
) -> impl Stream<Item = Result<SslStream<TcpStream>, io::Error>> {
    stream! {
        loop {
            let (stream, addr): (TcpStream, SocketAddr) = match listener.accept().await {
                Ok(pair) => pair,
                Err(e) => {
                    error!("TCP accept error: {}", e);
                    continue;
                }
            };

            let ssl = match Ssl::new(acceptor.context()) {
                Ok(ssl) => ssl,
                Err(e) => {
                    error!("Failed to create SSL context for {}: {}", addr, e);
                    continue;
                }
            };

            match SslStream::new(ssl, stream) {
                Ok(mut ssl_stream) => {
                    let mut pinned = Pin::new(&mut ssl_stream);
                    match pinned.as_mut().accept().await {
                        Ok(_) => {
                            info!("TLS handshake successful with {}", addr);
                            yield Ok(ssl_stream);
                        }
                        Err(e) => {
                            error!("TLS handshake failed with {}: {}", addr, e);
                        }
                    }
                }
                Err(e) => {
                    error!("Failed to create SSL stream for {}: {}", addr, e);
                }
            }
        }
    }
}
