use std::io;
use std::sync::Arc;

use async_stream::stream;
use futures_util::Stream;
use openssl::ssl::{Ssl, SslAcceptor};
use tokio::net::{TcpListener, TcpStream};
use tokio_openssl::SslStream;

pub fn tls_accept_stream(
    listener: TcpListener,
    acceptor: Arc<SslAcceptor>,
) -> impl Stream<Item = Result<SslStream<TcpStream>, io::Error>> {
    stream! {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(pair) => pair,
                Err(e) => {
                    yield Err(e);
                    continue;
                }
            };

            // Construct Ssl object from context
            let ssl = match Ssl::new(acceptor.context()) {
                Ok(ssl) => ssl,
                Err(e) => {
                    yield Err(io::Error::new(io::ErrorKind::Other, e));
                    continue;
                }
            };

            // Wrap TcpStream and perform TLS handshake asynchronously
            match SslStream::new(ssl, stream) {
                Ok(mut ssl_stream) => {
                    let mut pinned = std::pin::Pin::new(&mut ssl_stream);
                    match pinned.as_mut().accept().await {
                        Ok(_) => yield Ok(ssl_stream),
                        Err(e) => yield Err(io::Error::new(io::ErrorKind::Other, e)),
                    }
                }
                Err(e) => {
                    yield Err(io::Error::new(io::ErrorKind::Other, e));
                }
            }
        }
    }
}
