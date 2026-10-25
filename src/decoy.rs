use crate::fallback;
use anyhow::Result;
use bytes::Bytes;
use http::StatusCode;
use http_body_util::BodyExt;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::TokioExecutor;
use hyper_util::rt::TokioIo;
use hyper_util::server::conn::auto;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

pub async fn run(listen: SocketAddr, upstream: SocketAddr, tls: Arc<rustls::ServerConfig>) -> Result<()> {
    let listener = TcpListener::bind(listen).await?;
    let acceptor = TlsAcceptor::from(tls);

    loop {
        let (stream, _) = match listener.accept().await {
            Ok(value) => value,
            Err(err) => {
                tracing::debug!(?err, "decoy accept");
                continue;
            }
        };

        let acceptor = acceptor.clone();

        tokio::spawn(async move {
            let Ok(tls_stream) = acceptor.accept(stream).await else {
                return;
            };

            let service = service_fn(move |request| handle(upstream, request));
            let _ = auto::Builder::new(TokioExecutor::new()).serve_connection(TokioIo::new(tls_stream), service).await;
        });
    }
}

async fn handle(upstream: SocketAddr, request: hyper::Request<Incoming>) -> Result<hyper::Response<Full<Bytes>>> {
    let (parts, body) = request.into_parts();
    let body = body.collect().await?.to_bytes();

    match fallback::proxy_request(upstream, hyper::Request::from_parts(parts, ()), body).await {
        Ok(response) => Ok(response.map(Full::new)),
        Err(err) => {
            tracing::warn!(?err, "ошибка decoy proxy");
            let mut response = hyper::Response::new(Full::new(Bytes::from_static(b"bad gateway")));
            *response.status_mut() = StatusCode::BAD_GATEWAY;
            Ok(response)
        }
    }
}
