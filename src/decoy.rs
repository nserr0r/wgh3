use crate::fallback;
use anyhow::Result;
use bytes::Bytes;
use http_body_util::BodyExt;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
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
            Err(_) => continue,
        };

        let acceptor = acceptor.clone();

        tokio::spawn(async move {
            let tls_stream = match acceptor.accept(stream).await {
                Ok(value) => value,
                Err(_) => return,
            };

            let io = TokioIo::new(tls_stream);
            let service = service_fn(move |request| handle(upstream, request));

            let _ = hyper::server::conn::http1::Builder::new().keep_alive(true).serve_connection(io, service).await;
        });
    }
}

async fn handle(upstream: SocketAddr, request: hyper::Request<Incoming>) -> Result<hyper::Response<Full<Bytes>>> {
    let (parts, body) = request.into_parts();
    let bytes = body.collect().await?.to_bytes();
    let request = hyper::Request::from_parts(parts, ());

    match fallback::proxy_request(upstream, request, bytes).await {
        Ok(response) => {
            let (parts, body) = response.into_parts();
            Ok(hyper::Response::from_parts(parts, Full::new(body)))
        }
        Err(err) => {
            eprintln!("ошибка decoy proxy: {err:#}");
            Ok(hyper::Response::builder().status(502).body(Full::new(Bytes::from_static(b"bad gateway"))).unwrap())
        }
    }
}
