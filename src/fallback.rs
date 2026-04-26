use anyhow::Result;
use bytes::Bytes;
use http::Request;
use http::Response;
use http_body_util::BodyExt;
use http_body_util::Full;
use hyper_util::rt::TokioIo;
use std::net::SocketAddr;
use tokio::net::TcpStream;

pub async fn proxy_request(upstream: SocketAddr, request: Request<()>, body: Bytes) -> Result<Response<Bytes>> {
    let stream = TcpStream::connect(upstream).await?;
    let io = TokioIo::new(stream);

    let (mut sender, conn) = hyper::client::conn::http1::handshake::<_, Full<Bytes>>(io).await?;

    tokio::spawn(async move {
        let _ = conn.await;
    });

    let (parts, _) = request.into_parts();
    let upstream_request = Request::from_parts(parts, Full::new(body));

    let response = sender.send_request(upstream_request).await?;
    let (parts, body) = response.into_parts();
    let bytes = body.collect().await?.to_bytes();

    Ok(Response::from_parts(parts, bytes))
}
