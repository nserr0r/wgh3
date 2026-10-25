use anyhow::Result;
use bytes::Bytes;
use http::HeaderMap;
use http::HeaderValue;
use http::Request;
use http::Response;
use http::Uri;
use http::Version;
use http::header;
use http_body_util::BodyExt;
use http_body_util::Full;
use hyper_util::rt::TokioIo;
use std::net::SocketAddr;
use tokio::net::TcpStream;

const HOP_BY_HOP: [&str; 6] = ["connection", "keep-alive", "proxy-connection", "transfer-encoding", "upgrade", "te"];

pub async fn proxy_request(upstream: SocketAddr, request: Request<()>, body: Bytes) -> Result<Response<Bytes>> {
    let request = into_http1(request)?;

    let stream = TcpStream::connect(upstream).await?;
    let (mut sender, connection) = hyper::client::conn::http1::handshake::<_, Full<Bytes>>(TokioIo::new(stream)).await?;

    tokio::spawn(async move {
        let _ = connection.await;
    });

    let response = sender.send_request(request.map(|()| Full::new(body))).await?;
    let (mut parts, body) = response.into_parts();
    let body = body.collect().await?.to_bytes();

    remove_hop_by_hop(&mut parts.headers);
    Ok(Response::from_parts(parts, body))
}

fn into_http1(request: Request<()>) -> Result<Request<()>> {
    let (mut parts, ()) = request.into_parts();

    if !parts.headers.contains_key(header::HOST)
        && let Some(authority) = parts.uri.authority()
    {
        parts.headers.insert(header::HOST, HeaderValue::from_str(authority.as_str())?);
    }

    parts.uri = match parts.uri.path_and_query() {
        Some(path) => Uri::try_from(path.as_str())?,
        None => Uri::from_static("/"),
    };
    parts.version = Version::HTTP_11;
    remove_hop_by_hop(&mut parts.headers);

    Ok(Request::from_parts(parts, ()))
}

fn remove_hop_by_hop(headers: &mut HeaderMap) {
    for name in HOP_BY_HOP {
        headers.remove(name);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;

    async fn upstream_once(response: &'static str) -> (SocketAddr, tokio::task::JoinHandle<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();

        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buffer = vec![0; 4096];
            let size = stream.read(&mut buffer).await.unwrap();
            stream.write_all(response.as_bytes()).await.unwrap();
            String::from_utf8_lossy(&buffer[..size]).into_owned()
        });

        (address, task)
    }

    #[tokio::test]
    async fn http3_request_forwarded_as_http1() {
        let (upstream, received) = upstream_once("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: keep-alive\r\nX-Site: yes\r\n\r\nok").await;

        let request = Request::builder().version(Version::HTTP_3).uri("https://example.com/page?x=1").body(()).unwrap();
        let response = proxy_request(upstream, request, Bytes::new()).await.unwrap();

        assert_eq!(response.status(), 200);
        assert_eq!(response.body(), &Bytes::from_static(b"ok"));
        assert_eq!(response.headers()["x-site"], "yes");
        assert!(!response.headers().contains_key(header::CONNECTION));

        let received = received.await.unwrap().to_lowercase();
        assert!(received.starts_with("get /page?x=1 http/1.1\r\n"), "{received}");
        assert!(received.contains("host: example.com\r\n"), "{received}");
    }

    #[test]
    fn existing_host_header_kept() {
        let request = Request::builder().uri("https://other.example/").header(header::HOST, "example.com").body(()).unwrap();
        let request = into_http1(request).unwrap();

        assert_eq!(request.headers()[header::HOST], "example.com");
        assert_eq!(request.uri(), "/");
        assert_eq!(request.version(), Version::HTTP_11);
    }
}
