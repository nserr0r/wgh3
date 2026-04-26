use crate::config::Config;
use crate::decoy;
use crate::fallback;
use crate::masque;
use crate::tls;
use anyhow::Context;
use anyhow::Result;
use bytes::Buf;
use bytes::Bytes;
use h3::proto::stream::StreamId;
use h3_datagram::datagram_handler::HandleDatagramsExt;
use h3_quinn::Connection as H3QuinnConnection;
use http::Response;
use http::StatusCode;
use quinn::Endpoint;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tokio::sync::mpsc;

type SessionMap = Arc<Mutex<HashMap<StreamId, Session>>>;

enum Session {
    Pending(Vec<Bytes>),
    Active(mpsc::Sender<Bytes>),
}

pub async fn run(config: Config) -> Result<()> {
    let tls_config = config.tls.clone().context("требуется секция tls в конфиге")?;
    config.wireguard.as_ref().context("требуется секция wireguard в конфиге сервера")?;

    let server_config = tls::server_config(&tls_config.cert, &tls_config.key)?;
    let endpoint = Endpoint::server(server_config, config.listen)?;

    eprintln!("[server] quic слушает на {}", config.listen);

    if let Some(fallback) = config.fallback.clone()
        && let Some(listen_tcp) = fallback.listen_tcp
    {
        let rustls_config = tls::rustls_server_config(&tls_config.cert, &tls_config.key)?;

        eprintln!("[decoy] слушает на {} → {}", listen_tcp, fallback.upstream);

        tokio::spawn(async move {
            if let Err(err) = decoy::run(listen_tcp, fallback.upstream, rustls_config).await {
                eprintln!("[decoy] остановлен: {err:#}");
            }
        });
    }

    while let Some(incoming) = endpoint.accept().await {
        let config = config.clone();

        tokio::spawn(async move {
            match incoming.await {
                Ok(conn) => {
                    let conn = H3QuinnConnection::new(conn);

                    if let Err(err) = serve_h3(conn, config).await {
                        eprintln!("[server] ошибка h3: {err:#}");
                    }
                }
                Err(err) => eprintln!("[server] ошибка accept: {err:#}"),
            }
        });
    }

    Ok(())
}

async fn serve_h3(conn: H3QuinnConnection, config: Config) -> Result<()> {
    let mut h3 = h3::server::builder().build(conn).await?;
    let sessions: SessionMap = Arc::new(Mutex::new(HashMap::new()));

    {
        let sessions = sessions.clone();
        let mut reader = h3.get_datagram_reader();

        tokio::spawn(async move {
            loop {
                let datagram = match reader.read_datagram().await {
                    Ok(datagram) => datagram,
                    Err(_) => return,
                };

                let stream_id = datagram.stream_id();
                let payload = match masque::decode_datagram(datagram.into_payload()) {
                    Ok(payload) => payload,
                    Err(_) => continue,
                };

                let mut guard = sessions.lock().await;

                match guard.get_mut(&stream_id) {
                    Some(Session::Active(tx)) => {
                        let _ = tx.try_send(payload);
                    }
                    Some(Session::Pending(buffer)) => {
                        if buffer.len() < 32 {
                            buffer.push(payload);
                        }
                    }
                    None => {
                        guard.insert(stream_id, Session::Pending(vec![payload]));
                    }
                }
            }
        });
    }

    while let Some(resolver) = h3.accept().await? {
        let config = config.clone();
        let sessions = sessions.clone();

        let (request, stream) = match resolver.resolve_request().await {
            Ok(value) => value,
            Err(_) => continue,
        };

        let sender = h3.get_datagram_sender(stream.id());

        tokio::spawn(async move {
            if let Err(err) = handle_request(request, stream, sender, sessions, config).await {
                eprintln!("[server] ошибка запроса: {err:#}");
            }
        });
    }

    Ok(())
}

async fn handle_request<S, H>(
    request: http::Request<()>,
    mut stream: h3::server::RequestStream<S, Bytes>,
    mut sender: h3_datagram::datagram_handler::DatagramSender<H, Bytes>,
    sessions: SessionMap,
    config: Config,
) -> Result<()>
where
    S: h3::quic::BidiStream<Bytes> + Send + 'static,
    H: h3_datagram::quic_traits::SendDatagram<Bytes> + Send + 'static,
{
    let stream_id = stream.id();

    let is_connect_udp = masque::is_connect_udp(&request);
    let token_ok = masque::has_valid_token(&request, &config.token);
    let is_tunnel = is_connect_udp && token_ok;

    if !is_tunnel {
        return forward_to_fallback(request, stream, config).await;
    }

    eprintln!("[tunnel] открытие сессии {stream_id:?}");

    let wireguard = config.wireguard.as_ref().context("сервер без wireguard endpoint")?;
    let target = wireguard.endpoint;

    let bind: SocketAddr = if target.is_ipv4() { "0.0.0.0:0".parse()? } else { "[::]:0".parse()? };
    let socket = Arc::new(UdpSocket::bind(bind).await?);
    socket.connect(target).await?;

    let (tx, mut rx) = mpsc::channel::<Bytes>(1024);

    let early = {
        let mut guard = sessions.lock().await;

        let early = match guard.remove(&stream_id) {
            Some(Session::Pending(buffer)) => buffer,
            _ => Vec::new(),
        };

        guard.insert(stream_id, Session::Active(tx));
        early
    };

    let response = Response::builder().status(StatusCode::OK).header("capsule-protocol", "?1").body(())?;
    stream.send_response(response).await?;

    for packet in early {
        let _ = socket.send(&packet).await;
    }

    let downlink = {
        let socket = socket.clone();
        tokio::spawn(async move {
            while let Some(packet) = rx.recv().await {
                if socket.send(&packet).await.is_err() {
                    return;
                }
            }
        })
    };

    let uplink = {
        let socket = socket.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; masque::MAX_PACKET_SIZE];

            loop {
                let size = match socket.recv(&mut buf).await {
                    Ok(value) => value,
                    Err(_) => return,
                };

                let datagram = masque::encode_datagram(&buf[..size]);

                if let Err(err) = sender.send_datagram(datagram) {
                    if format!("{err:?}").contains("TooLarge") {
                        continue;
                    }
                    return;
                }
            }
        })
    };

    let result = loop {
        match stream.recv_data().await {
            Ok(Some(_)) => continue,
            Ok(None) => break Ok(()),
            Err(err) => break Err(err.into()),
        }
    };

    eprintln!("[tunnel] завершение сессии {stream_id:?}");

    sessions.lock().await.remove(&stream_id);
    uplink.abort();
    downlink.abort();
    let _ = stream.finish().await;

    result
}

async fn forward_to_fallback<S>(request: http::Request<()>, mut stream: h3::server::RequestStream<S, Bytes>, config: Config) -> Result<()>
where
    S: h3::quic::BidiStream<Bytes> + Send + 'static,
{
    let Some(fallback_config) = config.fallback else {
        reject(&mut stream, StatusCode::NOT_FOUND).await?;
        return Ok(());
    };

    let mut body = bytes::BytesMut::new();

    while let Some(mut chunk) = stream.recv_data().await? {
        while chunk.has_remaining() {
            let part = chunk.chunk().to_vec();
            let len = part.len();
            body.extend_from_slice(&part);
            chunk.advance(len);
        }
    }

    let response = match fallback::proxy_request(fallback_config.upstream, request, body.freeze()).await {
        Ok(value) => value,
        Err(_) => {
            reject(&mut stream, StatusCode::BAD_GATEWAY).await?;
            return Ok(());
        }
    };

    let (parts, body) = response.into_parts();
    let head = http::Response::from_parts(parts, ());

    stream.send_response(head).await?;

    if !body.is_empty() {
        stream.send_data(body).await?;
    }

    stream.finish().await?;
    Ok(())
}

async fn reject<S>(stream: &mut h3::server::RequestStream<S, Bytes>, status: StatusCode) -> Result<()>
where
    S: h3::quic::BidiStream<Bytes> + Send + 'static,
{
    let response = Response::builder().status(status).body(())?;
    stream.send_response(response).await?;
    stream.finish().await?;
    Ok(())
}
