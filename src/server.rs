use crate::config::Config;
use crate::config::PeerConfig;
use crate::decoy;
use crate::fallback;
use crate::masque;
use crate::network::lifecycle::Lifecycle;
use crate::tls;
use crate::wg;
use crate::wg::Tunnel;
use crate::wg::TunnelAction;
use anyhow::Context;
use anyhow::Result;
use bytes::Buf;
use bytes::Bytes;
use h3_datagram::datagram_handler::HandleDatagramsExt;
use h3_quinn::Connection as H3QuinnConnection;
use http::Response;
use http::StatusCode;
use ipnet::IpNet;
use quinn::Endpoint;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tokio::sync::mpsc;
use tun_rs::AsyncDevice;
use x25519_dalek::PublicKey;
use x25519_dalek::StaticSecret;

struct ServerPeer {
    public_key: PublicKey,
    preshared_key: Option<[u8; 32]>,
    allowed_ips: Vec<IpNet>,
    session: Mutex<Option<Arc<PeerSession>>>,
}

struct PeerSession {
    tunnel: Arc<Tunnel>,
    out_tx: mpsc::Sender<Bytes>,
}

pub async fn run(config: Config) -> Result<()> {
    let tls_config = config.tls.clone().context("требуется секция tls в конфиге")?;
    let listen = config.listen.context("требуется listen в конфиге сервера")?;

    let private_key = wg::parse_private_key(&config.wireguard.private_key)?;

    let peers = build_peers(&config.peers)?;
    tracing::info!(count = peers.len(), "загружено peers");

    let extra_subnets: Vec<IpNet> = peers.iter().flat_map(|p| p.allowed_ips.clone()).collect();

    let lifecycle = Lifecycle::setup(config.network.clone(), &extra_subnets).await?;

    let server_config = tls::server_config(&tls_config.cert, &tls_config.key)?;
    let endpoint = Endpoint::server(server_config, listen)?;
    tracing::info!(%listen, "quic слушает");

    if let Some(fallback) = config.fallback.clone()
        && let Some(listen_tcp) = fallback.listen_tcp
    {
        let rustls_config = tls::rustls_server_config(&tls_config.cert, &tls_config.key)?;
        tracing::info!(%listen_tcp, upstream = %fallback.upstream, "decoy слушает");

        tokio::spawn(async move {
            if let Err(err) = decoy::run(listen_tcp, fallback.upstream, rustls_config).await {
                tracing::error!(?err, "decoy остановлен");
            }
        });
    }

    let peers = Arc::new(peers);
    spawn_tun_dispatcher(lifecycle.tun.handle(), peers.clone());

    let result = tokio::select! {
        result = accept_loop(&endpoint, &config, peers, &private_key, lifecycle.tun.handle()) => result,
        _ = wait_shutdown() => {
            tracing::info!("получен сигнал завершения");
            Ok(())
        }
    };

    endpoint.close(0u32.into(), b"shutdown");
    lifecycle.teardown().await;
    result
}

async fn accept_loop(
    endpoint: &Endpoint,
    config: &Config,
    peers: Arc<Vec<Arc<ServerPeer>>>,
    private_key: &StaticSecret,
    device: Arc<AsyncDevice>,
) -> Result<()> {
    while let Some(incoming) = endpoint.accept().await {
        let config = config.clone();
        let peers = peers.clone();
        let private_key = private_key.clone();
        let device = device.clone();

        tokio::spawn(async move {
            match incoming.await {
                Ok(conn) => {
                    let conn = H3QuinnConnection::new(conn);

                    if let Err(err) = serve_h3(conn, config, peers, private_key, device).await {
                        tracing::warn!(?err, "ошибка h3");
                    }
                }
                Err(err) => tracing::warn!(?err, "ошибка accept"),
            }
        });
    }

    Ok(())
}

async fn wait_shutdown() {
    use tokio::signal::unix::SignalKind;
    use tokio::signal::unix::signal;

    let mut term = match signal(SignalKind::terminate()) {
        Ok(s) => s,
        Err(_) => return std::future::pending().await,
    };
    let mut int = match signal(SignalKind::interrupt()) {
        Ok(s) => s,
        Err(_) => return std::future::pending().await,
    };

    tokio::select! {
        _ = term.recv() => {},
        _ = int.recv() => {},
    }
}

fn build_peers(configs: &[PeerConfig]) -> Result<Vec<Arc<ServerPeer>>> {
    let mut peers = Vec::with_capacity(configs.len());

    for cfg in configs {
        let public_key = wg::parse_public_key(&cfg.public_key)?;
        let preshared_key = cfg.preshared_key.as_deref().map(wg::parse_preshared_key).transpose()?;

        peers.push(Arc::new(ServerPeer { public_key, preshared_key, allowed_ips: cfg.allowed_ips.clone(), session: Mutex::new(None) }));
    }

    Ok(peers)
}

fn spawn_tun_dispatcher(device: Arc<AsyncDevice>, peers: Arc<Vec<Arc<ServerPeer>>>) {
    tokio::spawn(async move {
        let mut buf = vec![0u8; crate::network::tun::MAX_PACKET_SIZE];

        loop {
            let size = match device.recv(&mut buf).await {
                Ok(value) => value,
                Err(err) => {
                    tracing::error!(?err, "tun recv");
                    return;
                }
            };

            let packet = &buf[..size];
            let dst = match destination_ip(packet) {
                Some(value) => value,
                None => continue,
            };

            let peer = match find_peer_by_ip(&peers, dst) {
                Some(value) => value,
                None => continue,
            };

            let session = {
                let guard = peer.session.lock().await;
                guard.clone()
            };

            let session = match session {
                Some(value) => value,
                None => continue,
            };

            let action = match session.tunnel.encapsulate(packet) {
                Ok(value) => value,
                Err(err) => {
                    tracing::debug!(?err, "encapsulate");
                    continue;
                }
            };

            if let TunnelAction::WriteToNetwork(data) = action {
                let _ = session.out_tx.send(data).await;
            }
        }
    });
}

fn destination_ip(packet: &[u8]) -> Option<IpAddr> {
    if packet.is_empty() {
        return None;
    }

    match packet[0] >> 4 {
        4 if packet.len() >= 20 => {
            let bytes = [packet[16], packet[17], packet[18], packet[19]];
            Some(IpAddr::V4(Ipv4Addr::from(bytes)))
        }
        6 if packet.len() >= 40 => {
            let mut bytes = [0u8; 16];
            bytes.copy_from_slice(&packet[24..40]);
            Some(IpAddr::V6(Ipv6Addr::from(bytes)))
        }
        _ => None,
    }
}

fn find_peer_by_ip(peers: &[Arc<ServerPeer>], ip: IpAddr) -> Option<Arc<ServerPeer>> {
    for peer in peers {
        for subnet in &peer.allowed_ips {
            if subnet.contains(&ip) {
                return Some(peer.clone());
            }
        }
    }
    None
}

async fn serve_h3(
    conn: H3QuinnConnection,
    config: Config,
    peers: Arc<Vec<Arc<ServerPeer>>>,
    private_key: StaticSecret,
    device: Arc<AsyncDevice>,
) -> Result<()> {
    let mut h3 = h3::server::builder().build(conn).await?;

    let datagram_inbound: Arc<Mutex<Option<mpsc::Sender<Bytes>>>> = Arc::new(Mutex::new(None));

    {
        let inbound = datagram_inbound.clone();
        let mut reader = h3.get_datagram_reader();

        tokio::spawn(async move {
            loop {
                let datagram = match reader.read_datagram().await {
                    Ok(value) => value,
                    Err(_) => return,
                };

                let payload = match masque::decode_datagram(datagram.into_payload()) {
                    Ok(value) => value,
                    Err(_) => continue,
                };

                let tx = {
                    let guard = inbound.lock().await;
                    guard.clone()
                };

                if let Some(tx) = tx
                    && tx.send(payload).await.is_err()
                {
                    tracing::debug!("inbound канал закрыт");
                }
            }
        });
    }

    while let Some(resolver) = h3.accept().await? {
        let config = config.clone();
        let peers = peers.clone();
        let private_key = private_key.clone();
        let inbound = datagram_inbound.clone();
        let device = device.clone();

        let (request, stream) = match resolver.resolve_request().await {
            Ok(value) => value,
            Err(_) => continue,
        };

        let sender = h3.get_datagram_sender(stream.id());

        tokio::spawn(async move {
            if let Err(err) = handle_request(request, stream, sender, config, peers, private_key, inbound, device).await {
                tracing::warn!(?err, "ошибка запроса");
            }
        });
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn handle_request<S, H>(
    request: http::Request<()>,
    mut stream: h3::server::RequestStream<S, Bytes>,
    mut sender: h3_datagram::datagram_handler::DatagramSender<H, Bytes>,
    config: Config,
    peers: Arc<Vec<Arc<ServerPeer>>>,
    private_key: StaticSecret,
    inbound: Arc<Mutex<Option<mpsc::Sender<Bytes>>>>,
    device: Arc<AsyncDevice>,
) -> Result<()>
where
    S: h3::quic::BidiStream<Bytes> + Send + 'static,
    H: h3_datagram::quic_traits::SendDatagram<Bytes> + Send + 'static,
{
    let is_connect_udp = masque::is_connect_udp(&request);
    let token_ok = masque::has_valid_token(&request, &config.token);
    let is_tunnel = is_connect_udp && token_ok;

    if !is_tunnel {
        return forward_to_fallback(request, stream, config).await;
    }

    let response = Response::builder().status(StatusCode::OK).header("capsule-protocol", "?1").body(())?;
    stream.send_response(response).await?;

    let (incoming_tx, mut incoming_rx) = mpsc::channel::<Bytes>(1024);
    {
        let mut guard = inbound.lock().await;
        *guard = Some(incoming_tx);
    }

    let (out_tx, mut out_rx) = mpsc::channel::<Bytes>(1024);

    let outbound = tokio::spawn(async move {
        while let Some(data) = out_rx.recv().await {
            let datagram = masque::encode_datagram(&data);
            if let Err(err) = sender.send_datagram(datagram) {
                let dbg = format!("{err:?}");
                if dbg.contains("TooLarge") {
                    tracing::debug!(size = data.len(), "datagram TooLarge — дроп");
                    continue;
                }
                tracing::warn!(?err, "send_datagram, останавливаем outbound");
                return;
            }
        }
    });

    let first_packet = match incoming_rx.recv().await {
        Some(value) => value,
        None => {
            outbound.abort();
            return Ok(());
        }
    };

    let (peer, tunnel, initial_actions) = match identify_peer(&peers, &private_key, &config, &first_packet) {
        Some(value) => value,
        None => {
            tracing::warn!("handshake от неизвестного peer'а");
            outbound.abort();
            return Ok(());
        }
    };

    let key_short = short_key(&peer.public_key);
    tracing::info!(peer = %key_short, "peer подключился");

    let session = Arc::new(PeerSession { tunnel: tunnel.clone(), out_tx: out_tx.clone() });

    {
        let mut guard = peer.session.lock().await;
        if guard.is_some() {
            tracing::info!(peer = %key_short, "вытеснение старой сессии");
        }
        *guard = Some(session.clone());
    }

    for action in initial_actions {
        match action {
            TunnelAction::WriteToNetwork(data) => {
                let _ = out_tx.send(data).await;
            }
            TunnelAction::WriteToTun(data) => {
                let _ = device.send(&data).await;
            }
            TunnelAction::None => {}
        }
    }

    let from_quic = {
        let tunnel = tunnel.clone();
        let device = device.clone();
        let out_tx = out_tx.clone();

        tokio::spawn(async move {
            while let Some(packet) = incoming_rx.recv().await {
                let actions = match tunnel.decapsulate(&packet) {
                    Ok(value) => value,
                    Err(err) => {
                        tracing::debug!(?err, "decapsulate");
                        continue;
                    }
                };

                for action in actions {
                    match action {
                        TunnelAction::WriteToTun(data) => {
                            if device.send(&data).await.is_err() {
                                return;
                            }
                        }
                        TunnelAction::WriteToNetwork(data) => {
                            if out_tx.send(data).await.is_err() {
                                return;
                            }
                        }
                        TunnelAction::None => {}
                    }
                }
            }
        })
    };

    let timers = {
        let tunnel = tunnel.clone();
        let out_tx = out_tx.clone();

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(1));
            loop {
                interval.tick().await;

                let action = match tunnel.update_timers() {
                    Ok(value) => value,
                    Err(err) => {
                        tracing::error!(?err, "timers");
                        return;
                    }
                };

                if let TunnelAction::WriteToNetwork(data) = action
                    && out_tx.send(data).await.is_err()
                {
                    return;
                }
            }
        })
    };

    drop(out_tx);

    let result = loop {
        match stream.recv_data().await {
            Ok(Some(_)) => continue,
            Ok(None) => break Ok(()),
            Err(err) => break Err(err.into()),
        }
    };

    tracing::info!(peer = %key_short, "peer отключился");

    {
        let mut guard = peer.session.lock().await;
        *guard = None;
    }
    {
        let mut guard = inbound.lock().await;
        *guard = None;
    }

    from_quic.abort();
    timers.abort();
    outbound.abort();

    let _ = stream.finish().await;
    result
}

fn identify_peer(
    peers: &[Arc<ServerPeer>],
    private_key: &StaticSecret,
    config: &Config,
    packet: &[u8],
) -> Option<(Arc<ServerPeer>, Arc<Tunnel>, Vec<TunnelAction>)> {
    if crate::wg::is_handshake_init(packet) && !crate::wg::verify_mac1(packet, private_key) {
        return None;
    }

    for peer in peers {
        let tunnel = match Tunnel::new(private_key.clone(), peer.public_key, peer.preshared_key, Some(config.wireguard.persistent_keepalive)) {
            Ok(value) => Arc::new(value),
            Err(_) => continue,
        };

        let actions = match tunnel.decapsulate(packet) {
            Ok(value) => value,
            Err(_) => continue,
        };

        if !actions.is_empty() {
            return Some((peer.clone(), tunnel, actions));
        }
    }

    None
}

fn short_key(key: &PublicKey) -> String {
    let encoded = crate::wg::encode_b64(key.as_bytes());
    encoded.chars().take(8).collect()
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
