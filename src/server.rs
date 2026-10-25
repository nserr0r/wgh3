use crate::config::Config;
use crate::config::PeerConfig;
use crate::decoy;
use crate::fallback;
use crate::masque;
use crate::masque::DatagramChannel;
use crate::mtu;
use crate::network::lifecycle::Lifecycle;
use crate::quic;
use crate::session::Session;
use crate::signal;
use crate::tls;
use crate::wg;
use crate::wg::Tunnel;
use anyhow::Context;
use anyhow::Result;
use boringtun::noise::Packet;
use boringtun::noise::Tunn;
use boringtun::noise::handshake::parse_handshake_anon;
use bytes::BufMut;
use bytes::Bytes;
use bytes::BytesMut;
use http::Request;
use http::Response;
use http::StatusCode;
use ipnet::IpNet;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;
use tun_rs::AsyncDevice;
use x25519_dalek::PublicKey;
use x25519_dalek::StaticSecret;

type RequestStream = h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>;

const SHUTDOWN_GRACE: Duration = Duration::from_secs(1);

pub async fn run(config: Config) -> Result<()> {
    let peers = build_peers(&config.peers)?;
    tracing::info!(count = peers.len(), "загружено peers");

    let routed: Vec<IpNet> = config.peers.iter().flat_map(|peer| peer.allowed_ips.iter().copied()).collect();
    let lifecycle = Lifecycle::setup(&config.network, &routed).await?;

    let result = serve(&config, peers, lifecycle.device.clone()).await;

    lifecycle.teardown().await;
    result
}

async fn serve(config: &Config, peers: Vec<Arc<Peer>>, device: Arc<AsyncDevice>) -> Result<()> {
    let tls = config.tls.as_ref().context("требуется секция [tls]")?;
    let listen = config.listen.context("требуется listen")?;
    let private_key = wg::parse_private_key(&config.wireguard.private_key)?;

    let endpoint = quic::server_endpoint(listen, tls::server_config(&tls.cert, &tls.key, tls::ALPN_H3)?, config.network.mtu)?;
    tracing::info!(%listen, "quic слушает");

    let decoy = async {
        match config.fallback.as_ref().and_then(|fallback| Some((fallback.listen_tcp?, fallback.upstream))) {
            Some((listen_tcp, upstream)) => {
                let tls = tls::server_config(&tls.cert, &tls.key, tls::ALPN_HTTPS)?;
                tracing::info!(%listen_tcp, %upstream, "decoy слушает");
                decoy::run(listen_tcp, upstream, Arc::new(tls)).await
            }
            None => std::future::pending().await,
        }
    };

    let server = Arc::new(Server {
        token: config.token.clone(),
        upstream: config.fallback.as_ref().map(|fallback| fallback.upstream),
        public_key: PublicKey::from(&private_key),
        private_key,
        keepalive: config.wireguard.persistent_keepalive,
        mtu: config.network.mtu,
        peers,
        device,
    });

    let result = tokio::select! {
        result = server.accept(&endpoint) => result,
        result = server.dispatch_device() => result,
        result = decoy => result.context("decoy остановлен"),
        result = signal::shutdown() => result,
    };

    endpoint.close(0u32.into(), b"shutdown");
    let _ = tokio::time::timeout(SHUTDOWN_GRACE, endpoint.wait_idle()).await;
    result
}

fn build_peers(configs: &[PeerConfig]) -> Result<Vec<Arc<Peer>>> {
    let mut peers = Vec::with_capacity(configs.len());

    for config in configs {
        peers.push(Arc::new(Peer {
            public_key: wg::parse_public_key(&config.public_key)?,
            preshared_key: config.preshared_key.as_deref().map(wg::parse_preshared_key).transpose()?,
            allowed_ips: config.allowed_ips.clone(),
            session: Mutex::new(None),
        }));
    }

    Ok(peers)
}

struct Peer {
    public_key: PublicKey,
    preshared_key: Option<[u8; 32]>,
    allowed_ips: Vec<IpNet>,
    session: Mutex<Option<Arc<Session>>>,
}

impl Peer {
    fn name(&self) -> String {
        wg::encode_b64(self.public_key.as_bytes()).chars().take(8).collect()
    }

    fn session(&self) -> Option<Arc<Session>> {
        self.lock().clone()
    }

    fn attach(&self, session: Arc<Session>) -> bool {
        self.lock().replace(session).is_some()
    }

    fn detach(&self, session: &Arc<Session>) {
        let mut current = self.lock();
        if current.as_ref().is_some_and(|active| Arc::ptr_eq(active, session)) {
            *current = None;
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Option<Arc<Session>>> {
        self.session.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

struct Server {
    token: String,
    upstream: Option<SocketAddr>,
    private_key: StaticSecret,
    public_key: PublicKey,
    keepalive: u16,
    mtu: u16,
    peers: Vec<Arc<Peer>>,
    device: Arc<AsyncDevice>,
}

impl Server {
    async fn accept(self: &Arc<Self>, endpoint: &quinn::Endpoint) -> Result<()> {
        while let Some(incoming) = endpoint.accept().await {
            let server = self.clone();
            tokio::spawn(async move {
                if let Err(err) = server.serve_connection(incoming).await {
                    tracing::debug!(error = format!("{err:#}"), "соединение закрыто");
                }
            });
        }

        Ok(())
    }

    async fn serve_connection(self: Arc<Self>, incoming: quinn::Incoming) -> Result<()> {
        let connection = incoming.await?;
        let mut h3 = h3::server::builder().enable_datagram(true).enable_extended_connect(true).build(h3_quinn::Connection::new(connection.clone())).await?;

        let mut tunnel_opened = false;

        while let Some(resolver) = h3.accept().await? {
            let (request, stream) = match resolver.resolve_request().await {
                Ok(value) => value,
                Err(err) => {
                    tracing::debug!(?err, "некорректный запрос");
                    continue;
                }
            };

            let server = self.clone();

            if !tunnel_opened && masque::is_connect_udp(&request) && masque::has_valid_token(&request, &self.token) {
                tunnel_opened = true;
                let connection = connection.clone();
                tokio::spawn(async move {
                    if let Err(err) = server.serve_tunnel(connection, stream).await {
                        tracing::warn!(error = format!("{err:#}"), "туннель завершился с ошибкой");
                    }
                });
            } else {
                tokio::spawn(async move {
                    if let Err(err) = server.forward_to_fallback(request, stream).await {
                        tracing::debug!(?err, "fallback");
                    }
                });
            }
        }

        Ok(())
    }

    async fn serve_tunnel(&self, connection: quinn::Connection, mut stream: RequestStream) -> Result<()> {
        let response = Response::builder().status(StatusCode::OK).header("capsule-protocol", "?1").body(())?;
        stream.send_response(response).await?;

        let channel = DatagramChannel::new(connection, stream.id().into_inner());
        let required = mtu::wireguard_packet(self.mtu);
        if channel.max_packet_size() < required {
            tracing::warn!(limit = channel.max_packet_size(), required, "network.mtu на клиенте меньше, чем на сервере: крупные пакеты будут отброшены");
        }

        let (peer, handshake) = tokio::select! {
            result = self.await_handshake(&channel) => result?,
            result = watch_stream(&mut stream) => return result,
        };

        let tunnel = Tunnel::new(self.private_key.clone(), peer.public_key, peer.preshared_key, Some(self.keepalive), self.mtu);
        let session = Arc::new(Session::new(tunnel, channel));
        session.deliver(&handshake, &self.device).await?;

        if peer.attach(session.clone()) {
            tracing::info!(peer = %peer.name(), "вытеснение старой сессии");
        }
        tracing::info!(peer = %peer.name(), "peer подключился");

        let result = tokio::select! {
            result = session.receive(&self.device) => result,
            result = session.run_timers() => result,
            result = watch_stream(&mut stream) => result,
        };

        peer.detach(&session);
        tracing::info!(peer = %peer.name(), "peer отключился");

        let _ = stream.finish().await;
        result
    }

    async fn await_handshake(&self, channel: &DatagramChannel) -> Result<(Arc<Peer>, Bytes)> {
        loop {
            let datagram = channel.recv().await?;
            if let Some(peer) = identify(&self.peers, &self.private_key, &self.public_key, &datagram) {
                return Ok((peer.clone(), datagram));
            }
        }
    }

    async fn dispatch_device(&self) -> Result<()> {
        let mut buffer = vec![0; usize::from(self.mtu)];

        loop {
            let size = self.device.recv(&mut buffer).await.context("чтение из TUN")?;
            let packet = &buffer[..size];

            let Some(session) = destination(packet).and_then(|ip| find_peer(&self.peers, ip)).and_then(|peer| peer.session()) else {
                continue;
            };

            if let Err(err) = session.send(packet) {
                tracing::debug!(?err, "отправка peer'у");
            }
        }
    }

    async fn forward_to_fallback(&self, request: Request<()>, mut stream: RequestStream) -> Result<()> {
        let Some(upstream) = self.upstream else {
            return reject(&mut stream, StatusCode::NOT_FOUND).await;
        };

        let mut body = BytesMut::new();
        while let Some(chunk) = stream.recv_data().await? {
            body.put(chunk);
        }

        let response = match fallback::proxy_request(upstream, request, body.freeze()).await {
            Ok(response) => response,
            Err(err) => {
                tracing::warn!(?err, "fallback недоступен");
                return reject(&mut stream, StatusCode::BAD_GATEWAY).await;
            }
        };

        let (parts, body) = response.into_parts();
        stream.send_response(Response::from_parts(parts, ())).await?;
        if !body.is_empty() {
            stream.send_data(body).await?;
        }
        stream.finish().await?;
        Ok(())
    }
}

fn identify<'a>(peers: &'a [Arc<Peer>], private_key: &StaticSecret, public_key: &PublicKey, datagram: &[u8]) -> Option<&'a Arc<Peer>> {
    let Ok(Packet::HandshakeInit(init)) = Tunn::parse_incoming_packet(datagram) else {
        return None;
    };

    let Ok(half) = parse_handshake_anon(private_key, public_key, &init) else {
        tracing::warn!("некорректный handshake");
        return None;
    };

    let peer = peers.iter().find(|peer| peer.public_key.as_bytes() == &half.peer_static_public);
    if peer.is_none() {
        tracing::warn!(key = %wg::encode_b64(&half.peer_static_public), "handshake от неизвестного peer'а");
    }
    peer
}

fn destination(packet: &[u8]) -> Option<IpAddr> {
    match packet.first()? >> 4 {
        4 => {
            let octets: [u8; 4] = packet.get(16..20)?.try_into().ok()?;
            Some(IpAddr::V4(Ipv4Addr::from(octets)))
        }
        6 => {
            let octets: [u8; 16] = packet.get(24..40)?.try_into().ok()?;
            Some(IpAddr::V6(Ipv6Addr::from(octets)))
        }
        _ => None,
    }
}

fn find_peer(peers: &[Arc<Peer>], ip: IpAddr) -> Option<&Arc<Peer>> {
    peers.iter().find(|peer| peer.allowed_ips.iter().any(|subnet| subnet.contains(&ip)))
}

async fn watch_stream(stream: &mut RequestStream) -> Result<()> {
    while stream.recv_data().await?.is_some() {}
    Ok(())
}

async fn reject(stream: &mut RequestStream, status: StatusCode) -> Result<()> {
    stream.send_response(Response::builder().status(status).body(())?).await?;
    stream.finish().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    fn peer(public_key: PublicKey, allowed_ips: &[&str]) -> Arc<Peer> {
        Arc::new(Peer { public_key, preshared_key: None, allowed_ips: allowed_ips.iter().map(|net| net.parse().unwrap()).collect(), session: Mutex::new(None) })
    }

    #[test]
    fn destination_parses_ipv4_and_ipv6() {
        let mut v4 = [0u8; 20];
        v4[0] = 0x45;
        v4[16..20].copy_from_slice(&[10, 0, 0, 2]);
        assert_eq!(destination(&v4), Some("10.0.0.2".parse().unwrap()));

        let mut v6 = [0u8; 40];
        v6[0] = 0x60;
        v6[24..40].copy_from_slice(&"fd00::2".parse::<Ipv6Addr>().unwrap().octets());
        assert_eq!(destination(&v6), Some("fd00::2".parse().unwrap()));
    }

    #[test]
    fn destination_rejects_truncated_and_unknown() {
        assert_eq!(destination(&[]), None);
        assert_eq!(destination(&[0x45; 19]), None);
        assert_eq!(destination(&[0x60; 39]), None);
        assert_eq!(destination(&[0x00; 40]), None);
    }

    #[test]
    fn find_peer_by_allowed_ips() {
        let first = StaticSecret::random_from_rng(OsRng);
        let second = StaticSecret::random_from_rng(OsRng);
        let peers = vec![peer(PublicKey::from(&first), &["10.0.0.2/32"]), peer(PublicKey::from(&second), &["10.0.1.0/24"])];

        assert!(Arc::ptr_eq(find_peer(&peers, "10.0.0.2".parse().unwrap()).unwrap(), &peers[0]));
        assert!(Arc::ptr_eq(find_peer(&peers, "10.0.1.77".parse().unwrap()).unwrap(), &peers[1]));
        assert!(find_peer(&peers, "10.0.0.3".parse().unwrap()).is_none());
    }

    #[test]
    fn identify_peer_by_handshake() {
        let server_secret = StaticSecret::random_from_rng(OsRng);
        let server_public = PublicKey::from(&server_secret);

        let known_secret = StaticSecret::random_from_rng(OsRng);
        let other_secret = StaticSecret::random_from_rng(OsRng);
        let peers = vec![peer(PublicKey::from(&other_secret), &["10.0.0.3/32"]), peer(PublicKey::from(&known_secret), &["10.0.0.2/32"])];

        let client = Tunnel::new(known_secret, server_public, None, None, mtu::DEFAULT_MTU);
        let handshake = client.initiate_handshake().unwrap().unwrap();

        let found = identify(&peers, &server_secret, &server_public, &handshake).unwrap();
        assert!(Arc::ptr_eq(found, &peers[1]));
    }

    #[test]
    fn identify_rejects_unknown_peer_and_garbage() {
        let server_secret = StaticSecret::random_from_rng(OsRng);
        let server_public = PublicKey::from(&server_secret);
        let peers = vec![peer(PublicKey::from(&StaticSecret::random_from_rng(OsRng)), &["10.0.0.2/32"])];

        let stranger = Tunnel::new(StaticSecret::random_from_rng(OsRng), server_public, None, None, mtu::DEFAULT_MTU);
        let handshake = stranger.initiate_handshake().unwrap().unwrap();

        assert!(identify(&peers, &server_secret, &server_public, &handshake).is_none());
        assert!(identify(&peers, &server_secret, &server_public, &[1, 2, 3]).is_none());
    }
}
