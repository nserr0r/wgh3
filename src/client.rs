use crate::config::Config;
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
use anyhow::bail;
use bytes::Bytes;
use h3::ext::Protocol;
use http::Method;
use http::Request;
use http::StatusCode;
use quinn::Endpoint;
use std::future::poll_fn;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::task::JoinSet;
use tun_rs::AsyncDevice;
use x25519_dalek::PublicKey;
use x25519_dalek::StaticSecret;

type RequestStream = h3::client::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>;

const RECONNECT_MIN: Duration = Duration::from_secs(1);
const RECONNECT_MAX: Duration = Duration::from_secs(10);

pub async fn run(config: Config) -> Result<()> {
    let client = Client::new(&config)?;
    let lifecycle = Lifecycle::setup(&config.network, &config.wireguard.peer_allowed_ips).await?;

    let result = tokio::select! {
        result = client.run(&lifecycle.device) => result,
        result = signal::shutdown() => result,
    };

    lifecycle.teardown().await;
    result
}

struct Client {
    server: SocketAddr,
    server_name: String,
    token: String,
    tls: rustls::ClientConfig,
    fwmark: Option<u32>,
    private_key: StaticSecret,
    peer_public_key: PublicKey,
    preshared_key: Option<[u8; 32]>,
    keepalive: u16,
    mtu: u16,
}

impl Client {
    fn new(config: &Config) -> Result<Self> {
        let wireguard = &config.wireguard;
        let peer_public_key = wireguard.peer_public_key.as_deref().context("требуется wireguard.peer_public_key")?;

        Ok(Self {
            server: config.server.context("требуется server")?,
            server_name: config.server_name.clone().context("требуется server_name")?,
            token: config.token.clone(),
            tls: tls::client_config(config.pin_sha256.as_deref(), config.insecure)?,
            fwmark: config.network.socket_mark(),
            private_key: wg::parse_private_key(&wireguard.private_key)?,
            peer_public_key: wg::parse_public_key(peer_public_key)?,
            preshared_key: wireguard.peer_preshared_key.as_deref().map(wg::parse_preshared_key).transpose()?,
            keepalive: wireguard.persistent_keepalive,
            mtu: config.network.mtu,
        })
    }

    async fn run(&self, device: &AsyncDevice) -> Result<()> {
        let mut backoff = RECONNECT_MIN;

        loop {
            if let Err(err) = self.connect(device, &mut backoff).await {
                tracing::warn!(error = format!("{err:#}"), backoff_secs = backoff.as_secs(), "сессия прервана, переподключение");
            }

            tokio::time::sleep(backoff).await;
            backoff = (backoff * 2).min(RECONNECT_MAX);
        }
    }

    async fn connect(&self, device: &AsyncDevice, backoff: &mut Duration) -> Result<()> {
        let endpoint = quic::client_endpoint(self.server, self.tls.clone(), self.mtu, self.fwmark)?;
        let result = self.session(&endpoint, device, backoff).await;
        endpoint.close(0u32.into(), b"reconnect");
        result
    }

    async fn session(&self, endpoint: &Endpoint, device: &AsyncDevice, backoff: &mut Duration) -> Result<()> {
        let connection = endpoint.connect(self.server, &self.server_name)?.await?;
        let (mut driver, mut requests) = h3::client::builder().enable_datagram(true).build(h3_quinn::Connection::new(connection.clone())).await?;

        let mut h3_driver = JoinSet::new();
        h3_driver.spawn(async move {
            poll_fn(|cx| driver.poll_close(cx)).await;
        });

        let request = Request::builder()
            .method(Method::CONNECT)
            .uri(format!("https://{}{}", self.server_name, masque::CONNECT_UDP_PATH))
            .header(http::header::AUTHORIZATION, format!("Bearer {}", self.token))
            .header("capsule-protocol", "?1")
            .extension(Protocol::CONNECT_UDP)
            .body(())?;

        let mut stream = requests.send_request(request).await?;
        let response = stream.recv_response().await?;
        if response.status() != StatusCode::OK {
            bail!("connect-udp отклонён: {}", response.status());
        }

        let channel = DatagramChannel::new(connection, stream.id().into_inner());
        let required = mtu::wireguard_packet(self.mtu);
        if channel.max_packet_size() < required {
            bail!("сервер принимает пакеты до {} байт, нужно {required}: network.mtu на сервере меньше, чем на клиенте", channel.max_packet_size());
        }

        let tunnel = Tunnel::new(self.private_key.clone(), self.peer_public_key, self.preshared_key, Some(self.keepalive), self.mtu);
        let session = Session::new(tunnel, channel);
        session.initiate_handshake()?;

        *backoff = RECONNECT_MIN;
        tracing::info!(server = %self.server, "туннель установлен");

        tokio::select! {
            result = session.receive(device) => result,
            result = session.run_timers() => result,
            result = forward_device(&session, device, self.mtu) => result,
            result = watch_stream(&mut stream) => result,
        }
    }
}

async fn forward_device(session: &Session, device: &AsyncDevice, mtu: u16) -> Result<()> {
    let mut buffer = vec![0; usize::from(mtu)];
    loop {
        let size = device.recv(&mut buffer).await.context("чтение из TUN")?;
        session.send(&buffer[..size])?;
    }
}

async fn watch_stream(stream: &mut RequestStream) -> Result<()> {
    while stream.recv_data().await?.is_some() {}
    bail!("сервер закрыл connect-udp поток")
}
