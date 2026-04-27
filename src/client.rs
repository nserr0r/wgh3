use crate::config::Config;
use crate::masque;
use crate::network::lifecycle::Lifecycle;
use crate::network::routes::DEFAULT_FWMARK;
use crate::network::routes::fwmark_for_socket;
use crate::network::tun::Tun;
use crate::tls;
use crate::wg;
use crate::wg::Tunnel;
use crate::wg::TunnelAction;
use anyhow::Context;
use anyhow::Result;
use anyhow::anyhow;
use bytes::Bytes;
use h3::ext::Protocol;
use h3_datagram::datagram_handler::HandleDatagramsExt;
use h3_quinn::Connection as H3QuinnConnection;
use http::Request;
use http::StatusCode;
use quinn::Endpoint;
use std::future::poll_fn;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::time::Duration;
use tokio::sync::mpsc;

const RECONNECT_MIN: Duration = Duration::from_secs(1);
const RECONNECT_MAX: Duration = Duration::from_secs(10);

pub async fn run(config: Config) -> Result<()> {
    let server = config.server.context("требуется адрес сервера")?;
    let server_name = config.server_name.clone().context("требуется server_name")?;

    let private_key = wg::parse_private_key(&config.wireguard.private_key)?;
    let peer_public_key_str = config.wireguard.peer_public_key.as_deref().context("требуется peer_public_key в конфиге клиента")?;
    let peer_public_key = wg::parse_public_key(peer_public_key_str)?;
    let preshared_key = config.wireguard.peer_preshared_key.as_deref().map(wg::parse_preshared_key).transpose()?;

    let lifecycle = Lifecycle::setup(config.network.clone(), &config.wireguard.peer_allowed_ips).await?;

    let bind: SocketAddr = if server.is_ipv4() { "0.0.0.0:0".parse()? } else { "[::]:0".parse()? };
    let fwmark = if config.network.auto_route { Some(config.network.fwmark.unwrap_or(DEFAULT_FWMARK)) } else { config.network.fwmark };

    let result = tokio::select! {
        result = run_loop(&config, server, &server_name, bind, lifecycle.tun.clone(), private_key, peer_public_key, preshared_key, fwmark) => result,
        _ = wait_shutdown() => {
            tracing::info!("получен сигнал завершения");
            Ok(())
        }
    };

    lifecycle.teardown().await;
    result
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

#[allow(clippy::too_many_arguments)]
async fn run_loop(
    config: &Config,
    server: SocketAddr,
    server_name: &str,
    bind: SocketAddr,
    tun: Arc<Tun>,
    private_key: x25519_dalek::StaticSecret,
    peer_public_key: x25519_dalek::PublicKey,
    preshared_key: Option<[u8; 32]>,
    fwmark: Option<u32>,
) -> Result<()> {
    let mut backoff = RECONNECT_MIN;

    loop {
        match session(config, server, server_name, bind, tun.clone(), private_key.clone(), peer_public_key, preshared_key, fwmark).await {
            Ok(()) => {
                backoff = RECONNECT_MIN;
            }
            Err(err) => {
                tracing::warn!(?err, backoff_secs = backoff.as_secs(), "сессия упала, переподключение");
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(RECONNECT_MAX);
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn session(
    config: &Config,
    server: SocketAddr,
    server_name: &str,
    bind: SocketAddr,
    tun: Arc<Tun>,
    private_key: x25519_dalek::StaticSecret,
    peer_public_key: x25519_dalek::PublicKey,
    preshared_key: Option<[u8; 32]>,
    fwmark: Option<u32>,
) -> Result<()> {
    let mut endpoint = build_endpoint(bind, fwmark)?;
    endpoint.set_default_client_config(tls::client_config(config.pin_sha256.as_deref(), config.insecure)?);

    let quic = endpoint.connect(server, server_name)?.await?;
    let conn = H3QuinnConnection::new(quic);

    let (mut driver, mut sender) = h3::client::new(conn).await?;
    let mut reader = driver.get_datagram_reader();

    let (stream_id_tx, mut stream_id_rx) = mpsc::channel(1);
    let (datagram_tx, mut datagram_rx) = mpsc::channel(1);

    let driver_task = tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = poll_fn(|cx| driver.poll_close(cx)) => return,

                stream_id = stream_id_rx.recv() => {
                    let Some(stream_id) = stream_id else {
                        return;
                    };

                    let datagram_sender = driver.get_datagram_sender(stream_id);

                    if datagram_tx.send(datagram_sender).await.is_err() {
                        return;
                    }
                }
            }
        }
    });

    let target = "0.0.0.0:0".parse::<SocketAddr>()?;
    let uri = format!("https://{}{}", server_name, masque::connect_udp_path(target));

    let request = Request::builder()
        .method(http::Method::CONNECT)
        .uri(uri)
        .header("authorization", format!("Bearer {}", config.token))
        .header("capsule-protocol", "?1")
        .extension(Protocol::CONNECT_UDP)
        .body(())?;

    let mut stream = sender.send_request(request).await?;
    let response = stream.recv_response().await?;

    if response.status() != StatusCode::OK {
        return Err(anyhow!("connect-udp отклонён: {}", response.status()));
    }

    tracing::info!("туннель установлен");

    stream_id_tx.send(stream.id()).await?;
    let mut datagram_sender = datagram_rx.recv().await.ok_or_else(|| anyhow!("отправитель датаграмм недоступен"))?;

    let tunnel = Arc::new(Tunnel::new(private_key, peer_public_key, preshared_key, Some(config.wireguard.persistent_keepalive))?);

    let stop = Arc::new(AtomicBool::new(false));
    let device = tun.handle();

    let (out_tx, mut out_rx) = mpsc::channel::<Bytes>(1024);

    let outbound = tokio::spawn(async move {
        while let Some(data) = out_rx.recv().await {
            let datagram = masque::encode_datagram(&data);
            if let Err(err) = datagram_sender.send_datagram(datagram) {
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

    if let Ok(TunnelAction::WriteToNetwork(data)) = tunnel.encapsulate(&[]) {
        let _ = out_tx.send(data).await;
    }

    let from_quic = {
        let tunnel = tunnel.clone();
        let device = device.clone();
        let stop = stop.clone();
        let out_tx = out_tx.clone();

        tokio::spawn(async move {
            while !stop.load(Ordering::Relaxed) {
                let datagram = match reader.read_datagram().await {
                    Ok(value) => value,
                    Err(_) => return,
                };

                let payload = match masque::decode_datagram(datagram.into_payload()) {
                    Ok(value) => value,
                    Err(_) => continue,
                };

                let actions = match tunnel.decapsulate(&payload) {
                    Ok(value) => value,
                    Err(err) => {
                        tracing::debug!(?err, "decapsulate");
                        continue;
                    }
                };

                for action in actions {
                    match action {
                        TunnelAction::WriteToTun(data) => {
                            if let Err(err) = device.send(&data).await {
                                tracing::error!(?err, "tun send");
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

    let from_tun = {
        let tunnel = tunnel.clone();
        let device = device.clone();
        let stop = stop.clone();
        let out_tx = out_tx.clone();

        tokio::spawn(async move {
            let mut buf = vec![0u8; crate::network::tun::MAX_PACKET_SIZE];

            while !stop.load(Ordering::Relaxed) {
                let size = match device.recv(&mut buf).await {
                    Ok(value) => value,
                    Err(err) => {
                        tracing::error!(?err, "tun recv");
                        return;
                    }
                };

                let action = match tunnel.encapsulate(&buf[..size]) {
                    Ok(value) => value,
                    Err(err) => {
                        tracing::debug!(?err, "encapsulate");
                        continue;
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

    let timers = {
        let tunnel = tunnel.clone();
        let stop = stop.clone();
        let out_tx = out_tx.clone();

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(1));
            while !stop.load(Ordering::Relaxed) {
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

    let monitor = tokio::spawn(async move {
        loop {
            match stream.recv_data().await {
                Ok(Some(_)) => continue,
                Ok(None) => return Err(anyhow!("сервер закрыл connect-udp поток")),
                Err(err) => return Err(err.into()),
            }
        }
    });

    let result = tokio::select! {
        _ = from_quic => Err(anyhow!("from_quic прервался")),
        _ = from_tun => Err(anyhow!("from_tun прервался")),
        _ = timers => Err(anyhow!("timers прервался")),
        _ = outbound => Err(anyhow!("outbound прервался")),
        result = monitor => result.unwrap_or_else(|err| Err(err.into())),
    };

    stop.store(true, Ordering::Relaxed);
    driver_task.abort();
    endpoint.close(0u32.into(), b"reconnect");
    result
}

fn build_endpoint(bind: SocketAddr, fwmark: Option<u32>) -> Result<Endpoint> {
    let socket = std::net::UdpSocket::bind(bind)?;

    if let Some(mark) = fwmark {
        fwmark_for_socket(&socket, mark)?;
    }

    let runtime = quinn::default_runtime().context("нет tokio runtime")?;
    Endpoint::new(quinn::EndpointConfig::default(), None, socket, runtime).map_err(Into::into)
}
