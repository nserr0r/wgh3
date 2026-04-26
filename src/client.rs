use crate::config::Config;
use crate::masque;
use crate::tls;
use anyhow::Context;
use anyhow::Result;
use anyhow::anyhow;
use h3::ext::Protocol;
use h3_datagram::datagram_handler::HandleDatagramsExt;
use h3_quinn::Connection as H3QuinnConnection;
use http::Request;
use http::StatusCode;
use quinn::Endpoint;
use std::future::poll_fn;
use std::net::SocketAddr;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

pub async fn run(config: Config) -> Result<()> {
    let server = config.server.context("требуется адрес сервера")?;
    let server_name = config.server_name.clone().context("требуется server_name")?;
    let target = config.server_target.context("требуется server_target")?;

    eprintln!("[client] server={server} server_name={server_name} target={target}");

    let bind: SocketAddr = if server.is_ipv4() { "0.0.0.0:0".parse()? } else { "[::]:0".parse()? };
    let mut endpoint = Endpoint::client(bind)?;
    endpoint.set_default_client_config(tls::client_config(config.pin_sha256.as_deref(), config.insecure)?);

    let quic = endpoint.connect(server, &server_name)?.await?;
    eprintln!("[client] quic установлен");

    let conn = H3QuinnConnection::new(quic);

    let (mut driver, mut sender) = h3::client::new(conn).await?;
    let mut reader = driver.get_datagram_reader();

    let (stream_id_tx, mut stream_id_rx) = mpsc::channel(1);
    let (datagram_tx, mut datagram_rx) = mpsc::channel(1);

    tokio::spawn(async move {
        loop {
            tokio::select! {
                result = poll_fn(|cx| driver.poll_close(cx)) => {
                    eprintln!("[client] h3 драйвер закрыт: {result:#}");
                    return;
                }

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

    eprintln!("[client] туннель установлен");

    stream_id_tx.send(stream.id()).await?;
    let mut datagram_sender = datagram_rx.recv().await.ok_or_else(|| anyhow!("отправитель датаграмм недоступен"))?;

    let local = UdpSocket::bind(config.listen).await?;
    eprintln!("[client] локальный udp слушает {}", config.listen);

    let mut peer: Option<SocketAddr> = None;
    let mut buf = vec![0u8; masque::MAX_PACKET_SIZE];

    loop {
        tokio::select! {
            received = local.recv_from(&mut buf) => {
                let (size, addr) = received?;
                if peer != Some(addr) {
                    eprintln!("[client] локальный пир: {addr}");
                }
                peer = Some(addr);

                let data = masque::encode_datagram(&buf[..size]);
                datagram_sender.send_datagram(data)?;
            }

            datagram = reader.read_datagram() => {
                let datagram = datagram?;
                let packet = masque::decode_datagram(datagram.into_payload())?;

                if let Some(addr) = peer {
                    local.send_to(&packet, addr).await?;
                }
            }

            data = stream.recv_data() => {
                match data? {
                    Some(_) => continue,
                    None => return Err(anyhow!("сервер закрыл connect-udp поток")),
                }
            }
        }
    }
}
