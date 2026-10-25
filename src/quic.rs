use crate::mtu;
use anyhow::Context;
use anyhow::Result;
use quinn::ClientConfig;
use quinn::Endpoint;
use quinn::EndpointConfig;
use quinn::ServerConfig;
use quinn::TransportConfig;
use quinn::crypto::rustls::QuicClientConfig;
use quinn::crypto::rustls::QuicServerConfig;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::net::SocketAddr;
use std::net::UdpSocket;
use std::sync::Arc;
use std::time::Duration;

pub fn server_endpoint(listen: SocketAddr, tls: rustls::ServerConfig, mtu: u16) -> Result<Endpoint> {
    let mut config = ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(tls)?));
    config.transport_config(Arc::new(transport_config(mtu)?));

    let socket = UdpSocket::bind(listen).with_context(|| format!("не удалось занять {listen}"))?;
    endpoint(socket, Some(config), mtu)
}

pub fn client_endpoint(server: SocketAddr, tls: rustls::ClientConfig, mtu: u16, fwmark: Option<u32>) -> Result<Endpoint> {
    let bind = if server.is_ipv4() { SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)) } else { SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)) };
    let socket = UdpSocket::bind(bind)?;

    if let Some(mark) = fwmark {
        set_mark(&socket, mark)?;
    }

    let mut config = ClientConfig::new(Arc::new(QuicClientConfig::try_from(tls)?));
    config.transport_config(Arc::new(transport_config(mtu)?));

    let mut endpoint = endpoint(socket, None, mtu)?;
    endpoint.set_default_client_config(config);
    Ok(endpoint)
}

fn endpoint(socket: UdpSocket, server: Option<ServerConfig>, mtu: u16) -> Result<Endpoint> {
    let mut config = EndpointConfig::default();
    config.max_udp_payload_size(mtu::udp_payload(mtu))?;

    let runtime = quinn::default_runtime().context("нет tokio runtime")?;
    Ok(Endpoint::new(config, server, socket, runtime)?)
}

fn transport_config(mtu: u16) -> Result<TransportConfig> {
    let udp_payload = mtu::udp_payload(mtu);

    let mut transport = TransportConfig::default();
    transport.initial_mtu(udp_payload);
    transport.min_mtu(udp_payload);
    transport.mtu_discovery_config(None);

    transport.max_idle_timeout(Some(Duration::from_secs(60).try_into()?));
    transport.keep_alive_interval(Some(Duration::from_secs(15)));
    transport.datagram_receive_buffer_size(Some(8 * 1024 * 1024));
    transport.datagram_send_buffer_size(8 * 1024 * 1024);
    transport.stream_receive_window((4u32 * 1024 * 1024).into());
    transport.receive_window((16u32 * 1024 * 1024).into());
    transport.send_window(16 * 1024 * 1024);
    transport.congestion_controller_factory(Arc::new(quinn::congestion::BbrConfig::default()));
    Ok(transport)
}

fn set_mark(socket: &UdpSocket, mark: u32) -> Result<()> {
    use std::os::fd::AsRawFd;

    let value = mark as libc::c_int;
    let size = std::mem::size_of::<libc::c_int>() as libc::socklen_t;

    // SAFETY: fd принадлежит живому сокету, указатель и размер описывают локальный c_int.
    let result = unsafe { libc::setsockopt(socket.as_raw_fd(), libc::SOL_SOCKET, libc::SO_MARK, (&value as *const libc::c_int).cast(), size) };

    if result != 0 {
        return Err(std::io::Error::last_os_error()).context("setsockopt(SO_MARK)");
    }

    Ok(())
}
