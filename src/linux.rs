use crate::client::Client;
use crate::client::Platform;
use crate::config::Config;
use crate::network::lifecycle::Lifecycle;
use crate::signal;
use anyhow::Context;
use anyhow::Result;
use std::net::UdpSocket;
use std::os::fd::AsRawFd;
use std::sync::Arc;

pub async fn run_client(config: Config) -> Result<()> {
    let platform = Arc::new(LinuxPlatform { fwmark: config.network.socket_mark() });
    let client = Client::new(&config, platform)?;
    let lifecycle = Lifecycle::setup(&config.network, &config.wireguard.peer_allowed_ips).await?;

    let result = tokio::select! {
        () = client.run(&lifecycle.device) => Ok(()),
        result = signal::shutdown() => result,
    };

    lifecycle.teardown().await;
    result
}

struct LinuxPlatform {
    fwmark: Option<u32>,
}

impl Platform for LinuxPlatform {
    fn protect(&self, socket: &UdpSocket) -> Result<()> {
        match self.fwmark {
            Some(mark) => set_mark(socket, mark),
            None => Ok(()),
        }
    }
}

fn set_mark(socket: &UdpSocket, mark: u32) -> Result<()> {
    let value = mark as libc::c_int;
    let size = std::mem::size_of::<libc::c_int>() as libc::socklen_t;

    // SAFETY: fd принадлежит живому сокету, указатель и размер описывают локальный c_int.
    let result = unsafe { libc::setsockopt(socket.as_raw_fd(), libc::SOL_SOCKET, libc::SO_MARK, (&value as *const libc::c_int).cast(), size) };

    if result != 0 {
        return Err(std::io::Error::last_os_error()).context("setsockopt(SO_MARK)");
    }

    Ok(())
}
