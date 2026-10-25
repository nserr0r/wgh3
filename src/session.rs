use crate::masque::DatagramChannel;
use crate::wg::Output;
use crate::wg::Tunnel;
use anyhow::Result;
use std::time::Duration;
use tun_rs::AsyncDevice;

const TIMER_TICK: Duration = Duration::from_secs(1);

pub struct Session {
    tunnel: Tunnel,
    channel: DatagramChannel,
}

impl Session {
    pub fn new(tunnel: Tunnel, channel: DatagramChannel) -> Self {
        Self { tunnel, channel }
    }

    pub fn initiate_handshake(&self) -> Result<()> {
        if let Some(packet) = self.tunnel.initiate_handshake()? {
            self.channel.send(&packet)?;
        }
        Ok(())
    }

    pub fn send(&self, packet: &[u8]) -> Result<()> {
        match self.tunnel.encapsulate(packet) {
            Ok(Some(datagram)) => self.channel.send(&datagram),
            Ok(None) => Ok(()),
            Err(err) => {
                tracing::debug!(?err, "encapsulate");
                Ok(())
            }
        }
    }

    pub async fn deliver(&self, datagram: &[u8], device: &AsyncDevice) -> Result<()> {
        let outputs = match self.tunnel.decapsulate(datagram) {
            Ok(outputs) => outputs,
            Err(err) => {
                tracing::debug!(?err, "decapsulate");
                return Ok(());
            }
        };

        for output in outputs {
            match output {
                Output::Network(packet) => self.channel.send(&packet)?,
                Output::Device(packet) => {
                    if let Err(err) = device.send(&packet).await {
                        tracing::warn!(?err, "запись в TUN");
                    }
                }
            }
        }

        Ok(())
    }

    pub async fn receive(&self, device: &AsyncDevice) -> Result<()> {
        loop {
            let datagram = self.channel.recv().await?;
            self.deliver(&datagram, device).await?;
        }
    }

    pub async fn run_timers(&self) -> Result<()> {
        let mut interval = tokio::time::interval(TIMER_TICK);
        loop {
            interval.tick().await;
            if let Some(packet) = self.tunnel.update_timers()? {
                self.channel.send(&packet)?;
            }
        }
    }
}
