use anyhow::Context;
use anyhow::Result;
use ipnet::IpNet;
use std::sync::Arc;
use tun_rs::AsyncDevice;
use tun_rs::DeviceBuilder;

pub const MAX_PACKET_SIZE: usize = 65535;

pub struct Tun {
    device: Arc<AsyncDevice>,
    name: String,
}

impl Tun {
    pub fn new(name: &str, address: IpNet, mtu: u16) -> Result<Self> {
        let prefix = address.prefix_len();
        let addr = address.addr();

        let device = DeviceBuilder::new().name(name).mtu(mtu as _).ipv4(addr, prefix, None).build_async().context("не удалось создать TUN-интерфейс")?;

        Ok(Self { device: Arc::new(device), name: name.to_string() })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn handle(&self) -> Arc<AsyncDevice> {
        self.device.clone()
    }
}
