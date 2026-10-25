use anyhow::Context;
use anyhow::Result;
use anyhow::bail;
use ipnet::IpNet;
use tun_rs::AsyncDevice;
use tun_rs::DeviceBuilder;

pub fn create(name: &str, address: IpNet, mtu: u16) -> Result<AsyncDevice> {
    let builder = DeviceBuilder::new().name(name).mtu(mtu);

    let builder = match address {
        IpNet::V4(net) => builder.ipv4(net.addr(), net.prefix_len(), None),
        IpNet::V6(net) => builder.ipv6(net.addr(), net.prefix_len()),
    };

    let device = builder.build_async().context("не удалось создать TUN-интерфейс")?;

    let actual = device.mtu().context("не удалось прочитать MTU TUN-интерфейса")?;
    if actual != mtu {
        bail!("MTU TUN-интерфейса {actual}, ожидалось {mtu}");
    }

    Ok(device)
}
