use crate::mtu;
use anyhow::Context;
use anyhow::Result;
use anyhow::bail;
use ipnet::IpNet;
use serde::Deserialize;
use std::fs;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::path::Path;

pub const DEFAULT_FWMARK: u32 = 51821;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    Server,
    Client,
}

#[derive(Clone, Deserialize)]
pub struct Config {
    pub mode: Mode,
    pub token: String,

    pub listen: Option<SocketAddr>,
    pub server: Option<SocketAddr>,
    pub server_name: Option<String>,
    pub pin_sha256: Option<String>,
    #[serde(default)]
    pub insecure: bool,

    pub wireguard: WireGuardConfig,
    pub network: NetworkConfig,
    pub tls: Option<TlsConfig>,
    pub fallback: Option<FallbackConfig>,

    #[serde(default, rename = "peer")]
    pub peers: Vec<PeerConfig>,
}

#[derive(Clone, Deserialize)]
pub struct WireGuardConfig {
    pub private_key: String,
    pub peer_public_key: Option<String>,
    pub peer_preshared_key: Option<String>,
    #[serde(default)]
    pub peer_allowed_ips: Vec<IpNet>,
    #[serde(default = "default_keepalive")]
    pub persistent_keepalive: u16,
}

#[derive(Clone, Deserialize)]
pub struct PeerConfig {
    pub public_key: String,
    pub preshared_key: Option<String>,
    pub allowed_ips: Vec<IpNet>,
}

#[derive(Clone, Deserialize)]
pub struct NetworkConfig {
    #[serde(default = "default_tun_name")]
    pub tun_name: String,
    pub address: IpNet,
    #[serde(default = "default_mtu")]
    pub mtu: u16,

    #[serde(default)]
    pub auto_route: bool,
    #[serde(default)]
    pub table: Table,
    pub fwmark: Option<u32>,

    #[serde(default)]
    pub dns: Vec<IpAddr>,

    #[serde(default)]
    pub pre_up: Vec<String>,
    #[serde(default)]
    pub post_up: Vec<String>,
    #[serde(default)]
    pub pre_down: Vec<String>,
    #[serde(default)]
    pub post_down: Vec<String>,
}

impl NetworkConfig {
    pub fn socket_mark(&self) -> Option<u32> {
        if self.auto_route { Some(self.fwmark.unwrap_or(DEFAULT_FWMARK)) } else { self.fwmark }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(try_from = "TableValue")]
pub enum Table {
    #[default]
    Auto,
    Main,
    Off,
    Number(u32),
}

#[derive(Deserialize)]
#[serde(untagged)]
enum TableValue {
    Number(u32),
    Name(String),
}

impl TryFrom<TableValue> for Table {
    type Error = String;

    fn try_from(value: TableValue) -> std::result::Result<Self, Self::Error> {
        match value {
            TableValue::Number(number) => Ok(Table::Number(number)),
            TableValue::Name(name) => match name.as_str() {
                "auto" => Ok(Table::Auto),
                "main" => Ok(Table::Main),
                "off" => Ok(Table::Off),
                other => other.parse().map(Table::Number).map_err(|_| format!("неверное значение table: {other}")),
            },
        }
    }
}

#[derive(Clone, Deserialize)]
pub struct TlsConfig {
    pub cert: String,
    pub key: String,
}

#[derive(Clone, Deserialize)]
pub struct FallbackConfig {
    pub upstream: SocketAddr,
    pub listen_tcp: Option<SocketAddr>,
}

fn default_tun_name() -> String {
    "wgh3".into()
}

fn default_mtu() -> u16 {
    mtu::DEFAULT_MTU
}

fn default_keepalive() -> u16 {
    25
}

impl Config {
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let data = fs::read_to_string(path).context("не удалось прочитать конфиг")?;
        Self::parse(&data)
    }

    fn parse(data: &str) -> Result<Self> {
        let config: Self = toml::from_str(data).context("не удалось разобрать конфиг")?;
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> Result<()> {
        let mtu = self.network.mtu;
        if !(mtu::MIN_MTU..=mtu::MAX_MTU).contains(&mtu) {
            bail!("network.mtu должен быть в диапазоне {}..={}, указано {mtu}", mtu::MIN_MTU, mtu::MAX_MTU);
        }

        if self.mode == Mode::Server {
            self.validate_peers()?;
        }

        Ok(())
    }

    fn validate_peers(&self) -> Result<()> {
        if self.peers.is_empty() {
            bail!("на сервере требуется хотя бы один [[peer]]");
        }

        let mut seen: Vec<&IpNet> = Vec::new();

        for subnet in self.peers.iter().flat_map(|peer| &peer.allowed_ips) {
            if let Some(existing) = seen.iter().find(|existing| subnets_overlap(subnet, existing)) {
                bail!("подсети peer'ов пересекаются: {subnet} и {existing}");
            }
            seen.push(subnet);
        }

        Ok(())
    }
}

fn subnets_overlap(a: &IpNet, b: &IpNet) -> bool {
    a.contains(&b.network()) || b.contains(&a.network())
}

#[cfg(test)]
mod tests {
    use super::*;

    const CLIENT: &str = r#"
        mode = "client"
        token = "secret"
        server = "1.2.3.4:443"
        server_name = "example.com"

        [wireguard]
        private_key = "key"

        [network]
        address = "10.0.0.2/24"
    "#;

    fn client_with_network(extra: &str) -> Result<Config> {
        Config::parse(&format!("{CLIENT}{extra}"))
    }

    #[test]
    fn defaults_applied() {
        let config = Config::parse(CLIENT).unwrap();

        assert_eq!(config.mode, Mode::Client);
        assert_eq!(config.network.mtu, mtu::DEFAULT_MTU);
        assert_eq!(config.network.tun_name, "wgh3");
        assert_eq!(config.network.table, Table::Auto);
        assert_eq!(config.network.socket_mark(), None);
        assert_eq!(config.wireguard.persistent_keepalive, 25);
    }

    #[test]
    fn table_accepts_numbers_and_names() {
        assert_eq!(client_with_network("table = 100").unwrap().network.table, Table::Number(100));
        assert_eq!(client_with_network("table = \"200\"").unwrap().network.table, Table::Number(200));
        assert_eq!(client_with_network("table = \"main\"").unwrap().network.table, Table::Main);
        assert_eq!(client_with_network("table = \"off\"").unwrap().network.table, Table::Off);
    }

    #[test]
    fn table_rejects_garbage() {
        assert!(client_with_network("table = \"nope\"").is_err());
        assert!(client_with_network("table = -1").is_err());
    }

    #[test]
    fn mtu_out_of_range_rejected() {
        assert!(client_with_network(&format!("mtu = {}", mtu::MIN_MTU - 1)).is_err());
        assert!(client_with_network(&format!("mtu = {}", mtu::MAX_MTU + 1)).is_err());
        assert!(client_with_network(&format!("mtu = {}", mtu::MIN_MTU)).is_ok());
    }

    #[test]
    fn auto_route_enables_default_fwmark() {
        let config = client_with_network("auto_route = true").unwrap();
        assert_eq!(config.network.socket_mark(), Some(DEFAULT_FWMARK));

        let config = client_with_network("auto_route = true\nfwmark = 7").unwrap();
        assert_eq!(config.network.socket_mark(), Some(7));
    }

    #[test]
    fn unknown_mode_rejected() {
        assert!(Config::parse(&CLIENT.replace("\"client\"", "\"proxy\"")).is_err());
    }

    fn server_with_peers(peers: &[&str]) -> Result<Config> {
        let mut data = String::from(
            r#"
            mode = "server"
            token = "secret"
            listen = "0.0.0.0:443"

            [wireguard]
            private_key = "key"

            [network]
            address = "10.0.0.1/24"
            "#,
        );

        for allowed_ips in peers {
            data.push_str(&format!("\n[[peer]]\npublic_key = \"key\"\nallowed_ips = [{allowed_ips}]\n"));
        }

        Config::parse(&data)
    }

    #[test]
    fn server_requires_peers() {
        assert!(server_with_peers(&[]).is_err());
    }

    #[test]
    fn server_rejects_overlapping_subnets() {
        assert!(server_with_peers(&["\"10.0.0.2/32\"", "\"10.0.0.3/32\""]).is_ok());
        assert!(server_with_peers(&["\"10.0.0.0/24\"", "\"10.0.0.3/32\""]).is_err());
        assert!(server_with_peers(&["\"10.0.0.2/32\", \"10.0.0.2/32\""]).is_err());
    }
}
