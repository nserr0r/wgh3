use anyhow::Context;
use anyhow::Result;
use anyhow::anyhow;
use ipnet::IpNet;
use serde::Deserialize;
use serde::de::Deserializer;
use std::fs;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::path::Path;

#[derive(Clone, Deserialize)]
pub struct Config {
    pub mode: String,
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
    #[serde(default, deserialize_with = "deserialize_table")]
    pub table: Table,
    #[serde(default)]
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

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum Table {
    #[default]
    Auto,
    Main,
    Off,
    Number(u32),
}

fn deserialize_table<'de, D>(deserializer: D) -> std::result::Result<Table, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::Error;
    use serde::de::Visitor;
    use std::fmt;

    struct TableVisitor;

    impl<'de> Visitor<'de> for TableVisitor {
        type Value = Table;

        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
            f.write_str("число routing-таблицы или строка \"main\" / \"off\" / \"auto\"")
        }

        fn visit_str<E: Error>(self, value: &str) -> std::result::Result<Table, E> {
            match value {
                "auto" => Ok(Table::Auto),
                "main" => Ok(Table::Main),
                "off" => Ok(Table::Off),
                other => other.parse::<u32>().map(Table::Number).map_err(|_| E::custom(format!("неверное значение table: {other}"))),
            }
        }

        fn visit_u64<E: Error>(self, value: u64) -> std::result::Result<Table, E> {
            Ok(Table::Number(value as u32))
        }

        fn visit_i64<E: Error>(self, value: i64) -> std::result::Result<Table, E> {
            if value < 0 {
                return Err(E::custom("table не может быть отрицательным"));
            }
            Ok(Table::Number(value as u32))
        }
    }

    deserializer.deserialize_any(TableVisitor)
}

#[derive(Clone, Deserialize)]
pub struct TlsConfig {
    pub cert: String,
    pub key: String,
}

#[derive(Clone, Deserialize)]
pub struct FallbackConfig {
    pub upstream: SocketAddr,
    #[serde(default)]
    pub listen_tcp: Option<SocketAddr>,
}

fn default_tun_name() -> String {
    "wgh3".into()
}

fn default_mtu() -> u16 {
    1380
}

fn default_keepalive() -> u16 {
    25
}

impl Config {
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let data = fs::read_to_string(path).context("не удалось прочитать конфиг")?;
        let config: Self = toml::from_str(&data).context("не удалось разобрать конфиг")?;
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> Result<()> {
        if self.mode == "server" {
            self.validate_server_peers()?;
        }
        Ok(())
    }

    fn validate_server_peers(&self) -> Result<()> {
        if self.peers.is_empty() {
            return Err(anyhow!("на сервере требуется хотя бы один [[peer]]"));
        }

        let mut all_subnets: Vec<&IpNet> = Vec::new();

        for peer in &self.peers {
            for subnet in &peer.allowed_ips {
                for existing in &all_subnets {
                    if subnets_overlap(subnet, existing) {
                        return Err(anyhow!("подсети peer'ов пересекаются: {} и {}", subnet, existing));
                    }
                }
                all_subnets.push(subnet);
            }
        }

        Ok(())
    }
}

fn subnets_overlap(a: &IpNet, b: &IpNet) -> bool {
    a.contains(&b.network()) || b.contains(&a.network())
}
