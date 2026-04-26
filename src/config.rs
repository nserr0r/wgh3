use anyhow::Context;
use anyhow::Result;
use serde::Deserialize;
use std::fs;
use std::net::SocketAddr;
use std::path::Path;

#[derive(Clone, Deserialize)]
pub struct Config {
    pub mode: String,
    pub token: String,
    pub listen: SocketAddr,

    pub server: Option<SocketAddr>,
    pub server_name: Option<String>,
    pub server_target: Option<SocketAddr>,
    pub pin_sha256: Option<String>,
    #[serde(default)]
    pub insecure: bool,

    pub wireguard: Option<WireGuardConfig>,
    pub tls: Option<TlsConfig>,
    pub fallback: Option<FallbackConfig>,
}

#[derive(Clone, Deserialize)]
pub struct WireGuardConfig {
    pub endpoint: SocketAddr,
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

impl Config {
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let data = fs::read_to_string(path).context("не удалось прочитать конфиг")?;
        toml::from_str(&data).context("не удалось разобрать конфиг")
    }
}
