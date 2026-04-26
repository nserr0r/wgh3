use anyhow::Result;
use anyhow::anyhow;
use tracing_subscriber::EnvFilter;
use wgh3::client;
use wgh3::config::Config;
use wgh3::server;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt().with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("wgh3=info"))).with_target(false).init();

    rustls::crypto::aws_lc_rs::default_provider().install_default().map_err(|_| anyhow!("не удалось установить CryptoProvider"))?;

    let path = std::env::args().nth(1).ok_or_else(|| anyhow!("использование: wgh3 <config.toml>"))?;

    let config = Config::load(path)?;

    match config.mode.as_str() {
        "server" => server::run(config).await,
        "client" => client::run(config).await,
        _ => Err(anyhow!("режим должен быть server или client")),
    }
}
