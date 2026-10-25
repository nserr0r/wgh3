use anyhow::Context;
use anyhow::Result;
use anyhow::anyhow;
use rand_core::OsRng;
use rand_core::RngCore;
use tracing_subscriber::EnvFilter;
use wgh3::client;
use wgh3::config::Config;
use wgh3::config::Mode;
use wgh3::network::lifecycle;
use wgh3::network::state::State;
use wgh3::server;
use wgh3::wg;
use x25519_dalek::PublicKey;
use x25519_dalek::StaticSecret;

const USAGE: &str = "использование: wgh3 <config.toml> | wgh3 keygen | wgh3 pubkey | wgh3 psk | wgh3 cleanup <tun_name>";

#[tokio::main]
async fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let command = args.next().ok_or_else(|| anyhow!(USAGE))?;

    match command.as_str() {
        "keygen" => keygen(),
        "pubkey" => pubkey(),
        "psk" => psk(),
        "cleanup" => {
            init_tracing();
            let tun_name = args.next().ok_or_else(|| anyhow!(USAGE))?;
            cleanup(&tun_name).await
        }
        path => run(path).await,
    }
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("wgh3=info"));
    tracing_subscriber::fmt().with_env_filter(filter).with_target(false).init();
}

async fn run(path: &str) -> Result<()> {
    init_tracing();

    rustls::crypto::aws_lc_rs::default_provider().install_default().map_err(|_| anyhow!("не удалось установить CryptoProvider"))?;

    let config = Config::load(path)?;
    match config.mode {
        Mode::Server => server::run(config).await,
        Mode::Client => client::run(config).await,
    }
}

async fn cleanup(tun_name: &str) -> Result<()> {
    let Some(state) = State::load(tun_name)? else {
        tracing::info!(%tun_name, "state-файл не найден, нечего чистить");
        return Ok(());
    };

    tracing::info!(%tun_name, "очистка");
    lifecycle::teardown(&state).await;
    Ok(())
}

fn keygen() -> Result<()> {
    let secret = StaticSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&secret);

    println!("private_key = \"{}\"", wg::encode_b64(secret.as_bytes()));
    println!("public_key  = \"{}\"", wg::encode_b64(public.as_bytes()));
    Ok(())
}

fn pubkey() -> Result<()> {
    let mut input = String::new();
    std::io::stdin().read_line(&mut input).context("не удалось прочитать stdin")?;

    let secret = StaticSecret::from(wg::parse_key(&input, "приватный ключ")?);
    println!("{}", wg::encode_b64(PublicKey::from(&secret).as_bytes()));
    Ok(())
}

fn psk() -> Result<()> {
    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);

    println!("preshared_key = \"{}\"", wg::encode_b64(&key));
    Ok(())
}
