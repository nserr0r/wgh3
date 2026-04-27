use anyhow::Result;
use anyhow::anyhow;
use rand_core::OsRng;
use rand_core::RngCore;
use std::io::BufRead;
use std::io::Write;
use tracing_subscriber::EnvFilter;
use wgh3::client;
use wgh3::config::Config;
use wgh3::network::dns::DnsManager;
use wgh3::network::hooks;
use wgh3::network::routes::RouteManager;
use wgh3::network::state::State;
use wgh3::server;
use wgh3::wg::decode_b64;
use wgh3::wg::encode_b64;
use x25519_dalek::PublicKey;
use x25519_dalek::StaticSecret;

#[tokio::main]
async fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let first = args.next().ok_or_else(|| anyhow!("использование: wgh3 <config.toml> | wgh3 keygen | wgh3 pubkey | wgh3 psk | wgh3 cleanup <tun_name>"))?;

    match first.as_str() {
        "keygen" => keygen(),
        "pubkey" => pubkey(),
        "psk" => psk(),
        "cleanup" => {
            init_tracing();
            let name = args.next().ok_or_else(|| anyhow!("использование: wgh3 cleanup <tun_name>"))?;
            cleanup(&name).await
        }
        path => run_daemon(path).await,
    }
}

fn init_tracing() {
    tracing_subscriber::fmt().with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("wgh3=info"))).with_target(false).init();
}

async fn run_daemon(path: &str) -> Result<()> {
    init_tracing();

    rustls::crypto::aws_lc_rs::default_provider().install_default().map_err(|_| anyhow!("не удалось установить CryptoProvider"))?;

    let config = Config::load(path)?;

    match config.mode.as_str() {
        "server" => server::run(config).await,
        "client" => client::run(config).await,
        _ => Err(anyhow!("режим должен быть server или client")),
    }
}

async fn cleanup(tun_name: &str) -> Result<()> {
    let state = match State::load(tun_name)? {
        Some(s) => s,
        None => {
            tracing::info!(%tun_name, "state-файл не найден, нечего чистить");
            return Ok(());
        }
    };

    tracing::info!(%tun_name, "очистка");

    hooks::run_all(&state.pre_down, tun_name, "pre_down").await;

    if state.dns_managed {
        let mut dns = DnsManager::new();
        let _ = dns.teardown();
    }

    let mut routes = RouteManager::new(tun_name.to_string());
    *routes.state_mut() = state.clone();
    routes.teardown();

    hooks::run_all(&state.post_down, tun_name, "post_down").await;

    State::remove(tun_name);
    tracing::info!("очистка готова");
    Ok(())
}

fn keygen() -> Result<()> {
    let secret = StaticSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&secret);

    let private_b64 = encode_b64(secret.as_bytes());
    let public_b64 = encode_b64(public.as_bytes());

    println!("private_key = \"{private_b64}\"");
    println!("public_key  = \"{public_b64}\"");
    Ok(())
}

fn pubkey() -> Result<()> {
    let stdin = std::io::stdin();
    let mut input = String::new();
    stdin.lock().read_line(&mut input)?;
    let input = input.trim();

    let bytes = decode_b64(input).map_err(|_| anyhow!("приватный ключ должен быть base64"))?;
    let array: [u8; 32] = bytes.try_into().map_err(|_| anyhow!("приватный ключ должен быть 32 байта"))?;

    let secret = StaticSecret::from(array);
    let public = PublicKey::from(&secret);

    let public_b64 = encode_b64(public.as_bytes());
    let stdout = std::io::stdout();
    writeln!(stdout.lock(), "{public_b64}")?;
    Ok(())
}

fn psk() -> Result<()> {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);

    let psk_b64 = encode_b64(&bytes);
    println!("preshared_key = \"{psk_b64}\"");
    Ok(())
}
