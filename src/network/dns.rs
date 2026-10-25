use crate::network::state::STATE_DIR;
use anyhow::Result;
use std::fs;
use std::net::IpAddr;
use std::path::Path;
use std::path::PathBuf;

const RESOLV_CONF: &str = "/etc/resolv.conf";

fn backup_path() -> PathBuf {
    Path::new(STATE_DIR).join("resolv.conf.bak")
}

pub fn apply(servers: &[IpAddr]) -> Result<bool> {
    let resolv = Path::new(RESOLV_CONF);

    if resolv.symlink_metadata().is_ok_and(|meta| meta.file_type().is_symlink()) {
        tracing::warn!("{RESOLV_CONF} — симлинк (вероятно systemd-resolved), DNS не управляем");
        return Ok(false);
    }

    fs::create_dir_all(STATE_DIR)?;
    if resolv.exists() {
        fs::copy(resolv, backup_path())?;
    }

    let mut content = String::from("# managed by wgh3\n");
    for server in servers {
        content.push_str(&format!("nameserver {server}\n"));
    }
    fs::write(resolv, content)?;

    tracing::info!(?servers, "DNS установлен");
    Ok(true)
}

pub fn restore() -> Result<()> {
    let backup = backup_path();
    if !backup.exists() {
        return Ok(());
    }

    fs::copy(&backup, RESOLV_CONF)?;
    fs::remove_file(&backup)?;
    tracing::info!("DNS восстановлен");
    Ok(())
}
