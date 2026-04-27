use anyhow::Result;
use std::fs;
use std::io::Write;
use std::net::IpAddr;
use std::path::Path;

const RESOLV_CONF: &str = "/etc/resolv.conf";
const BACKUP_PATH: &str = "/var/run/wgh3/resolv.conf.bak";

pub struct DnsManager {
    active: bool,
}

impl DnsManager {
    pub fn new() -> Self {
        Self { active: false }
    }

    pub fn setup(&mut self, servers: &[IpAddr]) -> Result<()> {
        if servers.is_empty() {
            return Ok(());
        }

        let resolv = Path::new(RESOLV_CONF);

        if resolv.symlink_metadata().map(|m| m.file_type().is_symlink()).unwrap_or(false) {
            tracing::warn!("/etc/resolv.conf — симлинк (вероятно systemd-resolved), DNS не управляем");
            return Ok(());
        }

        if let Some(parent) = Path::new(BACKUP_PATH).parent() {
            fs::create_dir_all(parent)?;
        }

        if resolv.exists() {
            fs::copy(RESOLV_CONF, BACKUP_PATH)?;
        }

        let mut content = String::from("# managed by wgh3\n");
        for server in servers {
            content.push_str(&format!("nameserver {server}\n"));
        }

        let mut file = fs::File::create(RESOLV_CONF)?;
        file.write_all(content.as_bytes())?;

        let list: Vec<String> = servers.iter().map(|s| s.to_string()).collect();
        tracing::info!(servers = list.join(", "), "DNS установлено");
        self.active = true;
        Ok(())
    }

    pub fn teardown(&mut self) -> Result<()> {
        if !self.active {
            return Ok(());
        }

        let backup = Path::new(BACKUP_PATH);
        if backup.exists() {
            fs::copy(BACKUP_PATH, RESOLV_CONF)?;
            let _ = fs::remove_file(BACKUP_PATH);
            tracing::info!("DNS восстановлен");
        }

        self.active = false;
        Ok(())
    }
}

impl Default for DnsManager {
    fn default() -> Self {
        Self::new()
    }
}
