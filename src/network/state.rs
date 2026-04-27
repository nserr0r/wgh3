use anyhow::Result;
use ipnet::IpNet;
use serde::Deserialize;
use serde::Serialize;
use std::fs;
use std::path::Path;
use std::path::PathBuf;

const STATE_DIR: &str = "/var/run/wgh3";

#[derive(Clone, Default, Serialize, Deserialize)]
pub struct State {
    pub tun_name: String,
    pub table: Option<u32>,
    pub fwmark: Option<u32>,
    pub default_v4_added: bool,
    pub default_v6_added: bool,
    pub rule_v4_added: bool,
    pub rule_v6_added: bool,
    #[serde(default)]
    pub subnet_routes: Vec<IpNet>,
    pub pre_down: Vec<String>,
    pub post_down: Vec<String>,
    pub dns_managed: bool,
}

impl State {
    pub fn path(tun_name: &str) -> PathBuf {
        Path::new(STATE_DIR).join(format!("{tun_name}.state"))
    }

    pub fn save(&self) -> Result<()> {
        fs::create_dir_all(STATE_DIR)?;
        let path = Self::path(&self.tun_name);
        let data = serde_json::to_string_pretty(self)?;
        fs::write(path, data)?;
        Ok(())
    }

    pub fn load(tun_name: &str) -> Result<Option<Self>> {
        let path = Self::path(tun_name);
        if !path.exists() {
            return Ok(None);
        }
        let data = fs::read_to_string(path)?;
        let state = serde_json::from_str(&data)?;
        Ok(Some(state))
    }

    pub fn remove(tun_name: &str) {
        let _ = fs::remove_file(Self::path(tun_name));
    }
}
