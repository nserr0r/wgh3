use anyhow::Result;
use ipnet::IpNet;
use serde::Deserialize;
use serde::Serialize;
use std::fs;
use std::io::ErrorKind;
use std::path::PathBuf;

pub const STATE_DIR: &str = "/var/run/wgh3";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Family {
    V4,
    V6,
}

impl Family {
    pub fn of(net: &IpNet) -> Self {
        match net {
            IpNet::V4(_) => Family::V4,
            IpNet::V6(_) => Family::V6,
        }
    }

    pub fn flag(self) -> &'static str {
        match self {
            Family::V4 => "-4",
            Family::V6 => "-6",
        }
    }
}

#[derive(Clone, Default, Serialize, Deserialize)]
pub struct State {
    pub tun_name: String,
    pub subnet_table: Option<u32>,
    pub subnet_routes: Vec<IpNet>,
    pub table: u32,
    pub fwmark: u32,
    pub default_routes: Vec<Family>,
    pub rules: Vec<Family>,
    pub dns_managed: bool,
    pub pre_down: Vec<String>,
    pub post_down: Vec<String>,
}

impl State {
    fn path(tun_name: &str) -> PathBuf {
        PathBuf::from(STATE_DIR).join(format!("{tun_name}.state"))
    }

    pub fn save(&self) -> Result<()> {
        fs::create_dir_all(STATE_DIR)?;
        fs::write(Self::path(&self.tun_name), serde_json::to_string_pretty(self)?)?;
        Ok(())
    }

    pub fn load(tun_name: &str) -> Result<Option<Self>> {
        match fs::read_to_string(Self::path(tun_name)) {
            Ok(data) => Ok(Some(serde_json::from_str(&data)?)),
            Err(err) if err.kind() == ErrorKind::NotFound => Ok(None),
            Err(err) => Err(err.into()),
        }
    }

    pub fn remove(tun_name: &str) {
        let _ = fs::remove_file(Self::path(tun_name));
    }
}
