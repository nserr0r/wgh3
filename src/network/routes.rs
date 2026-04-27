use crate::config::Table;
use crate::network::state::State;
use anyhow::Context;
use anyhow::Result;
use anyhow::anyhow;
use ipnet::IpNet;
use ipnet::Ipv4Net;
use ipnet::Ipv6Net;
use std::process::Command;

pub const DEFAULT_TABLE: u32 = 51821;
pub const DEFAULT_FWMARK: u32 = 51821;
pub const RULE_PRIORITY: u32 = 32700;
const MAIN_TABLE: u32 = 254;

pub struct RouteManager {
    state: State,
}

impl RouteManager {
    pub fn new(tun_name: String) -> Self {
        Self { state: State { tun_name, ..State::default() } }
    }

    pub fn state_mut(&mut self) -> &mut State {
        &mut self.state
    }

    pub fn setup_auto_route(&mut self, peer_allowed_ips: &[IpNet], table: &Table, fwmark: Option<u32>) -> Result<()> {
        if matches!(table, Table::Off) {
            return Ok(());
        }

        let table_num = resolve_table(table);
        let mark = fwmark.unwrap_or(DEFAULT_FWMARK);
        let separate_table = !matches!(table, Table::Main);

        let has_v4 = peer_allowed_ips.iter().any(|n| matches!(n, IpNet::V4(_)));
        let has_v6 = peer_allowed_ips.iter().any(|n| matches!(n, IpNet::V6(_)));

        let full_tunnel_v4 = peer_allowed_ips.iter().any(|n| matches!(n, IpNet::V4(_)) && n.prefix_len() == 0);
        let full_tunnel_v6 = peer_allowed_ips.iter().any(|n| matches!(n, IpNet::V6(_)) && n.prefix_len() == 0);

        if full_tunnel_v4 {
            ip(&["route", "add", "default", "dev", &self.state.tun_name, "table", &table_num.to_string()]).context("не удалось добавить default v4")?;
            self.state.default_v4_added = true;
        }
        if full_tunnel_v6 {
            ip(&["-6", "route", "add", "default", "dev", &self.state.tun_name, "table", &table_num.to_string()]).context("не удалось добавить default v6")?;
            self.state.default_v6_added = true;
        }

        if separate_table && has_v4 {
            ip(&["rule", "add", "not", "fwmark", &mark.to_string(), "table", &table_num.to_string(), "priority", &(RULE_PRIORITY + 1).to_string()])?;
            ip(&["rule", "add", "table", "main", "suppress_prefixlength", "0", "priority", &(RULE_PRIORITY - 1).to_string()])?;
            self.state.rule_v4_added = true;
        }
        if separate_table && has_v6 {
            ip(&["-6", "rule", "add", "not", "fwmark", &mark.to_string(), "table", &table_num.to_string(), "priority", &(RULE_PRIORITY + 1).to_string()])?;
            ip(&["-6", "rule", "add", "table", "main", "suppress_prefixlength", "0", "priority", &(RULE_PRIORITY - 1).to_string()])?;
            self.state.rule_v6_added = true;
        }

        self.state.table = Some(table_num);
        self.state.fwmark = Some(mark);

        tracing::info!(
            table = table_num,
            fwmark = mark,
            full_v4 = full_tunnel_v4,
            full_v6 = full_tunnel_v6,
            split_v4 = has_v4 && !full_tunnel_v4,
            split_v6 = has_v6 && !full_tunnel_v6,
            "auto-route настроен"
        );
        Ok(())
    }

    pub fn teardown(&mut self) {
        let table = self.state.table.unwrap_or(DEFAULT_TABLE);
        let mark = self.state.fwmark.unwrap_or(DEFAULT_FWMARK);

        if self.state.rule_v4_added {
            let _ = ip(&["rule", "del", "not", "fwmark", &mark.to_string(), "table", &table.to_string(), "priority", &(RULE_PRIORITY + 1).to_string()]);
            let _ = ip(&["rule", "del", "table", "main", "suppress_prefixlength", "0", "priority", &(RULE_PRIORITY - 1).to_string()]);
            self.state.rule_v4_added = false;
        }
        if self.state.rule_v6_added {
            let _ = ip(&["-6", "rule", "del", "not", "fwmark", &mark.to_string(), "table", &table.to_string(), "priority", &(RULE_PRIORITY + 1).to_string()]);
            let _ = ip(&["-6", "rule", "del", "table", "main", "suppress_prefixlength", "0", "priority", &(RULE_PRIORITY - 1).to_string()]);
            self.state.rule_v6_added = false;
        }
        if self.state.default_v4_added {
            let _ = ip(&["route", "del", "default", "dev", &self.state.tun_name, "table", &table.to_string()]);
            self.state.default_v4_added = false;
        }
        if self.state.default_v6_added {
            let _ = ip(&["-6", "route", "del", "default", "dev", &self.state.tun_name, "table", &table.to_string()]);
            self.state.default_v6_added = false;
        }

        for subnet in std::mem::take(&mut self.state.subnet_routes) {
            let dst = subnet.to_string();
            let mut args: Vec<String> = Vec::new();
            if let IpNet::V6(_) = subnet {
                args.push("-6".into());
            }
            args.extend(["route".into(), "del".into(), dst, "dev".into(), self.state.tun_name.clone()]);
            if let Some(t) = self.state.table {
                args.push("table".into());
                args.push(t.to_string());
            }
            let argv: Vec<&str> = args.iter().map(String::as_str).collect();
            let _ = ip(&argv);
        }

        tracing::info!("routes очищены");
    }

    pub fn add_subnet_route(&mut self, subnet: &IpNet, table: Option<u32>) {
        let Some(normalized) = normalize_subnet(subnet) else {
            tracing::warn!(%subnet, "некорректная подсеть");
            return;
        };

        let dst = normalized.to_string();
        let table_str = table.map(|t| t.to_string());

        let mut args: Vec<&str> = Vec::with_capacity(8);
        if matches!(normalized, IpNet::V6(_)) {
            args.push("-6");
        }
        args.extend_from_slice(&["route", "replace", &dst, "dev", &self.state.tun_name]);
        if let Some(ref t) = table_str {
            args.extend_from_slice(&["table", t]);
        }

        match ip(&args) {
            Ok(()) => {
                tracing::info!(%dst, tun = %self.state.tun_name, ?table, "маршрут на подсеть добавлен");
                self.state.subnet_routes.push(normalized);
            }
            Err(err) => {
                tracing::warn!(?err, %dst, "не удалось добавить маршрут на подсеть");
            }
        }
    }
}

fn resolve_table(table: &Table) -> u32 {
    match table {
        Table::Number(n) => *n,
        Table::Main => MAIN_TABLE,
        Table::Auto => DEFAULT_TABLE,
        Table::Off => MAIN_TABLE,
    }
}

pub fn table_for_subnet_routes(table: &Table) -> Option<u32> {
    match table {
        Table::Number(n) => Some(*n),
        Table::Main | Table::Off | Table::Auto => None,
    }
}

fn normalize_subnet(subnet: &IpNet) -> Option<IpNet> {
    match subnet {
        IpNet::V4(net) => Ipv4Net::new(net.network(), net.prefix_len()).ok().map(IpNet::V4),
        IpNet::V6(net) => Ipv6Net::new(net.network(), net.prefix_len()).ok().map(IpNet::V6),
    }
}

fn ip(args: &[&str]) -> Result<()> {
    let output = Command::new("ip").args(args).output().context("не удалось запустить ip")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow!("ip {}: {}", args.join(" "), stderr.trim()));
    }

    Ok(())
}

pub fn fwmark_for_socket(socket: &std::net::UdpSocket, mark: u32) -> Result<()> {
    use std::os::fd::AsRawFd;

    let fd = socket.as_raw_fd();
    let mark = mark as libc::c_int;

    let ret = unsafe {
        libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_MARK, &mark as *const _ as *const libc::c_void, std::mem::size_of::<libc::c_int>() as libc::socklen_t)
    };

    if ret != 0 {
        return Err(anyhow!("setsockopt(SO_MARK): {}", std::io::Error::last_os_error()));
    }

    Ok(())
}
