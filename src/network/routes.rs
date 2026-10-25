use crate::config::Table;
use crate::network::state::Family;
use crate::network::state::State;
use anyhow::Context;
use anyhow::Result;
use anyhow::bail;
use ipnet::IpNet;
use std::process::Command;

const DEFAULT_TABLE: u32 = 51821;
const MAIN_TABLE: u32 = 254;
const LOOKUP_PRIORITY: u32 = 32701;
const SUPPRESS_PRIORITY: u32 = 32699;

pub fn subnet_table(table: &Table) -> Option<u32> {
    match table {
        Table::Number(number) => Some(*number),
        Table::Auto | Table::Main | Table::Off => None,
    }
}

pub fn add_subnet_route(state: &mut State, subnet: &IpNet) {
    let subnet = subnet.trunc();
    let destination = subnet.to_string();
    let table = state.subnet_table.map(|table| table.to_string());

    let mut args = vec![Family::of(&subnet).flag(), "route", "replace", &destination, "dev", &state.tun_name];
    if let Some(table) = &table {
        args.extend(["table", table]);
    }

    match ip(&args) {
        Ok(()) => {
            tracing::info!(%destination, ?table, "маршрут на подсеть добавлен");
            state.subnet_routes.push(subnet);
        }
        Err(err) => tracing::warn!(?err, %destination, "не удалось добавить маршрут на подсеть"),
    }
}

pub fn add_auto_route(state: &mut State, allowed_ips: &[IpNet], table: &Table, fwmark: u32) -> Result<()> {
    let number = match table {
        Table::Off => return Ok(()),
        Table::Number(number) => *number,
        Table::Main => MAIN_TABLE,
        Table::Auto => DEFAULT_TABLE,
    };

    state.table = number;
    state.fwmark = fwmark;

    for family in [Family::V4, Family::V6] {
        let routed: Vec<&IpNet> = allowed_ips.iter().filter(|net| Family::of(net) == family).collect();
        if routed.is_empty() {
            continue;
        }

        if routed.iter().any(|net| net.prefix_len() == 0) {
            ip(&[family.flag(), "route", "add", "default", "dev", &state.tun_name, "table", &number.to_string()])
                .context("не удалось добавить default-маршрут")?;
            state.default_routes.push(family);
        }

        if *table != Table::Main {
            state.rules.push(family);
            update_rules("add", family, number, fwmark)?;
        }
    }

    tracing::info!(table = number, fwmark, defaults = ?state.default_routes, rules = ?state.rules, "auto-route настроен");
    Ok(())
}

pub fn remove_all(state: &State) {
    for family in &state.rules {
        let _ = update_rules("del", *family, state.table, state.fwmark);
    }

    for family in &state.default_routes {
        let _ = ip(&[family.flag(), "route", "del", "default", "dev", &state.tun_name, "table", &state.table.to_string()]);
    }

    let table = state.subnet_table.map(|table| table.to_string());
    for subnet in &state.subnet_routes {
        let destination = subnet.to_string();
        let mut args = vec![Family::of(subnet).flag(), "route", "del", &destination, "dev", &state.tun_name];
        if let Some(table) = &table {
            args.extend(["table", table]);
        }
        let _ = ip(&args);
    }

    tracing::info!("маршруты очищены");
}

fn update_rules(action: &str, family: Family, table: u32, fwmark: u32) -> Result<()> {
    let flag = family.flag();
    let table = table.to_string();
    let fwmark = fwmark.to_string();
    let lookup_priority = LOOKUP_PRIORITY.to_string();
    let suppress_priority = SUPPRESS_PRIORITY.to_string();

    ip(&[flag, "rule", action, "not", "fwmark", &fwmark, "table", &table, "priority", &lookup_priority])?;
    ip(&[flag, "rule", action, "table", "main", "suppress_prefixlength", "0", "priority", &suppress_priority])
}

fn ip(args: &[&str]) -> Result<()> {
    let output = Command::new("ip").args(args).output().context("не удалось запустить ip")?;

    if !output.status.success() {
        bail!("ip {}: {}", args.join(" "), String::from_utf8_lossy(&output.stderr).trim());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subnet_routes_use_only_explicit_table() {
        assert_eq!(subnet_table(&Table::Number(100)), Some(100));
        assert_eq!(subnet_table(&Table::Auto), None);
        assert_eq!(subnet_table(&Table::Main), None);
        assert_eq!(subnet_table(&Table::Off), None);
    }

    #[test]
    fn auto_route_off_does_nothing() {
        let mut state = State::default();
        let allowed: Vec<IpNet> = vec!["0.0.0.0/0".parse().unwrap()];

        add_auto_route(&mut state, &allowed, &Table::Off, 1).unwrap();

        assert!(state.default_routes.is_empty());
        assert!(state.rules.is_empty());
    }
}
