use crate::config::NetworkConfig;
use crate::mtu;
use crate::network::dns;
use crate::network::hooks;
use crate::network::routes;
use crate::network::state::State;
use crate::network::tun;
use anyhow::Result;
use ipnet::IpNet;
use std::sync::Arc;
use tun_rs::AsyncDevice;

pub struct Lifecycle {
    pub device: Arc<AsyncDevice>,
    state: State,
}

impl Lifecycle {
    pub async fn setup(network: &NetworkConfig, routed_subnets: &[IpNet]) -> Result<Self> {
        hooks::run_all(&network.pre_up, &network.tun_name, "pre_up").await;

        let device = Arc::new(tun::create(&network.tun_name, network.address, network.mtu)?);
        tracing::info!(
            tun = %network.tun_name,
            address = %network.address,
            mtu = network.mtu,
            udp_payload = mtu::udp_payload(network.mtu),
            ipv4_packet = mtu::ipv4_packet(network.mtu),
            ipv6_packet = mtu::ipv6_packet(network.mtu),
            "TUN поднят"
        );

        let mut state = State {
            tun_name: network.tun_name.clone(),
            subnet_table: routes::subnet_table(&network.table),
            pre_down: network.pre_down.clone(),
            post_down: network.post_down.clone(),
            ..State::default()
        };

        routes::add_subnet_route(&mut state, &network.address);
        for subnet in routed_subnets {
            if subnet.prefix_len() > 0 && !network.address.contains(&subnet.network()) {
                routes::add_subnet_route(&mut state, subnet);
            }
        }

        if network.auto_route
            && let Some(fwmark) = network.socket_mark()
            && let Err(err) = routes::add_auto_route(&mut state, routed_subnets, &network.table, fwmark)
        {
            tracing::error!(?err, "auto_route не настроен, откат");
            teardown(&state).await;
            return Err(err);
        }

        if !network.dns.is_empty() {
            match dns::apply(&network.dns) {
                Ok(applied) => state.dns_managed = applied,
                Err(err) => tracing::warn!(?err, "не удалось настроить DNS"),
            }
        }

        if let Err(err) = state.save() {
            tracing::warn!(?err, "не удалось сохранить state");
        }

        hooks::run_all(&network.post_up, &network.tun_name, "post_up").await;

        Ok(Self { device, state })
    }

    pub async fn teardown(self) {
        teardown(&self.state).await;
    }
}

pub async fn teardown(state: &State) {
    hooks::run_all(&state.pre_down, &state.tun_name, "pre_down").await;

    if state.dns_managed
        && let Err(err) = dns::restore()
    {
        tracing::warn!(?err, "не удалось восстановить DNS");
    }

    routes::remove_all(state);
    State::remove(&state.tun_name);

    hooks::run_all(&state.post_down, &state.tun_name, "post_down").await;
}
