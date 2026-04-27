use crate::config::NetworkConfig;
use crate::network::dns::DnsManager;
use crate::network::hooks;
use crate::network::routes::RouteManager;
use crate::network::routes::table_for_subnet_routes;
use crate::network::state::State;
use crate::network::tun::Tun;
use anyhow::Result;
use ipnet::IpNet;
use std::sync::Arc;

pub struct Lifecycle {
    pub tun: Arc<Tun>,
    pub routes: RouteManager,
    pub dns: DnsManager,
    pub network: NetworkConfig,
}

impl Lifecycle {
    pub async fn setup(network: NetworkConfig, extra_subnets: &[IpNet]) -> Result<Self> {
        hooks::run_all(&network.pre_up, &network.tun_name, "pre_up").await;

        let tun = Arc::new(Tun::new(&network.tun_name, network.address, network.mtu)?);
        tracing::info!(tun = %tun.name(), address = %network.address, mtu = network.mtu, "TUN поднят");

        let mut routes = RouteManager::new(network.tun_name.clone());

        let subnet_table = table_for_subnet_routes(&network.table);
        routes.add_subnet_route(&network.address, subnet_table);

        for subnet in extra_subnets {
            if subnet.prefix_len() == 0 {
                continue;
            }
            if network.address.contains(&subnet.network()) {
                continue;
            }
            routes.add_subnet_route(subnet, subnet_table);
        }

        if network.auto_route
            && let Err(err) = routes.setup_auto_route(extra_subnets, &network.table, network.fwmark)
        {
            tracing::error!(?err, "auto_route упал, откатываю");
            routes.teardown();
            hooks::run_all(&network.post_down, &network.tun_name, "post_down").await;
            return Err(err);
        }

        let mut dns = DnsManager::new();
        if !network.dns.is_empty() {
            match dns.setup(&network.dns) {
                Ok(()) => routes.state_mut().dns_managed = true,
                Err(err) => tracing::warn!(?err, "не удалось настроить DNS"),
            }
        }

        routes.state_mut().pre_down = network.pre_down.clone();
        routes.state_mut().post_down = network.post_down.clone();

        if let Err(err) = routes.state_mut().save() {
            tracing::warn!(?err, "не удалось сохранить state");
        }

        hooks::run_all(&network.post_up, &network.tun_name, "post_up").await;

        Ok(Self { tun, routes, dns, network })
    }

    pub async fn teardown(mut self) {
        hooks::run_all(&self.network.pre_down, &self.network.tun_name, "pre_down").await;

        let _ = self.dns.teardown();
        self.routes.teardown();

        State::remove(&self.network.tun_name);

        hooks::run_all(&self.network.post_down, &self.network.tun_name, "post_down").await;
    }
}
