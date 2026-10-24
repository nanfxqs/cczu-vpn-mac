//! Narrow macOS route adapter: explicit adds, verified ownership, reverse cleanup.
use anyhow::{Context, Result, bail, ensure};
use cczuvpnproto::{
    routes::{
        Ipv4Route, netmask_to_prefix, normalize_network, parse_split_tunnel_route, route_contains,
    },
    types::ProxyServer,
};
use std::{
    net::{IpAddr, Ipv4Addr},
    process::Output,
    time::Duration,
};
use tokio::process::Command;

const COMMAND_TIMEOUT: Duration = Duration::from_secs(3);

async fn command(program: &str, args: &[String]) -> Result<Output> {
    tokio::time::timeout(
        COMMAND_TIMEOUT,
        Command::new(program).args(args).kill_on_drop(true).output(),
    )
    .await
    .context("Network command timed out")?
    .context("Could not execute network command")
}

#[derive(Clone)]
pub struct RouteSnapshot {
    pub network: Option<Ipv4Route>,
    pub gateway: Option<Ipv4Addr>,
    pub interface: String,
}

impl RouteSnapshot {
    fn parse(text: &str) -> Result<Self> {
        let field = |name: &str| {
            text.lines()
                .filter_map(|line| line.trim().split_once(':'))
                .find_map(|(key, value)| (key == name).then_some(value.trim()))
        };
        let interface = field("interface")
            .context("Route lookup did not report an interface")?
            .to_owned();
        ensure!(
            !interface.is_empty() && interface.bytes().all(|byte| byte.is_ascii_alphanumeric()),
            "Invalid network interface"
        );
        let gateway = field("gateway").and_then(|value| value.parse().ok());
        let network = match field("destination") {
            Some("default") | None => None,
            Some(destination) => {
                let target = match field("mask") {
                    Some(mask) => format!("{destination}/{mask}"),
                    None => destination.to_owned(),
                };
                parse_split_tunnel_route(&target)?
            }
        };
        Ok(Self {
            network,
            gateway,
            interface,
        })
    }

    pub fn physical(&self) -> bool {
        !["utun", "ipsec", "ppp", "gif", "stf", "lo"]
            .iter()
            .any(|prefix| self.interface.starts_with(prefix))
    }
}

pub async fn lookup(target: &str) -> Result<Option<RouteSnapshot>> {
    let output = command(
        "/sbin/route",
        &["-n".into(), "get".into(), "-inet".into(), target.into()],
    )
    .await?;
    if !output.status.success() {
        return Ok(None);
    }
    Ok(Some(RouteSnapshot::parse(&String::from_utf8_lossy(
        &output.stdout,
    ))?))
}

pub fn cidr(route: Ipv4Route) -> Result<String> {
    Ok(format!(
        "{}/{}",
        route.destination,
        netmask_to_prefix(route.netmask)?
    ))
}

fn usable(address: Ipv4Addr) -> bool {
    !address.is_unspecified()
        && !address.is_loopback()
        && !address.is_multicast()
        && !address.is_broadcast()
        && !address.is_link_local()
}

pub fn campus_routes(server: &ProxyServer, protected: &[Ipv4Route]) -> Result<Vec<Ipv4Route>> {
    let address: Ipv4Addr = server
        .address
        .parse()
        .context("Invalid tunnel IPv4 address")?;
    let gateway: Ipv4Addr = server
        .gateway
        .parse()
        .context("Invalid tunnel IPv4 gateway")?;
    let mask: Ipv4Addr = server.mask.parse().context("Invalid tunnel IPv4 mask")?;
    ensure!(
        usable(address) && usable(gateway) && netmask_to_prefix(mask)? > 0,
        "Unsafe tunnel IPv4 configuration"
    );
    ensure!(
        !protected
            .iter()
            .any(|route| route_contains(*route, address)),
        "Tunnel address conflicts with a local network address"
    );
    let mut routes = Vec::new();
    for rule in &server.split_tunnel_routes {
        if let Some(route) = parse_split_tunnel_route(rule)? {
            let prefix = netmask_to_prefix(route.netmask)?;
            ensure!(
                prefix >= 8 && usable(route.destination),
                "Unsafe campus route: {}",
                cidr(route)?
            );
            let steals_local = protected.iter().any(|local| {
                let overlaps = route_contains(route, local.destination)
                    || route_contains(*local, route.destination);
                overlaps
                    && netmask_to_prefix(local.netmask)
                        .is_ok_and(|local_prefix| prefix >= local_prefix)
            });
            ensure!(
                !steals_local,
                "Campus route overlaps the active local network: {}",
                cidr(route)?
            );
            routes.push(route);
        }
    }
    let dns: IpAddr = server
        .dns
        .parse()
        .context("VPN did not provide a valid DNS address")?;
    if let IpAddr::V4(dns) = dns {
        ensure!(usable(dns), "Unsafe VPN DNS address");
        if dns.is_private() || routes.iter().any(|route| route_contains(*route, dns)) {
            ensure!(
                !protected.iter().any(|route| route_contains(*route, dns)),
                "VPN DNS conflicts with a local gateway/address"
            );
            routes.push(Ipv4Route {
                destination: dns,
                netmask: Ipv4Addr::BROADCAST,
            });
        }
    }
    routes.sort();
    routes.dedup();
    ensure!(
        !routes.is_empty(),
        "Server supplied no usable campus IPv4 routes"
    );
    ensure!(routes.len() <= 256, "Too many campus routes");
    Ok(routes)
}

#[derive(Clone)]
pub struct OwnedRoute {
    pub network: Ipv4Route,
    pub interface: String,
    pub gateway: Option<Ipv4Addr>,
}

impl OwnedRoute {
    fn matches(&self, current: &RouteSnapshot) -> bool {
        current.network == Some(self.network)
            && current.interface == self.interface
            && current.gateway == self.gateway
    }
    fn arguments(&self, action: &str) -> Result<Vec<String>> {
        let mut args = vec![
            "-n".into(),
            action.into(),
            "-net".into(),
            cidr(self.network)?,
        ];
        match self.gateway {
            Some(gateway) => args.push(gateway.to_string()),
            None => args.extend(["-interface".into(), self.interface.clone()]),
        }
        Ok(args)
    }
}

#[derive(Default)]
pub struct RouteSet {
    pub owned: Vec<OwnedRoute>,
}

impl RouteSet {
    pub async fn add(&mut self, route: OwnedRoute) -> Result<()> {
        if let Some(current) = lookup(&route.network.destination.to_string()).await?
            && current.network == Some(route.network)
        {
            ensure!(
                route.matches(&current),
                "A pre-existing route conflicts with {}",
                cidr(route.network)?
            );
            return Ok(()); // Never adopt or later delete pre-existing routes.
        }
        let output = command("/sbin/route", &route.arguments("add")?).await?;
        ensure!(
            output.status.success(),
            "Could not add campus/endpoint route {}: {}",
            cidr(route.network)?,
            String::from_utf8_lossy(&output.stderr).trim()
        );
        self.owned.push(route.clone());
        let current = lookup(&route.network.destination.to_string())
            .await?
            .context("New route is not visible")?;
        ensure!(
            route.matches(&current),
            "New route did not select the expected interface/gateway"
        );
        Ok(())
    }

    pub async fn cleanup(&mut self) -> Result<()> {
        let mut errors = Vec::new();
        for index in (0..self.owned.len()).rev() {
            let route = &self.owned[index];
            let result = async {
                match lookup(&route.network.destination.to_string()).await? {
                    Some(current) if route.matches(&current) => {
                        let output = command("/sbin/route", &route.arguments("delete")?).await?;
                        ensure!(
                            output.status.success(),
                            "Could not remove owned route {}",
                            cidr(route.network)?
                        );
                    }
                    Some(current) if current.network == Some(route.network) => bail!(
                        "Owned route {} changed; left untouched",
                        cidr(route.network)?
                    ),
                    _ => {} // Route is already absent, not a reason to touch another prefix.
                }
                Ok::<_, anyhow::Error>(())
            }
            .await;
            match result {
                Ok(()) => {
                    self.owned.remove(index);
                }
                Err(error) => errors.push(error.to_string()),
            }
        }
        ensure!(
            errors.is_empty(),
            "Network cleanup incomplete: {}",
            errors.join("; ")
        );
        Ok(())
    }
}

pub async fn endpoint_addresses() -> Result<Vec<Ipv4Addr>> {
    let addresses = tokio::time::timeout(
        Duration::from_secs(5),
        tokio::net::lookup_host(("zmvpn.cczu.edu.cn", 443)),
    )
    .await
    .context("VPN gateway DNS lookup timed out")??;
    let mut addresses: Vec<Ipv4Addr> = addresses
        .filter_map(|address| match address.ip() {
            IpAddr::V4(ip) => Some(ip),
            _ => None,
        })
        .collect();
    ensure!(
        !addresses.is_empty()
            && addresses.iter().all(|ip| usable(*ip)
                && !ip.is_private()
                && !matches!(ip.octets(), [198, 18 | 19, _, _])),
        "VPN entrypoint did not resolve to usable public IPv4 addresses; check Fake IP/DNS configuration"
    );
    addresses.extend([
        Ipv4Addr::new(211, 65, 64, 100),
        Ipv4Addr::new(211, 65, 66, 99),
    ]); // Same school bootstrap endpoints as Linux.
    addresses.sort();
    addresses.dedup();
    Ok(addresses)
}

pub async fn protect_endpoint(
    routes: &mut RouteSet,
    endpoint: Ipv4Addr,
    default: &RouteSnapshot,
) -> Result<()> {
    let current = lookup(&endpoint.to_string())
        .await?
        .context("No route to VPN endpoint")?;
    let host = Ipv4Route {
        destination: endpoint,
        netmask: Ipv4Addr::BROADCAST,
    };
    if current.network == Some(host) {
        ensure!(
            current.physical(),
            "VPN endpoint has a conflicting host route through another tunnel"
        );
        return Ok(());
    }
    let physical = if current.physical() {
        &current
    } else {
        default
    };
    ensure!(
        physical.physical(),
        "No physical route to the VPN endpoint; check existing VPN routing"
    );
    routes
        .add(OwnedRoute {
            network: host,
            interface: physical.interface.clone(),
            gateway: physical.gateway,
        })
        .await
}

pub async fn local_networks(interface: &str) -> Result<Vec<Ipv4Route>> {
    let output = command("/sbin/ifconfig", &[interface.into()]).await?;
    ensure!(
        output.status.success(),
        "Could not inspect physical interface"
    );
    let text = String::from_utf8_lossy(&output.stdout);
    let mut networks = Vec::new();
    for line in text.lines() {
        let words: Vec<_> = line.split_whitespace().collect();
        if words.first() != Some(&"inet") {
            continue;
        }
        let address: Ipv4Addr = words
            .get(1)
            .context("Missing physical IPv4 address")?
            .parse()?;
        let mask = words
            .windows(2)
            .find_map(|pair| (pair[0] == "netmask").then_some(pair[1]))
            .context("Missing physical IPv4 mask")?;
        let mask: Ipv4Addr = if let Some(hex) = mask.strip_prefix("0x") {
            Ipv4Addr::from(u32::from_str_radix(hex, 16)?)
        } else {
            mask.parse()?
        };
        ensure!(
            netmask_to_prefix(mask)? > 0,
            "Physical interface has an invalid mask"
        );
        let network = Ipv4Route {
            destination: normalize_network(address, mask),
            netmask: mask,
        };
        let current = lookup(&network.destination.to_string())
            .await?
            .context("Could not verify the local interface route")?;
        ensure!(
            current.network == Some(network) && current.interface == interface,
            "Local subnet is not protected by its expected physical route"
        );
        networks.push(network);
    }
    ensure!(
        !networks.is_empty(),
        "Physical interface has no IPv4 address"
    );
    Ok(networks)
}
