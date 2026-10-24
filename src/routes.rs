//! Shared IPv4 rules used by platform route adapters.
use anyhow::{Context, Result, bail, ensure};

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
pub struct Ipv4Route {
    pub destination: std::net::Ipv4Addr,
    pub netmask: std::net::Ipv4Addr,
}

pub fn prefix_to_netmask(prefix: u8) -> Result<std::net::Ipv4Addr> {
    if prefix > 32 {
        bail!("invalid IPv4 prefix length: {prefix}");
    }
    let bits = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - u32::from(prefix))
    };
    Ok(std::net::Ipv4Addr::from(bits))
}

pub fn normalize_network(
    address: std::net::Ipv4Addr,
    netmask: std::net::Ipv4Addr,
) -> std::net::Ipv4Addr {
    std::net::Ipv4Addr::from(u32::from(address) & u32::from(netmask))
}

pub fn netmask_to_prefix(netmask: std::net::Ipv4Addr) -> Result<u8> {
    let bits = u32::from(netmask);
    let prefix = bits.count_ones() as u8;
    ensure!(
        bits == u32::from(prefix_to_netmask(prefix)?),
        "non-contiguous IPv4 netmask: {netmask}"
    );
    Ok(prefix)
}

pub fn parse_split_tunnel_route(route: &str) -> Result<Option<Ipv4Route>> {
    let trimmed = route.trim();
    if trimmed.is_empty() {
        bail!("received an empty split-tunnel route");
    }

    let route_target = if trimmed.contains(';') {
        let mut parts = trimmed.split(';');
        let _protocol = parts
            .next()
            .with_context(|| format!("invalid split-tunnel rule format: {trimmed}"))?;
        let target = parts
            .next()
            .with_context(|| format!("invalid split-tunnel rule format: {trimmed}"))?;
        let _port = parts
            .next()
            .with_context(|| format!("invalid split-tunnel rule format: {trimmed}"))?;
        if parts.next().is_some() {
            bail!("invalid split-tunnel rule format: {trimmed}");
        }
        target.trim()
    } else {
        trimmed
    };

    let (address, netmask) = match route_target.split_once('/') {
        Some((address, suffix)) => {
            let address = match address.parse::<std::net::IpAddr>() {
                Ok(std::net::IpAddr::V4(address)) => address,
                Ok(std::net::IpAddr::V6(_)) => return Ok(None),
                Err(_) => {
                    bail!("invalid split-tunnel IP address: {route_target}");
                }
            };
            let netmask = match suffix.parse::<u8>() {
                Ok(prefix) => prefix_to_netmask(prefix)?,
                Err(_) => suffix.parse::<std::net::Ipv4Addr>().with_context(|| {
                    format!("invalid split-tunnel IPv4 netmask suffix: {route_target}")
                })?,
            };
            (address, netmask)
        }
        None => {
            let address = match route_target.parse::<std::net::IpAddr>() {
                Ok(std::net::IpAddr::V4(address)) => address,
                Ok(std::net::IpAddr::V6(_)) => return Ok(None),
                Err(_) => {
                    bail!("invalid split-tunnel IP host route: {route_target}");
                }
            };
            (address, std::net::Ipv4Addr::new(255, 255, 255, 255))
        }
    };

    Ok(Some(Ipv4Route {
        destination: normalize_network(address, netmask),
        netmask,
    }))
}

pub fn route_contains(route: Ipv4Route, address: std::net::Ipv4Addr) -> bool {
    normalize_network(address, route.netmask) == route.destination
}
