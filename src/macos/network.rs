//! Narrow macOS route adapter: explicit adds, verified ownership, reverse cleanup.
use super::service::effective_uid;
use anyhow::{Context, Result, bail, ensure};
use cczuvpnproto::{
    routes::{
        Ipv4Route, netmask_to_prefix, normalize_network, parse_split_tunnel_route, route_contains,
    },
    types::ProxyServer,
};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, OpenOptions},
    io::{Read, Write},
    net::{IpAddr, Ipv4Addr},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
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

#[derive(Clone, Serialize, Deserialize)]
pub struct RouteSnapshot {
    pub network: Option<Ipv4Route>,
    pub gateway: Option<Ipv4Addr>,
    pub interface: String,
    #[serde(default)]
    pub marked: bool,
    #[serde(default)]
    pub owner: Option<String>,
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
            marked: field("flags").is_some_and(|flags| flags.contains("PROTO2")),
            owner: None,
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

// route get performs longest-prefix lookup. A more-specific foreign route
// must not make us forget a still-present owned parent route.
async fn exact_route_exists(network: Ipv4Route) -> Result<bool> {
    let output = command(
        "/usr/sbin/netstat",
        &["-rn".into(), "-f".into(), "inet".into()],
    )
    .await?;
    ensure!(
        output.status.success(),
        "Could not inspect exact IPv4 routes"
    );
    for line in String::from_utf8_lossy(&output.stdout).lines() {
        let Some(destination) = line.split_whitespace().next() else {
            continue;
        };
        let (address, prefix) = destination
            .split_once('/')
            .map_or((destination, None), |(a, p)| (a, Some(p)));
        let octets: Vec<_> = address.split('.').collect();
        if octets.len() > 4 || octets.iter().any(|part| part.parse::<u8>().is_err()) {
            continue;
        }
        let mut full = octets.join(".");
        for _ in octets.len()..4 {
            full.push_str(".0");
        }
        let prefix = match prefix {
            Some(p) => p.to_string(),
            None => (octets.len() * 8).to_string(),
        };
        if parse_split_tunnel_route(&format!("{full}/{prefix}"))? == Some(network) {
            return Ok(true);
        }
    }
    Ok(false)
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

#[derive(Clone, Serialize, Deserialize)]
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
        if action == "add" {
            args.push("-proto2".into());
        }
        match self.gateway {
            Some(gateway) => args.push(gateway.to_string()),
            None => args.extend(["-interface".into(), self.interface.clone()]),
        }
        Ok(args)
    }
}

// The journal is an intent log: persist BEFORE mutation. A process death or
// command timeout must not lose the list of potentially-created resources.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Journal {
    version: u32,
    owner: String,
    routes: Vec<OwnedRoute>,
    pending: Vec<Ipv4Route>,
    boot: i64,
}

#[derive(Default)]
pub struct RouteSet {
    pub owned: Vec<OwnedRoute>,
    directory: Option<PathBuf>,
    offline: bool,
    owner: String,
    recovered: bool,
    pending: Vec<Ipv4Route>,
    boot: i64,
    same_boot: bool,
}

fn private_directory(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(meta) => ensure!(
            meta.is_dir()
                && !meta.file_type().is_symlink()
                && meta.uid() == effective_uid()
                && meta.mode() & 0o077 == 0,
            "Network state directory must be private and owned by the service"
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            fs::DirBuilder::new().mode(0o700).create(path)?;
        }
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

pub(super) fn read_state<T: serde::de::DeserializeOwned>(path: &Path) -> Result<Option<T>> {
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let meta = file.metadata()?;
    ensure!(
        meta.is_file()
            && meta.uid() == effective_uid()
            && meta.mode() & 0o777 == 0o600
            && meta.nlink() == 1,
        "Unsafe network state file"
    );
    let mut bytes = Vec::new();
    file.take(256 * 1024 + 1).read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= 256 * 1024, "Network state is too large");
    Ok(Some(
        serde_json::from_slice(&bytes).context("Invalid network ownership state")?,
    ))
}

pub(super) fn write_state(path: &Path, value: &impl Serialize) -> Result<()> {
    let parent = path.parent().context("Missing network state directory")?;
    private_directory(parent)?;
    // Existing state must have the same protections as a newly-created file.
    if fs::symlink_metadata(path).is_ok() {
        let _: Option<serde_json::Value> = read_state(path)?;
    }
    let temporary = parent.join(format!(".network-{:016x}", rand::random::<u64>()));
    let result = (|| -> Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)?;
        file.write_all(&serde_json::to_vec(value)?)?;
        file.sync_all()?;
        fs::rename(&temporary, path)?;
        std::fs::File::open(parent)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(temporary);
    }
    result
}

fn boot_epoch() -> Result<i64> {
    let mut value: libc::timeval = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::timeval>();
    // Read-only kernel boot identity; no credentials or system changes.
    let result = unsafe {
        libc::sysctlbyname(
            c"kern.boottime".as_ptr(),
            (&mut value as *mut libc::timeval).cast(),
            &mut len,
            std::ptr::null_mut(),
            0,
        )
    };
    ensure!(
        result == 0 && len == std::mem::size_of::<libc::timeval>(),
        "Could not identify system boot for route ownership"
    );
    Ok(value.tv_sec)
}

impl RouteSet {
    pub fn persistent(directory: PathBuf, offline: bool) -> Result<Self> {
        private_directory(&directory)?;
        let existing: Option<Journal> = read_state(&directory.join("network-journal.json"))?;
        let boot = if offline { 0 } else { boot_epoch()? };
        let mut same_boot = true;
        let mut journal_boot = boot;
        let (owner, owned, recovered, pending) = match existing {
            Some(journal) => {
                ensure!(
                    journal.version == 1
                        && !journal.owner.is_empty()
                        && journal.routes.len() <= 512,
                    "Invalid network journal version or contents"
                );
                for route in &journal.routes {
                    ensure!(
                        netmask_to_prefix(route.network.netmask)? >= 8
                            && usable(route.network.destination)
                            && route
                                .interface
                                .bytes()
                                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
                            && !route.interface.is_empty(),
                        "Unsafe route in network journal"
                    );
                }
                same_boot = journal.boot == boot;
                journal_boot = journal.boot;
                let recovered = !journal.routes.is_empty();
                (journal.owner, journal.routes, recovered, journal.pending)
            }
            None => (
                format!("{:032x}", rand::random::<u128>()),
                Vec::new(),
                false,
                Vec::new(),
            ),
        };
        Ok(Self {
            owned,
            directory: Some(directory),
            offline,
            owner,
            recovered,
            pending,
            boot: journal_boot,
            same_boot,
        })
    }

    pub async fn recover(directory: PathBuf, offline: bool) -> Result<()> {
        Self::persistent(directory, offline)?.cleanup().await
    }

    fn persist(&self) -> Result<()> {
        if let Some(directory) = &self.directory {
            write_state(
                &directory.join("network-journal.json"),
                &Journal {
                    version: 1,
                    owner: self.owner.clone(),
                    routes: self.owned.clone(),
                    pending: self.pending.clone(),
                    boot: self.boot,
                },
            )?;
        }
        Ok(())
    }

    async fn current(&self, route: &OwnedRoute) -> Result<Option<RouteSnapshot>> {
        if self.offline {
            let path = self
                .directory
                .as_ref()
                .context("Missing offline state directory")?
                .join("offline-routes.json");
            let table: Vec<RouteSnapshot> = read_state(&path)?.unwrap_or_default();
            Ok(table
                .into_iter()
                .find(|entry| entry.network == Some(route.network)))
        } else {
            let current = lookup(&route.network.destination.to_string()).await?;
            if current
                .as_ref()
                .is_some_and(|entry| entry.network == Some(route.network))
            {
                return Ok(current);
            }
            ensure!(
                !exact_route_exists(route.network).await?,
                "Owned route is shadowed by a different route; left untouched"
            );
            Ok(None)
        }
    }

    fn is_owned(&self, route: &OwnedRoute, current: &RouteSnapshot) -> bool {
        route.matches(current)
            && current.marked
            && (!self.offline || current.owner.as_deref() == Some(&self.owner))
    }

    async fn mutate(&self, route: &OwnedRoute, action: &str) -> Result<()> {
        if self.offline {
            let path = self
                .directory
                .as_ref()
                .context("Missing offline state directory")?
                .join("offline-routes.json");
            let mut table: Vec<RouteSnapshot> = read_state(&path)?.unwrap_or_default();
            match action {
                "add" => {
                    ensure!(
                        !table
                            .iter()
                            .any(|entry| entry.network == Some(route.network)),
                        "Offline route already exists"
                    );
                    table.push(RouteSnapshot {
                        network: Some(route.network),
                        gateway: route.gateway,
                        interface: route.interface.clone(),
                        marked: true,
                        owner: Some(self.owner.clone()),
                    });
                }
                "delete" => table.retain(|entry| entry.network != Some(route.network)),
                _ => bail!("Invalid route operation"),
            }
            return write_state(&path, &table);
        }
        let output = command("/sbin/route", &route.arguments(action)?).await?;
        ensure!(
            output.status.success(),
            "Could not {action} campus/endpoint route {}: {}",
            cidr(route.network)?,
            String::from_utf8_lossy(&output.stderr).trim()
        );
        Ok(())
    }

    pub async fn add(&mut self, route: OwnedRoute) -> Result<()> {
        ensure!(
            !self.recovered || self.owned.is_empty(),
            "Previous network recovery must finish before connecting"
        );
        if let Some(current) = self.current(&route).await?
            && current.network == Some(route.network)
        {
            ensure!(
                route.matches(&current),
                "A pre-existing route conflicts with {}",
                cidr(route.network)?
            );
            return Ok(()); // Never adopt a pre-existing route, even with our marker.
        }
        self.owned.push(route.clone());
        self.pending.push(route.network);
        self.persist()?; // Write-ahead, including mutations whose result may be uncertain.
        self.mutate(&route, "add").await?;
        self.pending.retain(|network| *network != route.network);
        self.persist()?;
        let current = self
            .current(&route)
            .await?
            .context("New route is not visible")?;
        ensure!(
            self.is_owned(&route, &current),
            "New route did not select expected ownership/interface/gateway"
        );
        Ok(())
    }

    pub async fn cleanup(&mut self) -> Result<()> {
        let mut errors = Vec::new();
        for index in (0..self.owned.len()).rev() {
            let route = &self.owned[index];
            let result = async {
                match self.current(route).await? {
                    Some(current) if self.is_owned(route, &current) => {
                        ensure!(
                            self.same_boot,
                            "Route journal belongs to another boot; matching route left untouched"
                        );
                        ensure!(
                            self.offline || !self.pending.contains(&route.network),
                            "Uncertain route mutation {}; ownership not confirmed, left untouched",
                            cidr(route.network)?
                        );
                        // utun names can be reused after death. A recovered journal does
                        // not own an open fd, so never infer live interface ownership.
                        ensure!(
                            !self.recovered || self.offline || !route.interface.starts_with("utun"),
                            "Cannot prove recovered utun ownership; route {} left untouched",
                            cidr(route.network)?
                        );
                        self.mutate(route, "delete").await?;
                        if let Some(current) = self.current(route).await? {
                            ensure!(
                                !self.is_owned(route, &current),
                                "Owned route remains after deletion"
                            );
                        }
                    }
                    Some(current) if current.network == Some(route.network) => bail!(
                        "Owned route {} changed; left untouched",
                        cidr(route.network)?
                    ),
                    _ => {} // Already gone; never touch a less/more-specific replacement.
                }
                Ok::<_, anyhow::Error>(())
            }
            .await;
            match result {
                Ok(()) => {
                    let removed = self.owned.remove(index);
                    let was_pending = self.pending.contains(&removed.network);
                    self.pending.retain(|network| *network != removed.network);
                    if let Err(error) = self.persist() {
                        if was_pending {
                            self.pending.push(removed.network);
                        }
                        self.owned.insert(index, removed);
                        errors.push(error.to_string());
                    }
                }
                Err(error) => errors.push(error.to_string()),
            }
        }
        ensure!(
            errors.is_empty(),
            "Network cleanup incomplete: {}",
            errors.join("; ")
        );
        self.recovered = false;
        self.boot = if self.offline { 0 } else { boot_epoch()? };
        self.same_boot = true;
        self.persist()?;
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
