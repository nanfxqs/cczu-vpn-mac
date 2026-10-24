use super::credentials::Credentials;
use super::network::{self, OwnedRoute, RouteSet};
use anyhow::{Context, Result, bail, ensure};
use cczuvpnproto::{types::ProxyServer, vpn::service};
use clap::ValueEnum;
use serde::{Deserialize, Serialize};
use std::{
    net::{IpAddr, Ipv4Addr},
    sync::Arc,
    time::Duration,
};
use tokio::{io::unix::AsyncFd, task::JoinHandle, time::Instant};
use tun_rs::{DeviceBuilder, SyncDevice};

#[derive(Clone, Copy, ValueEnum)]
pub enum TestScenario {
    Disabled,
    Ready,
    SetupFailure,
    UnsafeDefault,
    LocalOverlap,
    InvalidMask,
    BroadCampus,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ConnectionInfo {
    pub interface: String,
    pub address: String,
    pub mask: String,
    pub gateway: String,
    pub dns: String,
    pub peer: String,
    pub routes: Vec<String>,
    pub backend: String,
}

pub struct ConnectionManager {
    scenario: Option<TestScenario>,
    active: Option<ActiveConnection>,
}

impl ConnectionManager {
    pub fn new(scenario: Option<TestScenario>) -> Self {
        Self {
            scenario,
            active: None,
        }
    }
    pub async fn connect(&mut self, credentials: Credentials) -> Result<ConnectionInfo> {
        if self.forwarding_failed() {
            self.disconnect().await?;
        }
        if let Some(info) = self.active.as_ref().and_then(ActiveConnection::info) {
            return Ok(info.clone());
        }
        ensure!(
            self.active.is_none(),
            "Previous connection cleanup must finish before connecting again"
        );
        let active = match self.scenario {
            Some(TestScenario::Disabled) => bail!(
                "Offline daemon cannot establish a real VPN; choose an explicit offline test scenario"
            ),
            Some(scenario) => ActiveConnection::Offline {
                scenario,
                info: None,
            },
            None => ActiveConnection::Native(Box::default()),
        };
        self.active = Some(active);
        let result = self
            .active
            .as_mut()
            .expect("new connection")
            .start(credentials)
            .await;
        match result {
            Ok(info) => Ok(info),
            Err(error) => {
                if let Err(cleanup) = self.disconnect().await {
                    bail!("{error}; cleanup requires retry: {cleanup}");
                }
                Err(error)
            }
        }
    }
    pub async fn disconnect(&mut self) -> Result<()> {
        if let Some(active) = &mut self.active {
            active.stop().await?;
        }
        self.active = None;
        Ok(())
    }
    pub fn forwarding_failed(&self) -> bool {
        matches!(&self.active, Some(ActiveConnection::Native(connection)) if connection.forward.as_ref().is_some_and(JoinHandle::is_finished))
    }
}

enum ActiveConnection {
    Native(Box<NativeConnection>),
    Offline {
        scenario: TestScenario,
        info: Option<ConnectionInfo>,
    },
}

impl ActiveConnection {
    fn info(&self) -> Option<&ConnectionInfo> {
        match self {
            Self::Native(connection) => connection.info.as_ref(),
            Self::Offline { info, .. } => info.as_ref(),
        }
    }
    async fn start(&mut self, credentials: Credentials) -> Result<ConnectionInfo> {
        match self {
            Self::Native(connection) => connection.start(credentials).await,
            Self::Offline { scenario, info } => {
                tokio::time::sleep(Duration::from_millis(100)).await;
                ensure!(
                    !matches!(scenario, TestScenario::SetupFailure),
                    "Offline backend injected a network setup failure"
                );
                let mut server = offline_server();
                match scenario {
                    TestScenario::UnsafeDefault => {
                        server.split_tunnel_routes = vec!["0.0.0.0/0".into()]
                    }
                    TestScenario::LocalOverlap => {
                        server.split_tunnel_routes = vec!["192.0.2.128/25".into()]
                    }
                    TestScenario::InvalidMask => {
                        server.split_tunnel_routes = vec!["172.22.0.0/255.0.255.0".into()]
                    }
                    TestScenario::BroadCampus => {
                        server.split_tunnel_routes = vec!["172.16.0.0/12".into()]
                    }
                    _ => {}
                }
                let protected = if matches!(scenario, TestScenario::BroadCampus) {
                    cczuvpnproto::routes::Ipv4Route {
                        destination: Ipv4Addr::new(172, 28, 32, 0),
                        netmask: Ipv4Addr::new(255, 255, 248, 0),
                    }
                } else {
                    cczuvpnproto::routes::Ipv4Route {
                        destination: Ipv4Addr::new(192, 0, 2, 0),
                        netmask: Ipv4Addr::new(255, 255, 255, 0),
                    }
                };
                let routes = network::campus_routes(&server, &[protected])?;
                let ready = ConnectionInfo {
                    interface: "utun-test".into(),
                    address: server.address,
                    mask: server.mask,
                    gateway: server.gateway,
                    dns: server.dns,
                    peer: "211.65.64.100".into(),
                    routes: routes
                        .into_iter()
                        .map(network::cidr)
                        .collect::<Result<_>>()?,
                    backend: "offline".into(),
                };
                *info = Some(ready.clone());
                Ok(ready)
            }
        }
    }
    async fn stop(&mut self) -> Result<()> {
        match self {
            Self::Native(connection) => connection.stop().await,
            Self::Offline { info, .. } => {
                *info = None;
                Ok(())
            }
        }
    }
}

fn offline_server() -> ProxyServer {
    ProxyServer {
        address: "10.0.0.2".into(),
        mask: "255.255.255.0".into(),
        gateway: "10.0.0.1".into(),
        dns: "172.22.0.53".into(),
        wins: String::new(),
        split_tunnel_routes: vec!["172.22.0.0/16".into()],
    }
}

#[derive(Default)]
struct NativeConnection {
    info: Option<ConnectionInfo>,
    routes: RouteSet,
    device: Option<Arc<AsyncFd<SyncDevice>>>,
    forward: Option<JoinHandle<Result<()>>>,
}

impl NativeConnection {
    async fn start(&mut self, credentials: Credentials) -> Result<ConnectionInfo> {
        let deadline = Instant::now() + Duration::from_secs(60);
        let default = network::lookup("default")
            .await?
            .context("No default physical route")?;
        ensure!(
            default.physical(),
            "Default route belongs to another tunnel; cannot infer a safe physical path"
        );
        let mut protected = network::local_networks(&default.interface).await?;
        if let Some(gateway) = default.gateway {
            let gateway_route = network::lookup(&gateway.to_string())
                .await?
                .context("No physical route to the default gateway")?;
            ensure!(
                gateway_route.physical(),
                "Default gateway is routed through another tunnel"
            );
            protected.push(
                gateway_route.network.context(
                    "Cannot prove a specific physical route protects the default gateway",
                )?,
            );
        }
        let endpoints = network::endpoint_addresses().await?;
        for endpoint in &endpoints {
            ensure!(Instant::now() < deadline, "VPN bootstrap deadline expired");
            network::protect_endpoint(&mut self.routes, *endpoint, &default).await?;
        }

        let startup = tokio::time::timeout_at(
            deadline.min(Instant::now() + Duration::from_secs(45)),
            service::start_service(credentials.user, credentials.password),
        )
        .await;
        match startup {
            Ok(Ok(())) => {}
            Ok(Err(_)) => bail!(
                "VPN authentication or tunnel startup failed; verify campus credentials and gateway reachability"
            ),
            Err(_) => bail!("VPN authentication/tunnel startup timed out"),
        }
        ensure!(
            service::service_available().await,
            "VPN tunnel closed during startup"
        );
        let server =
            service::proxy_server().context("VPN tunnel did not provide a server configuration")?;
        let peer = service::proxy_peer_ip().context("VPN tunnel did not provide a peer address")?;
        let peer = match peer {
            IpAddr::V4(peer) => peer,
            _ => bail!("IPv6 tunnel peers are outside the current IPv4 support scope"),
        };
        if !endpoints.contains(&peer) {
            network::protect_endpoint(&mut self.routes, peer, &default).await?;
        }
        let campus = network::campus_routes(&server, &protected)?;
        ensure!(
            Instant::now() < deadline,
            "VPN network setup deadline expired"
        );
        let device = DeviceBuilder::new()
            .associate_route(false)
            .ipv4(
                server.address.as_str(),
                server.mask.as_str(),
                Some(server.gateway.as_str()),
            )
            .build_sync()
            .context("Could not create/configure macOS utun")?;
        let interface = device.name()?;
        ensure!(
            interface.starts_with("utun"),
            "Expected a new macOS utun interface"
        );
        device.set_nonblocking(true)?;
        self.device = Some(Arc::new(AsyncFd::new(device)?));
        for route in &campus {
            ensure!(
                Instant::now() < deadline,
                "VPN network setup deadline expired"
            );
            self.routes
                .add(OwnedRoute {
                    network: *route,
                    interface: interface.clone(),
                    gateway: None,
                })
                .await?;
        }
        ensure!(
            service::service_available().await,
            "VPN tunnel closed before network setup completed"
        );
        let device = self.device.as_ref().context("Missing utun device")?.clone();
        self.forward = Some(tokio::spawn(forward_packets(device)));
        let info = ConnectionInfo {
            interface,
            address: server.address,
            mask: server.mask,
            gateway: server.gateway,
            dns: server.dns,
            peer: peer.to_string(),
            routes: campus
                .into_iter()
                .map(network::cidr)
                .collect::<Result<_>>()?,
            backend: "native".into(),
        };
        self.info = Some(info.clone());
        Ok(info)
    }

    async fn stop(&mut self) -> Result<()> {
        self.info = None;
        if let Some(task) = self.forward.take() {
            task.abort();
            let _ = task.await;
        }
        let session_result = service::stop_service().await;
        // Keep the utun fd alive until route ownership has been checked and cleanup finished.
        self.routes.cleanup().await?;
        self.device = None;
        self.info = None;
        session_result.context("VPN session stopped with an error")
    }
}

async fn receive_tun(device: &AsyncFd<SyncDevice>, bytes: &mut [u8]) -> std::io::Result<usize> {
    loop {
        let mut ready = device.readable().await?;
        if let Ok(result) = ready.try_io(|device| device.get_ref().recv(bytes)) {
            return result;
        }
    }
}

async fn send_tun(device: &AsyncFd<SyncDevice>, bytes: &[u8]) -> std::io::Result<usize> {
    loop {
        let mut ready = device.writable().await?;
        if let Ok(result) = ready.try_io(|device| device.get_ref().send(bytes)) {
            return result;
        }
    }
}

async fn forward_packets(device: Arc<AsyncFd<SyncDevice>>) -> Result<()> {
    let to_proxy = async {
        let mut buffer = vec![0u8; 65536];
        loop {
            let count = receive_tun(&device, &mut buffer)
                .await
                .context("utun receive failed")?;
            ensure!(count > 0, "utun closed");
            tokio::time::timeout(
                Duration::from_secs(5),
                service::send_tcp_packet(&buffer[..count]),
            )
            .await
            .context("VPN packet send timed out")??;
        }
    };
    let from_proxy = async {
        loop {
            let packet = service::receive_packet(65536)
                .await
                .context("VPN packet receive failed")?;
            let count = tokio::time::timeout(Duration::from_secs(5), send_tun(&device, &packet))
                .await
                .context("utun send timed out")??;
            ensure!(count == packet.len(), "utun packet write was incomplete");
        }
    };
    tokio::select! { result=to_proxy => result, result=from_proxy => result }
}
