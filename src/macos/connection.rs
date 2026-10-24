use super::credentials::Credentials;
use super::network::{self, OwnedRoute, RouteSet};
use anyhow::{Context, Result, bail, ensure};
use cczuvpnproto::{failure::StartupFailure, types::ProxyServer, vpn::service};
use clap::ValueEnum;
use serde::{Deserialize, Serialize};
use std::{
    net::{IpAddr, Ipv4Addr},
    path::PathBuf,
    sync::Arc,
    time::Duration,
};
use tokio::{io::unix::AsyncFd, task::JoinHandle, time::Instant};
use tun_rs::{DeviceBuilder, SyncDevice};

#[derive(Clone, Copy, ValueEnum)]
pub enum TestScenario {
    AuthRejected,
    AuthTransport,
    AuthResponse,
    TlsFailure,
    TunnelFailure,
    SlowReady,
    StartupTimeout,
    ForwardFailure,
    Disabled,
    Ready,
    SetupFailure,
    NetworkDetail,
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
    directory: PathBuf,
}

impl ConnectionManager {
    pub fn new(scenario: Option<TestScenario>, directory: PathBuf) -> Self {
        Self {
            scenario,
            active: None,
            directory,
        }
    }
    pub async fn recover(&mut self) -> Result<()> {
        RouteSet::recover(self.directory.clone(), self.scenario.is_some()).await
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
        self.recover().await?;
        let routes = RouteSet::persistent(self.directory.clone(), self.scenario.is_some())?;
        let active = match self.scenario {
            Some(TestScenario::Disabled) => bail!(
                "Offline daemon cannot establish a real VPN; choose an explicit offline test scenario"
            ),
            Some(scenario) => ActiveConnection::Offline {
                scenario,
                info: Box::new(None),
                connected_at: None,
                routes,
            },
            None => ActiveConnection::Native(Box::new(NativeConnection {
                routes,
                ..Default::default()
            })),
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
                    return Err(error.context(format!("Cleanup requires retry: {cleanup}")));
                }
                Err(error)
            }
        }
    }
    pub async fn disconnect(&mut self) -> Result<()> {
        if let Some(active) = &mut self.active {
            active.stop().await?;
        } else {
            self.recover().await?;
        }
        self.active = None;
        Ok(())
    }
    pub fn startup_timeout(&self) -> Duration {
        if matches!(self.scenario, Some(TestScenario::StartupTimeout)) {
            Duration::from_millis(250)
        } else {
            Duration::from_secs(60)
        }
    }
    pub fn forwarding_failed(&self) -> bool {
        match &self.active {
            Some(ActiveConnection::Native(connection)) => connection
                .forward
                .as_ref()
                .is_some_and(JoinHandle::is_finished),
            Some(ActiveConnection::Offline {
                scenario: TestScenario::ForwardFailure,
                connected_at: Some(time),
                ..
            }) => time.elapsed() >= Duration::from_millis(200),
            _ => false,
        }
    }
    pub async fn forwarding_error(&mut self) -> Option<String> {
        if !self.forwarding_failed() {
            return None;
        }
        match self.active.as_mut() {
            Some(ActiveConnection::Native(connection)) => {
                let task = connection.forward.take()?;
                Some(match task.await {
                    Ok(Err(error)) => error.to_string(),
                    Ok(Ok(())) => "VPN packet forwarding stopped".into(),
                    Err(_) => "VPN packet forwarding task stopped unexpectedly".into(),
                })
            }
            Some(ActiveConnection::Offline { .. }) => {
                Some("Offline backend simulated proxy EOF".into())
            }
            None => None,
        }
    }
}

enum ActiveConnection {
    Native(Box<NativeConnection>),
    Offline {
        scenario: TestScenario,
        info: Box<Option<ConnectionInfo>>,
        connected_at: Option<Instant>,
        routes: RouteSet,
    },
}

impl ActiveConnection {
    fn info(&self) -> Option<&ConnectionInfo> {
        match self {
            Self::Native(connection) => connection.info.as_ref(),
            Self::Offline { info, .. } => info.as_ref().as_ref(),
        }
    }
    async fn start(&mut self, credentials: Credentials) -> Result<ConnectionInfo> {
        match self {
            Self::Native(connection) => connection.start(credentials).await,
            Self::Offline {
                scenario,
                info,
                connected_at,
                routes: owned,
            } => {
                if matches!(scenario, TestScenario::StartupTimeout) {
                    std::future::pending::<()>().await;
                }
                tokio::time::sleep(if matches!(scenario, TestScenario::SlowReady) {
                    Duration::from_secs(2)
                } else {
                    Duration::from_millis(100)
                })
                .await;

                if matches!(scenario, TestScenario::NetworkDetail) {
                    return Err(classify_startup_error(network_error(
                        "campus route installation",
                        anyhow::anyhow!("Network is unreachable (os error 51)"),
                    )));
                }
                let failure = match scenario {
                    TestScenario::AuthRejected => Some(StartupFailure::AuthenticationRejected),
                    TestScenario::AuthTransport => Some(StartupFailure::AuthenticationTransport),
                    TestScenario::AuthResponse => Some(StartupFailure::AuthenticationResponse),
                    TestScenario::TlsFailure => Some(StartupFailure::Tls),
                    TestScenario::TunnelFailure => Some(StartupFailure::TunnelNegotiation),
                    TestScenario::SetupFailure => Some(StartupFailure::NetworkConfiguration),
                    _ => None,
                };
                if let Some(failure) = failure {
                    return Err(classify_startup_error(failure.into()));
                }
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
                for route in &routes {
                    owned
                        .add(OwnedRoute {
                            network: *route,
                            interface: "utun-test".into(),
                            gateway: None,
                        })
                        .await?;
                }
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
                **info = Some(ready.clone());
                *connected_at = Some(Instant::now());
                Ok(ready)
            }
        }
    }
    async fn stop(&mut self) -> Result<()> {
        match self {
            Self::Native(connection) => connection.stop().await,
            Self::Offline {
                info,
                connected_at,
                routes,
                ..
            } => {
                routes.cleanup().await?;
                **info = None;
                *connected_at = None;
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

// Only explicitly marked network operations may expose their cause chain. Never
// use this adapter around authentication, TLS, or tunnel protocol operations.
#[derive(Debug)]
pub(super) struct NetworkDetail(String);
impl std::fmt::Display for NetworkDetail {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for NetworkDetail {}

fn network_error(stage: &'static str, error: anyhow::Error) -> anyhow::Error {
    if error.downcast_ref::<StartupFailure>().is_some() {
        return classify_startup_error(error);
    }
    let detail = NetworkDetail(format!(
        "{}: {stage}: {error:#}",
        StartupFailure::NetworkConfiguration
    ));
    anyhow::Error::new(detail).context(StartupFailure::NetworkConfiguration)
}

fn classify_startup_error(error: anyhow::Error) -> anyhow::Error {
    match error.downcast_ref::<StartupFailure>().copied() {
        Some(StartupFailure::NetworkConfiguration)
            if error.downcast_ref::<NetworkDetail>().is_some() =>
        {
            error
        }
        Some(failure) => failure.into(),
        None => StartupFailure::NetworkConfiguration.into(),
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
        self.start_inner(credentials)
            .await
            .map_err(classify_startup_error)
    }

    async fn start_inner(&mut self, credentials: Credentials) -> Result<ConnectionInfo> {
        let deadline = Instant::now() + Duration::from_secs(60);
        let (default, protected, endpoints) = async {
            let default = network::lookup("default")
                .await
                .map_err(|error| network_error("local route preflight", error))?
                .context("No default physical route")
                .map_err(|error| network_error("local route preflight", error))?;
            ensure!(
                default.physical(),
                "Default route belongs to another tunnel; cannot infer a safe physical path"
            );
            let mut protected = network::local_networks(&default.interface)
                .await
                .map_err(|error| network_error("local subnet preflight", error))?;
            if let Some(gateway) = default.gateway {
                let gateway_route = network::lookup(&gateway.to_string())
                    .await
                    .map_err(|error| network_error("default gateway preflight", error))?
                    .context("No physical route to the default gateway")
                    .map_err(|error| network_error("default gateway preflight", error))?;
                ensure!(
                    gateway_route.physical(),
                    "Default gateway is routed through another tunnel"
                );
                protected.push(gateway_route.network.context(
                    "Cannot prove a specific physical route protects the default gateway",
                )?);
            }
            let endpoints = network::endpoint_addresses()
                .await
                .map_err(|error| network_error("endpoint DNS preflight", error))?;
            Ok::<_, anyhow::Error>((default, protected, endpoints))
        }
        .await
        .map_err(|error| network_error("local network preflight", error))?;
        for endpoint in &endpoints {
            ensure!(Instant::now() < deadline, "VPN bootstrap deadline expired");
            network::protect_endpoint(&mut self.routes, *endpoint, &default)
                .await
                .map_err(|error| network_error("endpoint route protection", error))?;
        }

        let startup = tokio::time::timeout_at(
            deadline.min(Instant::now() + Duration::from_secs(45)),
            service::start_service(credentials.user, credentials.password),
        )
        .await;
        match startup {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                return Err(error
                    .downcast_ref::<StartupFailure>()
                    .copied()
                    .unwrap_or(StartupFailure::TunnelNegotiation)
                    .into());
            }
            Err(_) => return Err(StartupFailure::Timeout.into()),
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
            network::protect_endpoint(&mut self.routes, peer, &default)
                .await
                .map_err(|error| network_error("peer route protection", error))?;
        }
        let campus = network::campus_routes(&server, &protected)
            .map_err(|error| network_error("server route validation", error))?;
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
            .context("Could not create/configure macOS utun")
            .map_err(|error| network_error("utun configuration", error))?;
        let interface = device
            .name()
            .map_err(|error| network_error("utun name lookup", error.into()))?;
        ensure!(
            interface.starts_with("utun"),
            "Expected a new macOS utun interface"
        );
        device
            .set_nonblocking(true)
            .map_err(|error| network_error("utun nonblocking setup", error.into()))?;
        self.device =
            Some(Arc::new(AsyncFd::new(device).map_err(|error| {
                network_error("utun readiness setup", error.into())
            })?));
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
                .await
                .map_err(|error| network_error("campus route installation", error))?;
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
