//! Stable startup categories. Display never includes server responses or secrets.
use std::fmt;

#[derive(Debug, Clone, Copy)]
pub enum StartupFailure {
    AuthenticationRejected,
    AuthenticationTransport,
    AuthenticationResponse,
    Tls,
    TunnelTransport,
    TunnelNegotiation,
    NetworkConfiguration,
    Timeout,
}
impl StartupFailure {
    pub fn code(self) -> &'static str {
        match self {
            Self::AuthenticationRejected => "authentication_rejected",
            Self::AuthenticationTransport => "authentication_transport",
            Self::AuthenticationResponse => "authentication_response",
            Self::Tls => "tls_failed",
            Self::TunnelTransport => "tunnel_transport_failed",
            Self::TunnelNegotiation => "tunnel_negotiation_failed",
            Self::NetworkConfiguration => "network_configuration_failed",
            Self::Timeout => "connection_timeout",
        }
    }
}
impl fmt::Display for StartupFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::AuthenticationRejected => {
                "Authentication endpoint rejected the login request; check campus credentials"
            }
            Self::AuthenticationTransport => "Could not reach the campus authentication service",
            Self::AuthenticationResponse => "Campus authentication returned an unusable response",
            Self::Tls => "VPN TLS handshake failed",
            Self::TunnelTransport => "Could not reach the VPN tunnel endpoint",
            Self::TunnelNegotiation => "VPN tunnel negotiation failed",
            Self::NetworkConfiguration => "Could not configure the required VPN network",
            Self::Timeout => "VPN connection startup timed out",
        })
    }
}
impl std::error::Error for StartupFailure {}
