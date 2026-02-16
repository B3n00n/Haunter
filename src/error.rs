use std::net::Ipv4Addr;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum HaunterError {
    #[error("network interface '{0}' not found")]
    InterfaceNotFound(String),

    #[error("interface '{0}' has no IPv4 address")]
    NoIpv4Address(String),

    #[error("could not resolve MAC address for {0}")]
    MacResolutionFailed(Ipv4Addr),

    #[error("network error: {0}")]
    Network(String),

    #[error("insufficient permissions — run with sudo")]
    PermissionDenied,
}

pub type Result<T> = std::result::Result<T, HaunterError>;
