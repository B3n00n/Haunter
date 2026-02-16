use ipnetwork::Ipv4Network;
use pnet::datalink::{self, NetworkInterface};
use pnet::ipnetwork::IpNetwork;

use crate::error::{HaunterError, Result};

/// Return all available network interfaces.
pub fn list() -> Vec<NetworkInterface> {
    datalink::interfaces()
}

/// Resolve a network interface by name.
pub fn resolve(name: &str) -> Result<NetworkInterface> {
    datalink::interfaces()
        .into_iter()
        .find(|iface| iface.name == name)
        .ok_or_else(|| HaunterError::InterfaceNotFound(name.into()))
}

/// Get the first IPv4 network assigned to an interface.
pub fn ipv4_network(iface: &NetworkInterface) -> Result<Ipv4Network> {
    iface
        .ips
        .iter()
        .find_map(|ip| match ip {
            IpNetwork::V4(net) => Some(*net),
            _ => None,
        })
        .ok_or_else(|| HaunterError::NoIpv4Address(iface.name.clone()))
}
