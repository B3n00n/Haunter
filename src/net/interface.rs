use ipnetwork::Ipv4Network;
use pnet::datalink::{self, NetworkInterface};
use pnet::ipnetwork::IpNetwork;

use crate::error::{HaunterError, Result};

/// Print all available network interfaces.
pub fn list() {
    let interfaces = datalink::interfaces();

    if interfaces.is_empty() {
        println!("No network interfaces found.");
        return;
    }

    for iface in &interfaces {
        let mac = iface
            .mac
            .map(|m| m.to_string())
            .unwrap_or_else(|| "N/A".into());

        let ips: Vec<String> = iface.ips.iter().map(|ip| ip.to_string()).collect();

        println!(
            "{name:<16} MAC: {mac:<20} IPs: {ips}",
            name = iface.name,
            ips = if ips.is_empty() {
                "none".into()
            } else {
                ips.join(", ")
            },
        );
    }
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
