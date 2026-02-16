pub mod arp;
pub mod channel;
pub mod dns;
pub mod interface;

use std::net::Ipv4Addr;

use pnet::datalink::MacAddr;

/// A discovered device on the local network.
#[derive(Debug, Clone)]
pub struct Device {
    pub ip: Ipv4Addr,
    pub mac: MacAddr,
}

impl std::fmt::Display for Device {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:<16} {}", self.ip, self.mac)
    }
}
