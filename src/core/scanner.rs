use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use pnet::datalink::{MacAddr, NetworkInterface};

use crate::error::{HaunterError, Result};
use crate::net::channel::Channel;
use crate::net::{arp, interface, Device};

const READ_TIMEOUT: Duration = Duration::from_millis(100);

/// Scan the subnet of `iface` for active devices via ARP.
///
/// Sends an ARP request to every host address in the subnet,
/// then collects replies until `timeout` elapses.
pub fn scan(iface: &NetworkInterface, timeout: Duration) -> Result<Vec<Device>> {
    let mac = iface
        .mac
        .ok_or_else(|| HaunterError::Network("interface has no MAC address".into()))?;
    let network = interface::ipv4_network(iface)?;
    let our_ip = network.ip();

    let mut channel = Channel::open(iface, READ_TIMEOUT)?;
    let mut buffer = [0u8; arp::FRAME_SIZE];

    for ip in network.iter() {
        if ip == our_ip || ip == network.network() || ip == network.broadcast() {
            continue;
        }
        arp::build_request(&mut buffer, mac, our_ip, ip);
        channel.send(&buffer)?;
    }

    let mut devices = Vec::new();
    let deadline = Instant::now() + timeout;

    while Instant::now() < deadline {
        match channel.receive()? {
            Some(frame) => {
                if let Some((sender_mac, sender_ip)) = arp::parse_reply(frame) {
                    let is_new = sender_ip != our_ip
                        && !devices.iter().any(|d: &Device| d.ip == sender_ip);
                    if is_new {
                        devices.push(Device {
                            ip: sender_ip,
                            mac: sender_mac,
                        });
                    }
                }
            }
            None => continue,
        }
    }

    devices.sort_by_key(|d| u32::from(d.ip));
    Ok(devices)
}

/// Resolve the MAC address of a single IP via ARP request/reply.
///
/// Sends a few ARP requests and waits up to 3 seconds for a reply.
pub fn resolve_mac(
    iface: &NetworkInterface,
    our_mac: MacAddr,
    our_ip: Ipv4Addr,
    target_ip: Ipv4Addr,
) -> Result<MacAddr> {
    let mut channel = Channel::open(iface, READ_TIMEOUT)?;
    let mut buffer = [0u8; arp::FRAME_SIZE];
    let deadline = Instant::now() + Duration::from_secs(3);

    for _ in 0..3 {
        arp::build_request(&mut buffer, our_mac, our_ip, target_ip);
        channel.send(&buffer)?;
    }

    while Instant::now() < deadline {
        match channel.receive()? {
            Some(frame) => {
                if let Some((mac, ip)) = arp::parse_reply(frame) {
                    if ip == target_ip {
                        return Ok(mac);
                    }
                }
            }
            None => continue,
        }
    }

    Err(HaunterError::MacResolutionFailed(target_ip))
}
