use std::net::Ipv4Addr;
use std::process::Command;
use std::time::Duration;

use crate::net::arp;
use crate::net::Device;

/// Groups all anti-detection parameters for the spoofer.
pub struct StealthConfig {
    pub aggressive_lo: Duration,
    pub aggressive_hi: Duration,
    pub aggressive_duration: Duration,
    pub maintenance_lo: Duration,
    pub maintenance_hi: Duration,
    pub ramp_duration: Duration,
    pub ttl_restore: bool,
    pub watchdog: bool,
}

impl Default for StealthConfig {
    fn default() -> Self {
        Self {
            aggressive_lo: Duration::from_millis(200),
            aggressive_hi: Duration::from_millis(400),
            aggressive_duration: Duration::from_secs(10),
            maintenance_lo: Duration::from_millis(2000),
            maintenance_hi: Duration::from_millis(5000),
            ramp_duration: Duration::from_secs(5),
            ttl_restore: true,
            watchdog: true,
        }
    }
}

/// RAII guard that installs an iptables mangle rule to increment TTL by 1
/// on forwarded packets (compensating for the extra hop), and removes it
/// on drop — even on panic.
pub struct TtlGuard {
    active: bool,
}

impl TtlGuard {
    /// Install the iptables TTL-increment rule.
    ///
    /// Returns `(guard, true)` if the rule was installed successfully,
    /// or `(guard, false)` if iptables failed (e.g. missing xt_TTL module).
    /// The guard is still valid in both cases — a failed install simply
    /// means no cleanup will be attempted on drop.
    pub fn install() -> (Self, bool) {
        let status = Command::new("iptables")
            .args(["-t", "mangle", "-A", "FORWARD", "-j", "TTL", "--ttl-inc", "1"])
            .status();

        let active = match status {
            Ok(s) => s.success(),
            Err(_) => false,
        };

        (Self { active }, active)
    }

    /// Create a guard that does nothing (TTL restoration disabled).
    pub fn noop() -> Self {
        Self { active: false }
    }
}

impl Drop for TtlGuard {
    fn drop(&mut self) {
        if self.active {
            let _ = Command::new("iptables")
                .args(["-t", "mangle", "-D", "FORWARD", "-j", "TTL", "--ttl-inc", "1"])
                .status();
        }
    }
}

/// Check if a received frame is an ARP request from one of our targets
/// asking to resolve the gateway IP — indicating the target is
/// re-verifying its ARP cache.
pub fn is_watchdog_trigger(
    frame: &[u8],
    gateway_ip: Ipv4Addr,
    targets: &[Device],
) -> bool {
    if let Some((sender_ip, target_ip)) = arp::parse_request(frame) {
        target_ip == gateway_ip && targets.iter().any(|t| t.ip == sender_ip)
    } else {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pnet::datalink::MacAddr;

    const TARGET_MAC: MacAddr = MacAddr(0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01);
    const OTHER_MAC: MacAddr = MacAddr(0x11, 0x22, 0x33, 0x44, 0x55, 0x66);

    fn gateway_ip() -> Ipv4Addr {
        "192.168.1.1".parse().unwrap()
    }

    fn target_ip() -> Ipv4Addr {
        "192.168.1.50".parse().unwrap()
    }

    fn targets() -> Vec<Device> {
        vec![Device { ip: target_ip(), mac: TARGET_MAC }]
    }

    /// Build an ARP request frame from `sender` asking for `target`.
    fn make_request(sender_mac: MacAddr, sender_ip: Ipv4Addr, target_ip: Ipv4Addr) -> [u8; arp::FRAME_SIZE] {
        let mut buf = [0u8; arp::FRAME_SIZE];
        arp::build_request(&mut buf, sender_mac, sender_ip, target_ip);
        buf
    }

    #[test]
    fn watchdog_triggers_on_target_asking_for_gateway() {
        let frame = make_request(TARGET_MAC, target_ip(), gateway_ip());
        assert!(is_watchdog_trigger(&frame, gateway_ip(), &targets()));
    }

    #[test]
    fn watchdog_ignores_unknown_sender() {
        let unknown_ip: Ipv4Addr = "192.168.1.99".parse().unwrap();
        let frame = make_request(OTHER_MAC, unknown_ip, gateway_ip());
        assert!(!is_watchdog_trigger(&frame, gateway_ip(), &targets()));
    }

    #[test]
    fn watchdog_ignores_request_for_non_gateway() {
        let other_ip: Ipv4Addr = "192.168.1.200".parse().unwrap();
        let frame = make_request(TARGET_MAC, target_ip(), other_ip);
        assert!(!is_watchdog_trigger(&frame, gateway_ip(), &targets()));
    }

    #[test]
    fn watchdog_ignores_reply_frames() {
        let mut buf = [0u8; arp::FRAME_SIZE];
        arp::build_reply(&mut buf, TARGET_MAC, target_ip(), OTHER_MAC, gateway_ip());
        assert!(!is_watchdog_trigger(&buf, gateway_ip(), &targets()));
    }

    #[test]
    fn watchdog_ignores_garbage() {
        assert!(!is_watchdog_trigger(&[0u8; 10], gateway_ip(), &targets()));
    }
}
