use std::net::Ipv4Addr;

use pnet::datalink::MacAddr;
use pnet::packet::arp::{ArpHardwareTypes, ArpOperation, ArpOperations, ArpPacket, MutableArpPacket};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::{MutablePacket, Packet};

const ARP_PACKET_SIZE: usize = 28;
const ETHERNET_HEADER_SIZE: usize = 14;
const BROADCAST: MacAddr = MacAddr(0xff, 0xff, 0xff, 0xff, 0xff, 0xff);
const ZERO: MacAddr = MacAddr(0, 0, 0, 0, 0, 0);

/// Total buffer size for an ARP-over-Ethernet frame.
pub const FRAME_SIZE: usize = ETHERNET_HEADER_SIZE + ARP_PACKET_SIZE;

/// Build an ARP request: "who has `target_ip`? tell `src_ip` at `src_mac`."
pub fn build_request(
    buffer: &mut [u8],
    src_mac: MacAddr,
    src_ip: Ipv4Addr,
    target_ip: Ipv4Addr,
) {
    build_frame(
        buffer,
        src_mac,
        BROADCAST,
        ArpOperations::Request,
        src_mac,
        src_ip,
        ZERO,
        target_ip,
    );
}

/// Build an ARP reply: tells `target_ip` that `sender_ip` lives at `sender_mac`.
pub fn build_reply(
    buffer: &mut [u8],
    sender_mac: MacAddr,
    sender_ip: Ipv4Addr,
    target_mac: MacAddr,
    target_ip: Ipv4Addr,
) {
    build_frame(
        buffer,
        sender_mac,
        target_mac,
        ArpOperations::Reply,
        sender_mac,
        sender_ip,
        target_mac,
        target_ip,
    );
}

/// Parse an Ethernet frame containing an ARP request.
///
/// Returns `(sender_ip, target_ip)` if the frame is a valid ARP request.
pub fn parse_request(frame: &[u8]) -> Option<(Ipv4Addr, Ipv4Addr)> {
    let eth = EthernetPacket::new(frame)?;
    if eth.get_ethertype() != EtherTypes::Arp {
        return None;
    }
    let arp = ArpPacket::new(eth.payload())?;
    if arp.get_operation() != ArpOperations::Request {
        return None;
    }
    Some((arp.get_sender_proto_addr(), arp.get_target_proto_addr()))
}

/// Parse an Ethernet frame containing an ARP reply.
///
/// Returns `(sender_mac, sender_ip)` if the frame is a valid ARP reply.
pub fn parse_reply(frame: &[u8]) -> Option<(MacAddr, Ipv4Addr)> {
    let eth = EthernetPacket::new(frame)?;
    if eth.get_ethertype() != EtherTypes::Arp {
        return None;
    }
    let arp = ArpPacket::new(eth.payload())?;
    if arp.get_operation() != ArpOperations::Reply {
        return None;
    }
    Some((arp.get_sender_hw_addr(), arp.get_sender_proto_addr()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SRC_MAC: MacAddr = MacAddr(0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01);
    const DST_MAC: MacAddr = MacAddr(0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x02);

    #[test]
    fn parse_request_round_trip() {
        let src_ip: Ipv4Addr = "192.168.1.10".parse().unwrap();
        let target_ip: Ipv4Addr = "192.168.1.1".parse().unwrap();

        let mut buf = [0u8; FRAME_SIZE];
        build_request(&mut buf, SRC_MAC, src_ip, target_ip);

        let (sender, target) = parse_request(&buf).expect("should parse as ARP request");
        assert_eq!(sender, src_ip);
        assert_eq!(target, target_ip);
    }

    #[test]
    fn parse_request_rejects_reply() {
        let mut buf = [0u8; FRAME_SIZE];
        build_reply(&mut buf, SRC_MAC, "10.0.0.1".parse().unwrap(), DST_MAC, "10.0.0.2".parse().unwrap());

        assert!(parse_request(&buf).is_none(), "should not parse a reply as a request");
    }

    #[test]
    fn parse_request_rejects_truncated() {
        assert!(parse_request(&[0u8; 10]).is_none());
    }

    #[test]
    fn parse_reply_rejects_request() {
        let mut buf = [0u8; FRAME_SIZE];
        build_request(&mut buf, SRC_MAC, "10.0.0.1".parse().unwrap(), "10.0.0.2".parse().unwrap());

        assert!(parse_reply(&buf).is_none(), "should not parse a request as a reply");
    }
}

fn build_frame(
    buffer: &mut [u8],
    eth_src: MacAddr,
    eth_dst: MacAddr,
    operation: ArpOperation,
    sender_mac: MacAddr,
    sender_ip: Ipv4Addr,
    target_mac: MacAddr,
    target_ip: Ipv4Addr,
) {
    let mut eth = MutableEthernetPacket::new(buffer).expect("buffer too small for Ethernet header");
    eth.set_source(eth_src);
    eth.set_destination(eth_dst);
    eth.set_ethertype(EtherTypes::Arp);

    let mut arp = MutableArpPacket::new(eth.payload_mut()).expect("buffer too small for ARP packet");
    arp.set_hardware_type(ArpHardwareTypes::Ethernet);
    arp.set_protocol_type(EtherTypes::Ipv4);
    arp.set_hw_addr_len(6);
    arp.set_proto_addr_len(4);
    arp.set_operation(operation);
    arp.set_sender_hw_addr(sender_mac);
    arp.set_sender_proto_addr(sender_ip);
    arp.set_target_hw_addr(target_mac);
    arp.set_target_proto_addr(target_ip);
}
