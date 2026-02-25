use crate::flowspec::{FragmentFlags, PacketInfo};
use pnet::packet::icmp::IcmpPacket;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;

pub struct PacketMatcher;

impl PacketMatcher {
    pub fn extract_packet_info(ipv4_packet: &Ipv4Packet) -> Option<PacketInfo> {
        let src_addr = ipv4_packet.get_source();
        let dst_addr = ipv4_packet.get_destination();
        let protocol = ipv4_packet.get_next_level_protocol().0;
        let dscp = ipv4_packet.get_dscp();
        let length = ipv4_packet.packet().len();

        // Extract fragment flags from IP header
        let flags = ipv4_packet.get_flags();
        let fragment_offset = ipv4_packet.get_fragment_offset();
        let dont_fragment = (flags & 0b010) != 0; // DF bit
        let more_fragments = (flags & 0b001) != 0; // MF bit

        let fragment = FragmentFlags {
            dont_fragment,
            is_fragment: more_fragments || fragment_offset > 0,
            first_fragment: fragment_offset == 0 && more_fragments,
            last_fragment: fragment_offset > 0 && !more_fragments,
        };

        let mut src_port = None;
        let mut dst_port = None;
        let mut tcp_flags = None;
        let mut icmp_type = None;
        let mut icmp_code = None;

        match ipv4_packet.get_next_level_protocol() {
            IpNextHeaderProtocols::Tcp => {
                if let Some(tcp) = TcpPacket::new(ipv4_packet.payload()) {
                    src_port = Some(tcp.get_source());
                    dst_port = Some(tcp.get_destination());
                    tcp_flags = Some(tcp.get_flags() as u8);
                }
            }
            IpNextHeaderProtocols::Udp => {
                if let Some(udp) = UdpPacket::new(ipv4_packet.payload()) {
                    src_port = Some(udp.get_source());
                    dst_port = Some(udp.get_destination());
                }
            }
            IpNextHeaderProtocols::Icmp => {
                if let Some(icmp) = IcmpPacket::new(ipv4_packet.payload()) {
                    icmp_type = Some(icmp.get_icmp_type().0);
                    icmp_code = Some(icmp.get_icmp_code().0);
                }
            }
            _ => {}
        };

        Some(PacketInfo {
            dst_addr,
            src_addr,
            protocol,
            dst_port,
            src_port,
            icmp_type,
            icmp_code,
            tcp_flags,
            length,
            dscp,
            fragment,
        })
    }
}
