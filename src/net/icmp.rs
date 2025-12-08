use pnet::packet::icmp::destination_unreachable::{IcmpCodes, MutableDestinationUnreachablePacket};
use pnet::packet::icmp::{self, IcmpPacket, IcmpTypes};
use pnet::packet::icmpv6::{self, Icmpv6Types, MutableIcmpv6Packet};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{Ipv4Packet, MutableIpv4Packet};
use pnet::packet::ipv6::{Ipv6Packet, MutableIpv6Packet};

pub fn build_icmp_error(original: &[u8], mtu: u32) -> Option<Vec<u8>> {
    if let Some(ipv4) = Ipv4Packet::new(original)
        && ipv4.get_version() == 4
    {
        let quote_len = ipv4.get_header_length() as usize * 4 + 20; // IP header + 20 bytes of payload (fits TCP header)

        let mut icmp_buf =
            vec![0u8; MutableDestinationUnreachablePacket::minimum_packet_size() + quote_len];
        {
            let mut icmp_pkt = MutableDestinationUnreachablePacket::new(&mut icmp_buf)?;
            icmp_pkt.set_icmp_type(IcmpTypes::DestinationUnreachable);
            icmp_pkt.set_icmp_code(IcmpCodes::FragmentationRequiredAndDFFlagSet);
            icmp_pkt.set_next_hop_mtu(mtu as u16);
            icmp_pkt.set_payload(&original[..quote_len]);
        }
        let checksum = icmp::checksum(&IcmpPacket::new(&icmp_buf).unwrap());
        {
            let mut icmp_pkt = MutableDestinationUnreachablePacket::new(&mut icmp_buf)?;
            icmp_pkt.set_checksum(checksum);
        }
        let mut ipv4_buf = vec![0u8; MutableIpv4Packet::minimum_packet_size() + icmp_buf.len()];
        let len = ipv4_buf.len();
        let mut reply = MutableIpv4Packet::new(&mut ipv4_buf)?;
        reply.set_version(4);
        reply.set_header_length(5);
        reply.set_total_length(len as u16);
        reply.set_ttl(64);
        reply.set_next_level_protocol(IpNextHeaderProtocols::Icmp);
        reply.set_source(ipv4.get_destination());
        reply.set_destination(ipv4.get_source());
        reply.set_payload(&icmp_buf);
        let checksum = pnet::packet::ipv4::checksum(&reply.to_immutable());
        reply.set_checksum(checksum);
        return Some(ipv4_buf.to_vec());
    } else if let Some(ipv6) = Ipv6Packet::new(original)
        && ipv6.get_version() == 6
    {
        let quote_len = original.len().min(1200);
        let mut icmp_buf = vec![0u8; 80 + quote_len];
        {
            let mut icmp_pkt = MutableIcmpv6Packet::new(&mut icmp_buf)?;
            icmp_pkt.set_icmpv6_type(Icmpv6Types::PacketTooBig);
            icmp_pkt.set_payload(mtu.to_be_bytes().as_ref());

            let checksum = icmpv6::checksum(
                &icmp_pkt.to_immutable(),
                &ipv6.get_destination(),
                &ipv6.get_source(),
            );
            icmp_pkt.set_checksum(checksum);
        }
        let mut ipv6_buf = vec![0u8; MutableIpv6Packet::minimum_packet_size() + icmp_buf.len()];
        let mut reply = MutableIpv6Packet::new(&mut ipv6_buf)?;
        reply.set_version(6);
        reply.set_payload_length(icmp_buf.len() as u16);
        reply.set_next_header(IpNextHeaderProtocols::Icmpv6);
        reply.set_hop_limit(64);
        reply.set_source(ipv6.get_destination());
        reply.set_destination(ipv6.get_source());
        reply.set_payload(&icmp_buf);
        return Some(ipv6_buf.to_vec());
    }
    None
}
