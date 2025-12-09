use std::net::{Ipv4Addr, Ipv6Addr};

use pnet::packet::icmp::destination_unreachable::{IcmpCodes, MutableDestinationUnreachablePacket};
use pnet::packet::icmp::{self, IcmpPacket, IcmpTypes};
use pnet::packet::icmpv6::{self, Icmpv6Types, MutableIcmpv6Packet};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{Ipv4Packet, MutableIpv4Packet};
use pnet::packet::ipv6::{Ipv6Packet, MutableIpv6Packet};

#[derive(Debug)]
pub enum IcmpType {
    PacketTooBig(u32),
    DestinationUnreachable,
    SourceRouteFailed,
}

pub fn build_icmp_response(original: &[u8], icmp_type: IcmpType) -> Option<Vec<u8>> {
    if let Some(ipv4) = Ipv4Packet::new(original)
        && ipv4.get_version() == 4
    {
        match icmp_type {
            IcmpType::PacketTooBig(allowed_mtu) => {
                let quote_len = ipv4.get_header_length() as usize * 4 + 20; // IP header + 20 bytes of payload (fits TCP header)

                let mut icmp_buf = vec![
                    0u8;
                    MutableDestinationUnreachablePacket::minimum_packet_size()
                        + quote_len
                ];
                {
                    let mut icmp_pkt = MutableDestinationUnreachablePacket::new(&mut icmp_buf)?;
                    icmp_pkt.set_icmp_type(IcmpTypes::DestinationUnreachable);
                    icmp_pkt.set_icmp_code(IcmpCodes::FragmentationRequiredAndDFFlagSet);
                    icmp_pkt.set_next_hop_mtu(allowed_mtu as u16);
                    icmp_pkt.set_payload(&original[..quote_len]);
                }
                let checksum = icmp::checksum(&IcmpPacket::new(&icmp_buf).unwrap());
                {
                    let mut icmp_pkt = MutableDestinationUnreachablePacket::new(&mut icmp_buf)?;
                    icmp_pkt.set_checksum(checksum);
                }
                return package_icmp_in_ipv4(&icmp_buf, ipv4.get_destination(), ipv4.get_source());
            }
            IcmpType::DestinationUnreachable => {
                let quote_len = ipv4.get_header_length() as usize * 4 + 20; // IP header + 20 bytes of payload (fits TCP header)
                let mut icmp_buf = vec![
                    0u8;
                    MutableDestinationUnreachablePacket::minimum_packet_size()
                        + quote_len
                ];
                {
                    let mut icmp_pkt = MutableDestinationUnreachablePacket::new(&mut icmp_buf)?;
                    icmp_pkt.set_icmp_type(IcmpTypes::DestinationUnreachable);
                    icmp_pkt.set_icmp_code(IcmpCodes::DestinationHostUnreachable);
                    icmp_pkt.set_payload(&original[..quote_len]);
                }
                let checksum = icmp::checksum(&IcmpPacket::new(&icmp_buf).unwrap());
                {
                    let mut icmp_pkt = MutableDestinationUnreachablePacket::new(&mut icmp_buf)?;
                    icmp_pkt.set_checksum(checksum);
                }
                return package_icmp_in_ipv4(&icmp_buf, ipv4.get_destination(), ipv4.get_source());
            }
            IcmpType::SourceRouteFailed => {
                let quote_len = ipv4.get_header_length() as usize * 4 + 20; // IP header + 20 bytes of payload (fits TCP header)
                let mut icmp_buf = vec![
                    0u8;
                    MutableDestinationUnreachablePacket::minimum_packet_size()
                        + quote_len
                ];
                {
                    let mut icmp_pkt = MutableDestinationUnreachablePacket::new(&mut icmp_buf)?;
                    icmp_pkt.set_icmp_type(IcmpTypes::DestinationUnreachable);
                    icmp_pkt.set_icmp_code(IcmpCodes::SourceRouteFailed);
                    icmp_pkt.set_payload(&original[..quote_len]);
                }
                let checksum = icmp::checksum(&IcmpPacket::new(&icmp_buf).unwrap());
                {
                    let mut icmp_pkt = MutableDestinationUnreachablePacket::new(&mut icmp_buf)?;
                    icmp_pkt.set_checksum(checksum);
                }
                return package_icmp_in_ipv4(&icmp_buf, ipv4.get_destination(), ipv4.get_source());
            }
        }
    } else if let Some(ipv6) = Ipv6Packet::new(original)
        && ipv6.get_version() == 6
    {
        match icmp_type {
            IcmpType::PacketTooBig(allowed_mtu) => {
                let quote_len = original.len().min(1200);
                let mut icmp_buf = vec![0u8; 80 + quote_len];
                {
                    let mut icmp_pkt = MutableIcmpv6Packet::new(&mut icmp_buf)?;
                    icmp_pkt.set_icmpv6_type(Icmpv6Types::PacketTooBig);
                    icmp_pkt.set_payload(allowed_mtu.to_be_bytes().as_ref());

                    let checksum = icmpv6::checksum(
                        &icmp_pkt.to_immutable(),
                        &ipv6.get_destination(),
                        &ipv6.get_source(),
                    );
                    icmp_pkt.set_checksum(checksum);
                }
                return package_icmp_in_ipv6(&icmp_buf, ipv6.get_destination(), ipv6.get_source());
            }
            IcmpType::DestinationUnreachable => {
                let quote_len = original.len().min(1200);
                let mut icmp_buf = vec![0u8; 80 + quote_len];
                {
                    let mut icmp_pkt = MutableIcmpv6Packet::new(&mut icmp_buf)?;
                    icmp_pkt.set_icmpv6_type(Icmpv6Types::DestinationUnreachable);
                    icmp_pkt.set_payload(&original[..quote_len]);

                    let checksum = icmpv6::checksum(
                        &icmp_pkt.to_immutable(),
                        &ipv6.get_destination(),
                        &ipv6.get_source(),
                    );
                    icmp_pkt.set_checksum(checksum);
                }
                return package_icmp_in_ipv6(&icmp_buf, ipv6.get_destination(), ipv6.get_source());
            }
            IcmpType::SourceRouteFailed => {
                let quote_len = original.len().min(1200);
                let mut icmp_buf = vec![0u8; 80 + quote_len];
                {
                    let mut icmp_pkt = MutableIcmpv6Packet::new(&mut icmp_buf)?;
                    icmp_pkt.set_icmpv6_type(Icmpv6Types::DestinationUnreachable);
                    icmp_pkt.set_payload(&original[..quote_len]);

                    let checksum = icmpv6::checksum(
                        &icmp_pkt.to_immutable(),
                        &ipv6.get_destination(),
                        &ipv6.get_source(),
                    );
                    icmp_pkt.set_checksum(checksum);
                }
                return package_icmp_in_ipv6(&icmp_buf, ipv6.get_destination(), ipv6.get_source());
            }
        }
    }
    None
}

pub fn package_icmp_in_ipv4(icmp_payload: &[u8], src: Ipv4Addr, dst: Ipv4Addr) -> Option<Vec<u8>> {
    let mut ipv4_buf = vec![0u8; MutableIpv4Packet::minimum_packet_size() + icmp_payload.len()];
    let len = ipv4_buf.len();
    let mut ipv4_pkt = MutableIpv4Packet::new(&mut ipv4_buf)?;
    ipv4_pkt.set_version(4);
    ipv4_pkt.set_header_length(5);
    ipv4_pkt.set_total_length(len as u16);
    ipv4_pkt.set_ttl(64);
    ipv4_pkt.set_next_level_protocol(IpNextHeaderProtocols::Icmp);
    ipv4_pkt.set_source(src);
    ipv4_pkt.set_destination(dst);
    ipv4_pkt.set_payload(icmp_payload);
    let checksum = pnet::packet::ipv4::checksum(&ipv4_pkt.to_immutable());
    ipv4_pkt.set_checksum(checksum);
    Some(ipv4_buf.to_vec())
}

pub fn package_icmp_in_ipv6(icmp_payload: &[u8], src: Ipv6Addr, dst: Ipv6Addr) -> Option<Vec<u8>> {
    let mut ipv6_buf = vec![0u8; MutableIpv6Packet::minimum_packet_size() + icmp_payload.len()];
    let mut ipv6_pkt = MutableIpv6Packet::new(&mut ipv6_buf)?;
    ipv6_pkt.set_version(6);
    ipv6_pkt.set_payload_length(icmp_payload.len() as u16);
    ipv6_pkt.set_next_header(IpNextHeaderProtocols::Icmp);
    ipv6_pkt.set_hop_limit(64);
    ipv6_pkt.set_source(src);
    ipv6_pkt.set_destination(dst);
    ipv6_pkt.set_payload(icmp_payload);
    Some(ipv6_buf.to_vec())
}
