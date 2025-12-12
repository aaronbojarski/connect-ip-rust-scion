pub mod capsule;
pub mod request;

use std::collections::VecDeque;
use std::net::IpAddr;
use std::sync::Arc;

use anyhow::Result;
use ipnet::IpNet;
use octets::{Octets, OctetsMut};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use tokio::sync::{Mutex, mpsc};
use tracing::{debug, error, info, trace, warn};

use crate::connect_ip::capsule::{
    AddressAssignCapsule, AssignedAddress, Capsule, CapsuleError, DatagramCapsule,
    RouteAdvertisement, RouteAdvertisementCapsule,
};
use crate::net::icmp::build_icmp_response;
use crate::net::quic::MAX_DATAGRAM_SIZE;
use crate::net::tun::MAX_TUN_MTU;
use crate::net::{
    ForwardingDecision, ZERO_IPV4_ADDRESS, ZERO_IPV6_ADDRESS, check_packet_src_dst,
    get_next_avail_subnet, get_specific_subnet, is_ipv4, is_zero_address, tun,
};

const SEND_BUFFER_SIZE: usize = 65535;
const RCV_BUFFER_SIZE: usize = 65535;
const MAX_TUN_MTU_FOR_DATAGRAMS: usize = MAX_DATAGRAM_SIZE - 50;

/// Addresses and routes negotiated through capsule protocol.
#[derive(Clone, Debug)]
pub struct RoutingState {
    /// mtu of the tunnel
    pub mtu: u16,
    /// addresses we assign to the peer
    pub remote_addresses: Vec<IpNet>,
    /// addresses the peer assigns to us
    pub local_addresses: Vec<IpNet>,
    /// routes we advertise to the peer
    pub local_routes: Vec<IpNet>,
    /// routes the peer advertises to us
    pub remote_routes: Vec<IpNet>,
}

pub struct Endpoint {
    pub stream_id: u64,
    pub routing_state: RoutingState,
    available_addresses: Arc<Mutex<Vec<IpNet>>>,
    tx_forward_ingress: mpsc::Sender<Vec<u8>>,
    tx_routing_update: mpsc::Sender<tun::TunConfiguration>,
    peer_supports_datagrams: bool,
    stream_data_received: VecDeque<u8>, // data received from the stream, not yet processed
    stream_data_to_send: VecDeque<u8>, // needs to be sent on the stream, not yet sent due to flow control
    datagrams_to_send: VecDeque<Vec<u8>>, // datagrams to send, not yet sent due to flow control
}

impl Endpoint {
    pub fn new(
        stream_id: u64,
        mtu: u16,
        available_addresses: Arc<Mutex<Vec<IpNet>>>,
        routes: Vec<IpNet>,
        tx_forward_ingress: mpsc::Sender<Vec<u8>>,
        tx_routing_update: mpsc::Sender<tun::TunConfiguration>,
        peer_supports_datagrams: bool,
    ) -> Self {
        Self {
            stream_id,
            routing_state: RoutingState {
                mtu,
                remote_addresses: vec![],
                local_addresses: vec![],
                local_routes: routes,
                remote_routes: vec![],
            },
            available_addresses,
            tx_forward_ingress,
            tx_routing_update,
            peer_supports_datagrams,
            stream_data_received: VecDeque::with_capacity(RCV_BUFFER_SIZE),
            stream_data_to_send: VecDeque::with_capacity(SEND_BUFFER_SIZE),
            datagrams_to_send: VecDeque::new(),
        }
    }

    pub fn check_ingress_packet(&mut self, packet: &[u8]) -> ForwardingDecision {
        if packet.len() > self.routing_state.mtu as usize {
            debug!(
                "packet size {} exceeds TUN MTU {}",
                packet.len(),
                self.routing_state.mtu
            );
            return ForwardingDecision::RespondWithIcmp(crate::net::icmp::IcmpType::PacketTooBig(
                self.routing_state.mtu as u32,
            ));
        }

        let (src, dst) = if let Some(ipv4) = Ipv4Packet::new(packet)
            && ipv4.get_version() == 4
        {
            (
                IpAddr::V4(ipv4.get_source()),
                IpAddr::V4(ipv4.get_destination()),
            )
        } else if let Some(ipv6) = Ipv6Packet::new(packet) {
            (
                IpAddr::V6(ipv6.get_source()),
                IpAddr::V6(ipv6.get_destination()),
            )
        } else {
            error!("received non-IP packet in datagram, dropping");
            return ForwardingDecision::Drop;
        };

        debug!(
            "received IP packet from QUIC connection: {} -> {}, {} bytes",
            src,
            dst,
            packet.len()
        );

        debug!(
            "remote_addresses: {:?}, remote_routes: {:?}, local_addresses: {:?}, local_routes: {:?}",
            self.routing_state.remote_addresses,
            self.routing_state.remote_routes,
            self.routing_state.local_addresses,
            self.routing_state.local_routes,
        );

        check_packet_src_dst(
            src,
            dst,
            &self.routing_state.remote_addresses,
            &self.routing_state.remote_routes,
            &self.routing_state.local_addresses,
            &self.routing_state.local_routes,
        )
    }

    pub fn check_egress_packet(&mut self, packet: &[u8]) -> ForwardingDecision {
        if packet.len() > self.routing_state.mtu as usize {
            debug!(
                "packet size {} exceeds TUN MTU {}",
                packet.len(),
                self.routing_state.mtu
            );
            return ForwardingDecision::RespondWithIcmp(crate::net::icmp::IcmpType::PacketTooBig(
                self.routing_state.mtu as u32,
            ));
        }

        let (src, dst) = if let Some(ipv4) = Ipv4Packet::new(packet)
            && ipv4.get_version() == 4
        {
            (
                IpAddr::V4(ipv4.get_source()),
                IpAddr::V4(ipv4.get_destination()),
            )
        } else if let Some(ipv6) = Ipv6Packet::new(packet)
            && ipv6.get_version() == 6
        {
            (
                IpAddr::V6(ipv6.get_source()),
                IpAddr::V6(ipv6.get_destination()),
            )
        } else {
            error!("received non-IP packet from tun, dropping");
            return ForwardingDecision::Drop;
        };

        debug!(
            "received IP packet from TUN: {} -> {}, {} bytes",
            src,
            dst,
            packet.len()
        );

        check_packet_src_dst(
            src,
            dst,
            &self.routing_state.local_addresses,
            &self.routing_state.local_routes,
            &self.routing_state.remote_addresses,
            &self.routing_state.remote_routes,
        )
    }

    pub async fn forward_ingress_packet(&mut self, packet: &[u8]) -> Result<()> {
        self.tx_forward_ingress.send(packet.to_vec()).await?;
        Ok(())
    }

    pub fn forward_egress_packet(&mut self, packet: &[u8]) -> Result<()> {
        let mut buf = [0; MAX_TUN_MTU + 32];
        if self.peer_supports_datagrams
            && self.routing_state.mtu as usize <= MAX_TUN_MTU_FOR_DATAGRAMS
        {
            let mut octets = OctetsMut::with_slice(&mut buf);
            octets.put_varint(self.stream_id / 4)?;
            octets.put_varint(0)?;
            octets.put_bytes(packet)?;
            let len = octets.off();
            self.datagrams_to_send.push_back(buf[..len].to_vec());
        } else {
            let mut datagram_data = [0u8; MAX_TUN_MTU + 8];
            let mut datagram_octets = OctetsMut::with_slice(&mut datagram_data);
            datagram_octets.put_varint(0)?;
            datagram_octets.put_bytes(packet)?;
            let len = datagram_octets.off();
            let datagram_capsule = DatagramCapsule {
                data: datagram_data[..len].to_vec(),
            };
            let capsule = Capsule::Datagram(datagram_capsule);
            self.send_capsule(&capsule, false)?;
        }

        Ok(())
    }

    pub fn send_stream_data(&mut self, out: &mut [u8], len: usize) -> usize {
        self.stream_data_to_send.make_contiguous();
        let to_send = self.stream_data_to_send.as_slices().0;
        let send_len = std::cmp::min(len, to_send.len());
        let send_len = std::cmp::min(send_len, out.len());
        out[..send_len].copy_from_slice(&to_send[..send_len]);
        if send_len < to_send.len() {
            self.stream_data_to_send.drain(0..send_len);
        } else {
            self.stream_data_to_send.clear();
        }

        send_len
    }

    pub fn return_stream_data(&mut self, data: &[u8]) {
        // Add data to the front of the send buffer
        for &byte in data.iter().rev() {
            self.stream_data_to_send.push_front(byte);
        }
    }

    pub async fn recv_stream_data(&mut self, data: &[u8]) -> Result<()> {
        self.stream_data_received.extend(data);
        let mut consumed = 0;
        while consumed < self.stream_data_received.len() {
            match self.process_capsule_data(consumed).await {
                Ok(len) => {
                    consumed += len;
                }
                Err(e) => {
                    if let Some(capsule_err) = e.downcast_ref::<CapsuleError>()
                        && matches!(capsule_err, CapsuleError::Buffer(_))
                    {
                        trace!("need more data to process capsule.");
                        break;
                    }
                    error!("error processing capsule data: {}", e);
                    return Err(e);
                }
            }
        }
        self.stream_data_received.drain(0..consumed);
        Ok(())
    }

    pub fn send_datagram(&mut self) -> Option<Vec<u8>> {
        self.datagrams_to_send.pop_front()
    }

    pub fn return_datagram(&mut self, data: &[u8]) {
        self.datagrams_to_send.push_front(data.to_vec());
    }

    pub async fn recv_datagram(&mut self, data: &[u8]) -> Result<()> {
        let mut octets = Octets::with_slice(data);

        // The datagram format is:
        // - varint: quarter stream id (stream_id / 4)
        // - varint: context_id (must be 0)
        // - bytes: IP packet
        let stream_id = octets.get_varint()? * 4;
        let context_id = octets.get_varint()?;
        let packet_start = octets.off();

        if self.stream_id != stream_id {
            error!("received datagram on unknown stream id {}", stream_id);
            return Ok(());
        }

        if context_id != 0 {
            error!("received datagram with unknown context id {}", context_id);
            return Ok(());
        }

        let ip_packet = &data[packet_start..];
        match self.check_ingress_packet(ip_packet) {
            ForwardingDecision::Drop => {
                debug!("dropping invalid packet from QUIC");
                return Ok(());
            }
            ForwardingDecision::Forward => {
                self.forward_ingress_packet(ip_packet).await?;
            }
            ForwardingDecision::RespondWithIcmp(icmp_type) => {
                if let Some(icmp_response) = build_icmp_response(ip_packet, icmp_type) {
                    self.forward_egress_packet(&icmp_response)?;
                } else {
                    debug!("could not build ICMP error message, dropping packet");
                }
            }
        }
        Ok(())
    }

    pub fn send_capsule(&mut self, capsule: &Capsule, must_succeed: bool) -> Result<()> {
        let mut buf = [0; MAX_TUN_MTU + 32];
        let mut octets = OctetsMut::with_slice(&mut buf);
        capsule.append(&mut octets)?;
        let len = octets.off();
        if !must_succeed && self.stream_data_to_send.len() + len > SEND_BUFFER_SIZE {
            debug!(
                "too much remaining data to send ({} bytes), dropping capsule",
                self.stream_data_to_send.len() + len
            );
            return Ok(());
        }
        self.stream_data_to_send.extend(&buf[..len]);
        Ok(())
    }

    pub async fn update_tun_interface(&self, update: tun::TunConfiguration) -> Result<()> {
        self.tx_routing_update.send(update).await?;
        Ok(())
    }

    pub async fn process_capsule_data(&mut self, start: usize) -> Result<usize> {
        self.stream_data_received.make_contiguous();
        let mut octets = Octets::with_slice(&self.stream_data_received.as_slices().0[start..]);
        let capsule = Capsule::parse(&mut octets)?;
        let len = octets.off();
        match capsule {
            Capsule::Datagram(datagram_capsule) => {
                trace!("received Datagram capsule: {:?}", datagram_capsule);
                // Handle the datagram data as needed
                debug!(
                    "received datagram of length {} bytes",
                    datagram_capsule.data.len()
                );
                let mut octets = Octets::with_slice(&datagram_capsule.data);

                // The datagram format is:
                // - varint: context_id (must be 0)
                // - bytes: IP packet
                let context_id = octets.get_varint()?;
                let packet_start = octets.off();

                if context_id != 0 {
                    error!("received datagram with unknown context id {}", context_id);
                    return Ok(len);
                }

                match self.check_ingress_packet(&datagram_capsule.data[packet_start..]) {
                    ForwardingDecision::Drop => {
                        debug!("dropping invalid packet from datagram capsule");
                    }
                    ForwardingDecision::RespondWithIcmp(icmp_type) => {
                        warn!(
                            "packet from datagram capsule requires ICMP response: {:?}, sending ICMP Destination Unreachable",
                            icmp_type
                        );
                        if let Some(icmp_reply) =
                            build_icmp_response(&datagram_capsule.data[packet_start..], icmp_type)
                        {
                            self.forward_egress_packet(&icmp_reply)?;
                        }
                        return Ok(len);
                    }
                    ForwardingDecision::Forward => {
                        self.forward_ingress_packet(&datagram_capsule.data[packet_start..])
                            .await?;
                    }
                }
            }

            Capsule::AddressAssign(assign_capsule) => {
                debug!("received AddressAssign capsule: {:?}", assign_capsule);

                // Remove old addresses as they are no longer valid
                for addr in self.routing_state.local_addresses.iter() {
                    self.update_tun_interface(tun::TunConfiguration::RemoveAddress(*addr))
                        .await?;
                }

                self.routing_state.local_addresses.clear();

                // Add new addresses
                for assigned_address in assign_capsule.addresses {
                    if is_zero_address(&assigned_address.ip_net) {
                        warn!("received empty address from peer");
                        continue;
                    }
                    info!("received address from peer: {}", assigned_address.ip_net);

                    self.update_tun_interface(tun::TunConfiguration::AddAddress(
                        assigned_address.ip_net,
                    ))
                    .await?;
                    self.routing_state
                        .local_addresses
                        .push(assigned_address.ip_net);
                }

                // Removing addresses can have the effect that routes are removed aswell. Re-add all routes.
                for route in self
                    .routing_state
                    .remote_addresses
                    .iter()
                    .chain(self.routing_state.remote_routes.iter())
                {
                    self.update_tun_interface(tun::TunConfiguration::AddRoute(*route))
                        .await?;
                }
            }
            Capsule::AddressRequest(request_capsule) => {
                debug!("received AddressRequest capsule: {:?}", request_capsule);

                // Keep previous assigned addresses
                let mut assigned_addresses = self
                    .routing_state
                    .remote_addresses
                    .clone()
                    .into_iter()
                    .map(|ip_net| AssignedAddress {
                        request_id: 0,
                        ip_net,
                    })
                    .collect::<Vec<AssignedAddress>>();
                for requested_address in request_capsule.addresses {
                    let assigned_net = if is_zero_address(&requested_address.ip_net) {
                        get_next_avail_subnet(
                            self.available_addresses.clone(),
                            is_ipv4(&requested_address.ip_net),
                            requested_address.ip_net.prefix_len(),
                        )
                        .await
                    } else {
                        get_specific_subnet(
                            self.available_addresses.clone(),
                            requested_address.ip_net,
                        )
                        .await
                    };
                    if let Some(assigned_subnet) = assigned_net {
                        info!("assigning requested address to client: {}", assigned_subnet);
                        let assigned_address = AssignedAddress {
                            request_id: requested_address.request_id,
                            ip_net: assigned_subnet,
                        };
                        assigned_addresses.push(assigned_address);

                        self.update_tun_interface(tun::TunConfiguration::AddRoute(assigned_subnet))
                            .await?;
                        self.routing_state.remote_addresses.push(assigned_subnet);
                    } else {
                        let zero_ipnet = match requested_address.ip_net {
                            IpNet::V4(_) => IpNet::new_assert(ZERO_IPV4_ADDRESS, 32),
                            IpNet::V6(_) => IpNet::new_assert(ZERO_IPV6_ADDRESS, 128),
                        };
                        assigned_addresses.push(AssignedAddress {
                            request_id: requested_address.request_id,
                            ip_net: zero_ipnet,
                        });
                        warn!(
                            "requested address {} not available",
                            requested_address.ip_net
                        );
                    }
                }

                info!(
                    "sending AddressAssign capsule with addresses: {:?}",
                    assigned_addresses
                );
                let address_assign_capsule = AddressAssignCapsule {
                    addresses: assigned_addresses,
                };

                let capsule = Capsule::AddressAssign(address_assign_capsule);
                self.send_capsule(&capsule, true)?;
            }
            Capsule::RouteAdvertisement(route_capsule) => {
                debug!("received RouteAdvertisement capsule: {:?}", route_capsule);

                // TODO: add some validation here

                // remove old routes
                for route in self.routing_state.remote_routes.iter() {
                    self.update_tun_interface(tun::TunConfiguration::RemoveRoute(*route))
                        .await?;
                }
                self.routing_state.remote_routes.clear();

                // add new routes
                for route in route_capsule.routes {
                    info!("received route advertisement from peer: {}", route.ip_net);
                    self.update_tun_interface(tun::TunConfiguration::AddRoute(route.ip_net))
                        .await?;

                    self.routing_state.remote_routes.push(route.ip_net);
                }
            }
        }

        Ok(len)
    }

    pub async fn handle_initial_routing_setup(&mut self) -> Result<()> {
        // Assign a /128 IPv6 or /32 IPv4 address from the address pool to peer
        let mut assigned_addresses = vec![];
        if let Some(addr) = get_next_avail_subnet(self.available_addresses.clone(), false, 128)
            .await
            .or(get_next_avail_subnet(self.available_addresses.clone(), true, 32).await)
        {
            info!("assigning address to peer: {}", addr);
            self.routing_state.remote_addresses.push(addr);
            let assigned_address = AssignedAddress {
                request_id: 0,
                ip_net: addr,
            };
            assigned_addresses.push(assigned_address);

            let address_assign_capsule = AddressAssignCapsule {
                addresses: assigned_addresses,
            };
            let capsule = Capsule::AddressAssign(address_assign_capsule);
            self.send_capsule(&capsule, true)?;

            self.update_tun_interface(tun::TunConfiguration::AddRoute(addr))
                .await?;
        } else {
            error!("no available addresses to assign to peer");
        }

        // Advertise routes
        let mut routes = vec![];
        for route in &self.routing_state.local_routes {
            info!("advertising route to peer: {}", route);
            routes.push(RouteAdvertisement {
                ip_net: *route,
                proto: 0,
            });
        }
        let route_advertisement_capsule = RouteAdvertisementCapsule { routes };
        let capsule = Capsule::RouteAdvertisement(route_advertisement_capsule);
        self.send_capsule(&capsule, true)?;
        Ok(())
    }
}
