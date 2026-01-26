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
use tokio::sync::Mutex;
use tracing::{debug, error, info, trace, warn};

use crate::connect_ip::capsule::{
    AddressAssignCapsule, AssignedAddress, Capsule, CapsuleError, DatagramCapsule,
    RouteAdvertisement, RouteAdvertisementCapsule,
};
use crate::net::icmp::build_icmp_response;
use crate::net::quic::MAX_DATAGRAM_SIZE;
use crate::net::tun::MAX_TUN_MTU;
use crate::net::{
    ForwardingDecision, IpVersion, ZERO_IPV4_ADDRESS, ZERO_IPV6_ADDRESS, check_packet_src_dst,
    get_next_avail_subnet, get_specific_subnet, is_zero_address,
};

const SEND_BUFFER_SIZE: usize = 65535;
const RCV_BUFFER_SIZE: usize = 65535;
const MAX_TUN_MTU_FOR_DATAGRAMS: usize = MAX_DATAGRAM_SIZE - 50;

/// Routing configuration updates that should be applied to the system.
///
/// These updates are generated during capsule processing and represent changes
/// that need to be applied to the TUN device or system routing table.
pub enum RoutingUpdate {
    /// Add an IP address to the TUN interface
    AddAddress(IpNet),
    /// Remove an IP address from the TUN interface
    RemoveAddress(IpNet),
    /// Add a route to the system routing table
    AddRoute(IpNet),
    /// Remove a route from the system routing table
    RemoveRoute(IpNet),
    /// Set the MTU of the TUN interface
    SetMTU(u16),
}

/// Current routing state negotiated through the CONNECT-IP capsule protocol.
///
/// This structure tracks all addresses and routes that have been exchanged between
/// the local endpoint and the remote peer. It represents the agreed-upon routing
/// configuration for the tunnel.
#[derive(Clone, Debug)]
pub struct RoutingState {
    /// Maximum transmission unit for the tunnel in bytes
    pub mtu: u16,
    /// IP addresses assigned to the remote peer (by us)
    pub remote_addresses: Vec<IpNet>,
    /// IP addresses assigned to us (by the remote peer)
    pub local_addresses: Vec<IpNet>,
    /// Routes we advertise to the remote peer
    pub local_routes: Vec<IpNet>,
    /// Routes advertised to us by the remote peer
    pub remote_routes: Vec<IpNet>,
}

/// CONNECT-IP endpoint managing a tunnel.
///
/// This endpoint is designed to be transport-agnostic - it processes protocol logic
/// and manages internal state but doesn't perform I/O operations directly. Instead,
/// it queues data for the caller to send/receive through the actual transport layer
/// (QUIC connection, TUN interface, etc.).
///
/// The endpoint maintains separate queues for different types of data flow
/// and manages the capsule protocol state machine for address and route negotiation.
pub struct Endpoint {
    /// QUIC stream ID associated with this endpoint
    pub stream_id: u64,
    /// Current routing state negotiated with the peer
    pub routing_state: RoutingState,
    /// Pool of IP addresses available for assignment to peers
    available_addresses: Arc<Mutex<Vec<IpNet>>>,
    /// Optional pre-configured address to assign to the peer instead of dynamic allocation
    preconfigured_peer_address: Option<IpNet>,
    /// Queue of routing updates to be applied to the system
    routing_updates: VecDeque<RoutingUpdate>,
    /// Whether the peer supports QUIC datagrams
    peer_supports_datagrams: bool,
    /// Buffer for stream data received but not yet processed
    stream_data_received: VecDeque<u8>,
    /// Buffer for stream data to send, pending transmission
    stream_data_to_send: VecDeque<u8>,
    /// Queue of QUIC datagrams ready to send
    datagrams_to_send: VecDeque<Vec<u8>>,
    /// Queue of IP packets to forward via the TUN interface
    tun_packets_to_send: VecDeque<Vec<u8>>,
}

impl Endpoint {
    /// Creates a new endpoint for managing a CONNECT-IP tunnel.
    ///
    /// # Arguments
    /// * `stream_id` - The QUIC stream ID for this endpoint
    /// * `mtu` - Maximum transmission unit for the tunnel
    /// * `available_addresses` - Pool of addresses available for assignment to peers
    /// * `preconfigured_peer_address` - Optional pre-configured address to assign to the peer
    /// * `routes` - Local routes to advertise to the peer
    /// * `peer_supports_datagrams` - Whether the peer supports QUIC datagrams
    pub fn new(
        stream_id: u64,
        mtu: u16,
        available_addresses: Arc<Mutex<Vec<IpNet>>>,
        preconfigured_peer_address: Option<IpNet>,
        routes: Vec<IpNet>,
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
            preconfigured_peer_address,
            routing_updates: VecDeque::new(),
            peer_supports_datagrams,
            stream_data_received: VecDeque::with_capacity(RCV_BUFFER_SIZE),
            stream_data_to_send: VecDeque::with_capacity(SEND_BUFFER_SIZE),
            datagrams_to_send: VecDeque::new(),
            tun_packets_to_send: VecDeque::new(),
        }
    }

    /// Validates an ingress packet.
    ///
    /// Checks if the packet should be forwarded to the TUN interface, dropped,
    /// or if an ICMP error response should be sent. Validates packet size against
    /// MTU and checks source/destination addresses against negotiated addresses and routes.
    ///
    /// # Arguments
    /// * `packet` - The IP packet received (from the QUIC connection)
    ///
    /// # Returns
    /// A `ForwardingDecision` indicating how to handle the packet
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

        check_packet_src_dst(
            src,
            dst,
            &self.routing_state.remote_addresses,
            &self.routing_state.remote_routes,
            &self.routing_state.local_addresses,
            &self.routing_state.local_routes,
        )
    }

    /// Validates an egress packet.
    ///
    /// Checks if the packet should be forwarded over the QUIC connection, dropped,
    /// or if an ICMP error response should be sent. Validates packet size against
    /// MTU and checks source/destination addresses against negotiated addresses and routes.
    ///
    /// # Arguments
    /// * `packet` - The IP packet received (from the TUN interface)
    ///
    /// # Returns
    /// A `ForwardingDecision` indicating how to handle the packet
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

    /// Queues a packet to be forwarded locally.
    ///
    /// This method is called for packets received from the QUIC connection that
    /// should be forwarded to the local network.
    ///
    /// # Arguments
    /// * `packet` - The IP packet to forward (to the TUN interface)
    pub fn forward_ingress_packet(&mut self, packet: &[u8]) -> Result<()> {
        self.tun_packets_to_send.push_back(packet.to_vec());
        Ok(())
    }

    /// Queues a packet to be sent over the QUIC connection.
    ///
    /// Encapsulates the packet appropriately based on whether the peer supports
    /// QUIC datagrams. If datagrams are supported and the MTU allows, the packet
    /// is sent as a datagram. Otherwise, it's wrapped in a datagram capsule and
    /// sent over the stream.
    ///
    /// # Arguments
    /// * `packet` - The IP packet to forward over the QUIC connection
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

    /// Writes pending stream data into the provided buffer.
    ///
    /// Retrieves data from the send queue that should be transmitted on the QUIC stream.
    /// The data is removed from the queue after being copied to the output buffer.
    ///
    /// # Arguments
    /// * `out` - Buffer to write the stream data into
    /// * `len` - Maximum number of bytes to write
    ///
    /// # Returns
    /// The number of bytes actually written to the buffer
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

    /// Returns stream data to the front of the send queue.
    ///
    /// Used when data was retrieved for sending but couldn't be sent due to
    /// flow control or other issues. The data is added back to the front of
    /// the queue to preserve ordering.
    ///
    /// # Arguments
    /// * `data` - The data to return to the send queue
    pub fn return_stream_data(&mut self, data: &[u8]) {
        // Add data to the front of the send buffer
        for &byte in data.iter().rev() {
            self.stream_data_to_send.push_front(byte);
        }
    }

    /// Processes incoming data from the QUIC stream.
    ///
    /// Buffers the received data and attempts to parse and process complete capsules.
    /// Handles partial capsules by keeping incomplete data in the buffer for later
    /// processing when more data arrives.
    ///
    /// # Arguments
    /// * `data` - The data received from the QUIC stream
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

    /// Retrieves and removes the next routing update from the queue.
    ///
    /// This method should be called repeatedly after processing capsules to retrieve
    /// all pending routing updates that need to be applied to the system. Updates are
    /// returned in the order they were generated during capsule processing.
    ///
    /// The routing updates must be applied to the systems routing table (or TUN interface)
    /// for proper packet forwarding. Before applying updates, they should be validated
    /// against local policy and checked for conflicts with existing routes.
    ///
    /// # Returns
    /// - `Some(RoutingUpdate)` if there are pending updates in the queue
    /// - `None` if all updates have been processed
    pub fn next_routing_update(&mut self) -> Option<RoutingUpdate> {
        self.routing_updates.pop_front()
    }

    /// Retrieves the next packet to forward locally.
    /// Since we imagine this to be a TUN interface, the method is named accordingly.
    ///
    /// # Returns
    /// - `Some(Vec<u8>)` containing the next packet if available
    /// - `None` if no packets are queued
    pub fn send_tun_packet(&mut self) -> Option<Vec<u8>> {
        self.tun_packets_to_send.pop_front()
    }

    /// Retrieves the next datagram to send over the QUIC connection.
    ///
    /// # Returns
    /// - `Some(Vec<u8>)` containing the next datagram if available
    /// - `None` if no datagrams are queued
    pub fn send_datagram(&mut self) -> Option<Vec<u8>> {
        self.datagrams_to_send.pop_front()
    }

    /// Returns a datagram to the front of the send queue.
    ///
    /// Used when a datagram was retrieved for sending but couldn't be sent due to
    /// flow control or other issues. The datagram is added back to the front of
    /// the queue to preserve ordering.
    ///
    /// # Arguments
    /// * `data` - The datagram to return to the send queue
    pub fn return_datagram(&mut self, data: &[u8]) {
        self.datagrams_to_send.push_front(data.to_vec());
    }

    /// Processes an incoming QUIC datagram.
    ///
    /// Parses the datagram format (stream ID, context ID, and IP packet),
    /// validates the packet, and queues it for forwarding to the TUN interface
    /// if valid. May generate ICMP error responses for invalid packets.
    ///
    /// # Arguments
    /// * `data` - The datagram data received from the QUIC connection
    pub fn recv_datagram(&mut self, data: &[u8]) -> Result<()> {
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
                self.forward_ingress_packet(ip_packet)?;
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

    /// Serializes and queues a capsule for transmission on the QUIC stream.
    ///
    /// # Arguments
    /// * `capsule` - The capsule to send
    /// * `must_succeed` - If true, the capsule is always queued even if the send buffer
    ///   is full. If false, the capsule may be dropped if the buffer is full.
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

    /// Parses and processes a single capsule from the receive buffer.
    ///
    /// Handles different capsule types including address assignments, address requests,
    /// route advertisements, and datagrams. Updates routing state and generates routing
    /// updates as appropriate.
    ///
    /// # Arguments
    /// * `start` - Offset in the receive buffer where capsule parsing should begin
    ///
    /// # Returns
    /// The number of bytes consumed from the buffer
    async fn process_capsule_data(&mut self, start: usize) -> Result<usize> {
        self.stream_data_received.make_contiguous();
        let mut octets = Octets::with_slice(&self.stream_data_received.as_slices().0[start..]);
        let capsule = Capsule::parse(&mut octets)?;
        let len = octets.off();
        match capsule {
            Capsule::Datagram(datagram_capsule) => {
                // Handle the datagram data as needed
                trace!(
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
                        self.forward_ingress_packet(&datagram_capsule.data[packet_start..])?;
                    }
                }
            }

            Capsule::AddressAssign(assign_capsule) => {
                trace!("received AddressAssign capsule: {:?}", assign_capsule);

                let addresses_no_longer_valid = self
                    .routing_state
                    .local_addresses
                    .iter()
                    .filter(|addr| !assign_capsule.addresses.iter().any(|a| &a.ip_net == *addr))
                    .cloned()
                    .collect::<Vec<IpNet>>();

                // Remove old addresses that are no longer valid
                for addr in addresses_no_longer_valid.iter() {
                    self.routing_updates
                        .push_back(RoutingUpdate::RemoveAddress(*addr));
                }

                self.routing_state.local_addresses.clear();

                // Add new addresses
                for assigned_address in assign_capsule.addresses {
                    if is_zero_address(&assigned_address.ip_net) {
                        warn!("received empty address from peer");
                        continue;
                    }
                    info!("received address from peer: {}", assigned_address.ip_net);

                    self.routing_updates
                        .push_back(RoutingUpdate::AddAddress(assigned_address.ip_net));
                    self.routing_state
                        .local_addresses
                        .push(assigned_address.ip_net);
                }

                if !addresses_no_longer_valid.is_empty() {
                    // Removing addresses can have the effect that routes are removed aswell. Re-add all routes.
                    // TODO: this could be moved to the caller since it is specific to system routing table management
                    for route in self
                        .routing_state
                        .remote_addresses
                        .iter()
                        .chain(self.routing_state.remote_routes.iter())
                    {
                        self.routing_updates
                            .push_back(RoutingUpdate::AddRoute(*route));
                    }
                }
            }
            Capsule::AddressRequest(request_capsule) => {
                trace!("received AddressRequest capsule: {:?}", request_capsule);

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
                            IpVersion::from(&requested_address.ip_net),
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

                        self.routing_updates
                            .push_back(RoutingUpdate::AddRoute(assigned_subnet));
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
                trace!("received RouteAdvertisement capsule: {:?}", route_capsule);

                // remove old routes
                for route in self.routing_state.remote_routes.iter() {
                    self.routing_updates
                        .push_back(RoutingUpdate::RemoveRoute(*route));
                }
                self.routing_state.remote_routes.clear();

                // add new routes
                for route in route_capsule.routes {
                    info!("received route advertisement from peer: {}", route.ip_net);
                    self.routing_updates
                        .push_back(RoutingUpdate::AddRoute(route.ip_net));

                    self.routing_state.remote_routes.push(route.ip_net);
                }
            }
        }

        Ok(len)
    }

    /// Performs initial routing setup when establishing a new connection.
    ///
    /// Assigns an address to the peer (either from the preconfigured address or from
    /// the address pool) and advertises local routes. This should be called once when
    /// a new CONNECT-IP tunnel is established. Can be omitted if address assignment
    /// and route advertisement capsules are exchanged through other means.
    pub async fn handle_initial_routing_setup(&mut self) -> Result<()> {
        // Assign a /128 IPv6 or /32 IPv4 address from the address pool to peer
        let mut assigned_addresses = vec![];
        let addr = if let Some(addr) = self.preconfigured_peer_address {
            Some(addr)
        } else {
            let ipv6_addr =
                get_next_avail_subnet(self.available_addresses.clone(), IpVersion::V6, 128).await;
            if ipv6_addr.is_some() {
                ipv6_addr
            } else {
                get_next_avail_subnet(self.available_addresses.clone(), IpVersion::V4, 32).await
            }
        };

        if let Some(addr) = addr {
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

            self.routing_updates
                .push_back(RoutingUpdate::AddRoute(addr));
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
