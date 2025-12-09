use std::sync::Arc;

use anyhow::Result;
use ipnet::IpNet;
use octets::Octets;
use tokio::sync::Mutex;
use tracing::{debug, error, info, trace, warn};

use crate::connect_ip::capsule::{
    AddressAssignCapsule, AssignedAddress, Capsule, RouteAdvertisement, RouteAdvertisementCapsule,
};
use crate::net::icmp::build_icmp_error;
use crate::net::{
    ZERO_IPV4_ADDRESS, ZERO_IPV6_ADDRESS, get_next_avail_subnet, get_specific_subnet, is_ipv4,
    is_zero_address, tun,
};

pub trait ConnectIPEndpoint {
    fn check_ingress_packet(&mut self, packet: &[u8]) -> bool;
    fn check_egress_packet(&mut self, packet: &[u8]) -> bool;
    fn forward_ingress_packet(
        &mut self,
        packet: &[u8],
    ) -> impl std::future::Future<Output = Result<()>> + Send;
    fn forward_egress_packet(&mut self, packet: &[u8]) -> Result<()>;
    fn update_tun_interface(
        &self,
        update: tun::TunConfiguration,
    ) -> impl std::future::Future<Output = Result<()>> + Send;
    fn send_capsule(
        &mut self,
        capsule: Capsule,
    ) -> impl std::future::Future<Output = Result<()>> + Send;
    fn get_routing_state(&self) -> RoutingState;
    fn set_routing_state(&mut self, state: RoutingState);
}

/// Addresses and routes negotiated through capsule protocol.
#[derive(Clone, Debug)]
pub struct RoutingState {
    pub stream_id: Option<u64>,
    /// addresses we assign to the peer
    pub remote_addresses: Vec<IpNet>,
    /// addresses the peer assigns to us
    pub local_addresses: Vec<IpNet>,
    /// routes we advertise to the peer
    pub local_routes: Vec<IpNet>,
    /// routes the peer advertises to us
    pub remote_routes: Vec<IpNet>,
}

/// Handles incoming capsule data.
pub async fn handle_capsule_data<T: ConnectIPEndpoint>(
    data: &[u8],
    available_addresses: &Arc<Mutex<Vec<IpNet>>>,
    connect_ip_endpoint: &mut T,
    mtu: u16,
) -> Result<usize> {
    // parse capsule data here
    let mut octets = Octets::with_slice(data);
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

            if datagram_capsule.data.len() - packet_start > mtu as usize {
                warn!(
                    "received IP packet larger than MTU ({} > {}), sending ICMP Packet Too Big",
                    datagram_capsule.data.len() - packet_start,
                    mtu
                );

                if let Some(icmp_reply) =
                    build_icmp_error(&datagram_capsule.data[packet_start..], mtu as u32)
                {
                    connect_ip_endpoint.forward_egress_packet(&icmp_reply)?;
                }

                return Ok(len);
            }

            if !connect_ip_endpoint.check_ingress_packet(&datagram_capsule.data[packet_start..]) {
                // TODO: send ICMP error back to peer
                debug!("dropping packet from peer due to ingress filter");
                return Ok(len);
            }
            connect_ip_endpoint
                .forward_ingress_packet(&datagram_capsule.data[packet_start..])
                .await?;
        }

        Capsule::AddressAssign(assign_capsule) => {
            debug!("received AddressAssign capsule: {:?}", assign_capsule);

            let mut state = connect_ip_endpoint.get_routing_state();

            // Remove old addresses as they are no longer valid
            for addr in state.local_addresses.iter() {
                connect_ip_endpoint
                    .update_tun_interface(tun::TunConfiguration::RemoveAddress(*addr))
                    .await?;
            }

            state.local_addresses.clear();

            // Add new addresses
            for assigned_address in assign_capsule.addresses {
                if is_zero_address(&assigned_address.ip_net) {
                    warn!("received empty address from peer");
                    continue;
                }
                info!("received address from peer: {}", assigned_address.ip_net);

                connect_ip_endpoint
                    .update_tun_interface(tun::TunConfiguration::AddAddress(
                        assigned_address.ip_net,
                    ))
                    .await?;
                state.local_addresses.push(assigned_address.ip_net);
            }

            // Removing addresses can have the effect that routes are removed aswell. Re-add all routes.
            for route in state
                .remote_addresses
                .iter()
                .chain(state.remote_routes.iter())
            {
                connect_ip_endpoint
                    .update_tun_interface(tun::TunConfiguration::AddRoute(*route))
                    .await?;
            }
            connect_ip_endpoint.set_routing_state(state);
        }
        Capsule::AddressRequest(request_capsule) => {
            debug!("received AddressRequest capsule: {:?}", request_capsule);

            let mut state = connect_ip_endpoint.get_routing_state();

            // Keep previous assigned addresses
            let mut assigned_addresses = state
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
                        available_addresses,
                        is_ipv4(&requested_address.ip_net),
                        requested_address.ip_net.prefix_len(),
                    )
                    .await
                } else {
                    get_specific_subnet(available_addresses, requested_address.ip_net).await
                };
                if let Some(assigned_subnet) = assigned_net {
                    info!("assigning requested address to client: {}", assigned_subnet);
                    let assigned_address = AssignedAddress {
                        request_id: requested_address.request_id,
                        ip_net: assigned_subnet,
                    };
                    assigned_addresses.push(assigned_address);

                    connect_ip_endpoint
                        .update_tun_interface(tun::TunConfiguration::AddRoute(assigned_subnet))
                        .await?;
                    state.remote_addresses.push(assigned_subnet);
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
            connect_ip_endpoint.send_capsule(capsule).await?;
            connect_ip_endpoint.set_routing_state(state);
        }
        Capsule::RouteAdvertisement(route_capsule) => {
            debug!("received RouteAdvertisement capsule: {:?}", route_capsule);

            let mut state = connect_ip_endpoint.get_routing_state();

            // TODO: add some validation here

            // remove old routes
            for route in state.remote_routes.iter() {
                connect_ip_endpoint
                    .update_tun_interface(tun::TunConfiguration::RemoveRoute(*route))
                    .await?;
            }
            state.remote_routes.clear();

            // add new routes
            for route in route_capsule.routes {
                info!("received route advertisement from peer: {}", route.ip_net);
                connect_ip_endpoint
                    .update_tun_interface(tun::TunConfiguration::AddRoute(route.ip_net))
                    .await?;

                state.remote_routes.push(route.ip_net);
            }
            connect_ip_endpoint.set_routing_state(state);
        }
    }

    Ok(len)
}

pub async fn prepare_address_and_route_assignment<'a>(
    state: &mut RoutingState,
    available_addresses: Arc<Mutex<Vec<IpNet>>>,
    octets: &mut octets::OctetsMut<'a>,
) -> Result<Option<IpNet>> {
    let mut assigned_address = None;

    // Assign a /128 IPv6 or /32 IPv4 address from the address pool to peer
    let mut assigned_addresses = vec![];
    if let Some(addr) = get_next_avail_subnet(&available_addresses, false, 128)
        .await
        .or(get_next_avail_subnet(&available_addresses, true, 32).await)
    {
        info!("assigning address to peer: {}", addr);
        assigned_address = Some(addr);
        state.remote_addresses.push(addr);
        let assigned_address = AssignedAddress {
            request_id: 0,
            ip_net: addr,
        };
        assigned_addresses.push(assigned_address);

        let address_assign_capsule = AddressAssignCapsule {
            addresses: assigned_addresses,
        };
        let capsule = Capsule::AddressAssign(address_assign_capsule);
        capsule.append(octets)?;
    } else {
        error!("no available addresses to assign to peer");
    }

    // Advertise routes
    let mut routes = vec![];
    for route in &state.local_routes {
        info!("advertising route to peer: {}", route);
        routes.push(RouteAdvertisement {
            ip_net: *route,
            proto: 0,
        });
    }
    let route_advertisement_capsule = RouteAdvertisementCapsule { routes };
    let capsule = Capsule::RouteAdvertisement(route_advertisement_capsule);
    capsule.append(octets)?;
    Ok(assigned_address)
}
