use anyhow::{Result, anyhow};
use ipnet::IpNet;
use octets::Octets;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::{Mutex, mpsc};
use tracing::{debug, error, info, trace, warn};

use crate::connect_ip::capsule::{
    AddressAssignCapsule, AssignedAddress, Capsule, RouteAdvertisement, RouteAdvertisementCapsule,
};
use crate::net::{
    ZERO_IPV4_ADDRESS, ZERO_IPV6_ADDRESS, check_packet_src_dst, get_next_avail_subnet,
    get_specific_subnet, is_ipv4, is_zero_address, tun,
};

/// Addresses and routes negotiated through capsule protocol.
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
pub async fn handle_capsule_data(
    stream_id: u64,
    data: &[u8],
    state: &mut RoutingState,
    available_addresses: &Arc<Mutex<Vec<IpNet>>>,
    tx_address_updates: &mpsc::Sender<tun::AddressUpdate>,
    tx_quic_to_tun: &mpsc::Sender<Vec<u8>>,
    send_stream_buffer: &mut Vec<u8>,
) -> Result<usize> {
    if state.stream_id != Some(stream_id) {
        warn!("received capsule data on unknown stream id {}", stream_id);
        return Err(anyhow!("unknown stream id"));
    }

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

            let (src, dst) = if let Some(ipv4) =
                Ipv4Packet::new(&datagram_capsule.data[packet_start..])
                && ipv4.get_version() == 4
            {
                (
                    IpAddr::V4(ipv4.get_source()),
                    IpAddr::V4(ipv4.get_destination()),
                )
            } else if let Some(ipv6) = Ipv6Packet::new(&datagram_capsule.data[packet_start..]) {
                (
                    IpAddr::V6(ipv6.get_source()),
                    IpAddr::V6(ipv6.get_destination()),
                )
            } else {
                error!("received non-IP packet in datagram, dropping");
                return Ok(len);
            };

            debug!(
                "received IP packet from QUIC connection: {} -> {}, {} bytes",
                src,
                dst,
                datagram_capsule.data.len() - packet_start
            );

            if check_packet_src_dst(
                src,
                dst,
                &state.remote_addresses,
                &state.remote_routes,
                &state.local_addresses,
                &state.local_routes,
            ) {
                tx_quic_to_tun
                    .send(datagram_capsule.data[packet_start..].to_vec())
                    .await?;
            } else {
                debug!(
                    "dropping packet from peer with invalid src/dst: {} -> {}",
                    src, dst
                );
            }
        }

        Capsule::AddressAssign(assign_capsule) => {
            debug!("received AddressAssign capsule: {:?}", assign_capsule);
            // Remove old addresses as they are no longer valid
            for addr in state.local_addresses.iter() {
                tx_address_updates
                    .send(tun::AddressUpdate::RemoveAddress(*addr))
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
                tx_address_updates
                    .send(tun::AddressUpdate::AddAddress(assigned_address.ip_net))
                    .await?;
                state.local_addresses.push(assigned_address.ip_net);
            }

            // Removing addresses can have the effect that routes are removed aswell. Re-add all routes.
            for route in state
                .remote_addresses
                .iter()
                .chain(state.remote_routes.iter())
            {
                tx_address_updates
                    .send(tun::AddressUpdate::AddRoute(*route))
                    .await?;
            }
        }
        Capsule::AddressRequest(request_capsule) => {
            debug!("received AddressRequest capsule: {:?}", request_capsule);

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

                    tx_address_updates
                        .send(tun::AddressUpdate::AddRoute(assigned_subnet))
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

            let mut buf = vec![0u8; address_assign_capsule.len() + 16];
            let mut octets_mut = octets::OctetsMut::with_slice(&mut buf);

            let capsule = Capsule::AddressAssign(address_assign_capsule);
            capsule.append(&mut octets_mut)?;
            let payload_len = octets_mut.off();
            send_stream_buffer.extend_from_slice(&buf[..payload_len]);
        }
        Capsule::RouteAdvertisement(route_capsule) => {
            debug!("received RouteAdvertisement capsule: {:?}", route_capsule);
            // TODO: add some validation here

            // remove old routes
            for route in state.remote_routes.iter() {
                tx_address_updates
                    .send(tun::AddressUpdate::RemoveRoute(*route))
                    .await?;
            }
            state.remote_routes.clear();

            // add new routes
            for route in route_capsule.routes {
                info!("received route advertisement from peer: {}", route.ip_net);
                tx_address_updates
                    .send(tun::AddressUpdate::AddRoute(route.ip_net))
                    .await?;

                state.remote_routes.push(route.ip_net);
            }
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
