use std::sync::Arc;

use crate::{
    connect_ip::capsule::{
        CAPSULE_PROTOCOL_EMPTY_ADDRESS, RouteAdvertisement, RouteAdvertisementCapsule,
    },
    net::{get_next_avail_subnet, get_specific_subnet, tun},
};
use anyhow::{Result, anyhow};
use ipnet::IpNet;
use octets::Octets;
use tokio::sync::{Mutex, mpsc};
use tracing::{error, info, warn};

use crate::connect_ip::capsule::{AddressAssignCapsule, AssignedAddress, Capsule};

/// State for the capsule protocol.
pub struct CapsuleProtocolState {
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
    state: &mut CapsuleProtocolState,
    mut conn: &mut quiche::Connection,
    h3_conn: &mut Option<quiche::h3::Connection>,
    available_addresses: &Arc<Mutex<Vec<IpNet>>>,
    tx_address_updates: &mpsc::Sender<tun::AddressUpdate>,
) -> Result<usize> {
    if state.stream_id != Some(stream_id) {
        error!(
            "{} received capsule data on unknown stream id {}",
            conn.trace_id(),
            stream_id
        );
        return Err(anyhow!("unknown stream id"));
    }

    // parse capsule data here
    let mut octets = Octets::with_slice(data);
    let capsule = Capsule::parse(&mut octets)?;
    match capsule {
        Capsule::AddressAssign(assign_capsule) => {
            info!("received AddressAssign capsule: {:?}", assign_capsule);
            // Remove old addresses as they are no longer valid
            for addr in state.local_addresses.iter() {
                tx_address_updates
                    .send(tun::AddressUpdate::RemoveAddress(addr.clone()))
                    .await?;
            }
            state.local_addresses.clear();

            // Add new addresses
            for addr in assign_capsule.addresses {
                if addr.ip_net == CAPSULE_PROTOCOL_EMPTY_ADDRESS {
                    warn!("received empty address from peer");
                    continue;
                }
                tx_address_updates
                    .send(tun::AddressUpdate::AddAddress(addr.ip_net))
                    .await?;
                state.local_addresses.push(addr.ip_net);
            }

            // Removing addresses can have the effect that routes are removed aswell. Re-add all routes.
            for route in state
                .remote_addresses
                .iter()
                .chain(state.remote_routes.iter())
            {
                tx_address_updates
                    .send(tun::AddressUpdate::AddRoute(route.clone()))
                    .await?;
            }
        }
        Capsule::AddressRequest(request_capsule) => {
            info!("received AddressRequest capsule: {:?}", request_capsule);

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
            for addr in request_capsule.addresses {
                let assigned_net = if addr.ip_net == CAPSULE_PROTOCOL_EMPTY_ADDRESS {
                    get_next_avail_subnet(available_addresses, 32).await
                } else {
                    get_specific_subnet(available_addresses, addr.ip_net).await
                };
                if let Some(assigned_subnet) = assigned_net {
                    info!("assigning requested address to client: {}", assigned_subnet);
                    let assigned_address = AssignedAddress {
                        request_id: addr.request_id,
                        ip_net: assigned_subnet.clone(),
                    };
                    assigned_addresses.push(assigned_address);

                    tx_address_updates
                        .send(tun::AddressUpdate::AddRoute(assigned_subnet.clone()))
                        .await?;
                    state.remote_addresses.push(assigned_subnet);
                } else {
                    assigned_addresses.push(AssignedAddress {
                        request_id: addr.request_id,
                        ip_net: CAPSULE_PROTOCOL_EMPTY_ADDRESS,
                    });
                    warn!("requested address {} not available", addr.ip_net);
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
            let mut buf = vec![0u8; 1000];
            let mut octets_mut = octets::OctetsMut::with_slice(&mut buf);
            capsule.append(&mut octets_mut)?;
            let payload_len = octets_mut.off();
            h3_conn.as_mut().unwrap().send_body(
                &mut conn,
                stream_id,
                &buf[..payload_len],
                false,
            )?;
        }
        Capsule::RouteAdvertisement(route_capsule) => {
            info!("received RouteAdvertisement capsule: {:?}", route_capsule);
            // TODO: add some validation here

            // remove old routes
            for route in state.remote_routes.iter() {
                tx_address_updates
                    .send(tun::AddressUpdate::RemoveRoute(route.clone()))
                    .await?;
            }
            state.remote_routes.clear();

            // add new routes
            for route in route_capsule.routes {
                tx_address_updates
                    .send(tun::AddressUpdate::AddRoute(route.ip_net.clone()))
                    .await?;

                state.remote_routes.push(route.ip_net);
            }
        }
    }

    Ok(octets.off())
}

pub async fn prepare_address_and_route_assignment<'a>(
    state: &mut CapsuleProtocolState,
    mut available_addresses: Arc<Mutex<Vec<IpNet>>>,
    mut octets: &mut octets::OctetsMut<'a>,
) -> Result<Option<IpNet>> {
    let mut assigned_address = None;

    // Assign a /32 address from the address pool to peer
    let mut assigned_addresses = vec![];
    if let Some(addr) = get_next_avail_subnet(&mut available_addresses, 32).await {
        info!("assigning address to peer: {}", addr);
        assigned_address = Some(addr.clone());
        state.remote_addresses.push(addr.clone());
        let assigned_address = AssignedAddress {
            request_id: 0,
            ip_net: addr.clone(),
        };
        assigned_addresses.push(assigned_address);

        let address_assign_capsule = AddressAssignCapsule {
            addresses: assigned_addresses,
        };
        let capsule = Capsule::AddressAssign(address_assign_capsule);
        capsule.append(&mut octets)?;
    } else {
        error!("no available addresses to assign to peer");
    }

    // Advertise routes
    let mut routes = vec![];
    for route in &state.local_routes {
        info!("advertising route to peer: {}", route);
        routes.push(RouteAdvertisement {
            ip_net: route.clone(),
            proto: 0,
        });
    }
    let route_advertisement_capsule = RouteAdvertisementCapsule { routes: routes };
    let capsule = Capsule::RouteAdvertisement(route_advertisement_capsule);
    capsule.append(&mut octets)?;

    Ok(assigned_address)
}
