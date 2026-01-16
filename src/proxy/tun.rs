use std::net::IpAddr;

use anyhow::{Context, Result};
use ipnet::IpNet;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, warn};
use tun_rs::DeviceBuilder;

use crate::connect_ip::RoutingUpdates;
use crate::net::route::{add_route, remove_route};

pub const MAX_TUN_MTU: usize = 9000;

pub enum TunClientRegistration {
    Add(quiche::ConnectionId<'static>, Sender<Vec<u8>>),
    Remove(quiche::ConnectionId<'static>),
}

/// A TUN device handler that manages a network (tun) interface.
///
/// Creates and manages a TUN device, forwarding packets between the device
/// and QUIC connections via channels. Supports dynamic address and route
/// configuration through a control channel.
pub struct Tun {
    pub name: String,
    pub mtu: u16,
    pub rx_quic_to_tun: Receiver<Vec<u8>>,
    pub rx_tun_registration: Receiver<TunClientRegistration>,
    pub rx_address_updates: Receiver<(
        quiche::ConnectionId<'static>,
        Option<String>,
        RoutingUpdates,
    )>,
    pub cancel_token: CancellationToken,
    pub registered_connections:
        std::collections::HashMap<quiche::ConnectionId<'static>, Sender<Vec<u8>>>,
    pub routes: std::collections::HashMap<IpNet, (quiche::ConnectionId<'static>, Option<String>)>,
}

impl Tun {
    pub fn new(
        name: &str,
        mtu: u16,
        rx_quic_to_tun: Receiver<Vec<u8>>,
        rx_tun_registration: Receiver<TunClientRegistration>,
        rx_address_updates: Receiver<(
            quiche::ConnectionId<'static>,
            Option<String>,
            RoutingUpdates,
        )>,
        cancel_token: CancellationToken,
    ) -> Result<Self> {
        Ok(Tun {
            name: name.to_string(),
            mtu,
            rx_quic_to_tun,
            rx_tun_registration,
            rx_address_updates,
            cancel_token,
            registered_connections: std::collections::HashMap::new(),
            routes: std::collections::HashMap::new(),
        })
    }

    pub async fn start(&mut self) -> Result<()> {
        let dev = DeviceBuilder::new()
            .name(self.name.clone())
            .mtu(self.mtu)
            .build_async()?;

        debug!("TUN device handler task started");
        let mut buf = vec![0; MAX_TUN_MTU];
        loop {
            tokio::select! {
                // Check for cancellation signal
                _ = self.cancel_token.cancelled() => {
                    debug!("TUN device {} received shutdown signal", self.name);
                    break;
                }

                // Handle TUN client registrations
                Some(registration) = self.rx_tun_registration.recv() => {
                    match registration {
                        TunClientRegistration::Add(conn_id, tx) => {
                            debug!("Registered TUN client for connection ID {:?}", conn_id);
                            // Store the sender in a map if needed
                            self.registered_connections.insert(conn_id, tx);
                        }
                        TunClientRegistration::Remove(conn_id) => {
                            debug!("Unregistered TUN client for connection ID {:?}", conn_id);
                            // Remove the sender from the map if needed
                            self.registered_connections.remove(&conn_id);
                        }
                    }
                }

                // Handle address updates
                Some(update) = self.rx_address_updates.recv() => {
                    let (conn_id, client, routing_update) = update;
                    match routing_update {
                        RoutingUpdates::AddAddress(ipnet) => {
                            let res = self.routes.get(&ipnet);
                            if let Some((existing_conn_id, _)) = res {
                                // registered clients are allowed to override existing routes
                                if client.is_none() {
                                    warn!("Address {} already assigned to connection ID {:?}, skipping", ipnet, existing_conn_id);
                                    continue;
                                }
                            } else {
                                match ipnet.addr() {
                                    IpAddr::V4(address) => {
                                        dev.add_address_v4(address, ipnet.prefix_len())?;
                                    }
                                    IpAddr::V6(address) => {
                                        dev.add_address_v6(address, ipnet.prefix_len())?;
                                    }
                                }
                                debug!("Added address {} to TUN device {}", ipnet, self.name);
                            }
                            debug!("Assigned address {} to connection ID {:?} client {:?}", ipnet, conn_id, client);
                            self.routes.insert(ipnet, (conn_id, client));
                        }
                        RoutingUpdates::RemoveAddress(ipnet) => {
                            let res = self.routes.get(&ipnet);
                            if let Some((existing_conn_id, _)) = res {
                                if *existing_conn_id != conn_id {
                                    warn!("Address {} assigned to different connection ID {:?}, cannot remove for connection ID {:?}", ipnet, existing_conn_id, conn_id);
                                    continue;
                                }
                                dev.remove_address(ipnet.addr())?;
                                self.routes.remove(&ipnet);
                                debug!("Removed address {} from TUN device {}", ipnet, self.name);
                            } else {
                                warn!("Address {} not found in TUN device {}, skipping removal", ipnet, self.name);
                                continue;
                            }
                        }
                        RoutingUpdates::AddRoute(ipnet) => {
                            let res = self.routes.get(&ipnet);
                            if let Some((existing_conn_id, _)) = res {
                                // registered clients are allowed to override existing routes
                                if client.is_none() {
                                    warn!("Route {} already assigned to connection ID {:?}, skipping", ipnet, existing_conn_id);
                                    continue;
                                }
                            } else {
                                match add_route(&ipnet, &self.name) {
                                    Ok(true) => {
                                        debug!("Added route {} via TUN device {}", ipnet, self.name);
                                    }
                                    Ok(false) => {
                                        debug!("Route {} already exists, not adding again", ipnet);
                                    }
                                    Err(e) => {
                                        error!("Failed to add route {}: {}", ipnet, e);
                                    }
                                }
                            }
                            debug!("Assigned route {} to connection ID {:?} client {:?}", ipnet, conn_id, client);
                            self.routes.insert(ipnet, (conn_id, client));
                        }
                        RoutingUpdates::RemoveRoute(ipnet) => {
                            let res = self.routes.get(&ipnet);
                            if let Some((existing_conn_id, _)) = res {
                                if *existing_conn_id != conn_id {
                                    warn!("Route {} assigned to different connection ID {:?}, cannot remove for connection ID {:?}", ipnet, existing_conn_id, conn_id);
                                    continue;
                                }
                                if let Err(e) = remove_route(&ipnet, &self.name) {
                                    error!("Failed to remove route {}: {}", ipnet, e);
                                } else {
                                    debug!("Removed route {} via TUN device {}", ipnet, self.name);
                                }
                                self.routes.remove(&ipnet);
                                debug!("Removed route {} from TUN device {}", ipnet, self.name);
                            } else {
                                warn!("Route {} not found in TUN device {}, skipping removal", ipnet, self.name);
                                continue;
                            }
                        }
                        RoutingUpdates::SetMTU(_) => {
                            // Not supported on proxy side. The initial MTU is set during TUN device creation.
                            warn!("SetMTU operation is not supported on proxy TUN device {}", self.name);
                        }
                    }
                }

                // Receive from main task and write to TUN device
                Some(packet) = self.rx_quic_to_tun.recv() => {
                    dev.send(&packet).await.context("failed to send packet to TUN device")?;
                }

                // Read from TUN device and forward to registered connections
                _ = dev.readable() => {
                    match dev.try_recv(&mut buf) {
                        Ok(n) => {
                            let packet = buf[..n].to_vec();
                            if let Some(ipv4) = Ipv4Packet::new(&packet)
                                && ipv4.get_version() == 4
                            {
                                for prefix_len in (0..=32).rev() {
                                    let ipnet = IpNet::new(
                                        IpAddr::V4(ipv4.get_destination()),
                                        32 - prefix_len,
                                    )
                                    .unwrap().trunc();
                                    if let Some((conn_id, _)) = self.routes.get(&ipnet)
                                        && let Some(tx) = self.registered_connections.get(conn_id) {
                                        if let Err(e) = tx.try_send(packet) {
                                            warn!("Failed to forward packet to connection ID {:?}: {}", conn_id, e);
                                        }
                                        break;
                                    }
                                }
                            } else if let Some(ipv6) = Ipv6Packet::new(&packet) {
                                for prefix_len in (0..=128).rev() {
                                    let ipnet = IpNet::new(
                                        IpAddr::V6(ipv6.get_destination()),
                                        128 - prefix_len,
                                    )
                                    .unwrap().trunc();
                                    if let Some((conn_id, _)) = self.routes.get(&ipnet)
                                        && let Some(tx) = self.registered_connections.get(conn_id) {
                                        if let Err(e) = tx.try_send(packet) {
                                            warn!("Failed to forward packet to connection ID {:?}: {}", conn_id, e);
                                        }
                                        break;
                                    }
                                }
                            } else {
                                error!("received non-IP packet in datagram, dropping");
                                continue;
                            };
                        },
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            // This should not happen as we awaited readability. However, apparently those false positives are possible.
                            continue;
                        }
                        Err(e) => {
                            warn!("TUN device {} read error: {}, shutting down", self.name, e);
                            break;
                        }
                    }
                }
            }
        }

        debug!("TUN device {} shutting down cleanly", self.name);
        Ok(())
    }
}
