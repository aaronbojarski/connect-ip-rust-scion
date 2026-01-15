use std::net::IpAddr;

use anyhow::{Context, Result};
use tokio::sync::mpsc::{Permit, Receiver, Sender};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, warn};
use tun_rs::DeviceBuilder;

use crate::connect_ip::RoutingUpdates;
use crate::net::route::{add_route, remove_route};

pub const MAX_TUN_MTU: usize = 9000;

/// A TUN device handler that manages a network (tun) interface.
///
/// Creates and manages a TUN device, forwarding packets between the device
/// and QUIC connections via channels. Supports dynamic address and route
/// configuration through a control channel.
pub struct Tun {
    /// Name of the TUN interface (e.g., "tun0")
    pub name: String,
    pub mtu: u16,
    pub tx_tun_to_quic: Sender<Vec<u8>>,
    pub rx_quic_to_tun: Receiver<Vec<u8>>,
    pub rx_address_updates: Receiver<RoutingUpdates>,
    pub cancel_token: CancellationToken,
}

impl Tun {
    pub fn new(
        name: &str,
        mtu: u16,
        tx_tun_to_quic: Sender<Vec<u8>>,
        rx_quic_to_tun: Receiver<Vec<u8>>,
        rx_address_updates: Receiver<RoutingUpdates>,
        cancel_token: CancellationToken,
    ) -> Result<Self> {
        Ok(Tun {
            name: name.to_string(),
            mtu,
            tx_tun_to_quic,
            rx_quic_to_tun: rx_quic_to_tun,
            rx_address_updates,
            cancel_token,
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

                // Handle address updates
                Some(update) = self.rx_address_updates.recv() => {
                    match update {
                        RoutingUpdates::AddAddress(ipnet) => {
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
                        RoutingUpdates::RemoveAddress(ipnet) => {
                            dev.remove_address(ipnet.addr())?;
                            debug!("Removed address {} from TUN device {}", ipnet, self.name);
                        }
                        RoutingUpdates::AddRoute(ipnet) => {
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
                        RoutingUpdates::RemoveRoute(ipnet) => {
                            if let Err(e) = remove_route(&ipnet, &self.name) {
                                error!("Failed to remove route {}: {}", ipnet, e);
                            } else {
                                debug!("Removed route {} via TUN device {}", ipnet, self.name);
                            }
                        }
                        RoutingUpdates::SetMTU(mtu) => {
                            if let Err(e) = dev.set_mtu(mtu) {
                                error!("Failed to set MTU {} on TUN device {}: {}", mtu, self.name, e);
                            } else {
                                debug!("Set MTU {} on TUN device {}", mtu, self.name);
                            }
                        }
                    }
                }

                // Read from TUN device and send to main task
                // Reserve channel space first, then read - this blocks reading when channel is full
                // while allowing other select branches to continue
                result = async {
                    let permit = self.tx_tun_to_quic.reserve().await
                        .context("channel closed")?;
                    dev.readable().await?;
                    Ok::<Permit<'_, Vec<u8>>, anyhow::Error>(permit)
                } => {
                    match result {
                        Ok(permit) => {
                            match dev.try_recv(&mut buf) {
                                Ok(n) => {
                                    let packet = buf[..n].to_vec();
                                    permit.send(packet);
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
                        Err(e) => {
                            warn!("TUN device {} channel closed: {}, shutting down", self.name, e);
                            break;
                        }
                    }
                },

                // Receive from main task and write to TUN device
                Some(packet) = self.rx_quic_to_tun.recv() => {
                    dev.send(&packet).await.context("failed to send packet to TUN device")?;
                }

                // Channel closed
                else => {
                    warn!("TUN device {} channel closed", self.name);
                    break;
                }
            }
        }

        debug!("TUN device {} shutting down cleanly", self.name);
        Ok(())
    }
}
