use std::net::IpAddr;

use anyhow::{Context, Result};
use ipnet::IpNet;
use tokio::sync::mpsc::{Permit, Receiver, Sender};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, info_span, warn};
use tracing_futures::Instrument as _;
use tun_rs::DeviceBuilder;

use crate::net::route::{add_route, remove_route};

pub const MAX_TUN_MTU: usize = 9000;

/// Configuration commands for the TUN device.
pub enum TunConfiguration {
    AddAddress(IpNet),
    RemoveAddress(IpNet),
    AddRoute(IpNet),
    RemoveRoute(IpNet),
    SetMTU(u16),
}

/// A TUN device handler that manages a network (tun) interface.
///
/// Creates and manages a TUN device, forwarding packets between the device
/// and QUIC connections via channels. Supports dynamic address and route
/// configuration through a control channel.
pub struct Tun {
    /// Name of the TUN interface (e.g., "tun0")
    pub name: String,
    /// Channel for sending packets from TUN device to QUIC
    pub tx_tun_to_quic: Sender<Vec<u8>>,
    pub handle: Option<JoinHandle<()>>,
    pub mtu: u16,
}

impl Tun {
    pub fn new(name: &str, tx_tun_to_quic: Sender<Vec<u8>>, mtu: u16) -> Result<Self> {
        Ok(Tun {
            name: name.to_string(),
            tx_tun_to_quic,
            handle: None,
            mtu,
        })
    }

    pub async fn start(
        &mut self,
        mut rx_in_tun: Receiver<Vec<u8>>,
        mut rx_address_updates: Receiver<TunConfiguration>,
        cancel_token: CancellationToken,
    ) -> Result<()> {
        let dev = DeviceBuilder::new()
            .name(self.name.clone())
            .mtu(self.mtu)
            .build_async()?;

        let name = self.name.clone();
        let tx_tun_to_quic = self.tx_tun_to_quic.clone();

        let handle = tokio::spawn(
            async move {
                let result: Result<()> = async {
                    debug!("TUN device handler task started");
                    let mut buf = vec![0; MAX_TUN_MTU];
                    loop {
                        tokio::select! {
                            // Check for cancellation signal
                            _ = cancel_token.cancelled() => {
                                debug!("TUN device {} received shutdown signal", name);
                                break;
                            }

                            // Handle address updates
                            Some(update) = rx_address_updates.recv() => {
                                match update {
                                    TunConfiguration::AddAddress(ipnet) => {
                                        match ipnet.addr() {
                                            IpAddr::V4(address) => {
                                                dev.add_address_v4(address, ipnet.prefix_len())?;
                                            }
                                            IpAddr::V6(address) => {
                                                dev.add_address_v6(address, ipnet.prefix_len())?;
                                            }
                                        }
                                        debug!("Added address {} to TUN device {}", ipnet, name);
                                    }
                                    TunConfiguration::RemoveAddress(ipnet) => {
                                        dev.remove_address(ipnet.addr())?;
                                        debug!("Removed address {} from TUN device {}", ipnet, name);
                                    }
                                    TunConfiguration::AddRoute(ipnet) => {
                                        match add_route(&ipnet, &name) {
                                            Ok(true) => {
                                                debug!("Added route {} via TUN device {}", ipnet, name);
                                            }
                                            Ok(false) => {
                                                debug!("Route {} already exists, not adding again", ipnet);
                                            }
                                            Err(e) => {
                                                error!("Failed to add route {}: {}", ipnet, e);
                                            }
                                        }
                                    }
                                    TunConfiguration::RemoveRoute(ipnet) => {
                                        if let Err(e) = remove_route(&ipnet, &name) {
                                            error!("Failed to remove route {}: {}", ipnet, e);
                                        } else {
                                            debug!("Removed route {} via TUN device {}", ipnet, name);
                                        }
                                    }
                                    TunConfiguration::SetMTU(mtu) => {
                                        if let Err(e) = dev.set_mtu(mtu) {
                                            error!("Failed to set MTU {} on TUN device {}: {}", mtu, name, e);
                                        } else {
                                            debug!("Set MTU {} on TUN device {}", mtu, name);
                                        }
                                    }
                                }
                            }

                            // Read from TUN device and send to main task
                            // Reserve channel space first, then read - this blocks reading when channel is full
                            // while allowing other select branches to continue
                            result = async {
                                let permit = tx_tun_to_quic.reserve().await
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
                                                info!("TUN device {} read {} bytes and forwarded to QUIC", name, n);
                                            },
                                            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                                                // This should not happen as we awaited readability. However, apparently those false positives are possible.
                                                continue;
                                            }
                                            Err(e) => {
                                                warn!("TUN device {} read error: {}, shutting down", name, e);
                                                break;
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        warn!("TUN device {} channel closed: {}, shutting down", name, e);
                                        break;
                                    }
                                }
                            },

                            // Receive from main task and write to TUN device
                            Some(packet) = rx_in_tun.recv() => {
                                dev.send(&packet).await.context("failed to send packet to TUN device")?;
                            }

                            // Channel closed
                            else => {
                                warn!("TUN device {} channel closed", name);
                                break;
                            }
                        }
                    }

                    debug!("TUN device {} shutting down cleanly", name);
                    Ok(())
                }
                .await;

                if let Err(e) = result {
                    error!("TUN device task failed: {}", e);
                }
            }
            .instrument(info_span!("tun_device_handler")),
        );

        self.handle = Some(handle);
        Ok(())
    }

    pub fn abort(&mut self) {
        if let Some(handle) = &self.handle {
            handle.abort();
        }
        self.handle = None;
    }
}
