use anyhow::{Result, anyhow};
use std::net::Ipv4Addr;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, info_span};
use tracing_futures::Instrument as _;
use tun_rs::DeviceBuilder;

pub struct Tun {
    pub name: String,
    pub address: Ipv4Addr,
    pub mtu: u16,
}

impl Tun {
    pub fn new(name: &str, address: Ipv4Addr, mtu: u16) -> Self {
        Tun {
            name: name.to_string(),
            address,
            mtu,
        }
    }

    pub async fn start(
        &mut self,
        tx_from_tun: Sender<Vec<u8>>,
        mut rx_in_tun: Receiver<Vec<u8>>,
        cancel_token: CancellationToken,
    ) -> Result<JoinHandle<()>> {
        let address = self.address;
        let name = self.name.clone();

        let handle = tokio::spawn(
            async move {
                let result: Result<()> = async {
                    let dev = DeviceBuilder::new()
                        .name(name.clone())
                        .ipv4(address, 24, None)
                        .build_async()?;

                    // TODO: make address assignment better
                    dev.add_address_v4("10.248.2.128", 25)?;

                    let mut buf = vec![0; 65536];
                    loop {
                        tokio::select! {
                            // Check for cancellation signal
                            _ = cancel_token.cancelled() => {
                                info!("TUN device {} received shutdown signal", name);
                                break;
                            }

                            // Read from TUN device and send to main task
                            len = dev.recv(&mut buf) => {
                                let len = len?;
                                let packet_data = buf[..len].to_vec();
                                info!("TUN -> QUIC: {:?}", packet_data);

                                // If send fails, connection is closed
                                if tx_from_tun.send(packet_data).await.is_err() {
                                    info!("TUN device {} connection closed (send failed)", name);
                                    break;
                                }
                            }

                            // Receive from main task and write to TUN device
                            Some(packet) = rx_in_tun.recv() => {
                                info!("QUIC -> TUN: {:?}", packet);
                                dev.send(&packet).await
                                    .map_err(|_| anyhow!("failed to send packet to TUN"))?;
                            }

                            // Channel closed
                            else => {
                                info!("TUN device {} channel closed", name);
                                break;
                            }
                        }
                    }

                    info!("TUN device {} shutting down cleanly", name);
                    Ok(())
                }
                .await;

                if let Err(e) = result {
                    error!("TUN device task failed: {}", e);
                }
            }
            .instrument(info_span!("tap_device_handler")),
        );

        Ok(handle)
    }
}
