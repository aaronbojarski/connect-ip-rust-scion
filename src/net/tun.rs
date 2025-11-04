use std::net::IpAddr;

use anyhow::{Result, anyhow};
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, info_span, trace};
use tracing_futures::Instrument as _;
use tun_rs::DeviceBuilder;

pub struct AddressRange {
    pub base: IpAddr,
    pub prefix_len: u8,
}

pub struct Tun {
    pub name: String,
    pub tx_tun_to_quic: Sender<Vec<u8>>,
    pub handle: Option<JoinHandle<()>>,
    pub mtu: u16,
    pub addresses: Vec<AddressRange>,
}

impl Tun {
    pub fn new(name: &str, tx_tun_to_quic: Sender<Vec<u8>>, mtu: u16) -> Result<Self> {
        Ok(Tun {
            name: name.to_string(),
            tx_tun_to_quic,
            handle: None,
            mtu,
            addresses: Vec::new(),
        })
    }

    pub async fn start(
        &mut self,
        mut rx_in_tun: Receiver<Vec<u8>>,
        cancel_token: CancellationToken,
    ) -> Result<()> {
        let dev = DeviceBuilder::new()
            .name(self.name.clone())
            .mtu(self.mtu)
            .build_async()?;

        for addr in &self.addresses {
            match addr.base {
                IpAddr::V4(_) => {
                    dev.add_address_v4(addr.base, addr.prefix_len)?;
                }
                IpAddr::V6(_) => {
                    dev.add_address_v6(addr.base, addr.prefix_len)?;
                }
            }
        }

        let name = self.name.clone();
        let tx_tun_to_quic = self.tx_tun_to_quic.clone();

        let handle = tokio::spawn(
            async move {
                let result: Result<()> = async {
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
                                trace!("TUN -> QUIC: {:?}", packet_data);
                                if tx_tun_to_quic.send(packet_data.clone()).await.is_err() {
                                    info!("TUN device {} connection closed (send failed)", name);
                                    break;
                                }
                            }

                            // Receive from main task and write to TUN device
                            Some(packet) = rx_in_tun.recv() => {
                                trace!("QUIC -> TUN: {:?}", packet);
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

        self.handle = Some(handle);
        Ok(())
    }

    pub fn abort(&mut self) {
        if let Some(handle) = &self.handle {
            handle.abort();
        }
    }
}
