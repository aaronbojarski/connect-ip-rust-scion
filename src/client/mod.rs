use anyhow::{Context, Result, anyhow};
use ipnet::IpNet;
use scion_proto::address::IsdAsn;
use scion_stack::scionstack::ScionStackBuilder;
use std::fs;
use std::sync::Arc;
use tokio::sync::{Mutex, mpsc};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, trace};

use crate::client::connection::Connection;
use crate::net::UdpPacket;
use crate::net::quic::MAX_DATAGRAM_SIZE;

pub mod connection;

pub const CHANNEL_CAPACITY: usize = 1000;

#[derive(Clone)]
pub struct ClientConfig {
    pub bind: scion_proto::address::SocketAddr,
    pub remote: scion_proto::address::SocketAddr,
    pub host: Option<String>,
    pub endhost_api_address: Option<url::Url>,
    pub snap_token_path: Option<std::path::PathBuf>,
    pub ca_cert_path: std::path::PathBuf,
    pub cert_path: std::path::PathBuf,
    pub key_path: std::path::PathBuf,
    pub routes: Vec<IpNet>,
    pub address_pool: Vec<IpNet>,
    pub tun_name: String,
}

pub struct Client {
    config: ClientConfig,
}

impl Client {
    pub fn new(config: ClientConfig) -> Self {
        Client { config }
    }

    #[tokio::main]
    pub async fn run(&self) -> Result<()> {
        let mut buf = [0; 65535];
        let quic_config = crate::net::quic::configure_quic(
            &self.config.ca_cert_path,
            &self.config.cert_path,
            &self.config.key_path,
        )?;
        let available_addresses = Arc::new(Mutex::new(self.config.address_pool.clone()));

        // Channels between UDP and QUIC tasks. Contents are UDP datagrams (usually encrypted QUIC packets) with source address.
        let (tx_udp_to_quic, rx_udp_to_quic) = mpsc::channel::<UdpPacket>(CHANNEL_CAPACITY);
        let (tx_quic_to_udp, mut rx_quic_to_udp) = mpsc::channel::<UdpPacket>(CHANNEL_CAPACITY);

        // Create cancellation token for graceful shutdown
        let cancel_token = CancellationToken::new();

        let result = if self.config.remote.isd_asn() == IsdAsn::WILDCARD {
            let socket =
                tokio::net::UdpSocket::bind(self.config.bind.local_address().unwrap()).await?;
            // Get local address.
            let local_addr = socket.local_addr()?;

            let mut connection = Connection::new(
                self.config.host.clone().unwrap_or("localhost".to_string()),
                quic_config,
                scion_proto::address::SocketAddr::from_std(IsdAsn::WILDCARD, local_addr),
                self.config.remote,
                rx_udp_to_quic,
                tx_quic_to_udp,
                self.config.tun_name.clone(),
                available_addresses,
                self.config.routes.clone(),
            )?;

            // Spawn connection handler task
            let cancel_token_clone = cancel_token.clone();
            let mut quic_handle = tokio::spawn(async move {
                connection
                    .start_connection_handling(cancel_token_clone)
                    .await
            });

            // Main loop: handle UDP socket
            loop {
                tokio::select! {
                    // Receive datagram from UDP socket and pass to QUIC
                    Ok((len, src)) = socket.recv_from(&mut buf) => {
                        if tx_udp_to_quic.send(UdpPacket {
                            data: buf[..len].to_vec(),
                            src: scion_proto::address::SocketAddr::from_std(IsdAsn::WILDCARD, src),
                            dst: scion_proto::address::SocketAddr::from_std(IsdAsn::WILDCARD, local_addr),
                        }).await.is_err() {
                            info!("QUIC task closed, shutting down");
                            break Ok(());
                        }
                    }
                    // Send datagram from QUIC to UDP socket
                    Some(packet_data) = rx_quic_to_udp.recv() => {
                        socket.send_to(&packet_data.data, packet_data.dst.local_address().unwrap()).await?;
                        trace!("sent {} bytes to {}", packet_data.data.len(), packet_data.dst);
                    }
                    // Connection handler exited
                    quic_result = &mut quic_handle => {
                        match quic_result {
                            Ok(Ok(())) => {
                                info!("QUIC connection closed normally");
                                break Ok(());
                            }
                            Ok(Err(e)) => {
                                info!("QUIC connection error: {}", e);
                                break Err(e);
                            }
                            Err(e) => {
                                info!("QUIC task panicked: {}", e);
                                break Err(anyhow!("QUIC task panicked: {}", e));
                            }
                        }
                    }
                }
            }
        } else {
            let endhost_api_url = self.config.endhost_api_address.clone().context(
                "endhost API address must be provided when using SCION (with --endhost-api)",
            )?;

            let mut builder = ScionStackBuilder::new(endhost_api_url);
            if let Some(token_path) = &self.config.snap_token_path {
                let snap_token = fs::read_to_string(token_path)
                    .with_context(|| format!("failed to read token file {:?}", token_path))?
                    .trim()
                    .to_string();
                if snap_token.is_empty() {
                    anyhow::bail!("token file {:?} is empty", token_path);
                }
                builder = builder.with_auth_token(snap_token);
            }
            let client_network_stack = builder.build().await?;

            // Since we did not request a specific address, the SNAP will assign one
            let assigned_addr = client_network_stack
                .local_addresses()
                .first()
                .cloned()
                .context("client did not get any address assigned")?;

            let socket_address = scion_proto::address::SocketAddr::new(assigned_addr.into(), 10111);
            let socket = client_network_stack.bind(Some(socket_address)).await?;

            // Get local address.
            let local_addr = socket.local_addr();

            let mut connection = Connection::new(
                self.config.host.clone().unwrap_or("localhost".to_string()),
                quic_config,
                local_addr,
                self.config.remote,
                rx_udp_to_quic,
                tx_quic_to_udp,
                self.config.tun_name.clone(),
                available_addresses,
                self.config.routes.clone(),
            )?;

            // Spawn connection handler task
            let cancel_token_clone = cancel_token.clone();
            let mut quic_handle = tokio::spawn(async move {
                connection
                    .start_connection_handling(cancel_token_clone)
                    .await
            });

            // Main loop: handle UDP socket
            loop {
                tokio::select! {
                    // Receive datagram from UDP socket and pass to QUIC
                    Ok(result) = socket.recv_from(&mut buf) => {
                        let (len, src) = result;
                        if tx_udp_to_quic.send(UdpPacket {
                            data: buf[..len].to_vec(),
                            src,
                            dst: local_addr,
                        }).await.is_err() {
                            info!("QUIC task closed, shutting down");
                            break Ok(());
                        }
                    }
                    // Send datagram from QUIC to UDP socket
                    Some(packet_data) = rx_quic_to_udp.recv() => {
                        socket.send_to(&packet_data.data, packet_data.dst).await?;
                        trace!("sent {} bytes to {}", packet_data.data.len(), packet_data.dst);
                    }
                    // Connection handler exited
                    quic_result = &mut quic_handle => {
                        match quic_result {
                            Ok(Ok(())) => {
                                info!("QUIC connection closed normally");
                                break Ok(());
                            }
                            Ok(Err(e)) => {
                                info!("QUIC connection error: {}", e);
                                break Err(e);
                            }
                            Err(e) => {
                                info!("QUIC task panicked: {}", e);
                                break Err(anyhow!("QUIC task panicked: {}", e));
                            }
                        }
                    }
                }
            }
        };

        // Graceful shutdown
        debug!("shutting down remaining tasks");
        cancel_token.cancel();

        info!("client shutdown complete");
        result
    }
}
