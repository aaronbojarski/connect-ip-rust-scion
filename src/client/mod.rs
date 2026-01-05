pub mod connection;

use std::fs;
use std::sync::Arc;

use anyhow::{Context, Result, anyhow};
use ipnet::IpNet;
use scion_proto::address::IsdAsn;
use scion_proto::path::policy::acl::AclPolicy;
use scion_stack::scionstack::ScionStackBuilder;
use tokio::sync::{Mutex, mpsc};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info};

use crate::client::connection::{Config, Connection};
use crate::net::UdpPacket;
use crate::net::quic::MAX_DATAGRAM_SIZE;

pub const CHANNEL_CAPACITY: usize = 200;
pub const UDP_PACKET_BUFFER_SIZE: usize = 65535;

#[derive(Clone)]
pub struct ClientConfig {
    pub bind: Option<scion_proto::address::SocketAddr>,
    pub remote: scion_proto::address::SocketAddr,
    pub host: Option<String>,
    pub endhost_api_address: Option<url::Url>,
    pub snap_token_path: Option<std::path::PathBuf>,
    pub acl_policy: Option<AclPolicy>,
    pub ca_cert_path: std::path::PathBuf,
    pub cert_path: std::path::PathBuf,
    pub key_path: std::path::PathBuf,
    pub routes: Vec<IpNet>,
    pub address_pool: Vec<IpNet>,
    pub tun_name: String,
    pub tun_mtu: u16,
}

pub struct Client {
    config: ClientConfig,
}

impl Client {
    pub fn new(config: ClientConfig) -> Self {
        Client { config }
    }

    pub async fn run(&self) -> Result<()> {
        let mut buf = [0; UDP_PACKET_BUFFER_SIZE];
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
            let addr = match self.config.bind {
                Some(addr) => addr
                    .local_address()
                    .ok_or_else(|| anyhow!("invalid local address in bind socket addr"))?,
                None => std::net::SocketAddr::V4(std::net::SocketAddrV4::new(
                    std::net::Ipv4Addr::UNSPECIFIED,
                    0,
                )),
            };

            let socket = tokio::net::UdpSocket::bind(addr).await?;
            // Get local address.
            let local_addr = socket.local_addr()?;

            let config = Config {
                server_name: self
                    .config
                    .host
                    .clone()
                    .unwrap_or("connect-ip-rust-scion".to_string()),
                quic_config,
                local: scion_proto::address::SocketAddr::from_std(IsdAsn::WILDCARD, local_addr),
                remote: self.config.remote,
                tun_name: self.config.tun_name.clone(),
                configured_mtu: self.config.tun_mtu,
                routes: self.config.routes.clone(),
            };

            let mut connection = Connection::new(
                config,
                rx_udp_to_quic,
                tx_quic_to_udp,
                cancel_token.clone(),
                available_addresses,
            )?;

            // Spawn connection handler task
            let mut quic_handle =
                tokio::spawn(async move { connection.start_connection_handling().await });

            // Main loop: handle UDP socket
            loop {
                tokio::select! {
                    // Receive datagram from UDP socket and pass to QUIC
                    Ok((len, src)) = socket.recv_from(&mut buf) => {
                        debug!("received {} bytes on socket from {}", len, src);
                        match tx_udp_to_quic.try_send(UdpPacket {
                            data: buf[..len].to_vec(),
                            src: scion_proto::address::SocketAddr::from_std(IsdAsn::WILDCARD, src),
                            dst: scion_proto::address::SocketAddr::from_std(IsdAsn::WILDCARD, local_addr),
                        }) {
                            Ok(_) => {}
                            Err(mpsc::error::TrySendError::Full(_)) => {
                                debug!("UDP to QUIC channel full, dropping packet from {}", src);
                            }
                            Err(e) => {
                                error!("Failed to send packet to QUIC task: {}, shutting down", e);
                                break Err(anyhow!("QUIC task closed, shutting down. Error: {}", e));
                            }
                        }
                    }
                    // Send datagram from QUIC to UDP socket
                    Some(packet_data) = rx_quic_to_udp.recv() => {
                        let dst = packet_data.dst.local_address().ok_or_else(|| anyhow!("invalid dst address"))?;
                        socket.send_to(&packet_data.data, dst).await?;
                        debug!("sent {} bytes on socket to {}", packet_data.data.len(), packet_data.dst);
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
                                break Err(anyhow!("QUIC task panicked: {:?}", e));
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

            // When using SNAP, we will get an address assigned.
            let local_ias = client_network_stack.local_ases();

            if let Some(bind) = &self.config.bind {
                if !local_ias.contains(&bind.isd_asn()) {
                    anyhow::bail!(
                        "configured bind ISD-AS {} is not among the local ASes of the SCION stack: {:?}",
                        bind.isd_asn(),
                        local_ias
                    );
                }
            }

            let mut socket_config = scion_stack::scionstack::SocketConfig::new();
            if let Some(policy) = &self.config.acl_policy {
                info!("Using ACL policy: {:?}", policy);
                socket_config = socket_config.with_path_policy(policy.clone());
            } else {
                info!("No ACL policy specified, using default (allow all)");
            }

            let socket = client_network_stack
                .bind_with_config(self.config.bind, socket_config)
                .await?;

            // Get local address.
            let local_addr = socket.local_addr();

            let config = Config {
                server_name: self
                    .config
                    .host
                    .clone()
                    .unwrap_or("connect-ip-rust-scion".to_string()),
                quic_config,
                local: local_addr,
                remote: self.config.remote,
                tun_name: self.config.tun_name.clone(),
                configured_mtu: self.config.tun_mtu,
                routes: self.config.routes.clone(),
            };

            let mut connection = Connection::new(
                config,
                rx_udp_to_quic,
                tx_quic_to_udp,
                cancel_token.clone(),
                available_addresses,
            )?;

            // Spawn connection handler task
            let mut quic_handle =
                tokio::spawn(async move { connection.start_connection_handling().await });

            // Main loop: handle UDP socket
            loop {
                tokio::select! {
                    // Receive datagram from UDP socket and pass to QUIC
                    Ok((len, src)) = socket.recv_from(&mut buf) => {
                        debug!("received {} bytes on socket from {}", len, src);
                        match tx_udp_to_quic.try_send(UdpPacket {
                            data: buf[..len].to_vec(),
                            src,
                            dst: local_addr,
                        }) {
                            Ok(_) => {}
                            Err(mpsc::error::TrySendError::Full(_)) => {
                                debug!("UDP to QUIC channel full, dropping packet from {}", src);
                            }
                            Err(e) => {
                                error!("Failed to send packet to QUIC task: {}, shutting down", e);
                                break Err(anyhow!("QUIC task closed, shutting down. Error: {}", e));
                            }
                        }
                    }
                    // Send datagram from QUIC to UDP socket
                    Some(packet_data) = rx_quic_to_udp.recv() => {
                        socket.send_to(&packet_data.data, packet_data.dst).await?;
                        debug!("sent {} bytes on socket to {}", packet_data.data.len(), packet_data.dst);
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
