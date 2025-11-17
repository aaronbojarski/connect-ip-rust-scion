use anyhow::{Result, anyhow};
use ipnet::IpNet;
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::Arc;
use tokio::sync::{Mutex, mpsc};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, trace};
use url::Url;

use crate::client::connection::Connection;
use crate::net::UdpPacket;
use crate::net::quic::MAX_DATAGRAM_SIZE;

pub mod connection;

pub const CHANNEL_CAPACITY: usize = 1000;

#[derive(Clone)]
pub struct ClientConfig {
    pub bind: SocketAddr,
    pub url: Url,
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

        let url = &self.config.url;
        let url_host = url.host_str().ok_or_else(|| anyhow!("URL missing host"))?;
        let remote = (url_host, url.port().unwrap_or(4433))
            .to_socket_addrs()?
            .next()
            .ok_or_else(|| anyhow!("couldn't resolve to an address"))?;

        // TODO: The client could use connect instead of bind
        let socket = tokio::net::UdpSocket::bind(self.config.bind).await?;

        // Get local address.
        let local_addr = socket.local_addr().unwrap();

        // Channels between UDP and QUIC tasks. Contents are UDP datagrams (usually encrypted QUIC packets) with source address.
        let (tx_udp_to_quic, rx_udp_to_quic) = mpsc::channel::<UdpPacket>(CHANNEL_CAPACITY);
        let (tx_quic_to_udp, mut rx_quic_to_udp) = mpsc::channel::<UdpPacket>(CHANNEL_CAPACITY);

        let available_addresses = Arc::new(Mutex::new(self.config.address_pool.clone()));

        let quic_config = crate::net::quic::configure_quic(
            &self.config.ca_cert_path,
            &self.config.cert_path,
            &self.config.key_path,
        )?;
        let mut connection = Connection::new(
            "localhost".to_string(),
            quic_config,
            local_addr,
            remote,
            rx_udp_to_quic,
            tx_quic_to_udp,
            self.config.tun_name.clone(),
            available_addresses,
            self.config.routes.clone(),
        )?;

        // Create cancellation token for graceful shutdown
        let cancel_token = CancellationToken::new();

        // Spawn connection handler task
        let cancel_token_clone = cancel_token.clone();
        let mut quic_handle = tokio::spawn(async move {
            connection
                .start_connection_handling(cancel_token_clone)
                .await
        });

        // Main loop: handle UDP socket
        let result = loop {
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
                    let sent_len = socket.send_to(&packet_data.data, packet_data.dst).await?;
                    trace!("sent {} bytes to {}", sent_len, packet_data.dst);
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
        };

        // Graceful shutdown
        debug!("shutting down remaining tasks");
        cancel_token.cancel();

        info!("client shutdown complete");
        result
    }
}
