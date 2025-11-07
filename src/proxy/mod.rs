pub mod client_connection;

use anyhow::Result;
use ipnet::IpNet;
use ring::rand::SecureRandom;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::sync::mpsc;
use tracing::{debug, error, info, trace};

use crate::net::UdpPacket;
use crate::proxy::client_connection::ClientConnection;

const MAX_DATAGRAM_SIZE: usize = 1350;

pub struct ProxyConfig {
    pub listen: SocketAddr,
    pub cert_path: std::path::PathBuf,
    pub key_path: std::path::PathBuf,
    pub routes: Vec<IpNet>,
    pub address_pool: Vec<IpNet>,
}

pub struct Proxy {
    config: ProxyConfig,
}

impl Proxy {
    pub fn new(config: ProxyConfig) -> Self {
        Proxy { config }
    }

    #[tokio::main]
    pub async fn run(&self) -> Result<()> {
        let mut quic_config = Self::configure_quic(&self.config.cert_path, &self.config.key_path)?;

        let socket = tokio::net::UdpSocket::bind(self.config.listen).await?;
        let local_addr = socket.local_addr()?;
        info!("listening on {}", local_addr);

        // Channel for sending UDP packets
        let (tx_quic_to_udp, mut rx_quic_to_udp) = mpsc::channel::<UdpPacket>(1000);

        // Track active connections
        let connections: Arc<
            Mutex<HashMap<quiche::ConnectionId<'static>, mpsc::Sender<UdpPacket>>>,
        > = Arc::new(Mutex::new(HashMap::new()));

        let available_addresses = Arc::new(Mutex::new(self.config.address_pool.clone()));

        let mut buf = [0; 65535];
        let mut next_client = 0u8;

        // Main loop: handle UDP socket
        loop {
            tokio::select! {
                // Receive datagram from UDP socket
                Ok((len, src)) = socket.recv_from(&mut buf) => {
                    let packet_data = buf[..len].to_vec();

                    // Parse the QUIC packet header to identify connection
                    let mut packet_slice = packet_data.clone();
                    let hdr = match quiche::Header::from_slice(&mut packet_slice, quiche::MAX_CONN_ID_LEN) {
                        Ok(v) => v,
                        Err(e) => {
                            debug!("failed to parse header: {:?}", e);
                            continue;
                        }
                    };

                    // Check if this is an existing connection
                    if let Some(client_conn) = connections.lock().await.get(&hdr.dcid) {
                        // Forward to existing connection task
                        let _ = client_conn.send(UdpPacket {
                            data: packet_data,
                            src,
                            dst: local_addr,
                        }).await;
                    } else if hdr.ty == quiche::Type::Initial {
                        // New connection - create connection ID
                        let mut scid = [0; quiche::MAX_CONN_ID_LEN];
                        ring::rand::SystemRandom::new().fill(&mut scid).unwrap();
                        let scid = quiche::ConnectionId::from_ref(&scid);

                        info!("new connection from {} with scid {:?}", src, scid);

                        // Create QUIC connection
                        let mut conn = match quiche::accept(&scid, None, local_addr, src, &mut quic_config) {
                            Ok(c) => c,
                            Err(e) => {
                                error!("failed to create connection: {:?}", e);
                                continue;
                            }
                        };

                        // Process the initial packet
                        let recv_info = quiche::RecvInfo {
                            from: src,
                            to: local_addr,
                        };

                        match conn.recv(&mut packet_data.clone(), recv_info) {
                            Ok(_) => {
                                debug!("processed initial packet {} bytes", packet_data.len());
                            }
                            Err(e) => {
                                error!("failed to process initial packet: {:?}", e);
                                continue;
                            }
                        }

                        // Send response packets
                        loop {
                            let (write, send_info) = match conn.send(&mut buf) {
                                Ok(v) => v,
                                Err(quiche::Error::Done) => break,
                                Err(e) => {
                                    debug!("send failed: {:?}", e);
                                    break;
                                }
                            };

                            socket.send_to(&buf[..write], send_info.to).await?;
                        }

                        // Create channel for this connection
                        let (tx_to_connection, rx_from_main) = mpsc::channel::<UdpPacket>(1000);

                        // Allocate TUN IP for this client
                        let tun_name = format!("tun{}", next_client);
                        next_client += 1;

                        // Store connection info
                        let client_conn =
                            ClientConnection::new(
                                conn,
                                scid.clone().into_owned(),
                                src,
                                rx_from_main,
                                tx_quic_to_udp.clone(),
                                tun_name,
                                available_addresses.clone(),
                                self.config.routes.clone(),
                            );
                        connections.lock().await.insert(scid.clone().into_owned(), tx_to_connection);

                        // Spawn task for this connection
                        let scid_owned = scid.clone().into_owned();
                        let connections_clone = connections.clone();
                        tokio::spawn(async move {
                            if let Err(e) = client_conn.handle_client_connection().await {
                                error!("connection {:?} error: {:?}", scid_owned, e);
                            }
                            connections_clone.lock().await.remove(&scid_owned);
                        });
                    } else {
                        debug!("packet for unknown connection with dcid {:?}", hdr.dcid);
                    }
                }

                // Send QUIC packets over UDP socket
                Some(packet_data) = rx_quic_to_udp.recv() => {
                    let sent_len = socket.send_to(&packet_data.data, packet_data.dst).await?;
                    trace!("sent {} bytes to {}", sent_len, packet_data.dst);
                }
            }
        }
    }

    fn configure_quic(
        cert_path: &std::path::Path,
        key_path: &std::path::Path,
    ) -> Result<quiche::Config> {
        let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION)?;

        info!("Loading cert from {:?}", cert_path);
        info!("Loading key from {:?}", key_path);
        config.load_cert_chain_from_pem_file(cert_path.to_str().unwrap())?;
        config.load_priv_key_from_pem_file(key_path.to_str().unwrap())?;

        config.set_application_protos(quiche::h3::APPLICATION_PROTOCOL)?;
        config.set_max_idle_timeout(10000);
        config.set_max_recv_udp_payload_size(MAX_DATAGRAM_SIZE);
        config.set_max_send_udp_payload_size(MAX_DATAGRAM_SIZE);
        config.set_initial_max_data(10_000_000);
        config.set_initial_max_stream_data_bidi_local(1_000_000);
        config.set_initial_max_stream_data_bidi_remote(1_000_000);
        config.set_initial_max_stream_data_uni(1_000_000);
        config.set_initial_max_streams_bidi(100);
        config.set_initial_max_streams_uni(100);
        config.set_disable_active_migration(true);
        config.enable_early_data();
        config.enable_dgram(true, 30000, 30000);

        Ok(config)
    }
}
