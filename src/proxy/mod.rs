pub mod client_connection;

use anyhow::Result;
use ring::rand::SecureRandom;
use std::collections::HashMap;
use std::env;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::sync::mpsc;
use tracing::{debug, error, info};

use crate::net::UdpPacket;
use crate::proxy::client_connection::ClientConnection;

const MAX_DATAGRAM_SIZE: usize = 1350;

#[tokio::main]
pub async fn run(listen: SocketAddr) -> Result<()> {
    // Load or generate certificates
    let (cert_path, key_path) = {
        let cwd = env::current_dir()?;
        let cert_path = cwd.join("cert.pem");
        let key_path = cwd.join("key.pem");

        (cert_path, key_path)
    };

    let mut config = configure_quic(&cert_path, &key_path)?;

    let socket = tokio::net::UdpSocket::bind(listen).await?;
    let local_addr = socket.local_addr()?;
    info!("listening on {}", local_addr);

    // Channel for sending UDP packets
    let (tx_quic_to_udp, mut rx_quic_to_udp) = mpsc::channel::<UdpPacket>(1000);

    // Track active connections
    let connections: Arc<Mutex<HashMap<quiche::ConnectionId<'static>, mpsc::Sender<UdpPacket>>>> =
        Arc::new(Mutex::new(HashMap::new()));

    let mut buf = [0; 65535];
    let mut next_tun_ip = 7u8; // Start from 10.248.1.7

    // Main loop: handle UDP socket
    loop {
        tokio::select! {
            // Receive datagram from UDP socket
            Ok((len, src)) = socket.recv_from(&mut buf) => {
                debug!("received {} bytes from {}", len, src);

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
                    let mut conn = match quiche::accept(&scid, None, local_addr, src, &mut config) {
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

                        let sent_len = socket.send_to(&buf[..write], send_info.to).await?;
                        debug!("sent {} bytes to {}", sent_len, send_info.to);
                    }

                    // Create channel for this connection
                    let (tx_to_connection, rx_from_main) = mpsc::channel::<UdpPacket>(1000);

                    // Allocate TUN IP for this client
                    let tun_ip = Ipv4Addr::new(10, 248, 1, next_tun_ip);
                    let tun_name = format!("tun{}", next_tun_ip);
                    next_tun_ip += 1;

                    // Store connection info
                    let client_conn =
                        ClientConnection::new(
                            conn,
                            scid.clone().into_owned(),
                            src,
                            rx_from_main,
                            tx_quic_to_udp.clone(),
                        );
                    connections.lock().await.insert(scid.clone().into_owned(), tx_to_connection);

                    // Spawn task for this connection
                    let scid_owned = scid.clone().into_owned();
                    let connections_clone = connections.clone();
                    tokio::spawn(async move {
                        if let Err(e) = client_conn.handle_client_connection(
                            tun_name,
                            tun_ip,
                        ).await {
                            error!("connection {:?} error: {:?}", scid_owned, e);
                        }
                        connections_clone.lock().await.remove(&scid_owned);
                    });
                } else {
                    debug!("packet for unknown connection with dcid {:?}", hdr.dcid);
                }
            }

            // Send datagram from QUIC to UDP socket
            Some(packet_data) = rx_quic_to_udp.recv() => {
                let sent_len = socket.send_to(&packet_data.data, packet_data.dst).await?;
                debug!("sent {} bytes to {}", sent_len, packet_data.dst);
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
