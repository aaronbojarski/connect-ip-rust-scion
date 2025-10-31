use std::collections::HashMap;
use std::env;
use std::net::{Ipv4Addr, SocketAddr};

use anyhow::Result;
use clap::Parser;
use connect_ip_rust_scion::tun;
use pnet::packet::ipv4::Ipv4Packet;
use ring::rand::SecureRandom;
use tokio::sync::mpsc;
use tracing::{debug, error, info};

const MAX_DATAGRAM_SIZE: usize = 1350;

#[derive(Parser, Debug)]
#[clap(name = "server")]
struct Opt {
    /// Address to listen on
    #[clap(long = "listen", default_value = "127.0.0.1:4433")]
    listen: SocketAddr,
}

fn main() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .init();
    let opt = Opt::parse();
    let code = {
        if let Err(e) = run(opt) {
            eprintln!("ERROR: {e}");
            1
        } else {
            0
        }
    };
    ::std::process::exit(code);
}

pub struct UdpPacket {
    pub data: Vec<u8>,
    pub src: SocketAddr,
    pub dst: SocketAddr,
}

pub struct ClientConnection {
    pub remote_addr: SocketAddr,
    pub tx_to_connection: mpsc::Sender<UdpPacket>,
}

#[tokio::main]
async fn run(options: Opt) -> Result<()> {
    // Load or generate certificates
    let (cert_path, key_path) = {
        let cwd = env::current_dir()?;
        let cert_path = cwd.join("cert.pem");
        let key_path = cwd.join("key.pem");

        (cert_path, key_path)
    };

    let mut config = configure_quic(&cert_path, &key_path)?;

    let socket = tokio::net::UdpSocket::bind(options.listen).await?;
    let local_addr = socket.local_addr()?;
    info!("listening on {}", local_addr);

    // Channel for sending UDP packets
    let (tx_quic_to_udp, mut rx_quic_to_udp) = mpsc::channel::<UdpPacket>(1000);

    // Track active connections
    let mut connections: HashMap<quiche::ConnectionId<'static>, ClientConnection> = HashMap::new();

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
                if let Some(client_conn) = connections.get(&hdr.dcid) {
                    // Forward to existing connection task
                    let _ = client_conn.tx_to_connection.send(UdpPacket {
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

                    // Send any response packets
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
                    let client_conn = ClientConnection {
                        remote_addr: src,
                        tx_to_connection: tx_to_connection.clone(),
                    };
                    connections.insert(scid.clone().into_owned(), client_conn);

                    // Spawn task for this connection
                    let tx_quic_to_udp_clone = tx_quic_to_udp.clone();
                    let scid_owned = scid.into_owned();

                    tokio::spawn(async move {
                        if let Err(e) = handle_client_connection(
                            scid_owned.clone(),
                            conn,
                            rx_from_main,
                            tx_quic_to_udp_clone,
                            tun_name,
                            tun_ip,
                        ).await {
                            error!("connection {:?} error: {:?}", scid_owned, e);
                        }
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

    config.set_application_protos(&[b"h3"])?;

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
    config.enable_dgram(true, 30000, 30000);

    Ok(config)
}

async fn handle_client_connection(
    scid: quiche::ConnectionId<'static>,
    mut conn: quiche::Connection,
    mut rx_udp_packets: mpsc::Receiver<UdpPacket>,
    tx_quic_to_udp: mpsc::Sender<UdpPacket>,
    tun_name: String,
    tun_ip: Ipv4Addr,
) -> Result<()> {
    info!(
        "starting connection handler for {:?} with TUN {} ({})",
        scid, tun_name, tun_ip
    );

    // Create TUN interface for this connection
    let (tx_quic_to_tun, rx_quic_to_tun) = mpsc::channel::<Vec<u8>>(1000);
    let (tx_tun_to_quic, mut rx_tun_to_quic) = mpsc::channel::<Vec<u8>>(1000);

    let mut tun = tun::Tun::new(&tun_name, tun_ip, 1500);
    tun.start(tx_tun_to_quic, rx_quic_to_tun).await?;

    let mut buf = [0; MAX_DATAGRAM_SIZE];
    let mut keepalive_interval = tokio::time::interval(std::time::Duration::from_secs(5));

    loop {
        let timeout = conn.timeout().unwrap_or(std::time::Duration::from_secs(60));

        tokio::select! {
            // Handle connection timeout
            _ = tokio::time::sleep(timeout) => {
                conn.on_timeout();

                // Send any packets generated by timeout
                loop {
                    let (write, send_info) = match conn.send(&mut buf) {
                        Ok(v) => v,
                        Err(quiche::Error::Done) => break,
                        Err(e) => {
                            debug!("send failed: {:?}", e);
                            break;
                        }
                    };

                    tx_quic_to_udp.send(UdpPacket {
                        data: buf[..write].to_vec(),
                        src: send_info.from,
                        dst: send_info.to,
                    }).await?;
                }

                if conn.is_closed() {
                    info!("connection {:?} closed", scid);
                    break;
                }
            }

            // Handle incoming UDP packets (QUIC protocol packets)
            Some(packet) = rx_udp_packets.recv() => {
                let recv_info = quiche::RecvInfo {
                    from: packet.src,
                    to: packet.dst,
                };

                // Process the packet
                match conn.recv(&mut packet.data.clone(), recv_info) {
                    Ok(_) => {
                        debug!("processed {} bytes", packet.data.len());
                    }
                    Err(e) => {
                        debug!("recv failed: {:?}", e);
                        if conn.is_closed() {
                            info!("connection {:?} closed after recv error", scid);
                            break;
                        }
                        continue;
                    }
                }

                // Handle datagrams if connection is established
                if conn.is_established() && !conn.is_in_early_data() {
                    // Receive datagrams from QUIC and forward to TUN
                    while let Ok(len) = conn.dgram_recv(&mut buf) {
                        debug!("received {} bytes from QUIC datagram", len);

                        if let Some(ipv4) = Ipv4Packet::new(&buf[..len]) {
                            let src = ipv4.get_source();
                            let dest = ipv4.get_destination();
                            info!("forwarding IP packet to TUN: {} -> {}, {} bytes", src, dest, len);
                        }

                        tx_quic_to_tun.send(buf[..len].to_vec()).await?;
                    }
                }
            }

            // Handle outgoing IP packets from TUN
            Some(ip_packet) = rx_tun_to_quic.recv() => {
                if let Some(ipv4) = Ipv4Packet::new(&ip_packet) {
                    let src = ipv4.get_source();
                    let dest = ipv4.get_destination();
                    info!("received IP packet from TUN: {} -> {}, {} bytes", src, dest, ip_packet.len());
                }

                if conn.is_established() {
                    match conn.dgram_send(&ip_packet) {
                        Ok(_) => {
                            debug!("sent {} bytes as QUIC datagram", ip_packet.len());

                        }
                        Err(e) => {
                            debug!("dgram_send failed: {:?}", e);
                        }
                    }
                } else {
                    debug!("connection not established yet, dropping packet");
                }
            }

            // Periodic keepalive
            _ = keepalive_interval.tick() => {
                if conn.is_established() {
                    conn.send_ack_eliciting().unwrap();
                    debug!("sending keepalive for connection {:?}", scid);
                }
            }
        }

        // Send any pending QUIC packets
        loop {
            let (write, send_info) = match conn.send(&mut buf) {
                Ok(v) => v,
                Err(quiche::Error::Done) => break,
                Err(e) => {
                    debug!("send failed: {:?}", e);
                    break;
                }
            };

            tx_quic_to_udp
                .send(UdpPacket {
                    data: buf[..write].to_vec(),
                    src: send_info.from,
                    dst: send_info.to,
                })
                .await?;
        }
    }

    info!("connection {:?} handler exiting", scid);
    Ok(())
}
