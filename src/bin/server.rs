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
    tracing_subscriber::fmt().init();
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

#[tokio::main]
async fn run(options: Opt) -> Result<()> {
    // Load or generate certificates
    let (cert_path, key_path) = {
        let cwd = env::current_dir()?;
        let cert_path = cwd.join("cert.pem");
        let key_path = cwd.join("key.pem");

        (cert_path, key_path)
    };

    let config = configure_quic(&cert_path, &key_path)?;

    let socket = tokio::net::UdpSocket::bind(options.listen).await?;
    info!("listening on {}", socket.local_addr()?);

    // Channels between TUN and QUIC
    let (tx_quic_to_tun, rx_quic_to_tun) = mpsc::channel::<Vec<u8>>(1000);
    let (tx_tun_to_quic, rx_tun_to_quic) = mpsc::channel::<Vec<u8>>(1000);

    // Channels between UDP and QUIC
    let (tx_udp_to_quic, rx_udp_to_quic) = mpsc::channel::<UdpPacket>(1000);
    let (tx_quic_to_udp, mut rx_quic_to_udp) = mpsc::channel::<UdpPacket>(1000);

    // Start TUN interface
    let mut tun = tun::Tun::new("tun0", "10.248.1.7".parse::<Ipv4Addr>()?, 1500);
    tun.start(tx_tun_to_quic, rx_quic_to_tun).await?;

    // Spawn QUIC connection handler task
    tokio::spawn(handle_quic_connections(
        config,
        socket.local_addr()?,
        rx_udp_to_quic,
        tx_quic_to_udp.clone(),
        rx_tun_to_quic,
        tx_quic_to_tun,
    ));

    let mut buf = [0; 65535];

    // Main loop: handle UDP socket
    loop {
        tokio::select! {
            // Receive datagram from UDP socket and pass to QUIC
            Ok(result) = socket.recv_from(&mut buf) => {
                let (len, src) = result;
                debug!("received {} bytes from {}", len, src);
                tx_udp_to_quic.send(UdpPacket {
                    data: buf[..len].to_vec(),
                    src,
                    dst: socket.local_addr()?,
                }).await.unwrap();
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

    config.set_max_idle_timeout(5000);
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

async fn handle_quic_connections(
    mut config: quiche::Config,
    local_addr: SocketAddr,
    mut rx_udp_to_quic: mpsc::Receiver<UdpPacket>,
    tx_quic_to_udp: mpsc::Sender<UdpPacket>,
    mut rx_tun_to_quic: mpsc::Receiver<Vec<u8>>,
    tx_quic_to_tun: mpsc::Sender<Vec<u8>>,
) -> Result<()> {
    let mut buf = [0; MAX_DATAGRAM_SIZE];
    let mut connections: HashMap<quiche::ConnectionId<'static>, quiche::Connection> =
        HashMap::new();

    loop {
        tokio::select! {
            // Handle incoming UDP packets (QUIC protocol packets)
            Some(packet) = rx_udp_to_quic.recv() => {
                let recv_info = quiche::RecvInfo {
                    from: packet.src,
                    to: packet.dst,
                };

                // Parse the QUIC packet header
                let mut packet_data = packet.data.clone();
                let hdr = match quiche::Header::from_slice(&mut packet_data, quiche::MAX_CONN_ID_LEN) {
                    Ok(v) => v,
                    Err(e) => {
                        debug!("failed to parse header: {:?}", e);
                        continue;
                    }
                };

                // Check if this is a new connection
                let conn = if !connections.contains_key(&hdr.dcid) {
                    if hdr.ty != quiche::Type::Initial {
                        debug!("packet is not Initial");
                        continue;
                    }

                    // Generate connection IDs
                    let mut scid = [0; quiche::MAX_CONN_ID_LEN];
                    ring::rand::SystemRandom::new().fill(&mut scid).unwrap();
                    let scid = quiche::ConnectionId::from_ref(&scid);

                    // Accept the connection
                    let conn = match quiche::accept(&scid, None, local_addr, packet.src, &mut config) {
                        Ok(v) => v,
                        Err(e) => {
                            error!("failed to accept connection: {:?}", e);
                            continue;
                        }
                    };

                    info!("new connection from {} with scid {:?}", packet.src, scid);

                    connections.insert(scid.clone().into_owned(), conn);
                    connections.get_mut(&scid.into_owned()).unwrap()
                } else {
                    connections.get_mut(&hdr.dcid).unwrap()
                };

                // Process the packet
                match conn.recv(&mut packet.data.clone(), recv_info) {
                    Ok(_) => {
                        debug!("processed {} bytes", packet.data.len());
                    }
                    Err(e) => {
                        debug!("recv failed: {:?}", e);
                    }
                }

                // Handle HTTP/3 if connection is established
                if conn.is_established() && !conn.is_in_early_data() {
                    // TODO: Handle HTTP/3 requests for address allocation
                    // For now, we'll just handle datagrams

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

                    tx_quic_to_udp.send(UdpPacket {
                        data: buf[..write].to_vec(),
                        src: send_info.from,
                        dst: send_info.to,
                    }).await?;
                }

                // Clean up closed connections
                connections.retain(|_, conn| !conn.is_closed());
            }

            // Handle outgoing IP packets from TUN
            Some(ip_packet) = rx_tun_to_quic.recv() => {
                if let Some(ipv4) = Ipv4Packet::new(&ip_packet) {
                    let src = ipv4.get_source();
                    let dest = ipv4.get_destination();
                    info!("received IP packet from TUN: {} -> {}, {} bytes", src, dest, ip_packet.len());
                }

                // Forward to all established connections
                let mut packets_to_send = Vec::new();

                for (conn_id, conn) in connections.iter_mut() {
                    if conn.is_established() {
                        match conn.dgram_send(&ip_packet) {
                            Ok(_) => {
                                debug!("sent {} bytes as QUIC datagram to {:?}", ip_packet.len(), conn_id);

                                // Collect packets to send
                                loop {
                                    let (write, send_info) = match conn.send(&mut buf) {
                                        Ok(v) => v,
                                        Err(quiche::Error::Done) => break,
                                        Err(e) => {
                                            debug!("send failed: {:?}", e);
                                            break;
                                        }
                                    };

                                    packets_to_send.push(UdpPacket {
                                        data: buf[..write].to_vec(),
                                        src: send_info.from,
                                        dst: send_info.to,
                                    });
                                }
                            }
                            Err(e) => {
                                debug!("dgram_send failed: {:?}", e);
                            }
                        }
                    }
                }

                // Send all collected packets
                for packet in packets_to_send {
                    tx_quic_to_udp.send(packet).await?;
                }
            }
        }
    }
}
