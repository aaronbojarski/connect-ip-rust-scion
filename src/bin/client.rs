use std::net::{SocketAddr, ToSocketAddrs};

use anyhow::{Result, anyhow};
use clap::Parser;
use connect_ip_rust_scion::tun;
use ring::rand::{SecureRandom, SystemRandom};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info};
use url::Url;

const MAX_DATAGRAM_SIZE: usize = 1350;

#[derive(Parser, Debug)]
#[clap(name = "client")]
struct Opt {
    url: Url,

    /// Override hostname used for certificate verification
    #[clap(long = "host")]
    host: Option<String>,

    /// Address to bind on
    #[clap(long = "bind", default_value = "0.0.0.0:0")]
    bind: SocketAddr,
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

#[tokio::main]
async fn run(options: Opt) -> Result<()> {
    let mut buf = [0; 65535];

    let config = configure_quic().unwrap();
    let url = options.url;
    let url_host = "10.248.100.11";
    let remote = (url_host, url.port().unwrap_or(4433))
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| anyhow!("couldn't resolve to an address"))?;

    let socket = tokio::net::UdpSocket::bind(options.bind).await?;

    // Get local address.
    let local_addr = socket.local_addr().unwrap();

    // convert the received bytes to an IPv4 address
    let received_address = "10.248.2.180";

    // Channels between TUN and QUIC tasks. Contents are IP packets.
    let (tx_quic_to_tun, rx_quic_to_tun) = mpsc::channel::<Vec<u8>>(1000);
    let (tx_tun_to_quic, rx_tun_to_quic) = mpsc::channel::<Vec<u8>>(1000);

    // Channels between UDP and QUIC tasks. Contents are UDP datagrams (usually encrypted QUIC packets) with source address.
    let (tx_udp_to_quic, rx_udp_to_quic) = mpsc::channel::<UdpPacket>(1000);
    let (tx_quic_to_udp, mut rx_quic_to_udp) = mpsc::channel::<UdpPacket>(1000);

    // Create cancellation token for TUN interface
    let cancel_token = CancellationToken::new();

    let mut tun = tun::Tun::new("tun0", received_address.parse().unwrap(), 1500);
    let tun_handle = tun
        .start(tx_tun_to_quic, rx_quic_to_tun, cancel_token.clone())
        .await?;

    // Spawn QUIC connection handler task
    let mut quic_handle = tokio::spawn(handle_quic_connection(
        config,
        "localhost".to_string(),
        local_addr,
        remote,
        rx_udp_to_quic,
        tx_quic_to_udp,
        rx_tun_to_quic,
        tx_quic_to_tun,
    ));

    // Main loop: handle UDP socket
    let result = loop {
        tokio::select! {
            // Receive datagram from UDP socket and pass to QUIC
            Ok(result) = socket.recv_from(&mut buf) => {
                let (len, src) = result;
                debug!("received {} bytes from {}", len, src);
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
                debug!("sent {} bytes to {}", sent_len, packet_data.dst);
            }
            // QUIC connection handler exited
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
    info!("shutting down TUN interface");
    cancel_token.cancel();

    // Wait for TUN task to finish with timeout
    let _ = tokio::time::timeout(std::time::Duration::from_secs(2), tun_handle).await;

    info!("client shutdown complete");
    result
}

fn configure_quic() -> Result<quiche::Config> {
    // Create the configuration for the QUIC connection.
    let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();

    // *CAUTION*: this should not be set to `false` in production!!!
    config.verify_peer(false);

    config.set_application_protos(&[b"h3"]).unwrap();

    config.set_max_idle_timeout(10000);
    config.set_max_recv_udp_payload_size(MAX_DATAGRAM_SIZE);
    config.set_max_send_udp_payload_size(MAX_DATAGRAM_SIZE);
    config.set_initial_max_data(10_000_000);
    config.set_initial_max_stream_data_bidi_local(1_000_000);
    config.set_initial_max_stream_data_bidi_remote(1_000_000);
    config.set_initial_max_streams_bidi(100);
    config.set_initial_max_streams_uni(100);
    config.set_disable_active_migration(true);
    config.enable_dgram(true, 30000, 30000);

    Ok(config)
}

async fn handle_quic_connection(
    mut config: quiche::Config,
    server_name: String,
    local_addr: SocketAddr,
    remote: SocketAddr,
    mut rx_udp_to_quic: mpsc::Receiver<UdpPacket>,
    tx_quic_to_udp: mpsc::Sender<UdpPacket>,
    mut rx_tun_to_quic: mpsc::Receiver<Vec<u8>>,
    tx_quic_to_tun: mpsc::Sender<Vec<u8>>,
) -> Result<()> {
    let mut buf = [0; MAX_DATAGRAM_SIZE];

    // Generate a random source connection ID for the connection.
    let mut scid = [0; quiche::MAX_CONN_ID_LEN];
    SystemRandom::new().fill(&mut scid[..]).unwrap();
    let scid = quiche::ConnectionId::from_ref(&scid);

    // Create a QUIC connection and initiate handshake.
    let mut conn = quiche::connect(Some(&server_name), &scid, local_addr, remote, &mut config)?;

    info!(
        "connecting to {:} from {:} with scid {:?}",
        remote, local_addr, scid
    );

    // Send initial packet
    let (write, send_info) = conn.send(&mut buf).expect("initial send failed");
    tx_quic_to_udp
        .send(UdpPacket {
            data: buf[..write].to_vec(),
            src: send_info.from,
            dst: send_info.to,
        })
        .await?;

    let mut keepalive_interval = tokio::time::interval(std::time::Duration::from_secs(5));

    loop {
        let timeout = conn.timeout();
        tokio::select! {
            // Handle connection timeout
            _ = tokio::time::sleep(timeout.unwrap_or(std::time::Duration::from_secs(24 * 60 * 60))) => {
                debug!("connection timeout");
                conn.on_timeout();
            }

            _ = keepalive_interval.tick() => {
                if conn.is_established() {
                    conn.send_ack_eliciting().unwrap();
                    debug!("keepalive tick. time until timeout: {:?}", conn.timeout());
                }
            }

            // Handle incoming UDP packets (QUIC protocol packets)
            Some(packet) = rx_udp_to_quic.recv() => {
                let recv_info = quiche::RecvInfo {
                    from: packet.src,
                    to: packet.dst,
                };

                match conn.recv(&mut packet.data.clone(), recv_info) {
                    Ok(_) => {
                        debug!("processed {} bytes from QUIC packet", packet.data.len());
                    }
                    Err(e) => {
                        debug!("recv failed: {:?}", e);
                        if conn.is_closed() {
                            info!("connection closed after recv error");
                            break;
                        }
                    }
                }
            }

            // Handle outgoing IP packets from TUN
            Some(ip_packet) = rx_tun_to_quic.recv() => {
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
        }

        // Check if connection is closed
        if conn.is_closed() {
            info!("connection closed, {:?}", conn.stats());
            break;
        }

        // Check if connection is established
        if conn.is_established() {
            // Receive datagrams from QUIC and forward to TUN
            while let Ok(len) = conn.dgram_recv(&mut buf) {
                debug!("received {} bytes from QUIC datagram", len);
                if tx_quic_to_tun.send(buf[..len].to_vec()).await.is_err() {
                    info!("TUN channel closed, stopping datagram forwarding");
                    break;
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

            if tx_quic_to_udp
                .send(UdpPacket {
                    data: buf[..write].to_vec(),
                    src: send_info.from,
                    dst: send_info.to,
                })
                .await
                .is_err()
            {
                info!("UDP channel closed, cannot send packets");
                break;
            }
        }
    }

    info!("QUIC connection handler exiting");
    Ok(())
}
