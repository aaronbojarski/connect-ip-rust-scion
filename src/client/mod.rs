use std::net::{IpAddr, Ipv4Addr, SocketAddr, ToSocketAddrs};

use anyhow::{Result, anyhow};
use ipnet::IpNet;
use octets::Octets;
use quiche::h3::NameValue;
use ring::rand::{SecureRandom, SystemRandom};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, trace};
use url::Url;

use crate::connect_ip::capsule::{AddressRequestCapsule, Capsule, RequestedAddress};
use crate::net::{UdpPacket, tun};

const MAX_DATAGRAM_SIZE: usize = 1350;

#[tokio::main]
pub async fn run(url: Url, bind: SocketAddr) -> Result<()> {
    let mut buf = [0; 65535];

    let url = url;
    let url_host = url.host_str().ok_or_else(|| anyhow!("URL missing host"))?;
    let remote = (url_host, url.port().unwrap_or(4433))
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| anyhow!("couldn't resolve to an address"))?;

    let socket = tokio::net::UdpSocket::bind(bind).await?;

    // Get local address.
    let local_addr = socket.local_addr().unwrap();

    // Channels between UDP and QUIC tasks. Contents are UDP datagrams (usually encrypted QUIC packets) with source address.
    let (tx_udp_to_quic, rx_udp_to_quic) = mpsc::channel::<UdpPacket>(1000);
    let (tx_quic_to_udp, mut rx_quic_to_udp) = mpsc::channel::<UdpPacket>(1000);

    // Create cancellation token for graceful shutdown
    let cancel_token = CancellationToken::new();

    let mut connection = Connection::new(
        "localhost".to_string(),
        local_addr,
        remote,
        rx_udp_to_quic,
        tx_quic_to_udp,
    )?;

    // Spawn QUIC connection handler task
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
    debug!("shutting down remaining tasks");
    cancel_token.cancel();

    info!("client shutdown complete");
    result
}

struct CapsuleProtocolState {
    request_sent: bool,
    stream_established: bool,
    stream_id: u64,
    address_requested: bool,
    tunnel_established: bool,
    addresses: Vec<IpNet>,
    routes: Vec<IpNet>,
    updated: bool,
}

struct Connection {
    conn: quiche::Connection,
    h3_conn: Option<quiche::h3::Connection>,
    rx_udp_to_quic: mpsc::Receiver<UdpPacket>,
    tx_quic_to_udp: mpsc::Sender<UdpPacket>,
    capsule_state: CapsuleProtocolState,
}

impl Connection {
    pub fn new(
        server_name: String,
        local_addr: SocketAddr,
        remote: SocketAddr,
        rx_udp_to_quic: mpsc::Receiver<UdpPacket>,
        tx_quic_to_udp: mpsc::Sender<UdpPacket>,
    ) -> Result<Self> {
        let mut config = Self::configure_quic().unwrap();

        // Generate a random source connection ID for the connection.
        let mut scid = [0; quiche::MAX_CONN_ID_LEN];
        SystemRandom::new().fill(&mut scid[..]).unwrap();
        let scid = quiche::ConnectionId::from_ref(&scid);

        // Create a QUIC connection and initiate handshake.
        let conn = quiche::connect(Some(&server_name), &scid, local_addr, remote, &mut config)?;

        info!(
            "connecting to {:} from {:} with scid {:?}",
            remote, local_addr, scid
        );

        Ok(Connection {
            conn,
            h3_conn: None,
            rx_udp_to_quic,
            tx_quic_to_udp,
            capsule_state: CapsuleProtocolState {
                request_sent: false,
                stream_id: 0,
                stream_established: false,
                address_requested: false,
                tunnel_established: false,
                addresses: Vec::new(),
                routes: Vec::new(),
                updated: false,
            },
        })
    }

    fn configure_quic() -> Result<quiche::Config> {
        // Create the configuration for the QUIC connection.
        let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();

        // TODO: Load certificates properly and verify server identity
        config.verify_peer(false);

        config.set_application_protos(quiche::h3::APPLICATION_PROTOCOL)?;

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

    pub async fn start_connection_handling(
        &mut self,
        cancel_token: CancellationToken,
    ) -> Result<()> {
        let mut buf = [0; MAX_DATAGRAM_SIZE];

        // Channels between TUN and QUIC tasks. Contents are IP packets.
        let (mut tx_quic_to_tun, mut rx_quic_to_tun) = mpsc::channel::<Vec<u8>>(1000);
        let (tx_tun_to_quic, mut rx_tun_to_quic) = mpsc::channel::<Vec<u8>>(1000);

        let mut tun = tun::Tun::new("tun0", tx_tun_to_quic.clone(), 1350)?;

        // Send initial packet
        let (write, send_info) = self.conn.send(&mut buf).expect("initial send failed");
        self.tx_quic_to_udp
            .send(UdpPacket {
                data: buf[..write].to_vec(),
                src: send_info.from,
                dst: send_info.to,
            })
            .await?;

        let mut h3_config = quiche::h3::Config::new().unwrap();
        h3_config.enable_extended_connect(true);
        let req = vec![
            quiche::h3::Header::new(b":method", b"CONNECT"),
            quiche::h3::Header::new(b":protocol", b"connect-ip"),
            quiche::h3::Header::new(b":scheme", b"https"),
            quiche::h3::Header::new(b":authority", b"localhost"),
            quiche::h3::Header::new(b":path", b"/vpn"),
            quiche::h3::Header::new(b"capsule-protocol", b"?1"),
        ];

        let mut keepalive_interval = tokio::time::interval(std::time::Duration::from_secs(5));
        loop {
            let timeout = self.conn.timeout();
            tokio::select! {
                _ = cancel_token.cancelled() => {
                    info!("connection handler received shutdown signal");
                    break;
                }

                // Handle connection timeout
                _ = tokio::time::sleep(timeout.unwrap_or(std::time::Duration::from_secs(24 * 60 * 60))) => {
                    debug!("connection timeout");
                    self.conn.on_timeout();
                }

                _ = keepalive_interval.tick() => {
                    if self.conn.is_established() {
                        self.conn.send_ack_eliciting().unwrap();
                        trace!("keepalive tick. time until timeout: {:?}", self.conn.timeout());
                    }
                }

                // Handle incoming UDP packets (QUIC protocol packets)
                Some(packet) = self.rx_udp_to_quic.recv() => {
                    let recv_info = quiche::RecvInfo {
                        from: packet.src,
                        to: packet.dst,
                    };

                    match self.conn.recv(&mut packet.data.clone(), recv_info) {
                        Ok(_) => {
                            trace!("processed {} bytes from QUIC packet", packet.data.len());
                        }
                        Err(e) => {
                            debug!("recv failed: {:?}", e);
                            if self.conn.is_closed() {
                                info!("connection closed after recv error");
                                break;
                            }
                        }
                    }
                }

                // Handle outgoing IP packets from TUN
                Some(ip_packet) = rx_tun_to_quic.recv() => {
                    if self.conn.is_established() {
                        if let Err(e) = self.conn.dgram_send(&ip_packet) {
                            debug!("dgram_send failed: {:?}", e);
                        }
                    } else {
                        debug!("connection not established yet, dropping packet");
                    }
                }
            }

            // Check if connection is closed
            if self.conn.is_closed() {
                info!("connection closed, {:?}", self.conn.stats());
                break;
            }

            // Create a new HTTP/3 connection once the QUIC connection is established.
            if self.conn.is_established() && self.h3_conn.is_none() {
                self.h3_conn = Some(
                    quiche::h3::Connection::with_transport(&mut self.conn, &h3_config)
                        .expect("Unable to create HTTP/3 connection, check the server's uni stream limit and window size"),
                );
            }

            // Send HTTP requests once the QUIC connection is established, and until
            // all requests have been sent.
            if let Some(h3_conn) = &mut self.h3_conn {
                if !self.capsule_state.request_sent {
                    info!("sending HTTP request {req:?}");
                    h3_conn.send_request(&mut self.conn, &req, false).unwrap();
                    self.capsule_state.request_sent = true;
                }
            }

            if self.h3_conn.is_some() {
                // Process HTTP/3 events.
                loop {
                    let http3_conn = self.h3_conn.as_mut().unwrap();
                    match http3_conn.poll(&mut self.conn) {
                        Ok((stream_id, quiche::h3::Event::Headers { list, .. })) => {
                            info!(
                                "got response headers {:?} on stream id {}",
                                hdrs_to_strings(&list),
                                stream_id
                            );
                            if Self::check_response(&list) {
                                self.capsule_state.stream_id = stream_id;
                                self.capsule_state.stream_established = true;
                            } else {
                                error!("unexpected response from server, closing connection");
                                self.conn
                                    .close(true, 0x100, b"unexpected response")
                                    .unwrap();
                            }
                        }

                        Ok((stream_id, quiche::h3::Event::Data)) => {
                            info!(
                                "{} got data on stream id {}",
                                self.conn.trace_id(),
                                stream_id
                            );
                            while let Ok(read) = self.h3_conn.as_mut().unwrap().recv_body(
                                &mut self.conn,
                                stream_id,
                                &mut buf,
                            ) {
                                trace!("got {read} bytes of response data on stream {stream_id}");
                                let data = buf[..read].to_vec();
                                // TODO: make sure all data is handled
                                self.handle_capsule_data(stream_id, &data)?;
                            }
                        }

                        Ok((_stream_id, quiche::h3::Event::Finished)) => {
                            info!("stream finished, closing connection");
                            self.conn.close(true, 0x100, b"kthxbye").unwrap();
                        }

                        Ok((_stream_id, quiche::h3::Event::Reset(e))) => {
                            error!("request was reset by peer with {e}, closing...");
                            self.conn.close(true, 0x100, b"kthxbye").unwrap();
                        }

                        Ok((_, quiche::h3::Event::PriorityUpdate)) => unreachable!(),

                        Ok((goaway_id, quiche::h3::Event::GoAway)) => {
                            info!("GOAWAY id={goaway_id}");
                        }

                        Err(quiche::h3::Error::Done) => {
                            break;
                        }

                        Err(e) => {
                            error!("HTTP/3 processing failed: {e:?}");

                            break;
                        }
                    }
                }
            }

            // TODO: update tun state based on capsule protocol state
            if self.capsule_state.updated {
                tun.abort();
                drop(tun);
                drop(tx_quic_to_tun);
                (tx_quic_to_tun, rx_quic_to_tun) = mpsc::channel::<Vec<u8>>(1000);
                tun = tun::Tun::new("tun0", tx_tun_to_quic.clone(), 1350)?;

                tun.addresses.clear();
                for addr in &self.capsule_state.addresses {
                    tun.addresses.push(addr.clone());
                }
                self.capsule_state.updated = false;
                tun.start(rx_quic_to_tun, cancel_token.clone()).await?;
                info!("TUN device updated with new addresses, {:?}", tun.addresses);
            }

            if self.capsule_state.stream_established {
                // Send initial capsules if not already sent
                if !self.capsule_state.address_requested {
                    self.send_initial_capsules()?;
                    info!("sent initial capsules to establish tunnel");
                    self.capsule_state.address_requested = true;
                }
            }

            // Check if connection is established
            if self.conn.is_established() && self.capsule_state.tunnel_established {
                // Receive datagrams from QUIC and forward to TUN
                while let Ok(len) = self.conn.dgram_recv(&mut buf) {
                    trace!("received {} bytes from QUIC datagram", len);
                    if tx_quic_to_tun.send(buf[..len].to_vec()).await.is_err() {
                        info!("TUN channel closed, stopping datagram forwarding");
                        break;
                    }
                }
            }

            // Send any pending QUIC packets
            loop {
                let (write, send_info) = match self.conn.send(&mut buf) {
                    Ok(v) => v,
                    Err(quiche::Error::Done) => break,
                    Err(e) => {
                        debug!("send failed: {:?}", e);
                        break;
                    }
                };

                if self
                    .tx_quic_to_udp
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

        cancel_token.cancel();

        if let Some(tun_handle) = tun.handle.take() {
            let _ = tokio::time::timeout(std::time::Duration::from_secs(2), tun_handle).await;
        }

        info!("QUIC connection handler exiting");
        Ok(())
    }

    fn check_response(headers: &[quiche::h3::Header]) -> bool {
        // Handle response headers and start capsule protocol
        let mut capsule_protocol = None;
        let mut status = None;
        for hdr in headers {
            match hdr.name() {
                b":status" => status = Some(hdr.value()),
                b"capsule-protocol" => capsule_protocol = Some(hdr.value()),
                _ => (),
            }
        }

        match (status, capsule_protocol) {
            (Some(b"200"), Some(b"?1")) => (),
            _ => {
                return false;
            }
        };
        true
    }

    fn send_initial_capsules(&mut self) -> Result<()> {
        let stream_id = self.capsule_state.stream_id;
        // Send Address Request capsule
        let addr_req = AddressRequestCapsule {
            addresses: vec![RequestedAddress {
                request_id: 1,
                ip_net: IpNet::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 32).unwrap(),
            }],
        };
        let capsule = Capsule::AddressRequest(addr_req);
        let mut buf = vec![0u8; 100];
        let mut octets_mut = octets::OctetsMut::with_slice(&mut buf);
        capsule.append(&mut octets_mut).unwrap();
        let payload_len = octets_mut.off();
        self.h3_conn
            .as_mut()
            .unwrap()
            .send_body(&mut self.conn, stream_id, &buf[..payload_len], false)
            .unwrap();
        Ok(())
    }

    /// Handles incoming capsule data.
    fn handle_capsule_data(&mut self, stream_id: u64, data: &[u8]) -> Result<usize> {
        info!(
            "{} got capsule data on stream id {}: {:?}",
            self.conn.trace_id(),
            stream_id,
            data
        );
        if self.capsule_state.stream_id != stream_id {
            error!(
                "{} received capsule data on unknown stream id {}",
                self.conn.trace_id(),
                stream_id
            );
            return Err(anyhow!("unknown stream id"));
        }

        // parse capsule data here
        let mut octets = Octets::with_slice(data);
        let capsule = Capsule::parse(&mut octets)?;
        match capsule {
            Capsule::AddressAssign(assign_capsule) => {
                info!("received AddressAssign capsule: {:?}", assign_capsule);
                self.capsule_state.addresses.clear();
                self.capsule_state.updated = true;

                for addr in assign_capsule.addresses {
                    self.capsule_state.addresses.push(addr.ip_net);
                }
                self.capsule_state.tunnel_established = true;
            }
            Capsule::AddressRequest(addr_req_capsule) => {
                info!("received AddressRequest capsule: {:?}", addr_req_capsule);
            }
            Capsule::RouteAdvertisement(route_advertisement_capsule) => {
                info!(
                    "received RouteAdvertisement capsule: {:?}",
                    route_advertisement_capsule
                );
            }
        }

        Ok(octets.off())
    }
}

pub fn hdrs_to_strings(hdrs: &[quiche::h3::Header]) -> Vec<(String, String)> {
    hdrs.iter()
        .map(|h| {
            let name = String::from_utf8_lossy(h.name()).to_string();
            let value = String::from_utf8_lossy(h.value()).to_string();

            (name, value)
        })
        .collect()
}
