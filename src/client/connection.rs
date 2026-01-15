use std::sync::Arc;

use anyhow::{Result, anyhow};
use ipnet::IpNet;
use ring::rand::{SecureRandom, SystemRandom};
use tokio::sync::{Mutex, mpsc};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, trace, warn};

use crate::client::MAX_DATAGRAM_SIZE;
use crate::connect_ip::RoutingUpdates;
use crate::connect_ip::capsule::{AddressRequestCapsule, Capsule, RequestedAddress};
use crate::connect_ip::request::{build_request, check_response, headers_to_strings};
use crate::net::quic::{DEFAULT_TIMEOUT, HTTP3_STREAM_OVERHEAD, KEEPALIVE_INTERVAL};
use crate::net::{ForwardingDecision, UdpPacket, ZERO_IPV4_ADDRESS};

const RCV_MANY_CAPACITY: usize = 10; // number of packets
const SEND_ADDRESS_REQUEST_AFTER: std::time::Duration = std::time::Duration::from_secs(2);

struct TunnelStatus {
    http_request_stream: Option<u64>,
    established: bool,
    addresses_assigned: bool,
    address_requested: bool,
}

pub struct Config {
    pub server_name: String,
    pub quic_config: quiche::Config,
    pub local: scion_proto::address::SocketAddr,
    pub remote: scion_proto::address::SocketAddr,
    pub tun_name: String,
    pub configured_mtu: u16,
    pub routes: Vec<IpNet>,
}

pub struct Connection {
    config: Config,
    conn: quiche::Connection,
    h3_conn: Option<quiche::h3::Connection>,
    connect_ip_endpoint: Option<crate::connect_ip::Endpoint>,
    rx_udp_to_quic: mpsc::Receiver<UdpPacket>,
    tx_quic_to_udp: mpsc::Sender<UdpPacket>,
    tx_tun_configuration: mpsc::Sender<RoutingUpdates>,
    tx_quic_to_tun: mpsc::Sender<Vec<u8>>,
    rx_tun_to_quic: mpsc::Receiver<Vec<u8>>,
    cancel_token: CancellationToken,
    available_addresses: Arc<Mutex<Vec<IpNet>>>,
    tunnel_status: TunnelStatus,
    address_request_timer: std::time::Instant,
}

impl Connection {
    pub fn new(
        mut config: Config,
        rx_udp_to_quic: mpsc::Receiver<UdpPacket>,
        tx_quic_to_udp: mpsc::Sender<UdpPacket>,
        tx_tun_configuration: mpsc::Sender<RoutingUpdates>,
        tx_quic_to_tun: mpsc::Sender<Vec<u8>>,
        rx_tun_to_quic: mpsc::Receiver<Vec<u8>>,
        cancel_token: CancellationToken,
        available_addresses: Arc<Mutex<Vec<IpNet>>>,
    ) -> Result<Self> {
        // Generate a random source connection ID for the connection.
        let mut scid = [0; quiche::MAX_CONN_ID_LEN];
        if let Err(e) = SystemRandom::new().fill(&mut scid[..]) {
            return Err(anyhow::anyhow!("failed to generate scid: {:?}", e));
        }
        let scid = quiche::ConnectionId::from_ref(&scid);

        // Create a QUIC connection and initiate handshake.
        let conn = quiche::connect(
            Some(&config.server_name),
            &scid,
            config.local.local_address().ok_or(anyhow::anyhow!(
                "failed to get local address from {:?}",
                config.local
            ))?,
            config.remote.local_address().ok_or(anyhow::anyhow!(
                "failed to get remote address from {:?}",
                config.remote
            ))?,
            &mut config.quic_config,
        )?;

        info!(
            "connecting to {:} from {:} with scid {:?}",
            config.remote, config.local, scid
        );

        Ok(Connection {
            config,
            conn,
            h3_conn: None,
            connect_ip_endpoint: None,
            rx_udp_to_quic,
            tx_quic_to_udp,
            tx_tun_configuration,
            tx_quic_to_tun,
            rx_tun_to_quic,
            cancel_token,
            available_addresses,
            tunnel_status: TunnelStatus {
                http_request_stream: None,
                established: false,
                addresses_assigned: false,
                address_requested: false,
            },
            address_request_timer: std::time::Instant::now(),
        })
    }

    pub async fn start_connection_handling(&mut self) -> Result<()> {
        let mut buf = [0; MAX_DATAGRAM_SIZE];
        let mut stream_buf = vec![0; 65535];

        // Send initial packet
        let (write, send_info) = self.conn.send(&mut buf)?;
        self.tx_quic_to_udp
            .send(UdpPacket {
                data: buf[..write].to_vec(),
                src: scion_proto::address::SocketAddr::from_std(
                    self.config.local.isd_asn(),
                    send_info.from,
                ),
                dst: scion_proto::address::SocketAddr::from_std(
                    self.config.remote.isd_asn(),
                    send_info.to,
                ),
            })
            .await?;

        let mut udp_packet_buf: Vec<UdpPacket> = Vec::with_capacity(RCV_MANY_CAPACITY); // buffer for incoming UDP packets. Used for processing multiple packets at once.
        let mut tun_packet_buf: Vec<Vec<u8>> = Vec::with_capacity(RCV_MANY_CAPACITY); // buffer for incoming TUN packets. Used for processing multiple packets at once.

        let mut keepalive_interval =
            tokio::time::interval(std::time::Duration::from_millis(KEEPALIVE_INTERVAL));
        loop {
            udp_packet_buf.clear();
            tun_packet_buf.clear();
            let timeout = self
                .conn
                .timeout()
                .unwrap_or(std::time::Duration::from_millis(DEFAULT_TIMEOUT));

            tokio::select! {
                // Connection timeout
                _ = tokio::time::sleep(timeout) => {
                    debug!("connection timeout");
                    self.conn.on_timeout();
                }

                // Connection keepalive
                _ = keepalive_interval.tick() => {
                    if self.conn.is_established() {
                        self.conn.send_ack_eliciting()?;
                        trace!("keepalive tick. time until timeout: {:?}", self.conn.timeout());
                    }
                }

                // Incoming UDP packets (QUIC protocol packets)
                num_packets = self.rx_udp_to_quic.recv_many(&mut udp_packet_buf, RCV_MANY_CAPACITY) => {
                    self.process_udp_packets(&mut udp_packet_buf, num_packets).await?;
                }

                // Handle outgoing IP packets from TUN
                num_packets = self.rx_tun_to_quic.recv_many(&mut tun_packet_buf, RCV_MANY_CAPACITY) => {
                    for packet in tun_packet_buf.iter().take(num_packets) {
                        self.process_tun_packet(packet).await?;
                    }
                }

                _ = self.cancel_token.cancelled() => {
                    info!("cancellation requested, shutting down connection handler");
                    break;
                }
            }

            // Check if connection is closed
            if self.conn.is_closed() {
                info!("connection closed");
                if self.conn.is_timed_out() {
                    warn!("connection hit local idle-timeout");
                }
                if let Some(err) = self.conn.peer_error() {
                    warn!(
                        "peer closed connection (is_app={}, code={}, reason={:?})",
                        err.is_app,
                        err.error_code,
                        String::from_utf8_lossy(&err.reason)
                    );
                }
                debug!("connection stats, {:?}", self.conn.stats());
                break;
            }

            if let Some(connect_ip_endpoint) = &mut self.connect_ip_endpoint {
                // Handle routing updates
                while let Some(tun_update) = connect_ip_endpoint.next_routing_update() {
                    self.tx_tun_configuration.send(tun_update).await?;
                }

                // Send pending datagrams from Connect-IP endpoint
                while !self.conn.is_dgram_send_queue_full()
                    && let Some(datagram) = connect_ip_endpoint.send_datagram()
                {
                    match self.conn.dgram_send(&datagram) {
                        Ok(()) => {
                            debug!("sent {} bytes datagram via QUIC", datagram.len());
                        }
                        Err(quiche::Error::Done) => {
                            debug!("dgram_send would block, buffering datagram");
                            connect_ip_endpoint.return_datagram(&datagram);
                            break;
                        }
                        Err(e) => {
                            error!("dgram_send failed: {:?}", e);
                            return Err(anyhow!("dgram_send failed: {:?}", e));
                        }
                    }
                }

                let stream_capacity = self.conn.stream_capacity(connect_ip_endpoint.stream_id)?;
                if stream_capacity > HTTP3_STREAM_OVERHEAD {
                    let sent = connect_ip_endpoint
                        .send_stream_data(&mut stream_buf, stream_capacity - HTTP3_STREAM_OVERHEAD);
                    if sent > 0 {
                        match self.h3_conn.as_mut().unwrap().send_body(
                            &mut self.conn,
                            connect_ip_endpoint.stream_id,
                            &stream_buf[..sent],
                            false,
                        ) {
                            Ok(sent_h3) => {
                                debug!(
                                    "send_body sent {} bytes on stream {}",
                                    sent_h3, connect_ip_endpoint.stream_id
                                );
                                if sent_h3 < sent {
                                    // This should generally not happen, since we checked stream capacity before.
                                    // However, quiche may handle flow control however it wants to. There we handle it.
                                    debug!(
                                        "send_body would block, buffering unsent data, sent {}/{} bytes",
                                        sent_h3, sent
                                    );
                                    connect_ip_endpoint
                                        .return_stream_data(&stream_buf[sent_h3..sent]);
                                }
                            }
                            Err(quiche::h3::Error::Done) => {
                                debug!("send_body would block, buffering unsent data");
                                connect_ip_endpoint.return_stream_data(&stream_buf[..sent]);
                            }
                            Err(e) => {
                                error!("send_body failed: {:?}", e);
                                return Err(anyhow!("send_body failed: {:?}", e));
                            }
                        }
                    }
                }

                // Handle outgoing TUN packets from Connect-IP endpoint
                while let Some(tun_packet) = connect_ip_endpoint.send_tun_packet() {
                    self.tx_quic_to_tun.send(tun_packet).await?;
                }
            }

            // Send any pending QUIC packets
            loop {
                let (write, send_info) = match self.conn.send(&mut buf) {
                    Ok(v) => v,
                    Err(quiche::Error::Done) => break,
                    Err(e) => {
                        error!("send failed: {:?}", e);
                        break;
                    }
                };

                if self
                    .tx_quic_to_udp
                    .send(UdpPacket {
                        data: buf[..write].to_vec(),
                        src: scion_proto::address::SocketAddr::from_std(
                            self.config.local.isd_asn(),
                            send_info.from,
                        ),
                        dst: scion_proto::address::SocketAddr::from_std(
                            self.config.remote.isd_asn(),
                            send_info.to,
                        ),
                    })
                    .await
                    .is_err()
                {
                    info!("UDP channel closed, cannot send packets");
                    break;
                }
            }
        }

        // Graceful shutdown of remaining tasks
        self.cancel_token.cancel();

        info!("QUIC connection handler exiting");
        Ok(())
    }

    async fn process_udp_packets(
        &mut self,
        packet_buf: &mut [UdpPacket],
        num_packets: usize,
    ) -> Result<()> {
        let mut buf = [0; MAX_DATAGRAM_SIZE];
        for packet in packet_buf.iter_mut().take(num_packets) {
            let recv_info = quiche::RecvInfo {
                from: packet
                    .src
                    .local_address()
                    .ok_or_else(|| anyhow!("invalid src address"))?,
                to: packet
                    .dst
                    .local_address()
                    .ok_or_else(|| anyhow!("invalid dst address"))?,
            };

            self.conn.recv(&mut packet.data, recv_info)?;
        }

        // Handle HTTP/3 connection establishment and process HTTP/3 data
        self.handle_http3().await?;

        // Handle address negotiation (initial address assignment and route advertisement)
        self.handle_address_negotiation().await?;

        // Handle datagrams if connection is established
        if self.conn.is_established() && !self.conn.is_in_early_data() {
            // Receive datagrams from QUIC and forward to TUN
            while let Ok(len) = self.conn.dgram_recv(&mut buf) {
                if let Some(connect_ip_endpoint) = &mut self.connect_ip_endpoint {
                    connect_ip_endpoint.recv_datagram(&buf[..len]).await?;
                } else {
                    debug!("Connect-IP connection not established yet, dropping datagram.");
                }
            }
        }

        Ok(())
    }

    async fn process_tun_packet(&mut self, ip_packet: &[u8]) -> Result<()> {
        if let Some(connect_ip_endpoint) = &mut self.connect_ip_endpoint {
            match connect_ip_endpoint.check_egress_packet(ip_packet) {
                ForwardingDecision::Drop => {
                    debug!("dropping invalid packet from TUN");
                }
                ForwardingDecision::Forward => {
                    connect_ip_endpoint.forward_egress_packet(ip_packet)?;
                }
                ForwardingDecision::RespondWithIcmp(_) => {
                    // For now, we do not send ICMP for invalid tun packets (since this should be handled by the OS)
                }
            }
        } else {
            debug!("Connect-IP connection not established yet, dropping packet.");
        }

        Ok(())
    }

    async fn handle_http3(&mut self) -> Result<()> {
        // Create a new HTTP/3 connection once the QUIC connection is established.
        if self.conn.is_established() && self.h3_conn.is_none() {
            let mut h3_config = quiche::h3::Config::new()?;
            h3_config.enable_extended_connect(true);
            self.h3_conn = Some(quiche::h3::Connection::with_transport(
                &mut self.conn,
                &h3_config,
            )?);
        }

        // Send HTTP requests.
        if let Some(h3_conn) = &mut self.h3_conn
            && self.tunnel_status.http_request_stream.is_none()
        {
            let req = build_request(
                "localhost".to_string(),
                "/vpn".to_string(),
                self.config.configured_mtu,
            );
            debug!("sending HTTP request {req:?}");
            let stream_id = h3_conn.send_request(&mut self.conn, &req, false)?;
            self.tunnel_status.http_request_stream = Some(stream_id);
            debug!("sent CONNECT request on stream {}", stream_id);
        }

        // Process HTTP/3 events.
        if self.h3_conn.is_some() {
            'h3_events: loop {
                let http3_conn = self.h3_conn.as_mut().unwrap();
                match http3_conn.poll(&mut self.conn) {
                    Ok((stream_id, quiche::h3::Event::Headers { list, .. })) => {
                        debug!(
                            "got response headers {:?} on stream id {}",
                            headers_to_strings(&list),
                            stream_id
                        );
                        if Some(stream_id) != self.tunnel_status.http_request_stream {
                            error!(
                                "{} got headers on unknown stream id {}. Closing connection.",
                                self.conn.trace_id(),
                                stream_id
                            );
                            self.conn.close(true, 0x108, b"headers on unknown stream")?;
                            break;
                        }
                        let (valid, tun_mtu) = check_response(&list);
                        if valid {
                            self.tunnel_status.established = true;
                            let tun_mtu = tun_mtu.unwrap_or(self.config.configured_mtu);
                            self.tx_tun_configuration
                                .send(RoutingUpdates::SetMTU(tun_mtu))
                                .await?;

                            info!("connected. negotiated TUN MTU: {}", tun_mtu);

                            // Create Connect-IP endpoint
                            self.connect_ip_endpoint = Some(crate::connect_ip::Endpoint::new(
                                self.tunnel_status.http_request_stream.unwrap(),
                                tun_mtu,
                                self.available_addresses.clone(),
                                self.config.routes.clone(),
                                self.conn.dgram_max_writable_len().is_some(),
                            ));
                        } else {
                            error!("unexpected response from server, closing connection");
                            self.conn.close(true, 0x100, b"unexpected response")?;
                            break;
                        }
                    }

                    Ok((stream_id, quiche::h3::Event::Data)) => {
                        let mut buf = [0; RCV_MANY_CAPACITY * MAX_DATAGRAM_SIZE];

                        while let Ok(read) = self.h3_conn.as_mut().unwrap().recv_body(
                            &mut self.conn,
                            stream_id,
                            &mut buf,
                        ) {
                            trace!("got {read} bytes of response data on stream {stream_id}");

                            if self.connect_ip_endpoint.is_none() {
                                error!(
                                    "got data before successful request on stream id {}. Closing connection.",
                                    stream_id
                                );
                                self.conn.close(true, 0x109, b"data on unknown stream")?;
                                break 'h3_events;
                            }
                            if let Some(connect_ip_endpoint) = &mut self.connect_ip_endpoint {
                                if connect_ip_endpoint.stream_id != stream_id {
                                    error!(
                                        "got data on unknown stream id {}. Closing connection.",
                                        stream_id
                                    );
                                    self.conn.close(true, 0x109, b"data on unknown stream")?;
                                    break 'h3_events;
                                }

                                match connect_ip_endpoint.recv_stream_data(&buf[..read]).await {
                                    Ok(()) => {}
                                    Err(err) => {
                                        error!(
                                            "error handling capsule data: {:?}, closing connection",
                                            err
                                        );
                                        self.conn.close(true, 0x10e, b"capsule data error")?;
                                        break 'h3_events;
                                    }
                                }
                            }
                        }
                    }

                    Ok((_stream_id, quiche::h3::Event::Finished)) => {
                        info!("stream finished, closing connection");
                        self.conn.close(true, 0x100, b"kthxbye")?;
                        break;
                    }

                    Ok((_stream_id, quiche::h3::Event::Reset(e))) => {
                        error!("request was reset by peer with {e}, closing...");
                        self.conn.close(true, 0x100, b"kthxbye")?;
                        break;
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
                        self.conn.close(true, 0x102, b"HTTP/3 error")?;
                        break;
                    }
                }
            }
        }

        Ok(())
    }

    async fn handle_address_negotiation(&mut self) -> Result<()> {
        if let Some(connect_ip_endpoint) = &mut self.connect_ip_endpoint
            && connect_ip_endpoint.routing_state.local_addresses.is_empty()
            && !self.tunnel_status.address_requested
            && self.tunnel_status.established
        {
            // Send request only if no address has been assigned within first second
            if self.address_request_timer.elapsed() > SEND_ADDRESS_REQUEST_AFTER {
                self.send_address_request()?;
                info!("sent address request capsule");
                self.tunnel_status.address_requested = true;
            }
        }

        if !self.tunnel_status.addresses_assigned
            && self.tunnel_status.established
            && let Some(connect_ip_endpoint) = &mut self.connect_ip_endpoint
        {
            connect_ip_endpoint.handle_initial_routing_setup().await?;

            self.tunnel_status.addresses_assigned = true;
        }
        Ok(())
    }

    fn send_address_request(&mut self) -> Result<()> {
        // At the moment we just request one /32 IPv4 address
        let zero_ipnet = IpNet::new_assert(ZERO_IPV4_ADDRESS, 32);
        let addr_req = AddressRequestCapsule {
            addresses: vec![RequestedAddress {
                request_id: 1,
                ip_net: zero_ipnet,
            }],
        };
        let capsule = Capsule::AddressRequest(addr_req);
        self.connect_ip_endpoint
            .as_mut()
            .ok_or_else(|| anyhow!("Connect-IP endpoint not established"))?
            .send_capsule(&capsule, true)?;

        Ok(())
    }
}
