use anyhow::{Result, anyhow};
use ipnet::IpNet;
use octets::{Octets, OctetsMut};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use ring::rand::{SecureRandom, SystemRandom};
use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::{Mutex, mpsc};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, trace, warn};

use crate::client::{CHANNEL_CAPACITY, MAX_DATAGRAM_SIZE};
use crate::connect_ip::capsule::{
    AddressRequestCapsule, Capsule, CapsuleError, DatagramCapsule, RequestedAddress,
};
use crate::connect_ip::capsule_protocol::{
    RoutingState, handle_capsule_data, prepare_address_and_route_assignment,
};
use crate::connect_ip::request::{build_request, check_response, headers_to_strings};
use crate::net::quic::{DEFAULT_TIMEOUT, KEEPALIVE_INTERVAL};
use crate::net::tun::MAX_TUN_MTU;
use crate::net::{UdpPacket, ZERO_IPV4_ADDRESS, check_packet_src_dst, tun};

const SEND_BUFFER_SIZE: usize = 65535; // bytes
const RCV_BUFFER_SIZE: usize = 65535; // bytes
const RCV_MANY_CAPACITY: usize = 10; // number of packets
const SEND_ADDRESS_REQUEST_AFTER: std::time::Duration = std::time::Duration::from_secs(2);

pub struct Connection {
    local: scion_proto::address::SocketAddr,
    remote: scion_proto::address::SocketAddr,
    conn: quiche::Connection,
    h3_conn: Option<quiche::h3::Connection>,
    rx_udp_to_quic: mpsc::Receiver<UdpPacket>,
    tx_quic_to_udp: mpsc::Sender<UdpPacket>,
    tun_name: String,
    tun_mtu: u16,
    available_addresses: Arc<Mutex<Vec<IpNet>>>,
    capsule_state: RoutingState,
    tunnel_established: bool,
    assigned_addresses: bool,
    requested_address: bool,
    address_request_timer: std::time::Instant,
    remaining_data: Vec<u8>,
    remaining_sending_data: Vec<u8>,
}

impl Connection {
    pub fn new(
        server_name: String,
        mut quic_config: quiche::Config,
        local: scion_proto::address::SocketAddr,
        remote: scion_proto::address::SocketAddr,
        rx_udp_to_quic: mpsc::Receiver<UdpPacket>,
        tx_quic_to_udp: mpsc::Sender<UdpPacket>,
        tun_name: String,
        tun_mtu: u16,
        available_addresses: Arc<Mutex<Vec<IpNet>>>,
        routes: Vec<IpNet>,
    ) -> Result<Self> {
        // Generate a random source connection ID for the connection.
        let mut scid = [0; quiche::MAX_CONN_ID_LEN];
        if let Err(e) = SystemRandom::new().fill(&mut scid[..]) {
            return Err(anyhow::anyhow!("failed to generate scid: {:?}", e));
        }
        let scid = quiche::ConnectionId::from_ref(&scid);

        // Create a QUIC connection and initiate handshake.
        let conn = quiche::connect(
            Some(&server_name),
            &scid,
            local.local_address().ok_or(anyhow::anyhow!(
                "failed to get local address from {:?}",
                local
            ))?,
            remote.local_address().ok_or(anyhow::anyhow!(
                "failed to get remote address from {:?}",
                remote
            ))?,
            &mut quic_config,
        )?;

        info!(
            "connecting to {:} from {:} with scid {:?}",
            remote, local, scid
        );

        Ok(Connection {
            local,
            remote,
            conn,
            h3_conn: None,
            rx_udp_to_quic,
            tx_quic_to_udp,
            tun_name,
            tun_mtu,
            available_addresses,
            capsule_state: RoutingState {
                stream_id: None,
                remote_addresses: vec![],
                local_addresses: vec![],
                local_routes: routes,
                remote_routes: vec![],
            },
            tunnel_established: false,
            assigned_addresses: false,
            requested_address: false,
            address_request_timer: std::time::Instant::now(),
            remaining_data: Vec::with_capacity(RCV_BUFFER_SIZE),
            remaining_sending_data: Vec::with_capacity(SEND_BUFFER_SIZE),
        })
    }

    pub async fn start_connection_handling(
        &mut self,
        cancel_token: CancellationToken,
    ) -> Result<()> {
        let mut buf = [0; MAX_DATAGRAM_SIZE];

        // Channels between TUN and QUIC tasks. Contents are IP packets.
        let (mut tx_quic_to_tun, rx_quic_to_tun) = mpsc::channel::<Vec<u8>>(CHANNEL_CAPACITY);
        let (tx_tun_to_quic, mut rx_tun_to_quic) = mpsc::channel::<Vec<u8>>(CHANNEL_CAPACITY);

        let mut tun = tun::Tun::new(&self.tun_name, tx_tun_to_quic.clone(), self.tun_mtu)?;
        let (tx_tun_configuration, rx_tun_configuration) =
            mpsc::channel::<tun::TunConfiguration>(CHANNEL_CAPACITY);
        tun.start(rx_quic_to_tun, rx_tun_configuration, cancel_token.clone())
            .await?;

        // Send initial packet
        let (write, send_info) = self.conn.send(&mut buf)?;
        self.tx_quic_to_udp
            .send(UdpPacket {
                data: buf[..write].to_vec(),
                src: scion_proto::address::SocketAddr::from_std(
                    self.local.isd_asn(),
                    send_info.from,
                ),
                dst: scion_proto::address::SocketAddr::from_std(
                    self.remote.isd_asn(),
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
                    self.process_udp_packets(&mut udp_packet_buf, num_packets, &mut tx_quic_to_tun, &tx_tun_configuration).await?;
                }

                // Handle outgoing IP packets from TUN
                num_packets = rx_tun_to_quic.recv_many(&mut tun_packet_buf, RCV_MANY_CAPACITY) => {
                    for packet in tun_packet_buf.iter().take(num_packets) {
                        self.process_tun_packet(packet).await?;
                    }
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

            if !self.remaining_sending_data.is_empty() {
                let to_send = self.remaining_sending_data.split_off(0);
                if let Some(stream_id) = self.capsule_state.stream_id {
                    match self.h3_conn.as_mut().unwrap().send_body(
                        &mut self.conn,
                        stream_id,
                        &to_send,
                        false,
                    ) {
                        Ok(sent) => {
                            debug!("send_body sent {} bytes on stream {}", sent, stream_id);
                            if sent < to_send.len() {
                                debug!(
                                    "only sent {} out of {} bytes, storing remaining",
                                    sent,
                                    to_send.len()
                                );
                                self.remaining_sending_data
                                    .extend_from_slice(&to_send[sent..]);
                            }
                        }
                        Err(quiche::h3::Error::Done) => {
                            self.remaining_sending_data.extend_from_slice(&to_send);
                        }
                        Err(e) => {
                            error!("send_body failed: {:?}", e);
                            return Err(anyhow!("send_body failed: {:?}", e));
                        }
                    }
                } else {
                    warn!("no stream id for sending data, dropping");
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
                            self.local.isd_asn(),
                            send_info.from,
                        ),
                        dst: scion_proto::address::SocketAddr::from_std(
                            self.remote.isd_asn(),
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

        // Graceful shutdown of TUN task
        cancel_token.cancel();
        if let Some(tun_handle) = tun.handle.take() {
            let _ = tokio::time::timeout(std::time::Duration::from_secs(2), tun_handle).await;
        }

        info!("QUIC connection handler exiting");
        Ok(())
    }

    async fn process_udp_packets(
        &mut self,
        packet_buf: &mut [UdpPacket],
        num_packets: usize,
        tx_quic_to_tun: &mut mpsc::Sender<Vec<u8>>,
        tx_tun_configuration: &mpsc::Sender<tun::TunConfiguration>,
    ) -> Result<()> {
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
        self.handle_http3(tx_tun_configuration, tx_quic_to_tun)
            .await?;

        // Handle address negotiation (initial address assignment and route advertisement)
        self.handle_address_negotiation(tx_tun_configuration)
            .await?;

        // Handle datagrams and forward to TUN if tunnel is established
        if self.conn.is_established() && self.tunnel_established {
            // Receive datagrams from QUIC and forward to TUN
            let mut buf = [0; MAX_DATAGRAM_SIZE];
            while let Ok(len) = self.conn.dgram_recv(&mut buf) {
                let mut octets = Octets::with_slice(&buf[..len]);
                let stream_id = octets.get_varint()? * 4;
                let context_id = octets.get_varint()?;
                let packet_start = octets.off();

                if self.capsule_state.stream_id != Some(stream_id) {
                    error!(
                        "{} received datagram on unknown stream id {}",
                        self.conn.trace_id(),
                        stream_id
                    );
                    continue;
                }

                if context_id != 0 {
                    error!(
                        "{} received datagram with unknown context id {}",
                        self.conn.trace_id(),
                        context_id
                    );
                    continue;
                }

                let (src, dst) = if let Some(ipv4) = Ipv4Packet::new(&buf[packet_start..len])
                    && ipv4.get_version() == 4
                {
                    (
                        IpAddr::V4(ipv4.get_source()),
                        IpAddr::V4(ipv4.get_destination()),
                    )
                } else if let Some(ipv6) = Ipv6Packet::new(&buf[packet_start..len])
                    && ipv6.get_version() == 6
                {
                    (
                        IpAddr::V6(ipv6.get_source()),
                        IpAddr::V6(ipv6.get_destination()),
                    )
                } else {
                    error!("received non-IP packet in datagram, dropping");
                    continue;
                };

                debug!(
                    "received IP packet from QUIC connection: {} -> {}, {} bytes",
                    src,
                    dst,
                    len - packet_start
                );

                if check_packet_src_dst(
                    src,
                    dst,
                    &self.capsule_state.remote_addresses,
                    &self.capsule_state.remote_routes,
                    &self.capsule_state.local_addresses,
                    &self.capsule_state.local_routes,
                ) {
                    tx_quic_to_tun.send(buf[packet_start..len].to_vec()).await?;
                } else {
                    debug!(
                        "dropping packet from peer with invalid src/dst: {} -> {}",
                        src, dst
                    );
                }
            }
        }

        Ok(())
    }

    async fn process_tun_packet(&mut self, ip_packet: &Vec<u8>) -> Result<()> {
        let mut buf = [0; MAX_TUN_MTU + 32]; // extra space for capsule overhead
        let (src, dst) = if let Some(ipv4) = Ipv4Packet::new(ip_packet)
            && ipv4.get_version() == 4
        {
            (
                IpAddr::V4(ipv4.get_source()),
                IpAddr::V4(ipv4.get_destination()),
            )
        } else if let Some(ipv6) = Ipv6Packet::new(ip_packet)
            && ipv6.get_version() == 6
        {
            (
                IpAddr::V6(ipv6.get_source()),
                IpAddr::V6(ipv6.get_destination()),
            )
        } else {
            error!("received non-IP packet from tun, dropping");
            return Ok(());
        };

        debug!(
            "received IP packet from TUN: {} -> {}, {} bytes",
            src,
            dst,
            ip_packet.len()
        );

        if !check_packet_src_dst(
            src,
            dst,
            &self.capsule_state.local_addresses,
            &self.capsule_state.local_routes,
            &self.capsule_state.remote_addresses,
            &self.capsule_state.remote_routes,
        ) {
            debug!(
                "dropping packet from TUN with invalid src/dst: {} -> {}",
                src, dst
            );
            return Ok(());
        }

        let datagram = false;

        if self.conn.is_established()
            && let Some(stream_id) = self.capsule_state.stream_id
        {
            if datagram {
                let mut octets = OctetsMut::with_slice(&mut buf);
                octets.put_varint(stream_id / 4)?;
                octets.put_varint(0)?;
                octets.put_bytes(ip_packet)?;
                let len = octets.off();
                if let Err(e) = self.conn.dgram_send(&buf[..len]) {
                    error!("dgram_send failed: {:?}", e);
                }
            } else {
                let mut datagram_data = [0u8; MAX_TUN_MTU + 8]; // extra space for context ID
                let mut datagram_octets = OctetsMut::with_slice(&mut datagram_data);
                datagram_octets.put_varint(0)?;
                datagram_octets.put_bytes(ip_packet)?;
                let len_datagram = datagram_octets.off();
                let datagram_capsule = DatagramCapsule {
                    data: datagram_data[..len_datagram].to_vec(),
                };
                let capsule = Capsule::Datagram(datagram_capsule);
                let mut octets = OctetsMut::with_slice(&mut buf);
                capsule.append(&mut octets)?;
                let len = octets.off();
                if self.remaining_sending_data.len() + len > SEND_BUFFER_SIZE {
                    debug!(
                        "too much remaining data to send ({} bytes), dropping packet",
                        self.remaining_sending_data.len() + len
                    );
                    return Ok(());
                }
                self.remaining_sending_data.extend_from_slice(&buf[..len]);
            }
        } else {
            debug!("connection not established yet, dropping packet");
        }
        Ok(())
    }

    async fn handle_http3(
        &mut self,
        tx_tun_configuration: &mpsc::Sender<tun::TunConfiguration>,
        tx_quic_to_tun: &mut mpsc::Sender<Vec<u8>>,
    ) -> Result<()> {
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
            && self.capsule_state.stream_id.is_none()
        {
            let req = build_request("localhost".to_string(), "/vpn".to_string(), self.tun_mtu);
            debug!("sending HTTP request {req:?}");
            let stream_id = h3_conn.send_request(&mut self.conn, &req, false)?;
            self.capsule_state.stream_id = Some(stream_id);
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
                        if Some(stream_id) != self.capsule_state.stream_id {
                            error!(
                                "{} got headers on unknown stream id {}. Closing connection.",
                                self.conn.trace_id(),
                                stream_id
                            );
                            self.conn.close(true, 0x100, b"headers on unknown stream")?;
                            break;
                        }
                        let (valid, tun_mtu) = check_response(&list);
                        if valid {
                            self.tunnel_established = true;
                            if let Some(mtu) = tun_mtu {
                                self.tun_mtu = mtu;
                            }
                            tx_tun_configuration
                                .send(tun::TunConfiguration::SetMTU(self.tun_mtu))
                                .await?;
                            info!("connected. negotiated TUN MTU: {}", self.tun_mtu);
                        } else {
                            error!("unexpected response from server, closing connection");
                            self.conn.close(true, 0x100, b"unexpected response")?;
                            break;
                        }
                    }

                    Ok((stream_id, quiche::h3::Event::Data)) => {
                        trace!(
                            "{} got data on stream id {}",
                            self.conn.trace_id(),
                            stream_id
                        );

                        let mut buf = [0; RCV_MANY_CAPACITY * MAX_DATAGRAM_SIZE];

                        while let Ok(read) = self.h3_conn.as_mut().unwrap().recv_body(
                            &mut self.conn,
                            stream_id,
                            &mut buf,
                        ) {
                            trace!("got {read} bytes of response data on stream {stream_id}");
                            self.remaining_data.extend_from_slice(&buf[..read]);

                            let mut consumed = 0;
                            'process_capsule_data: while consumed < self.remaining_data.len() {
                                match handle_capsule_data(
                                    stream_id,
                                    &self.remaining_data[consumed..],
                                    &mut self.capsule_state,
                                    &self.available_addresses,
                                    tx_tun_configuration,
                                    tx_quic_to_tun,
                                    &mut self.remaining_sending_data,
                                )
                                .await
                                {
                                    Ok(len) => {
                                        debug!(
                                            "{} processed capsule data of length {} on stream {}",
                                            self.conn.trace_id(),
                                            len,
                                            stream_id
                                        );
                                        consumed += len;
                                    }
                                    Err(err) if err.is::<CapsuleError>() => {
                                        // Need more data to process capsule. Store remaining data for later processing.
                                        debug!("need more data to process capsule. Err {:?}", err);
                                        break 'process_capsule_data;
                                    }
                                    Err(e) => {
                                        error!(
                                            "{} error handling capsule data: {:?}, closing connection",
                                            self.conn.trace_id(),
                                            e
                                        );
                                        self.conn.close(true, 0x100, b"capsule data error")?;
                                        break 'h3_events;
                                    }
                                }
                            }
                            self.remaining_data = self.remaining_data[consumed..].to_vec();
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
                        self.conn.close(true, 0x100, b"HTTP/3 error")?;
                        break;
                    }
                }
            }
        }
        Ok(())
    }

    async fn handle_address_negotiation(
        &mut self,
        tx_tun_configuration: &mpsc::Sender<tun::TunConfiguration>,
    ) -> Result<()> {
        if self.capsule_state.local_addresses.is_empty()
            && !self.requested_address
            && self.tunnel_established
        {
            // Send request only if no address has been assigned within first second
            if self.address_request_timer.elapsed() > SEND_ADDRESS_REQUEST_AFTER {
                self.send_address_request()?;
                info!("sent address request capsule");
                self.requested_address = true;
            }
        }

        if !self.assigned_addresses
            && self.tunnel_established
            && self.capsule_state.stream_id.is_some()
        {
            let mut buf = [0; 1000];
            let mut octets = OctetsMut::with_slice(&mut buf);
            let assigned_address = prepare_address_and_route_assignment(
                &mut self.capsule_state,
                self.available_addresses.clone(),
                &mut octets,
            )
            .await?;

            if let Some(assigned_address) = assigned_address {
                tx_tun_configuration
                    .send(tun::TunConfiguration::AddRoute(assigned_address))
                    .await?;
            }

            let payload_len = octets.off();
            if payload_len == 0 {
                error!("no capsule prepared, not sending");
                return Ok(());
            }

            self.remaining_sending_data
                .extend_from_slice(&buf[..payload_len]);

            self.assigned_addresses = true;
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
        let mut buf = [0; 30];
        let mut octets_mut = octets::OctetsMut::with_slice(&mut buf);
        capsule.append(&mut octets_mut)?;
        let payload_len = octets_mut.off();
        self.remaining_sending_data
            .extend_from_slice(&buf[..payload_len]);

        Ok(())
    }
}
