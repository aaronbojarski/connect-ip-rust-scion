use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::vec;

use anyhow::{Result, anyhow};
use ipnet::IpNet;
use octets::{Octets, OctetsMut};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use scion_proto::address::IsdAsn;
use tokio::sync::{Mutex, mpsc};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, trace, warn};

use crate::connect_ip::capsule::{Capsule, CapsuleError, DatagramCapsule};
use crate::connect_ip::capsule_protocol::{
    ConnectIPEndpoint, RoutingState, handle_capsule_data, prepare_address_and_route_assignment,
};
use crate::connect_ip::request::{build_response, headers_to_strings};
use crate::net::icmp::build_icmp_response;
use crate::net::quic::{DEFAULT_TIMEOUT, KEEPALIVE_INTERVAL, MAX_DATAGRAM_SIZE};
use crate::net::tun::MAX_TUN_MTU;
use crate::net::{ForwardingDecision, UdpPacket, check_packet_src_dst, tun};
use crate::proxy::CLIENT_CHANNEL_CAPACITY;

const SEND_BUFFER_SIZE: usize = 65535; // bytes
const RCV_BUFFER_SIZE: usize = 65535; // bytes
const RCV_MANY_CAPACITY: usize = 10; // number of packets to receive at once
const MAX_TUN_MTU_FOR_DATAGRAMS: usize = MAX_DATAGRAM_SIZE - 50;
struct PartialResponse {
    headers: Option<Vec<quiche::h3::Header>>,
}

pub struct Connection {
    conn: quiche::Connection,
    scid: quiche::ConnectionId<'static>,
    h3_conn: Option<quiche::h3::Connection>,
    local_isd_as: IsdAsn,
    remote_isd_as: IsdAsn,
    rx_udp_to_quic: mpsc::Receiver<UdpPacket>,
    tx_quic_to_udp: mpsc::Sender<UdpPacket>,
    tx_quic_to_tun: Option<mpsc::Sender<Vec<u8>>>,
    tx_tun_configuration: Option<mpsc::Sender<tun::TunConfiguration>>,
    tun_name: String,
    tun_mtu: u16,
    cancel_token: CancellationToken,
    available_addresses: Arc<Mutex<Vec<IpNet>>>,
    partial_responses: HashMap<u64, PartialResponse>,
    assign_addresses_and_routes_done: bool,
    client_cert_timer: std::time::Instant,
    pub capsule_state: RoutingState,
    remaining_data: Vec<u8>,
    remaining_sending_data: Vec<u8>,
}

impl Connection {
    pub fn new(
        conn: quiche::Connection,
        scid: quiche::ConnectionId<'static>,
        local_isd_as: IsdAsn,
        remote_isd_as: IsdAsn,
        rx_udp_to_quic: mpsc::Receiver<UdpPacket>,
        tx_quic_to_udp: mpsc::Sender<UdpPacket>,
        tun_name: String,
        tun_mtu: u16,
        cancel_token: CancellationToken,
        available_addresses: Arc<Mutex<Vec<IpNet>>>,
        routes: Vec<IpNet>,
    ) -> Self {
        Connection {
            conn,
            scid,
            h3_conn: None,
            local_isd_as,
            remote_isd_as,
            rx_udp_to_quic,
            tx_quic_to_udp,
            tx_quic_to_tun: None,
            tx_tun_configuration: None,
            tun_name,
            tun_mtu,
            cancel_token,
            available_addresses,
            partial_responses: HashMap::new(),
            assign_addresses_and_routes_done: false,
            client_cert_timer: std::time::Instant::now(),
            capsule_state: RoutingState {
                stream_id: None,
                local_addresses: vec![],
                remote_addresses: vec![],
                local_routes: routes,
                remote_routes: vec![],
            },
            remaining_data: Vec::with_capacity(RCV_BUFFER_SIZE),
            remaining_sending_data: Vec::with_capacity(SEND_BUFFER_SIZE),
        }
    }

    pub async fn handle_client_connection(&mut self) -> Result<()> {
        let mut buf = [0; MAX_DATAGRAM_SIZE];

        // Send initial response packets
        loop {
            let (write, send_info) = match self.conn.send(&mut buf) {
                Ok(v) => v,
                Err(quiche::Error::Done) => break,
                Err(e) => {
                    error!("send failed: {:?}", e);
                    break;
                }
            };

            let packet = UdpPacket {
                data: buf[..write].to_vec(),
                src: scion_proto::address::SocketAddr::from_std(self.local_isd_as, send_info.from),
                dst: scion_proto::address::SocketAddr::from_std(self.remote_isd_as, send_info.to),
            };

            self.tx_quic_to_udp.send(packet).await?;
        }

        info!("starting connection handler with TUN {}", self.tun_name);
        // Create cancellation token for clean shutdown
        let cancel_token = CancellationToken::new();

        // Create TUN interface for this connection
        let (tx_quic_to_tun, rx_quic_to_tun) = mpsc::channel::<Vec<u8>>(CLIENT_CHANNEL_CAPACITY);
        let (tx_tun_to_quic, mut rx_tun_to_quic) =
            mpsc::channel::<Vec<u8>>(CLIENT_CHANNEL_CAPACITY);
        let mut tun = tun::Tun::new(&self.tun_name, tx_tun_to_quic, self.tun_mtu)?;

        let (tx_tun_configuration, rx_address_updates) =
            mpsc::channel::<tun::TunConfiguration>(CLIENT_CHANNEL_CAPACITY);
        tun.start(rx_quic_to_tun, rx_address_updates, cancel_token.clone())
            .await?;

        self.tx_quic_to_tun = Some(tx_quic_to_tun.clone());
        self.tx_tun_configuration = Some(tx_tun_configuration.clone());

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
                // Handle connection timeout
                _ = tokio::time::sleep(timeout) => {
                    self.conn.on_timeout();
                }

                // Periodic keepalive
                _ = keepalive_interval.tick() => {
                    if self.conn.is_established() {
                        self.conn.send_ack_eliciting()?;
                        trace!("sending keepalive for connection {:?}", self.scid);
                    }
                }

                // Handle incoming UDP packets
                num_packets = self.rx_udp_to_quic.recv_many(&mut udp_packet_buf, RCV_MANY_CAPACITY) => {
                    self.process_udp_packets(&mut udp_packet_buf, num_packets).await?;
                }

                // Handle outgoing IP packets from TUN
                num_packets = rx_tun_to_quic.recv_many(&mut tun_packet_buf, RCV_MANY_CAPACITY) => {
                    for packet in tun_packet_buf.iter().take(num_packets) {
                        self.process_tun_packet(packet).await?;
                    }
                }

                _ = self.cancel_token.cancelled() => {
                    info!("cancellation requested, shutting down connection handler");
                    break;
                }
            }

            // Check if connection was closed while processing packets
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
                debug!(
                    "having {} bytes of remaining data to send, attempting to send",
                    self.remaining_sending_data.len()
                );
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
                            debug!("send_body would block, storing all {} bytes", to_send.len());
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

                self.tx_quic_to_udp
                    .send(UdpPacket {
                        data: buf[..write].to_vec(),
                        src: scion_proto::address::SocketAddr::from_std(
                            self.local_isd_as,
                            send_info.from,
                        ),
                        dst: scion_proto::address::SocketAddr::from_std(
                            self.remote_isd_as,
                            send_info.to,
                        ),
                    })
                    .await?;
            }
        }

        info!("connection handler exiting, stopping TUN interface",);
        cancel_token.cancel();

        // Wait for TUN task to finish with timeout
        if let Some(tun_handle) = tun.handle {
            let _ = tokio::time::timeout(std::time::Duration::from_secs(2), tun_handle).await;
        }

        Ok(())
    }

    async fn process_udp_packets(
        &mut self,
        packet_buf: &mut [UdpPacket],
        num_packets: usize,
    ) -> Result<()> {
        let mut buf = [0; MAX_DATAGRAM_SIZE];
        for packet in packet_buf.iter_mut().take(num_packets) {
            let src_ip_addr = packet
                .src
                .local_address()
                .ok_or_else(|| anyhow!("Invalid src address."))?;
            let dst_ip_addr = packet
                .dst
                .local_address()
                .ok_or_else(|| anyhow!("Invalid dst address."))?;
            let recv_info = quiche::RecvInfo {
                from: src_ip_addr,
                to: dst_ip_addr,
            };

            // Process the packet
            if let Err(e) = self.conn.recv(&mut packet.data, recv_info) {
                error!("recv failed: {:?}, recv_info: {:?}", e, recv_info);
                continue;
            }
        }

        // Quiche checks if a provided certificate is valid and aborts if not. However, we need to check if the peer provided one at all.
        if self.conn.peer_cert().is_none() {
            debug!("no client certificate provided yet");
            if self.client_cert_timer.elapsed() > std::time::Duration::from_secs(5) {
                warn!("closing connection due to missing client certificate");
                self.conn.close(true, 0x100, b"no client certificate")?;
            }
            return Ok(());
        }

        // Handle HTTP/3 connection establishment and process HTTP/3 data
        self.handle_http3_connection().await?;

        // Handle initial address assignment and route advertisement
        if !self.assign_addresses_and_routes_done && self.capsule_state.stream_id.is_some() {
            let mut octets = OctetsMut::with_slice(&mut buf);
            let assigned_address = prepare_address_and_route_assignment(
                &mut self.capsule_state,
                self.available_addresses.clone(),
                &mut octets,
            )
            .await?;

            if let Some(assigned_address) = assigned_address {
                self.update_tun_interface(tun::TunConfiguration::AddRoute(assigned_address))
                    .await?;
            }

            let payload_len = octets.off();
            if payload_len == 0 {
                error!("{} no capsule prepared, not sending", self.conn.trace_id());
                return Ok(());
            }

            self.remaining_sending_data
                .extend_from_slice(&buf[..payload_len]);

            self.assign_addresses_and_routes_done = true;
        }

        // Handle datagrams if connection is established
        if self.conn.is_established() && !self.conn.is_in_early_data() {
            // Receive datagrams from QUIC and forward to TUN
            while let Ok(len) = self.conn.dgram_recv(&mut buf) {
                let mut octets = Octets::with_slice(&buf[..len]);

                // The datagram format is:
                // - varint: quarter stream id (stream_id / 4)
                // - varint: context_id (must be 0)
                // - bytes: IP packet
                let stream_id = octets.get_varint()? * 4;
                let context_id = octets.get_varint()?;
                let packet_start = octets.off();

                if self.capsule_state.stream_id != Some(stream_id) {
                    error!("received datagram on unknown stream id {}", stream_id);
                    continue;
                }

                if context_id != 0 {
                    error!("received datagram with unknown context id {}", context_id);
                    continue;
                }

                let ip_packet = &buf[packet_start..len];
                match self.check_ingress_packet(ip_packet) {
                    ForwardingDecision::Drop => {
                        debug!("dropping invalid packet from QUIC");
                        continue;
                    }
                    ForwardingDecision::Forward => {
                        self.forward_egress_packet(ip_packet)?;
                    }
                    ForwardingDecision::RespondWithIcmp(icmp_type) => {
                        if let Some(icmp_response) = build_icmp_response(ip_packet, icmp_type) {
                            self.forward_egress_packet(&icmp_response)?;
                        } else {
                            debug!("could not build ICMP error message, dropping packet");
                        }
                    }
                }
            }
        }
        Ok(())
    }

    async fn process_tun_packet(&mut self, ip_packet: &[u8]) -> Result<()> {
        match self.check_egress_packet(ip_packet) {
            ForwardingDecision::Drop => {
                debug!("dropping invalid packet from TUN");
            }
            ForwardingDecision::Forward => {
                self.forward_egress_packet(ip_packet)?;
            }
            ForwardingDecision::RespondWithIcmp(_) => {
                // For now, we do not send ICMP for invalid tun packets (since this should be handled by the OS)
            }
        }

        Ok(())
    }

    async fn handle_http3_connection(&mut self) -> Result<()> {
        let mut buf = [0; RCV_MANY_CAPACITY * MAX_DATAGRAM_SIZE];

        // Setup HTTP/3 connection if not already done
        if (self.conn.is_in_early_data() || self.conn.is_established()) && self.h3_conn.is_none() {
            let mut h3_config = quiche::h3::Config::new()?;
            h3_config.enable_extended_connect(true);
            let h3_conn = match quiche::h3::Connection::with_transport(&mut self.conn, &h3_config) {
                Ok(v) => v,

                Err(e) => {
                    error!("failed to create HTTP/3 connection: {e}");
                    return Ok(());
                }
            };

            self.h3_conn = Some(h3_conn);
            debug!("HTTP/3 connection established");
        }

        // Handle HTTP/3 connection
        if self.h3_conn.is_some() {
            // Handle writable streams.
            for stream_id in self.conn.writable() {
                self.handle_writable(stream_id);
            }

            // Process HTTP/3 events.
            'h3_events: loop {
                let http3_conn = self.h3_conn.as_mut().unwrap();
                match http3_conn.poll(&mut self.conn) {
                    Ok((stream_id, quiche::h3::Event::Headers { list, .. })) => {
                        if self.capsule_state.stream_id.is_some() {
                            error!(
                                "got headers after successful request on stream id {}. Closing connection.",
                                stream_id
                            );
                            self.conn.close(true, 0x108, b"headers on unknown stream")?;
                            continue;
                        }
                        self.handle_request(stream_id, &list).await?;
                    }

                    Ok((stream_id, quiche::h3::Event::Data)) => {
                        while let Ok(read) = self.h3_conn.as_mut().unwrap().recv_body(
                            &mut self.conn,
                            stream_id,
                            &mut buf,
                        ) {
                            if Some(stream_id) != self.capsule_state.stream_id {
                                error!(
                                    "got data on unknown stream id {}. Closing connection.",
                                    stream_id
                                );
                                self.conn.close(true, 0x109, b"data on unknown stream")?;
                                break 'h3_events;
                            }
                            trace!("got {read} bytes of response data on stream {stream_id}");

                            let mut data = self.remaining_data.split_off(0);
                            data.extend_from_slice(&buf[..read]);
                            let mut consumed = 0;
                            'process_capsule_data: while consumed < data.len() {
                                match handle_capsule_data(
                                    &data[consumed..],
                                    &self.available_addresses.clone(),
                                    self,
                                )
                                .await
                                {
                                    Ok(len) => {
                                        trace!(
                                            "processed capsule data of length {} on stream {}",
                                            len, stream_id
                                        );
                                        consumed += len;
                                    }
                                    Err(err) => {
                                        if let Some(capsule_err) =
                                            err.downcast_ref::<CapsuleError>()
                                            && matches!(capsule_err, CapsuleError::Buffer(_))
                                        {
                                            trace!("need more data to process capsule.");
                                            break 'process_capsule_data;
                                        }

                                        error!(
                                            "error handling capsule data: {:?}, closing connection",
                                            err
                                        );
                                        self.conn.close(true, 0x10e, b"capsule data error")?;
                                        break 'h3_events;
                                    }
                                }
                            }
                            self.remaining_data.extend_from_slice(&data[consumed..]);
                        }
                    }

                    Ok((_stream_id, quiche::h3::Event::Finished)) => {
                        info!("stream finished, closing connection");
                        self.conn.close(true, 0x100, b"kthxbye")?;
                    }

                    Ok((_stream_id, quiche::h3::Event::Reset(e))) => {
                        error!("request was reset by peer with {e}, closing...");
                        self.conn.close(true, 0x100, b"kthxbye")?;
                    }

                    Ok((_prioritized_element_id, quiche::h3::Event::PriorityUpdate)) => (),

                    Ok((_goaway_id, quiche::h3::Event::GoAway)) => (),

                    Err(quiche::h3::Error::Done) => {
                        break;
                    }

                    Err(e) => {
                        error!("{} HTTP/3 error {:?}", self.conn.trace_id(), e);
                        self.conn.close(true, 0x102, b"HTTP/3 error")?;
                        break;
                    }
                }
            }
        }
        Ok(())
    }

    /// Handles incoming HTTP/3 requests.
    async fn handle_request(
        &mut self,
        stream_id: u64,
        headers: &[quiche::h3::Header],
    ) -> Result<(), quiche::h3::Error> {
        debug!(
            "got request {:?} on stream id {}",
            headers_to_strings(headers),
            stream_id
        );

        if self.h3_conn.is_none() {
            error!("no HTTP/3 connection for request on stream {}", stream_id);
            return Err(quiche::h3::Error::InternalError);
        }

        let (headers, negotiated_mtu, status) = build_response(headers, self.tun_mtu);
        self.tun_mtu = negotiated_mtu;

        if let Err(e) = self
            .update_tun_interface(tun::TunConfiguration::SetMTU(self.tun_mtu))
            .await
        {
            error!("failed to send MTU update to TUN: {}", e);
        }

        if let Some(http3_conn) = &mut self.h3_conn {
            match http3_conn.send_response(&mut self.conn, stream_id, &headers, false) {
                Ok(v) => v,

                Err(quiche::h3::Error::StreamBlocked) => {
                    let response = PartialResponse {
                        headers: Some(headers),
                    };

                    self.partial_responses.insert(stream_id, response);
                }

                Err(e) => {
                    error!(
                        "{} stream send response failed {:?}",
                        self.conn.trace_id(),
                        e
                    );
                    return Err(e);
                }
            }
            self.capsule_state.stream_id = Some(stream_id);

            if status != 200 {
                error!(
                    "unsupported request on stream id {}, closing connection",
                    stream_id
                );
                self.conn.close(true, 0x100, b"unsupported request")?;
            }
        }
        Ok(())
    }

    /// Handles newly writable streams. This is quiche boilerplate for handling partial writes.
    fn handle_writable(&mut self, stream_id: u64) {
        let http3_conn = match &mut self.h3_conn {
            Some(v) => v,

            None => {
                error!("no HTTP/3 connection for writable stream {}", stream_id);
                return;
            }
        };

        let resp = match self.partial_responses.get_mut(&stream_id) {
            Some(v) => v,

            None => {
                return;
            }
        };

        if let Some(ref headers) = resp.headers {
            match http3_conn.send_response(&mut self.conn, stream_id, headers, false) {
                Ok(_) => (),

                Err(quiche::h3::Error::StreamBlocked) => {
                    return;
                }

                Err(e) => {
                    error!("{} stream send failed {:?}", self.conn.trace_id(), e);
                    return;
                }
            }
        }

        self.partial_responses.remove(&stream_id);
    }
}

impl ConnectIPEndpoint for Connection {
    fn check_ingress_packet(&mut self, packet: &[u8]) -> ForwardingDecision {
        if packet.len() > self.tun_mtu as usize {
            debug!(
                "packet size {} exceeds TUN MTU {}",
                packet.len(),
                self.tun_mtu
            );
            return ForwardingDecision::RespondWithIcmp(crate::net::icmp::IcmpType::PacketTooBig(
                self.tun_mtu as u32,
            ));
        }

        let (src, dst) = if let Some(ipv4) = Ipv4Packet::new(packet)
            && ipv4.get_version() == 4
        {
            (
                IpAddr::V4(ipv4.get_source()),
                IpAddr::V4(ipv4.get_destination()),
            )
        } else if let Some(ipv6) = Ipv6Packet::new(packet) {
            (
                IpAddr::V6(ipv6.get_source()),
                IpAddr::V6(ipv6.get_destination()),
            )
        } else {
            error!("received non-IP packet in datagram, dropping");
            return ForwardingDecision::Drop;
        };

        debug!(
            "received IP packet from QUIC connection: {} -> {}, {} bytes",
            src,
            dst,
            packet.len()
        );

        check_packet_src_dst(
            src,
            dst,
            &self.capsule_state.remote_addresses,
            &self.capsule_state.remote_routes,
            &self.capsule_state.local_addresses,
            &self.capsule_state.local_routes,
        )
    }

    fn check_egress_packet(&mut self, packet: &[u8]) -> ForwardingDecision {
        if packet.len() > self.tun_mtu as usize {
            debug!(
                "packet size {} exceeds TUN MTU {}",
                packet.len(),
                self.tun_mtu
            );
            return ForwardingDecision::RespondWithIcmp(crate::net::icmp::IcmpType::PacketTooBig(
                self.tun_mtu as u32,
            ));
        }

        let (src, dst) = if let Some(ipv4) = Ipv4Packet::new(packet)
            && ipv4.get_version() == 4
        {
            (
                IpAddr::V4(ipv4.get_source()),
                IpAddr::V4(ipv4.get_destination()),
            )
        } else if let Some(ipv6) = Ipv6Packet::new(packet)
            && ipv6.get_version() == 6
        {
            (
                IpAddr::V6(ipv6.get_source()),
                IpAddr::V6(ipv6.get_destination()),
            )
        } else {
            error!("received non-IP packet from tun, dropping");
            return ForwardingDecision::Drop;
        };

        debug!(
            "received IP packet from TUN: {} -> {}, {} bytes",
            src,
            dst,
            packet.len()
        );

        check_packet_src_dst(
            src,
            dst,
            &self.capsule_state.local_addresses,
            &self.capsule_state.local_routes,
            &self.capsule_state.remote_addresses,
            &self.capsule_state.remote_routes,
        )
    }

    async fn forward_ingress_packet(&mut self, packet: &[u8]) -> Result<()> {
        if let Some(tx_quic_to_tun) = &self.tx_quic_to_tun {
            tx_quic_to_tun.send(packet.to_vec()).await?;
        } else {
            error!("no channel to TUN available, dropping packet");
        }

        Ok(())
    }

    fn forward_egress_packet(&mut self, packet: &[u8]) -> Result<()> {
        if self.conn.is_established()
            && let Some(stream_id) = self.capsule_state.stream_id
        {
            let mut buf = [0; MAX_TUN_MTU + 32];
            if self.conn.dgram_max_writable_len().is_some()
                && self.tun_mtu as usize <= MAX_TUN_MTU_FOR_DATAGRAMS
            {
                let mut octets = OctetsMut::with_slice(&mut buf);
                octets.put_varint(stream_id / 4)?;
                octets.put_varint(0)?;
                octets.put_bytes(packet)?;
                let len = octets.off();
                match self.conn.dgram_send(&buf[..len]) {
                    Ok(_) => {}
                    Err(quiche::Error::Done) => {
                        debug!("datagram send queue full, dropping packet");
                    }
                    Err(e) => {
                        error!("failed to send datagram: {:?}", e);
                    }
                }
            } else {
                let mut datagram_data = [0u8; MAX_TUN_MTU + 8];
                let mut datagram_octets = OctetsMut::with_slice(&mut datagram_data);
                datagram_octets.put_varint(0)?;
                datagram_octets.put_bytes(packet)?;
                let len = datagram_octets.off();
                let datagram_capsule = DatagramCapsule {
                    data: datagram_data[..len].to_vec(),
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

    async fn update_tun_interface(&self, update: tun::TunConfiguration) -> Result<()> {
        if let Some(tx_tun_configuration) = &self.tx_tun_configuration {
            tx_tun_configuration.send(update).await?;
        } else {
            error!("no channel to TUN available, cannot update configuration");
        }
        Ok(())
    }

    async fn send_capsule(&mut self, capsule: Capsule) -> Result<()> {
        let mut buf = [0; MAX_TUN_MTU + 32];
        let mut octets = OctetsMut::with_slice(&mut buf);
        capsule.append(&mut octets)?;
        let len = octets.off();
        if self.remaining_sending_data.len() + len > SEND_BUFFER_SIZE {
            debug!(
                "too much remaining data to send ({} bytes), dropping capsule",
                self.remaining_sending_data.len() + len
            );
            return Ok(());
        }
        self.remaining_sending_data.extend_from_slice(&buf[..len]);
        Ok(())
    }

    fn get_routing_state(&self) -> RoutingState {
        self.capsule_state.clone()
    }

    fn set_routing_state(&mut self, state: RoutingState) {
        self.capsule_state = state;
    }
}
