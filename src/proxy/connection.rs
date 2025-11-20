use anyhow::Result;
use ipnet::IpNet;
use octets::{Octets, OctetsMut};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use scion_proto::address::IsdAsn;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::vec;
use tokio::sync::{Mutex, mpsc};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, trace, warn};

use crate::connect_ip::capsule_protocol::{
    CapsuleProtocolState, handle_capsule_data, prepare_address_and_route_assignment,
};
use crate::connect_ip::request::{build_response, headers_to_strings};
use crate::net::quic::{DEFAULT_TIMEOUT, KEEPALIVE_INTERVAL, MAX_DATAGRAM_SIZE};
use crate::net::{UdpPacket, check_packet_src_dst, return_subnet, tun};
use crate::proxy::CLIENT_CHANNEL_CAPACITY;

struct PartialResponse {
    headers: Option<Vec<quiche::h3::Header>>,
    body: Vec<u8>,
    written: usize,
}

pub struct Connection {
    pub conn: quiche::Connection,
    pub scid: quiche::ConnectionId<'static>,
    pub h3_conn: Option<quiche::h3::Connection>,
    pub local_isd_as: IsdAsn,
    pub remote_isd_as: IsdAsn,
    pub rx_udp_to_quic: mpsc::Receiver<UdpPacket>,
    pub tx_quic_to_udp: mpsc::Sender<UdpPacket>,
    pub tun_name: String,
    available_addresses: Arc<Mutex<Vec<IpNet>>>,
    partial_responses: HashMap<u64, PartialResponse>,
    assign_addresses_and_routes_done: bool,
    capsule_state: CapsuleProtocolState,
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
            tun_name,
            available_addresses,
            partial_responses: HashMap::new(),
            assign_addresses_and_routes_done: false,
            capsule_state: CapsuleProtocolState {
                stream_id: None,
                local_addresses: vec![],
                remote_addresses: vec![],
                local_routes: routes,
                remote_routes: vec![],
            },
        }
    }

    pub async fn handle_client_connection(mut self) -> Result<()> {
        info!("starting connection handler with TUN {}", self.tun_name);
        // Create cancellation token for clean shutdown
        let cancel_token = CancellationToken::new();

        // Create TUN interface for this connection
        let (mut tx_quic_to_tun, rx_quic_to_tun) =
            mpsc::channel::<Vec<u8>>(CLIENT_CHANNEL_CAPACITY);
        let (tx_tun_to_quic, mut rx_tun_to_quic) =
            mpsc::channel::<Vec<u8>>(CLIENT_CHANNEL_CAPACITY);
        let mut tun = tun::Tun::new(
            &self.tun_name,
            tx_tun_to_quic,
            (MAX_DATAGRAM_SIZE - 50).try_into().unwrap(), // 12 bytes QUIC header, 16 bytes aead, at most 16 bytes datagram format
        )?;

        let (tx_address_updates, rx_address_updates) = mpsc::channel::<tun::AddressUpdate>(10);
        tun.start(rx_quic_to_tun, rx_address_updates, cancel_token.clone())
            .await?;

        let mut buf = [0; MAX_DATAGRAM_SIZE];
        let mut packet_buf: Vec<UdpPacket> = Vec::with_capacity(10); // buffer for incoming UDP packets. Used for processing multiple packets at once.
        let mut keepalive_interval =
            tokio::time::interval(std::time::Duration::from_millis(KEEPALIVE_INTERVAL));

        loop {
            packet_buf.clear();
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
                        self.conn.send_ack_eliciting().unwrap();
                        trace!("sending keepalive for connection {:?}", self.scid);
                    }
                }

                // Handle incoming UDP packets
                num_packets = self.rx_udp_to_quic.recv_many(&mut packet_buf, 10) => {
                    self.process_udp_packets(&mut packet_buf, num_packets, &mut tx_quic_to_tun, &tx_address_updates).await?;
                }

                // Handle outgoing IP packets from TUN
                Some(ip_packet) = rx_tun_to_quic.recv() => {
                    self.process_tun_packet(ip_packet).await?;
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

                let src =
                    scion_proto::address::SocketAddr::from_std(self.local_isd_as, send_info.from);
                let dst =
                    scion_proto::address::SocketAddr::from_std(self.remote_isd_as, send_info.to);

                self.tx_quic_to_udp
                    .send(UdpPacket {
                        data: buf[..write].to_vec(),
                        src,
                        dst,
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

        // TODO: return addresses also if connection fails before releasing them
        for addr in self.capsule_state.remote_addresses.iter() {
            info!("Releasing address {}", addr);
            return_subnet(&self.available_addresses, *addr).await;
        }

        Ok(())
    }

    async fn process_udp_packets(
        &mut self,
        packet_buf: &mut [UdpPacket],
        num_packets: usize,
        tx_quic_to_tun: &mut mpsc::Sender<Vec<u8>>,
        tx_address_updates: &mpsc::Sender<tun::AddressUpdate>,
    ) -> Result<()> {
        let mut buf = [0; MAX_DATAGRAM_SIZE];
        for packet in packet_buf.iter_mut().take(num_packets) {
            let src_ip_addr = packet.src.local_address().unwrap();
            let dst_ip_addr = packet.dst.local_address().unwrap();
            let recv_info = quiche::RecvInfo {
                from: src_ip_addr,
                to: dst_ip_addr,
            };

            // Process the packet
            if let Err(e) = self.conn.recv(&mut packet.data, recv_info) {
                // TODO: handle specific errors
                error!("recv failed: {:?}, recv_info: {:?}", e, recv_info);
                continue;
            }
        }

        // Quiche checks if a provided certificate is valid and aborts if not. However, we need to check if the peer provided one at all.
        if self.conn.peer_cert().is_none() {
            warn!("no client certificate provided by {:?}", self.scid);
            // TODO: should we close the connection or wait for some time (~1s) before closing?
            // At the moment we expect the client to always provide a certificate immediately.
            self.conn.close(true, 0x100, b"peer certificate required")?;
            return Ok(());
        }

        // Handle HTTP/3 connection establishment and process HTTP/3 data
        self.handle_http3_connection(tx_address_updates).await?;

        // Handle initial address assignment and route advertisement
        if self.h3_conn.is_some()
            && self.capsule_state.stream_id.is_some()
            && !self.assign_addresses_and_routes_done
        {
            let mut octets = OctetsMut::with_slice(&mut buf);
            let assigned_address = prepare_address_and_route_assignment(
                &mut self.capsule_state,
                self.available_addresses.clone(),
                &mut octets,
            )
            .await?;

            if let Some(assigned_address) = assigned_address {
                tx_address_updates
                    .send(tun::AddressUpdate::AddRoute(assigned_address))
                    .await?;
            }

            let payload_len = octets.off();
            if payload_len == 0 {
                error!("{} no capsule prepared, not sending", self.conn.trace_id());
                return Ok(());
            }
            self.h3_conn.as_mut().unwrap().send_body(
                &mut self.conn,
                self.capsule_state.stream_id.unwrap(),
                &buf[..payload_len],
                false,
            )?;

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
                } else if let Some(ipv6) = Ipv6Packet::new(&buf[packet_start..len]) {
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

    async fn process_tun_packet(&mut self, ip_packet: Vec<u8>) -> Result<()> {
        let (src, dst) = if let Some(ipv4) = Ipv4Packet::new(&ip_packet)
            && ipv4.get_version() == 4
        {
            (
                IpAddr::V4(ipv4.get_source()),
                IpAddr::V4(ipv4.get_destination()),
            )
        } else if let Some(ipv6) = Ipv6Packet::new(&ip_packet)
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

        if self.conn.is_established() && self.capsule_state.stream_id.is_some() {
            let mut buf = [0; MAX_DATAGRAM_SIZE];
            let mut octets = OctetsMut::with_slice(&mut buf);

            // The datagram format is:
            // - varint: quarter stream id (stream_id / 4)
            // - varint: context_id (must be 0)
            // - bytes: IP packet
            octets.put_varint(self.capsule_state.stream_id.unwrap() / 4)?;
            octets.put_varint(0)?;
            octets.put_bytes(&ip_packet)?;
            let len = octets.off();
            if let Err(e) = self.conn.dgram_send(&buf[..len]) {
                error!("dgram_send failed: {:?}", e);
            }
        } else {
            debug!("connection not established yet, dropping packet");
        }
        Ok(())
    }

    async fn handle_http3_connection(
        &mut self,
        tx_address_updates: &mpsc::Sender<tun::AddressUpdate>,
    ) -> Result<()> {
        let mut buf = [0; MAX_DATAGRAM_SIZE];

        // Setup HTTP/3 connection if not already done
        if (self.conn.is_in_early_data() || self.conn.is_established()) && self.h3_conn.is_none() {
            let mut h3_config = quiche::h3::Config::new().unwrap();
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
            loop {
                let http3_conn = self.h3_conn.as_mut().unwrap();
                match http3_conn.poll(&mut self.conn) {
                    Ok((stream_id, quiche::h3::Event::Headers { list, .. })) => {
                        if self.capsule_state.stream_id.is_some() {
                            error!(
                                "{} got headers after successful request on stream id {}. Closing connection.",
                                self.conn.trace_id(),
                                stream_id
                            );
                            self.conn
                                .close(true, 0x100, b"headers on unknown stream")
                                .unwrap();
                            continue;
                        }
                        self.handle_request(stream_id, &list);
                    }

                    Ok((stream_id, quiche::h3::Event::Data)) => {
                        trace!(
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
                            let mut consumed = 0;
                            while consumed < read {
                                consumed += handle_capsule_data(
                                    stream_id,
                                    &buf[consumed..read],
                                    &mut self.capsule_state,
                                    &mut self.conn,
                                    &mut self.h3_conn,
                                    &self.available_addresses,
                                    tx_address_updates,
                                )
                                .await?;
                            }
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

                    Ok((_prioritized_element_id, quiche::h3::Event::PriorityUpdate)) => (),

                    Ok((_goaway_id, quiche::h3::Event::GoAway)) => (),

                    Err(quiche::h3::Error::Done) => {
                        break;
                    }

                    Err(e) => {
                        error!("{} HTTP/3 error {:?}", self.conn.trace_id(), e);
                        break;
                    }
                }
            }
        }
        Ok(())
    }

    /// Handles incoming HTTP/3 requests.
    fn handle_request(&mut self, stream_id: u64, headers: &[quiche::h3::Header]) {
        debug!(
            "{} got request {:?} on stream id {}",
            self.conn.trace_id(),
            headers_to_strings(headers),
            stream_id
        );

        let headers = build_response(headers);
        let http3_conn = self.h3_conn.as_mut().unwrap();

        match http3_conn.send_response(&mut self.conn, stream_id, &headers, false) {
            Ok(v) => v,

            Err(quiche::h3::Error::StreamBlocked) => {
                let response = PartialResponse {
                    headers: Some(headers),
                    body: vec![],
                    written: 0,
                };

                self.partial_responses.insert(stream_id, response);
                return;
            }

            Err(e) => {
                error!("{} stream send failed {:?}", self.conn.trace_id(), e);
                return;
            }
        }
        self.capsule_state.stream_id = Some(stream_id);
    }

    /// Handles newly writable streams. This is quiche boilerplate for handling partial writes.
    fn handle_writable(&mut self, stream_id: u64) {
        let http3_conn = match &mut self.h3_conn {
            Some(v) => v,

            None => {
                error!(
                    "{} no HTTP/3 connection for writable stream {}",
                    self.conn.trace_id(),
                    stream_id
                );
                return;
            }
        };

        if !self.partial_responses.contains_key(&stream_id) {
            return;
        }

        let resp = self.partial_responses.get_mut(&stream_id).unwrap();

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

        resp.headers = None;
        let body = &resp.body[resp.written..];
        let written = match http3_conn.send_body(&mut self.conn, stream_id, body, false) {
            Ok(v) => v,

            Err(quiche::h3::Error::Done) => 0,

            Err(e) => {
                self.partial_responses.remove(&stream_id);

                error!("{} stream send failed {:?}", self.conn.trace_id(), e);
                return;
            }
        };

        resp.written += written;

        if resp.written == resp.body.len() {
            self.partial_responses.remove(&stream_id);
        }
    }
}
