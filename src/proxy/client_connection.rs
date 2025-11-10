use anyhow::Result;
use ipnet::IpNet;
use octets::{Octets, OctetsMut};
use pnet::packet::ipv4::Ipv4Packet;
use quiche::h3::NameValue;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::vec;
use tokio::sync::{Mutex, mpsc};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, trace};

use crate::connect_ip::capsule_protocol::{
    CapsuleProtocolState, assign_addresses_and_routes, handle_capsule_data,
};
use crate::net::{UdpPacket, tun};
use crate::proxy::MAX_DATAGRAM_SIZE;

struct PartialResponse {
    headers: Option<Vec<quiche::h3::Header>>,
    body: Vec<u8>,
    written: usize,
}

pub struct ClientConnection {
    pub conn: quiche::Connection,
    pub scid: quiche::ConnectionId<'static>,
    pub h3_conn: Option<quiche::h3::Connection>,
    pub remote_addr: SocketAddr,
    pub rx_udp_to_quic: mpsc::Receiver<UdpPacket>,
    pub tx_quic_to_udp: mpsc::Sender<UdpPacket>,
    pub tun_name: String,
    available_addresses: Arc<Mutex<Vec<IpNet>>>,
    partial_responses: HashMap<u64, PartialResponse>,
    assign_addresses_and_routes_done: bool,
    capsule_state: CapsuleProtocolState,
}

impl ClientConnection {
    pub fn new(
        conn: quiche::Connection,
        scid: quiche::ConnectionId<'static>,
        remote_addr: SocketAddr,
        rx_udp_to_quic: mpsc::Receiver<UdpPacket>,
        tx_quic_to_udp: mpsc::Sender<UdpPacket>,
        tun_name: String,
        available_addresses: Arc<Mutex<Vec<IpNet>>>,
        routes: Vec<IpNet>,
    ) -> Self {
        ClientConnection {
            conn,
            scid,
            h3_conn: None,
            remote_addr,
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
        info!(
            "starting connection handler for {:?} with TUN {}",
            self.scid, self.tun_name
        );
        // Create cancellation token for clean shutdown
        let cancel_token = CancellationToken::new();

        // Create TUN interface for this connection
        let (mut tx_quic_to_tun, rx_quic_to_tun) = mpsc::channel::<Vec<u8>>(1000);
        let (tx_tun_to_quic, mut rx_tun_to_quic) = mpsc::channel::<Vec<u8>>(1000);
        let mut tun = tun::Tun::new(&self.tun_name, tx_tun_to_quic, 1350)?;

        let (mut tx_address_updates, rx_address_updates) = mpsc::channel::<tun::AddressUpdate>(100);
        tun.start(rx_quic_to_tun, rx_address_updates, cancel_token.clone())
            .await?;

        let mut buf = [0; MAX_DATAGRAM_SIZE];
        let mut keepalive_interval = tokio::time::interval(std::time::Duration::from_secs(5));

        loop {
            let timeout = self
                .conn
                .timeout()
                .unwrap_or(std::time::Duration::from_secs(60));

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
                Some(packet) = self.rx_udp_to_quic.recv() => {
                    self.process_udp_packet(packet, &mut buf, &mut tx_quic_to_tun, &mut tx_address_updates).await?;
                }

                // Handle outgoing IP packets from TUN
                Some(ip_packet) = rx_tun_to_quic.recv() => {
                    self.process_tun_packet(ip_packet).await?;
                }
            }

            // Check if connection was closed while processing packets
            if self.conn.is_closed() {
                info!("connection {:?} closed", self.scid);
                break;
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

                self.tx_quic_to_udp
                    .send(UdpPacket {
                        data: buf[..write].to_vec(),
                        src: send_info.from,
                        dst: send_info.to,
                    })
                    .await?;
            }
        }

        info!(
            "connection {:?} handler exiting, stopping TUN interface",
            self.scid
        );
        cancel_token.cancel();

        // Wait for TUN task to finish with timeout
        if let Some(tun_handle) = tun.handle.take() {
            let _ = tokio::time::timeout(std::time::Duration::from_secs(2), tun_handle).await;
        }

        Ok(())
    }

    async fn process_udp_packet(
        &mut self,
        packet: UdpPacket,
        buf: &mut [u8],
        tx_quic_to_tun: &mut mpsc::Sender<Vec<u8>>,
        tx_address_updates: &mut mpsc::Sender<tun::AddressUpdate>,
    ) -> Result<()> {
        let recv_info = quiche::RecvInfo {
            from: packet.src,
            to: packet.dst,
        };

        // Process the packet
        if let Err(e) = self.conn.recv(&mut packet.data.clone(), recv_info) {
            debug!("recv failed: {:?}", e);
            return Ok(());
        }

        // Handle HTTP/3 connection establishment and process HTTP/3 data
        self.handle_http3_connection(tx_address_updates, buf)
            .await?;

        // Handle initial address assignment and route advertisement
        if self.h3_conn.is_some()
            && !self.capsule_state.stream_id.is_none()
            && !self.assign_addresses_and_routes_done
        {
            assign_addresses_and_routes(
                &mut self.capsule_state,
                &mut self.conn,
                &mut self.h3_conn,
                &mut self.available_addresses,
                tx_address_updates,
            )
            .await?;
            self.assign_addresses_and_routes_done = true;
        }

        // Handle datagrams if connection is established
        if self.conn.is_established() && !self.conn.is_in_early_data() {
            // Receive datagrams from QUIC and forward to TUN
            while let Ok(len) = self.conn.dgram_recv(buf) {
                debug!("received {} bytes from QUIC datagram", len);
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

                if let Some(ipv4) = Ipv4Packet::new(&buf[packet_start..len]) {
                    let src = ipv4.get_source();
                    let dest = ipv4.get_destination();
                    info!(
                        "forwarding IP packet to TUN: {} -> {}, {} bytes",
                        src,
                        dest,
                        len - packet_start
                    );
                    // TODO: validate packet addresses before sending to TUN
                    tx_quic_to_tun.send(buf[packet_start..len].to_vec()).await?;
                }
            }
        }
        Ok(())
    }

    async fn process_tun_packet(&mut self, ip_packet: Vec<u8>) -> Result<()> {
        if let Some(ipv4) = Ipv4Packet::new(&ip_packet) {
            let src = ipv4.get_source();
            let dest = ipv4.get_destination();
            info!(
                "received IP packet from TUN: {} -> {}, {} bytes",
                src,
                dest,
                ip_packet.len()
            );
        }

        if self.conn.is_established() && self.capsule_state.stream_id.is_some() {
            let mut buf = vec![0u8; MAX_DATAGRAM_SIZE];
            let mut octets = OctetsMut::with_slice(&mut buf);
            octets.put_varint(self.capsule_state.stream_id.unwrap() / 4)?;
            octets.put_varint(0)?;
            octets.put_bytes(&ip_packet)?;
            let len = octets.off();
            if let Err(e) = self.conn.dgram_send(&buf[..len]) {
                debug!("dgram_send failed: {:?}", e);
            }
        } else {
            debug!("connection not established yet, dropping packet");
        }
        Ok(())
    }

    async fn handle_http3_connection(
        &mut self,
        tx_address_updates: &mut mpsc::Sender<tun::AddressUpdate>,
        buf: &mut [u8],
    ) -> Result<()> {
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
                    // TODO: only allow request for one stream per connection
                    Ok((stream_id, quiche::h3::Event::Headers { list, .. })) => {
                        self.handle_request(stream_id, &list);
                    }

                    Ok((stream_id, quiche::h3::Event::Data)) => {
                        trace!(
                            "{} got data on stream id {}",
                            self.conn.trace_id(),
                            stream_id
                        );
                        while let Ok(read) =
                            self.h3_conn
                                .as_mut()
                                .unwrap()
                                .recv_body(&mut self.conn, stream_id, buf)
                        {
                            trace!("got {read} bytes of response data on stream {stream_id}");
                            let mut consumed = 0;
                            while consumed < read {
                                consumed += handle_capsule_data(
                                    stream_id,
                                    &buf[consumed..read].to_vec(),
                                    &mut self.capsule_state,
                                    &mut self.conn,
                                    &mut self.h3_conn,
                                    &mut self.available_addresses,
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
        info!(
            "{} got request {:?} on stream id {}",
            self.conn.trace_id(),
            hdrs_to_strings(headers),
            stream_id
        );

        let (headers, body) = self.build_response(headers);
        let http3_conn = self.h3_conn.as_mut().unwrap();

        match http3_conn.send_response(&mut self.conn, stream_id, &headers, false) {
            Ok(v) => v,

            Err(quiche::h3::Error::StreamBlocked) => {
                let response = PartialResponse {
                    headers: Some(headers),
                    body,
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

        let written = match http3_conn.send_body(&mut self.conn, stream_id, &body, false) {
            Ok(v) => v,

            Err(quiche::h3::Error::Done) => 0,

            Err(e) => {
                error!("{} stream send failed {:?}", self.conn.trace_id(), e);
                return;
            }
        };

        if written < body.len() {
            let response = PartialResponse {
                headers: None,
                body,
                written,
            };

            self.partial_responses.insert(stream_id, response);
        }
        self.capsule_state.stream_id = Some(stream_id);
    }

    /// Builds an HTTP/3 response given a request.
    fn build_response(
        &mut self,
        request: &[quiche::h3::Header],
    ) -> (Vec<quiche::h3::Header>, Vec<u8>) {
        let mut method = None;
        let mut protocol = None;

        for hdr in request {
            match hdr.name() {
                b":protocol" => protocol = Some(hdr.value()),

                b":method" => method = Some(hdr.value()),

                _ => (),
            }
        }

        let (status, body) = match (method, protocol) {
            (Some(b"CONNECT"), Some(b"connect-ip")) => (200, Vec::new()),
            _ => (405, Vec::new()),
        };

        let headers = vec![
            quiche::h3::Header::new(b":status", status.to_string().as_bytes()),
            quiche::h3::Header::new(b"capsule-protocol", "?1".as_bytes()),
        ];

        (headers, body)
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

pub fn hdrs_to_strings(hdrs: &[quiche::h3::Header]) -> Vec<(String, String)> {
    hdrs.iter()
        .map(|h| {
            let name = String::from_utf8_lossy(h.name()).to_string();
            let value = String::from_utf8_lossy(h.value()).to_string();

            (name, value)
        })
        .collect()
}
