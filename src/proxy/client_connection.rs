use anyhow::Result;
use pnet::packet::ipv4::Ipv4Packet;
use quiche::h3::NameValue;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::net::SocketAddr;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info};

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
    partial_responses: HashMap<u64, PartialResponse>,
}

impl ClientConnection {
    pub fn new(
        conn: quiche::Connection,
        scid: quiche::ConnectionId<'static>,
        remote_addr: SocketAddr,
        rx_udp_to_quic: mpsc::Receiver<UdpPacket>,
        tx_quic_to_udp: mpsc::Sender<UdpPacket>,
    ) -> Self {
        ClientConnection {
            conn,
            scid,
            h3_conn: None,
            remote_addr,
            rx_udp_to_quic,
            tx_quic_to_udp,
            partial_responses: HashMap::new(),
        }
    }

    pub async fn handle_client_connection(
        mut self,
        tun_name: String,
        tun_ip: Ipv4Addr,
    ) -> Result<()> {
        info!(
            "starting connection handler for {:?} with TUN {} ({})",
            self.scid, tun_name, tun_ip
        );

        // Create TUN interface for this connection
        let (tx_quic_to_tun, rx_quic_to_tun) = mpsc::channel::<Vec<u8>>(1000);
        let (tx_tun_to_quic, mut rx_tun_to_quic) = mpsc::channel::<Vec<u8>>(1000);

        let mut tun = tun::Tun::new(&tun_name, tun_ip, 1500);

        // Create cancellation token for clean shutdown
        let cancel_token = CancellationToken::new();
        let tun_handle = tun
            .start(tx_tun_to_quic, rx_quic_to_tun, cancel_token.clone())
            .await?;

        let mut h3_config = quiche::h3::Config::new().unwrap();
        h3_config.enable_extended_connect(true);

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
                        debug!("sending keepalive for connection {:?}", self.scid);
                    }
                }

                // Handle incoming UDP packets (QUIC protocol packets)
                Some(packet) = self.rx_udp_to_quic.recv() => {
                    let recv_info = quiche::RecvInfo {
                        from: packet.src,
                        to: packet.dst,
                    };

                    // Process the packet
                    match self.conn.recv(&mut packet.data.clone(), recv_info) {
                        Ok(_) => {
                            debug!("processed {} bytes", packet.data.len());
                        }
                        Err(e) => {
                            debug!("recv failed: {:?}", e);
                            if self.conn.is_closed() {
                                info!("connection {:?} closed after recv error", self.scid);
                                break;
                            }
                            continue;
                        }
                    }

                     if (self.conn.is_in_early_data() || self.conn.is_established()) &&
                        self.h3_conn.is_none()
                    {
                        debug!(
                            "{} QUIC handshake completed, now trying HTTP/3",
                            self.conn.trace_id()
                        );

                        let h3_conn = match quiche::h3::Connection::with_transport(
                            &mut self.conn,
                            &h3_config,
                        ) {
                            Ok(v) => v,

                            Err(e) => {
                                error!("failed to create HTTP/3 connection: {e}");
                                continue;
                            },
                        };

                        // TODO: sanity check h3 connection before adding to map
                        self.h3_conn = Some(h3_conn);

                        debug!("HTTP/3 connection established");
                    }


                    if self.h3_conn.is_some() {
                        // Handle writable streams.
                        for stream_id in self.conn.writable() {
                            self.handle_writable(stream_id);
                        }

                        // Process HTTP/3 events.
                        loop {
                            let http3_conn = self.h3_conn.as_mut().unwrap();

                            match http3_conn.poll(&mut self.conn) {
                                Ok((
                                    stream_id,
                                    quiche::h3::Event::Headers { list, .. },
                                )) => {
                                    self.handle_request(
                                        stream_id,
                                        &list,
                                        "examples/root",
                                    );
                                },

                                Ok((stream_id, quiche::h3::Event::Data)) => {
                                    info!(
                                        "{} got data on stream id {}",
                                        self.conn.trace_id(),
                                        stream_id
                                    );
                                },

                                Ok((_stream_id, quiche::h3::Event::Finished)) => (),

                                Ok((_stream_id, quiche::h3::Event::Reset { .. })) => (),

                                Ok((
                                    _prioritized_element_id,
                                    quiche::h3::Event::PriorityUpdate,
                                )) => (),

                                Ok((_goaway_id, quiche::h3::Event::GoAway)) => (),

                                Err(quiche::h3::Error::Done) => {
                                    break;
                                },

                                Err(e) => {
                                    error!("{} HTTP/3 error {:?}", self.conn.trace_id(), e);
                                    break;
                                },
                            }
                        }
                    }


                    // Handle datagrams if connection is established
                    if self.conn.is_established() && !self.conn.is_in_early_data() {
                        // Receive datagrams from QUIC and forward to TUN
                        while let Ok(len) = self.conn.dgram_recv(&mut buf) {
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

                    if self.conn.is_established() {
                        match self.conn.dgram_send(&ip_packet) {
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

            if self.conn.is_closed() {
                info!("connection {:?} closed", self.scid);
                break;
            }
        }

        info!(
            "connection {:?} handler exiting, stopping TUN interface",
            self.scid
        );
        cancel_token.cancel();

        // Wait for TUN task to finish with timeout
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), tun_handle).await;

        Ok(())
    }

    /// Handles incoming HTTP/3 requests.
    fn handle_request(&mut self, stream_id: u64, headers: &[quiche::h3::Header], root: &str) {
        info!(
            "{} got request {:?} on stream id {}",
            self.conn.trace_id(),
            hdrs_to_strings(headers),
            stream_id
        );

        // Check if HTTP/3 connection exists before proceeding
        if self.h3_conn.is_none() {
            error!(
                "{} no HTTP/3 connection for request on stream {}",
                self.conn.trace_id(),
                stream_id
            );
            return;
        }

        let (headers, body) = self.build_response(root, headers);

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

        let written = match http3_conn.send_body(&mut self.conn, stream_id, &body, true) {
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
    }

    /// Builds an HTTP/3 response given a request.
    fn build_response(
        &mut self,
        root: &str,
        request: &[quiche::h3::Header],
    ) -> (Vec<quiche::h3::Header>, Vec<u8>) {
        let mut method = None;
        let mut protocol = None;

        // Look for the request's path and method.
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

    /// Handles newly writable streams.
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

        debug!("{} stream {} is writable", self.conn.trace_id(), stream_id);

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

        let written = match http3_conn.send_body(&mut self.conn, stream_id, body, true) {
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
