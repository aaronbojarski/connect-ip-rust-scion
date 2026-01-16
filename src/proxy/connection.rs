use std::collections::HashMap;
use std::sync::Arc;

use anyhow::{Result, anyhow};
use ipnet::IpNet;
use scion_proto::address::IsdAsn;
use tokio::sync::{Mutex, mpsc};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, info_span, trace, warn};
use tracing_futures::Instrument;
use x509_parser::prelude::{FromDer, X509Certificate};

use crate::connect_ip::request::{build_response, headers_to_strings};
use crate::connect_ip::{self, Endpoint};
use crate::net::quic::{
    DEFAULT_TIMEOUT, HTTP3_STREAM_OVERHEAD, KEEPALIVE_INTERVAL, MAX_DATAGRAM_SIZE,
};
use crate::net::{ForwardingDecision, UdpPacket, tun};
use crate::proxy::{ActiveKnownClient, CLIENT_CHANNEL_CAPACITY};

const RCV_MANY_CAPACITY: usize = 10; // number of packets to receive at once

struct PartialResponse {
    headers: Option<Vec<quiche::h3::Header>>,
}

pub struct Config {
    pub tun_name: String,
    pub local_isd_as: IsdAsn,
    pub remote_isd_as: IsdAsn,
    pub mtu: u16,
    pub routes: Vec<IpNet>,
}

pub struct Connection {
    pub config: Config,
    scid: quiche::ConnectionId<'static>,
    conn: quiche::Connection,
    h3_conn: Option<quiche::h3::Connection>,
    pub connect_ip_endpoint: Option<crate::connect_ip::Endpoint>,
    rx_udp_to_quic: mpsc::Receiver<UdpPacket>,
    tx_quic_to_udp: mpsc::Sender<UdpPacket>,
    tun: Option<tun::Tun>,
    rx_tun_to_quic: mpsc::Receiver<Vec<u8>>,
    tx_quic_to_tun: mpsc::Sender<Vec<u8>>,
    tx_routing_updates: mpsc::Sender<connect_ip::RoutingUpdate>,
    cancel_token: CancellationToken,
    available_addresses: Arc<Mutex<Vec<IpNet>>>,
    active_clients: Arc<Mutex<HashMap<String, ActiveKnownClient>>>,
    partial_responses: HashMap<u64, PartialResponse>,
    assign_addresses_and_routes_done: bool,
    client_cert_timer: std::time::Instant,
    client_cert_processed: bool,
    pub client_cert_subject_cn: Option<String>,
}

impl Connection {
    pub fn new(
        config: Config,
        scid: quiche::ConnectionId<'static>,
        conn: quiche::Connection,
        rx_udp_to_quic: mpsc::Receiver<UdpPacket>,
        tx_quic_to_udp: mpsc::Sender<UdpPacket>,
        cancel_token: CancellationToken,
        available_addresses: Arc<Mutex<Vec<IpNet>>>,
        active_clients: Arc<Mutex<HashMap<String, ActiveKnownClient>>>,
    ) -> Self {
        // Channels between TUN and QUIC tasks. Contents are IP packets.
        let (tx_quic_to_tun, rx_quic_to_tun) = mpsc::channel::<Vec<u8>>(CLIENT_CHANNEL_CAPACITY);
        let (tx_tun_to_quic, rx_tun_to_quic) = mpsc::channel::<Vec<u8>>(CLIENT_CHANNEL_CAPACITY);

        // Channel for TUN routing configuration updates.
        let (tx_routing_updates, rx_routing_updates) =
            mpsc::channel::<connect_ip::RoutingUpdate>(CLIENT_CHANNEL_CAPACITY);

        // Initialize TUN device handler
        let tun = tun::Tun::new(
            &config.tun_name,
            config.mtu,
            tx_tun_to_quic,
            rx_quic_to_tun,
            rx_routing_updates,
            cancel_token.clone(),
        );

        Connection {
            config,
            scid,
            conn,
            h3_conn: None,
            connect_ip_endpoint: None,
            rx_udp_to_quic,
            tx_quic_to_udp,
            tun: Some(tun),
            rx_tun_to_quic,
            tx_quic_to_tun,
            tx_routing_updates,
            cancel_token,
            available_addresses,
            active_clients,
            partial_responses: HashMap::new(),
            assign_addresses_and_routes_done: false,
            client_cert_timer: std::time::Instant::now(),
            client_cert_processed: false,
            client_cert_subject_cn: None,
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
                src: scion_proto::address::SocketAddr::from_std(
                    self.config.local_isd_as,
                    send_info.from,
                ),
                dst: scion_proto::address::SocketAddr::from_std(
                    self.config.remote_isd_as,
                    send_info.to,
                ),
            };

            self.tx_quic_to_udp.send(packet).await?;
        }

        info!(
            "starting connection handler with TUN {}",
            self.config.tun_name
        );

        let mut tun = self.tun.take().unwrap();
        let tun_name = self.config.tun_name.clone();
        let mut tun_handle = tokio::spawn(async move {
            tun.start()
                .instrument(info_span!("tun_handler", tun_name = %tun_name))
                .await
        });

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
                        trace!("sending keepalive");
                    }
                }

                // Handle incoming UDP packets
                num_packets = self.rx_udp_to_quic.recv_many(&mut udp_packet_buf, RCV_MANY_CAPACITY) => {
                    self.process_udp_packets(&mut udp_packet_buf, num_packets).await?;
                }

                // Handle outgoing IP packets from TUN
                num_packets = self.rx_tun_to_quic.recv_many(&mut tun_packet_buf, RCV_MANY_CAPACITY) => {
                    for packet in tun_packet_buf.iter().take(num_packets) {
                        self.process_tun_packet(packet).await?;
                    }
                }

                // TUN handler exited
                tun_result = &mut tun_handle => {
                    match tun_result {
                        Ok(Ok(())) => {
                            info!("TUN device handler closed normally");
                            return Ok(());
                        }
                        Ok(Err(e)) => {
                            error!("TUN device handler failed: {}", e);
                            return Err(anyhow!("TUN device handler failed: {}", e));
                        }
                        Err(e) => {
                            error!("TUN device handler panicked: {}", e);
                            return Err(anyhow!("TUN device handler panicked: {}", e));
                        }
                    }
                }

                _ = self.cancel_token.cancelled() => {
                    info!("cancellation requested, shutting down connection handler");
                    let _ = tokio::time::timeout(std::time::Duration::from_secs(2), tun_handle).await;
                    return Ok(());
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

            if let Some(connect_ip_endpoint) = &mut self.connect_ip_endpoint {
                // Handle routing updates
                while let Some(tun_update) = connect_ip_endpoint.next_routing_update() {
                    self.tx_routing_updates.send(tun_update).await?;
                }

                // Send pending datagrams from Connect-IP endpoint
                while !self.conn.is_dgram_send_queue_full()
                    && let Some(datagram) = connect_ip_endpoint.send_datagram()
                {
                    match self.conn.dgram_send(&datagram) {
                        Ok(()) => {
                            trace!("sent {} bytes datagram via QUIC", datagram.len());
                        }
                        Err(quiche::Error::Done) => {
                            trace!("dgram_send would block, buffering datagram");
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
                        .send_stream_data(&mut buf, stream_capacity - HTTP3_STREAM_OVERHEAD);
                    if sent > 0 {
                        match self.h3_conn.as_mut().unwrap().send_body(
                            &mut self.conn,
                            connect_ip_endpoint.stream_id,
                            &buf[..sent],
                            false,
                        ) {
                            Ok(sent_h3) => {
                                trace!(
                                    "send_body sent {} bytes on stream {}",
                                    sent_h3, connect_ip_endpoint.stream_id
                                );
                                if sent_h3 < sent {
                                    // This should generally not happen, since we checked stream capacity before.
                                    // However, quiche may handle flow control however it wants to. There we handle it.
                                    trace!(
                                        "send_body would block, buffering unsent data, sent {}/{} bytes",
                                        sent_h3, sent
                                    );
                                    connect_ip_endpoint.return_stream_data(&buf[sent_h3..sent]);
                                }
                            }
                            Err(quiche::h3::Error::Done) => {
                                trace!("send_body would block, buffering unsent data");
                                connect_ip_endpoint.return_stream_data(&buf[..sent]);
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

                self.tx_quic_to_udp
                    .send(UdpPacket {
                        data: buf[..write].to_vec(),
                        src: scion_proto::address::SocketAddr::from_std(
                            self.config.local_isd_as,
                            send_info.from,
                        ),
                        dst: scion_proto::address::SocketAddr::from_std(
                            self.config.remote_isd_as,
                            send_info.to,
                        ),
                    })
                    .await?;
            }
        }

        // Graceful shutdown of TUN task
        self.cancel_token.cancel();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), tun_handle).await;

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

        // 1. Check if the client certificate has already been processed
        //    If so, skip re-processing
        // 2. Parse the certificate and get the subject common name
        //    If none is set, just continue processing
        // 3. Check if the client has an open connection
        //    If so, tear down the existing connection and get the routing info for this client

        if !self.client_cert_processed {
            let res = X509Certificate::from_der(self.conn.peer_cert().unwrap());
            match res {
                Ok((_, cert)) => {
                    let cn = cert
                        .tbs_certificate
                        .subject
                        .iter_common_name()
                        .next()
                        .and_then(|cn| cn.as_str().ok())
                        .map(|s| s.to_string());
                    self.client_cert_subject_cn = cn.clone();
                }
                _ => {
                    warn!("failed to parse client certificate");
                }
            }
            if let Some(cn) = &self.client_cert_subject_cn {
                info!("client certificate CN: {}", cn);
                let mut active_clients_guard = self.active_clients.lock().await;

                let existing_connection = active_clients_guard.get(cn).cloned();
                if let Some(existing_client) = existing_connection {
                    info!(
                        "existing connection found for {}, cancelling connection {:?}",
                        cn, existing_client.conn_id
                    );

                    // Remove IP addresses of existing connection from its TUN device
                    if let Err(e) = crate::net::route::flush_ip_addresses(&existing_client.tun_name)
                    {
                        warn!(
                            "failed to flush IP addresses of interface {} for existing connection of {}: {}",
                            existing_client.tun_name, cn, e
                        );
                    } else {
                        info!(
                            "flushed IP addresses of interface {} for existing connection of {}",
                            existing_client.tun_name, cn
                        );
                    }

                    // Remove routes of the existing connection by setting interface down
                    if let Err(e) = crate::net::route::set_interface_down(&existing_client.tun_name)
                    {
                        warn!(
                            "failed to set interface {} down for existing connection of {}: {}",
                            existing_client.tun_name, cn, e
                        );
                    } else {
                        info!(
                            "set interface {} down for existing connection of {}",
                            existing_client.tun_name, cn
                        );
                    }
                    existing_client.cancel_token.cancel();
                }

                active_clients_guard.insert(
                    cn.clone(),
                    ActiveKnownClient {
                        conn_id: self.scid.clone(),
                        tun_name: self.config.tun_name.clone(),
                        cancel_token: self.cancel_token.clone(),
                    },
                );
            }

            self.client_cert_processed = true;
        }

        // Handle HTTP/3 connection establishment and process HTTP/3 data
        self.handle_http3_connection().await?;

        // Handle initial address assignment and route advertisement
        if !self.assign_addresses_and_routes_done
            && let Some(connect_ip_endpoint) = &mut self.connect_ip_endpoint
        {
            connect_ip_endpoint.handle_initial_routing_setup().await?;
            self.assign_addresses_and_routes_done = true;
        }

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
                        if self.connect_ip_endpoint.is_some() {
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

        let (headers, negotiated_mtu, status) = build_response(headers, self.config.mtu);

        if let Err(e) = self
            .tx_routing_updates
            .send(connect_ip::RoutingUpdate::SetMTU(negotiated_mtu))
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

            if status == 200 {
                // Create Connect-IP endpoint for this connection
                let connect_ip_endpoint = Endpoint::new(
                    stream_id,
                    negotiated_mtu,
                    self.available_addresses.clone(),
                    self.config.routes.clone(),
                    self.conn.dgram_max_writable_len().is_some(),
                );

                self.connect_ip_endpoint = Some(connect_ip_endpoint);
                info!(
                    "Connect-IP endpoint established on stream id {} with MTU {}",
                    stream_id, negotiated_mtu
                );
            } else {
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
