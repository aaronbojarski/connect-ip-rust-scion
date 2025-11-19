use anyhow::Result;
use ipnet::IpNet;
use octets::{Octets, OctetsMut};
use pnet::packet::ipv4::Ipv4Packet;
use ring::rand::{SecureRandom, SystemRandom};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use tokio::sync::{Mutex, mpsc};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, trace, warn};

use crate::client::{CHANNEL_CAPACITY, MAX_DATAGRAM_SIZE};
use crate::connect_ip::capsule::{AddressRequestCapsule, Capsule, RequestedAddress};
use crate::connect_ip::capsule_protocol::{
    CapsuleProtocolState, handle_capsule_data, prepare_address_and_route_assignment,
};
use crate::connect_ip::request::{build_request, check_response, headers_to_strings};
use crate::net::quic::{DEFAULT_TIMEOUT, KEEPALIVE_INTERVAL};
use crate::net::{UdpPacket, check_packet_src_dst, tun};

#[derive(Debug, Eq, PartialEq)]
enum StreamStatus {
    Initialized,
    RequestSent,
    TunnelEstablished,
}

pub struct Connection {
    local: scion_proto::address::SocketAddr,
    remote: scion_proto::address::SocketAddr,
    conn: quiche::Connection,
    h3_conn: Option<quiche::h3::Connection>,
    rx_udp_to_quic: mpsc::Receiver<UdpPacket>,
    tx_quic_to_udp: mpsc::Sender<UdpPacket>,
    tun_name: String,
    available_addresses: Arc<Mutex<Vec<IpNet>>>,
    stream_state: StreamStatus,
    capsule_state: CapsuleProtocolState,
    assigned_addresses: bool,
    requested_address: bool,
    address_request_timer: std::time::Instant,
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
            local.local_address().unwrap(),
            remote.local_address().unwrap(),
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
            available_addresses,
            stream_state: StreamStatus::Initialized,
            capsule_state: CapsuleProtocolState {
                stream_id: None,
                remote_addresses: vec![],
                local_addresses: vec![],
                local_routes: routes,
                remote_routes: vec![],
            },
            assigned_addresses: false,
            requested_address: false,
            address_request_timer: std::time::Instant::now(),
        })
    }

    pub async fn start_connection_handling(
        &mut self,
        cancel_token: CancellationToken,
    ) -> Result<()> {
        let mut buf = [0; MAX_DATAGRAM_SIZE];

        // Channels between TUN and QUIC tasks. Contents are IP packets.
        let (tx_quic_to_tun, rx_quic_to_tun) = mpsc::channel::<Vec<u8>>(CHANNEL_CAPACITY);
        let (tx_tun_to_quic, mut rx_tun_to_quic) = mpsc::channel::<Vec<u8>>(CHANNEL_CAPACITY);

        let mut tun = tun::Tun::new(
            &self.tun_name,
            tx_tun_to_quic.clone(),
            (MAX_DATAGRAM_SIZE - 50).try_into().unwrap(), // 12 bytes QUIC header, 16 bytes aead, at most 16 bytes datagram format
        )?;
        let (tx_address_updates, rx_address_updates) = mpsc::channel::<tun::AddressUpdate>(100);
        tun.start(rx_quic_to_tun, rx_address_updates, cancel_token.clone())
            .await?;

        // Send initial packet
        let (write, send_info) = self.conn.send(&mut buf).expect("initial send failed");
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

        let mut packet_buf: Vec<UdpPacket> = Vec::with_capacity(10);
        let mut keepalive_interval =
            tokio::time::interval(std::time::Duration::from_millis(KEEPALIVE_INTERVAL));
        loop {
            packet_buf.clear();
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
                        self.conn.send_ack_eliciting().unwrap();
                        trace!("keepalive tick. time until timeout: {:?}", self.conn.timeout());
                    }
                }

                // Incoming UDP packets (QUIC protocol packets)
                num_packets = self.rx_udp_to_quic.recv_many(&mut packet_buf, 10) => {
                    self.process_udp_packets(&mut packet_buf, num_packets, &tx_quic_to_tun, &tx_address_updates).await?;
                }

                // Outgoing IP packets from TUN
                Some(ip_packet) = rx_tun_to_quic.recv() => {
                    self.process_tun_packet(ip_packet).await?;
                }
            }

            // Check if connection is closed
            if self.conn.is_closed() {
                info!("connection closed, {:?}", self.conn.stats());
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
        packet_buf: &mut Vec<UdpPacket>,
        num_packets: usize,
        tx_quic_to_tun: &mpsc::Sender<Vec<u8>>,
        tx_address_updates: &mpsc::Sender<tun::AddressUpdate>,
    ) -> Result<()> {
        for i in 0..num_packets {
            let packet = &mut packet_buf[i];
            let recv_info = quiche::RecvInfo {
                from: packet.src.local_address().unwrap(),
                to: packet.dst.local_address().unwrap(),
            };

            if let Err(e) = self.conn.recv(&mut packet.data, recv_info) {
                error!("recv failed: {:?}, recv_info: {:?}", e, recv_info);
                continue;
            }
        }

        // Handle HTTP/3 connection establishment and process HTTP/3 data
        self.handle_http3(tx_address_updates).await?;

        // Handle capsule protocol (initial address assignment and route advertisement)
        self.handle_capsule_protocol(tx_address_updates).await?;

        // Handle datagrams and forward to TUN if tunnel is established
        if self.conn.is_established() && self.stream_state == StreamStatus::TunnelEstablished {
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

                if let Some(ipv4) = Ipv4Packet::new(&buf[packet_start..len]) {
                    let src = ipv4.get_source();
                    let dest = ipv4.get_destination();
                    debug!(
                        "received IP packet from QUIC: {} -> {}, {} bytes",
                        src,
                        dest,
                        len - packet_start
                    );

                    if check_packet_src_dst(
                        IpAddr::V4(src),
                        IpAddr::V4(dest),
                        &self.capsule_state.remote_addresses,
                        &self.capsule_state.remote_routes,
                        &self.capsule_state.local_addresses,
                        &self.capsule_state.local_routes,
                    ) {
                        tx_quic_to_tun.send(buf[packet_start..len].to_vec()).await?;
                    } else {
                        warn!(
                            "dropping packet from peer with invalid src/dst: {} -> {}",
                            src, dest
                        );
                    }
                }
            }
        }

        Ok(())
    }

    async fn process_tun_packet(&mut self, ip_packet: Vec<u8>) -> Result<()> {
        let mut buf = [0; MAX_DATAGRAM_SIZE];
        if let Some(ipv4) = Ipv4Packet::new(&ip_packet) {
            let src = ipv4.get_source();
            let dest = ipv4.get_destination();
            debug!(
                "received IP packet from TUN: {} -> {}, {} bytes",
                src,
                dest,
                ip_packet.len()
            );
            if !check_packet_src_dst(
                IpAddr::V4(src),
                IpAddr::V4(dest),
                &self.capsule_state.local_addresses,
                &self.capsule_state.local_routes,
                &self.capsule_state.remote_addresses,
                &self.capsule_state.remote_routes,
            ) {
                warn!(
                    "dropping packet from TUN with invalid src/dst: {} -> {}",
                    src, dest
                );
                return Ok(());
            }
        } else {
            debug!(
                "received non-IPv4 packet from TUN, {} bytes",
                ip_packet.len()
            );
            return Ok(());
        }

        if self.conn.is_established() && self.capsule_state.stream_id.is_some() {
            let mut octets = OctetsMut::with_slice(&mut buf);
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

    async fn handle_http3(
        &mut self,
        tx_address_updates: &mpsc::Sender<tun::AddressUpdate>,
    ) -> Result<()> {
        // Create a new HTTP/3 connection once the QUIC connection is established.
        if self.conn.is_established() && self.h3_conn.is_none() {
            let mut h3_config = quiche::h3::Config::new().unwrap();
            h3_config.enable_extended_connect(true);
            self.h3_conn = Some(
                quiche::h3::Connection::with_transport(&mut self.conn, &h3_config)
                    .expect("Unable to create HTTP/3 connection, check the server's uni stream limit and window size"),
            );
        }

        // Send HTTP requests.
        if let Some(h3_conn) = &mut self.h3_conn {
            if self.stream_state == StreamStatus::Initialized {
                let req = build_request("localhost".to_string(), "/vpn".to_string());
                info!("sending HTTP request {req:?}");
                let stream_id = h3_conn.send_request(&mut self.conn, &req, false).unwrap();
                self.capsule_state.stream_id = Some(stream_id);
                info!("sent CONNECT request on stream {}", stream_id);
                self.stream_state = StreamStatus::RequestSent;
            }
        }

        // Process HTTP/3 events.
        if self.h3_conn.is_some() {
            loop {
                let http3_conn = self.h3_conn.as_mut().unwrap();
                match http3_conn.poll(&mut self.conn) {
                    Ok((stream_id, quiche::h3::Event::Headers { list, .. })) => {
                        info!(
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
                            self.conn
                                .close(true, 0x100, b"headers on unknown stream")
                                .unwrap();
                            break;
                        }
                        if check_response(&list) {
                            self.stream_state = StreamStatus::TunnelEstablished;
                        } else {
                            error!("unexpected response from server, closing connection");
                            self.conn
                                .close(true, 0x100, b"unexpected response")
                                .unwrap();
                            break;
                        }
                    }

                    Ok((stream_id, quiche::h3::Event::Data)) => {
                        trace!(
                            "{} got data on stream id {}",
                            self.conn.trace_id(),
                            stream_id
                        );
                        let mut buf = [0; MAX_DATAGRAM_SIZE];
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
                        break;
                    }

                    Ok((_stream_id, quiche::h3::Event::Reset(e))) => {
                        error!("request was reset by peer with {e}, closing...");
                        self.conn.close(true, 0x100, b"kthxbye").unwrap();
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
                        break;
                    }
                }
            }
        }
        Ok(())
    }

    async fn handle_capsule_protocol(
        &mut self,
        tx_address_updates: &mpsc::Sender<tun::AddressUpdate>,
    ) -> Result<()> {
        if self.capsule_state.local_addresses.is_empty()
            && self.requested_address == false
            && self.stream_state == StreamStatus::TunnelEstablished
        {
            // Send request only if no address has been assigned within first second
            if self.address_request_timer.elapsed().as_millis() > 1000 {
                self.send_address_request()?;
                info!("sent address request capsule");
                self.requested_address = true;
            }
        }

        if !self.assigned_addresses
            && self.stream_state == StreamStatus::TunnelEstablished
            && self.capsule_state.stream_id.is_some()
        {
            let mut buf = [0; 100];
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

            self.assigned_addresses = true;
        }
        Ok(())
    }

    fn send_address_request(&mut self) -> Result<()> {
        let stream_id = self.capsule_state.stream_id.unwrap();
        // Send Address Request capsule
        let addr_req = AddressRequestCapsule {
            addresses: vec![RequestedAddress {
                request_id: 1,
                ip_net: IpNet::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 32).unwrap(),
            }],
        };
        let capsule = Capsule::AddressRequest(addr_req);
        let mut buf = [0u8; 100];
        let mut octets_mut = octets::OctetsMut::with_slice(&mut buf);
        capsule.append(&mut octets_mut)?;
        let payload_len = octets_mut.off();
        self.h3_conn
            .as_mut()
            .unwrap()
            .send_body(&mut self.conn, stream_id, &buf[..payload_len], false)
            .unwrap();
        Ok(())
    }
}
