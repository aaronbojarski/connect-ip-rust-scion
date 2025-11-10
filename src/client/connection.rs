use anyhow::Result;
use ipnet::IpNet;
use octets::{Octets, OctetsMut};
use pnet::packet::ipv4::Ipv4Packet;
use quiche::h3::NameValue;
use ring::rand::{SecureRandom, SystemRandom};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use tokio::sync::{Mutex, mpsc};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, trace};

use crate::client::MAX_DATAGRAM_SIZE;
use crate::connect_ip::capsule::{AddressRequestCapsule, Capsule, RequestedAddress};
use crate::connect_ip::capsule_protocol::{
    CapsuleProtocolState, assign_addresses_and_routes, handle_capsule_data,
};
use crate::net::{UdpPacket, tun};

#[derive(Debug, Eq, PartialEq)]
enum StreamStatus {
    Initialized,
    RequestSent,
    TunnelEstablished,
}

pub struct Connection {
    conn: quiche::Connection,
    h3_conn: Option<quiche::h3::Connection>,
    rx_udp_to_quic: mpsc::Receiver<UdpPacket>,
    tx_quic_to_udp: mpsc::Sender<UdpPacket>,
    tun_name: String,
    available_addresses: Arc<Mutex<Vec<IpNet>>>,
    stream_state: StreamStatus,
    capsule_state: CapsuleProtocolState,
    assign_address_done: bool,
    request_address_done: bool,
}

impl Connection {
    pub fn new(
        server_name: String,
        local_addr: SocketAddr,
        remote: SocketAddr,
        rx_udp_to_quic: mpsc::Receiver<UdpPacket>,
        tx_quic_to_udp: mpsc::Sender<UdpPacket>,
        tun_name: String,
        available_addresses: Arc<Mutex<Vec<IpNet>>>,
        routes: Vec<IpNet>,
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
            assign_address_done: false,
            request_address_done: false,
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
        let (tx_quic_to_tun, rx_quic_to_tun) = mpsc::channel::<Vec<u8>>(1000);
        let (tx_tun_to_quic, mut rx_tun_to_quic) = mpsc::channel::<Vec<u8>>(1000);

        let mut tun = tun::Tun::new(&self.tun_name, tx_tun_to_quic.clone(), 1350)?;
        let (mut tx_address_updates, rx_address_updates) = mpsc::channel::<tun::AddressUpdate>(100);
        tun.start(rx_quic_to_tun, rx_address_updates, cancel_token.clone())
            .await?;

        // Send initial packet
        let (write, send_info) = self.conn.send(&mut buf).expect("initial send failed");
        self.tx_quic_to_udp
            .send(UdpPacket {
                data: buf[..write].to_vec(),
                src: send_info.from,
                dst: send_info.to,
            })
            .await?;

        let mut keepalive_interval = tokio::time::interval(std::time::Duration::from_secs(5));
        loop {
            let timeout = self.conn.timeout();
            tokio::select! {
                // Connection timeout
                _ = tokio::time::sleep(timeout.unwrap_or(std::time::Duration::from_secs(24 * 60 * 60))) => {
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
                Some(packet) = self.rx_udp_to_quic.recv() => {
                    self.process_udp_packet(packet, tx_quic_to_tun.clone(), &mut tx_address_updates).await?;
                }

                // Outgoing IP packets from TUN
                Some(ip_packet) = rx_tun_to_quic.recv() => {
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

        // Graceful shutdown of TUN task
        cancel_token.cancel();
        if let Some(tun_handle) = tun.handle.take() {
            let _ = tokio::time::timeout(std::time::Duration::from_secs(2), tun_handle).await;
        }

        info!("QUIC connection handler exiting");
        Ok(())
    }

    async fn process_udp_packet(
        &mut self,
        packet: UdpPacket,
        tx_quic_to_tun: mpsc::Sender<Vec<u8>>,
        tx_address_updates: &mut mpsc::Sender<tun::AddressUpdate>,
    ) -> Result<()> {
        let recv_info = quiche::RecvInfo {
            from: packet.src,
            to: packet.dst,
        };

        if let Err(e) = self.conn.recv(&mut packet.data.clone(), recv_info) {
            debug!("recv failed: {:?}", e);
            return Ok(());
        }

        // Handle HTTP/3 connection establishment and process HTTP/3 data
        self.handle_http3(tx_address_updates).await?;

        // Handle capsule protocol (initial address assignment and route advertisement)
        self.handle_capsule_protocol(tx_address_updates).await?;

        // Handle datagrams and forward to TUN if tunnel is established
        if self.conn.is_established() && self.stream_state == StreamStatus::TunnelEstablished {
            // Receive datagrams from QUIC and forward to TUN
            let mut buf = vec![0; MAX_DATAGRAM_SIZE];
            while let Ok(len) = self.conn.dgram_recv(&mut buf) {
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

    async fn handle_http3(
        &mut self,
        tx_address_updates: &mut mpsc::Sender<tun::AddressUpdate>,
    ) -> Result<()> {
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

        // Create a new HTTP/3 connection once the QUIC connection is established.
        if self.conn.is_established() && self.h3_conn.is_none() {
            self.h3_conn = Some(
                quiche::h3::Connection::with_transport(&mut self.conn, &h3_config)
                    .expect("Unable to create HTTP/3 connection, check the server's uni stream limit and window size"),
            );
        }

        // Send HTTP requests.
        if let Some(h3_conn) = &mut self.h3_conn {
            if self.stream_state == StreamStatus::Initialized {
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
                            hdrs_to_strings(&list),
                            stream_id
                        );
                        // TODO: Drop connection if another stream already exists
                        if Self::check_response(&list) {
                            // self.capsule_state.stream_id = Some(stream_id);
                            self.stream_state = StreamStatus::TunnelEstablished;
                        } else {
                            error!("unexpected response from server, closing connection");
                            self.conn
                                .close(true, 0x100, b"unexpected response")
                                .unwrap();
                        }
                    }

                    Ok((stream_id, quiche::h3::Event::Data)) => {
                        trace!(
                            "{} got data on stream id {}",
                            self.conn.trace_id(),
                            stream_id
                        );
                        let mut buf = vec![0; MAX_DATAGRAM_SIZE];
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
        Ok(())
    }

    async fn handle_capsule_protocol(
        &mut self,
        tx_address_updates: &mut mpsc::Sender<tun::AddressUpdate>,
    ) -> Result<()> {
        if self.request_address_done == false
            && self.stream_state == StreamStatus::TunnelEstablished
        {
            self.send_address_request()?;
            info!("sent initial capsules to establish tunnel");
            self.request_address_done = true;
        }

        if !self.assign_address_done
            && self.stream_state == StreamStatus::TunnelEstablished
            && self.capsule_state.stream_id.is_some()
        {
            assign_addresses_and_routes(
                &mut self.capsule_state,
                &mut self.conn,
                &mut self.h3_conn,
                &mut self.available_addresses,
                tx_address_updates,
            )
            .await?;
            self.assign_address_done = true;
        }
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
