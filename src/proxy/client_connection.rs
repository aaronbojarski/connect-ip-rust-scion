use anyhow::{Result, anyhow};
use ipnet::IpNet;
use octets::Octets;
use pnet::packet::ipv4::Ipv4Packet;
use quiche::h3::NameValue;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::process::Command;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, trace};

use crate::connect_ip::capsule::{
    AddressAssignCapsule, AssignedAddress, Capsule, RouteAdvertisement, RouteAdvertisementCapsule,
};
use crate::net::{UdpPacket, tun};
use crate::proxy::MAX_DATAGRAM_SIZE;

struct PartialResponse {
    headers: Option<Vec<quiche::h3::Header>>,
    body: Vec<u8>,
    written: usize,
}
struct CapsuleProtocolState {
    stream_id: Option<u64>,
    /// addresses we assigned to the client
    client_addresses: Vec<IpNet>,
    /// addresses assigned to us by the client (site to site)
    proxy_addresses: Vec<IpNet>,
    /// routes we advertise to the client
    local_routes: Vec<IpNet>,
    /// routes the client advertised to us
    remote_routes: Vec<IpNet>,
}

pub struct ClientConnection {
    pub conn: quiche::Connection,
    pub scid: quiche::ConnectionId<'static>,
    pub h3_conn: Option<quiche::h3::Connection>,
    pub remote_addr: SocketAddr,
    pub rx_udp_to_quic: mpsc::Receiver<UdpPacket>,
    pub tx_quic_to_udp: mpsc::Sender<UdpPacket>,
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
    ) -> Self {
        ClientConnection {
            conn,
            scid,
            h3_conn: None,
            remote_addr,
            rx_udp_to_quic,
            tx_quic_to_udp,
            partial_responses: HashMap::new(),
            assign_addresses_and_routes_done: false,
            capsule_state: CapsuleProtocolState {
                stream_id: None,
                client_addresses: vec![
                    IpNet::new(IpAddr::V4(Ipv4Addr::new(10, 248, 1, 180)), 32).unwrap(),
                ],
                proxy_addresses: vec![],
                local_routes: vec![
                    IpNet::new(IpAddr::V4(Ipv4Addr::new(10, 248, 2, 0)), 24).unwrap(),
                ],
                remote_routes: vec![],
            },
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
        // Create cancellation token for clean shutdown
        let cancel_token = CancellationToken::new();

        // Create TUN interface for this connection
        let (mut tx_quic_to_tun, rx_quic_to_tun) = mpsc::channel::<Vec<u8>>(1000);
        let (tx_tun_to_quic, mut rx_tun_to_quic) = mpsc::channel::<Vec<u8>>(1000);
        let mut tun = tun::Tun::new(&tun_name, tx_tun_to_quic, 1350)?;

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

            // Assign addresses and routes to client (capsule protocol)
            if self.h3_conn.is_some() && !self.assign_addresses_and_routes_done {
                if let Some(stream_id) = self.capsule_state.stream_id {
                    self.assign_addresses_and_routes(stream_id).await?;
                    self.assign_addresses_and_routes_done = true;
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
        match self.conn.recv(&mut packet.data.clone(), recv_info) {
            Ok(_) => {
                // debug!("processed {} bytes", packet.data.len());
            }
            Err(e) => {
                debug!("recv failed: {:?}", e);
                return Ok(());
            }
        }

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
                        info!(
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
                                consumed += self
                                    .handle_capsule_data(
                                        stream_id,
                                        &buf[consumed..read].to_vec(),
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

        // Handle datagrams if connection is established
        // TODO: only forward if actually connected and data on correct stream
        if self.conn.is_established() && !self.conn.is_in_early_data() {
            // Receive datagrams from QUIC and forward to TUN
            while let Ok(len) = self.conn.dgram_recv(buf) {
                debug!("received {} bytes from QUIC datagram", len);

                if let Some(ipv4) = Ipv4Packet::new(&buf[..len]) {
                    let src = ipv4.get_source();
                    let dest = ipv4.get_destination();
                    info!(
                        "forwarding IP packet to TUN: {} -> {}, {} bytes",
                        src, dest, len
                    );
                }

                tx_quic_to_tun.send(buf[..len].to_vec()).await?;
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

        if self.conn.is_established() {
            if let Err(e) = self.conn.dgram_send(&ip_packet) {
                debug!("dgram_send failed: {:?}", e);
            }
        } else {
            debug!("connection not established yet, dropping packet");
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

    /// Handles incoming capsule data.
    async fn handle_capsule_data(
        &mut self,
        stream_id: u64,
        data: &[u8],
        tx_address_updates: &mut mpsc::Sender<tun::AddressUpdate>,
    ) -> Result<usize> {
        info!(
            "{} got capsule data on stream id {}: {:?}",
            self.conn.trace_id(),
            stream_id,
            data
        );
        if self.capsule_state.stream_id != Some(stream_id) {
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
                info!(
                    "received AddressAssign capsule: {:?}",
                    assign_capsule.addresses
                );
                // Remove old addresses as they are no longer valid
                for addr in self.capsule_state.proxy_addresses.iter() {
                    tx_address_updates
                        .send(tun::AddressUpdate::Remove(addr.clone()))
                        .await?;
                }
                self.capsule_state.proxy_addresses.clear();

                // Add new addresses
                for addr in assign_capsule.addresses {
                    tx_address_updates
                        .send(tun::AddressUpdate::Add(addr.ip_net))
                        .await?;
                    self.capsule_state.proxy_addresses.push(addr.ip_net);
                }
            }
            Capsule::AddressRequest(request_capsule) => {
                info!(
                    "received AddressRequest capsule: {:?}",
                    request_capsule.addresses
                );

                let mut assigned_addresses = vec![];
                for addr in request_capsule.addresses {
                    // TODO: properly assign addresses
                    let assigned_addr = AssignedAddress {
                        request_id: addr.request_id,
                        ip_net: IpNet::new(IpAddr::V4(Ipv4Addr::new(10, 248, 2, 180)), 32).unwrap(),
                    };
                    info!("requested address: {:?}", addr.ip_net);
                    assigned_addresses.push(assigned_addr);
                }

                let address_assign_capsule = AddressAssignCapsule {
                    addresses: assigned_addresses,
                };
                let capsule = Capsule::AddressAssign(address_assign_capsule);
                let mut buf = vec![0u8; 1000];
                let mut octets_mut = octets::OctetsMut::with_slice(&mut buf);
                capsule.append(&mut octets_mut).unwrap();
            }
            Capsule::RouteAdvertisement(route_capsule) => {
                info!(
                    "received RouteAdvertisement capsule: {:?}",
                    route_capsule.routes
                );
                // TODO: add some validation here

                // remove old routes
                for route in self.capsule_state.remote_routes.iter() {
                    let status = Command::new("ip")
                        .args(&["route", "del", &route.to_string(), "dev", "tun0"])
                        .status()?;
                    info!("Removed route {} with status {:?}", route, status);
                }
                self.capsule_state.remote_routes.clear();

                // add new routes
                for route in route_capsule.routes {
                    let status = Command::new("ip")
                        .args(&["route", "add", &route.ip_net.to_string(), "dev", "tun0"])
                        .status()?;
                    info!("Added route {} with status {:?}", route.ip_net, status);
                    self.capsule_state.remote_routes.push(route.ip_net);
                }
            }
        }

        Ok(octets.off())
    }

    async fn assign_addresses_and_routes(&mut self, stream_id: u64) -> Result<()> {
        info!(
            "{} assigning addresses and routes to client",
            self.conn.trace_id()
        );

        let mut buf = vec![0u8; 1000];
        let mut octets_mut = octets::OctetsMut::with_slice(&mut buf);

        // Assign addresses to client
        let mut assigned_addresses = vec![];
        for addr in &self.capsule_state.client_addresses {
            info!("assigning address to client: {}", addr);
            let assigned_address = AssignedAddress {
                request_id: 0,
                ip_net: addr.clone(),
            };
            assigned_addresses.push(assigned_address);

            let status = Command::new("ip")
                .args(&["route", "add", &addr.to_string(), "dev", "tun7"])
                .status()?;
            info!("Added route {} with status {:?}", addr, status);
        }

        let address_assign_capsule = AddressAssignCapsule {
            addresses: assigned_addresses,
        };
        let capsule = Capsule::AddressAssign(address_assign_capsule);
        capsule.append(&mut octets_mut)?;

        // Advertise route
        let mut routes = vec![];
        for route in &self.capsule_state.local_routes {
            info!("advertising route to client: {}", route);
            routes.push(RouteAdvertisement {
                ip_net: route.clone(),
                proto: 0,
            });
        }
        let route_advertisement_capsule = RouteAdvertisementCapsule { routes: routes };
        let capsule = Capsule::RouteAdvertisement(route_advertisement_capsule);
        capsule.append(&mut octets_mut)?;

        let payload_len = octets_mut.off();
        self.h3_conn
            .as_mut()
            .unwrap()
            .send_body(&mut self.conn, stream_id, &buf[..payload_len], false)
            .unwrap();

        Ok(())
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
