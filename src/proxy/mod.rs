pub mod connection;

use anyhow::{Context, Result, anyhow};
use ipnet::IpNet;
use ring::rand::SystemRandom;
use scion_proto::address::IsdAsn;
use scion_stack::scionstack::ScionStackBuilder;
use std::collections::HashMap;
use std::fs;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::{Mutex, mpsc};
use tracing::instrument::Instrument;
use tracing::{debug, error, info, trace, warn};

use crate::net::UdpPacket;
use crate::net::quic::MAX_DATAGRAM_SIZE;
use crate::proxy::connection::Connection;

const TOKEN_PREFIX: &[u8] = b"connect-ip-rust-scion";
const HMAC_TAG_LEN: usize = 32;
const MAIN_CHANNEL_CAPACITY: usize = 10000;
const CLIENT_CHANNEL_CAPACITY: usize = 200;
const UDP_PACKET_BUFFER_SIZE: usize = 65535;

pub struct ProxyConfig {
    pub listen: scion_proto::address::SocketAddr,
    pub endhost_api_address: Option<url::Url>,
    pub snap_token_path: Option<std::path::PathBuf>,
    pub ca_cert_path: std::path::PathBuf,
    pub cert_path: std::path::PathBuf,
    pub key_path: std::path::PathBuf,
    pub routes: Vec<IpNet>,
    pub address_pool: Vec<IpNet>,
    pub tun_mtu: u16,
}

pub struct Proxy {
    config: ProxyConfig,
    token_key: ring::hmac::Key,
    conn_id_seed: ring::hmac::Key,
    connections: Arc<Mutex<HashMap<quiche::ConnectionId<'static>, mpsc::Sender<UdpPacket>>>>,
    available_addresses: Arc<Mutex<Vec<IpNet>>>,
}

impl Proxy {
    pub fn new(config: ProxyConfig) -> Self {
        let available_addresses = Arc::new(Mutex::new(config.address_pool.clone()));
        Proxy {
            config,
            token_key: ring::hmac::Key::generate(ring::hmac::HMAC_SHA256, &SystemRandom::new())
                .unwrap(),
            conn_id_seed: ring::hmac::Key::generate(ring::hmac::HMAC_SHA256, &SystemRandom::new())
                .unwrap(),
            connections: Arc::new(Mutex::new(HashMap::new())),
            available_addresses,
        }
    }

    pub async fn run(&self) -> Result<()> {
        let mut quic_config = crate::net::quic::configure_quic(
            &self.config.ca_cert_path,
            &self.config.cert_path,
            &self.config.key_path,
        )?;

        // Channel for sending UDP packets
        let (tx_quic_to_udp, mut rx_quic_to_udp) =
            mpsc::channel::<UdpPacket>(MAIN_CHANNEL_CAPACITY);

        let mut buf = [0; UDP_PACKET_BUFFER_SIZE];
        let mut next_client = 0u32;

        if self.config.listen.isd_asn() == IsdAsn::WILDCARD {
            let local_addr = self
                .config
                .listen
                .local_address()
                .ok_or_else(|| anyhow!("invalid local address"))?;
            let socket = tokio::net::UdpSocket::bind(local_addr).await?;
            info!("listening on {}", local_addr);
            loop {
                tokio::select! {
                    // Receive datagram from UDP socket
                    Ok((len, src)) = socket.recv_from(&mut buf) => {
                        let src_scion = scion_proto::address::SocketAddr::from_std(
                            IsdAsn::WILDCARD,
                            src,
                        );
                        debug!("received {} bytes on socket from {}", len, src);
                        self.handle_udp_packet(&mut buf, len, src, src_scion, local_addr, self.config.listen, &tx_quic_to_udp, &mut quic_config, &mut next_client).await?;
                    }

                    // Send QUIC packets over UDP socket
                    Some(packet_data) = rx_quic_to_udp.recv() => {
                        let dst = if let Some(addr) = packet_data.dst.local_address() {
                            addr
                        } else {
                            warn!("Could not get destination address from SCION SocketAddr. Skipping packet.");
                            continue;
                        };
                        socket.send_to(&packet_data.data, dst).await?;
                        debug!("sent {} bytes on socket to {}", packet_data.data.len(), dst);
                    }
                }
            }
        } else {
            let endhost_api_url = self.config.endhost_api_address.clone().context(
                "endhost API address must be provided when using SCION (with --endhost-api)",
            )?;

            let mut builder = ScionStackBuilder::new(endhost_api_url);
            if let Some(token_path) = &self.config.snap_token_path {
                let snap_token = fs::read_to_string(token_path)
                    .with_context(|| format!("failed to read token file {:?}", token_path))?
                    .trim()
                    .to_string();
                if snap_token.is_empty() {
                    anyhow::bail!("token file {:?} is empty", token_path);
                }
                builder = builder.with_auth_token(snap_token);
            }
            let scion_network_stack = builder
                .build()
                .in_current_span()
                .await
                .context("error building proxy SCION stack")?;

            // TODO: Check how address selection is handled with Udp Underlay
            let proxy_addr = scion_network_stack
                .local_addresses()
                .first()
                .cloned()
                .context("proxy did not get any address assigned")?;

            let socket_address = scion_proto::address::SocketAddr::new(proxy_addr.into(), 4433);

            let socket = scion_network_stack.bind(Some(socket_address)).await?;

            let local_scion_addr = socket.local_addr();
            info!("listening on {}", local_scion_addr);
            let local_addr = local_scion_addr
                .local_address()
                .ok_or_else(|| anyhow!("invalid local address"))?;

            // Main loop: handle UDP socket
            loop {
                tokio::select! {
                    // Receive datagram from UDP socket
                    Ok((len, src)) = socket.recv_from(&mut buf) => {
                        let src_ip_addr = match src.local_address() {
                            Some(addr) => addr,
                            None => {
                                warn!("Could not get source IP address from SCION SocketAddr.");
                                continue;
                            }
                        };
                        debug!("received {} bytes on socket from {}", len, src);
                        self.handle_udp_packet(&mut buf, len, src_ip_addr, src, local_addr, local_scion_addr, &tx_quic_to_udp, &mut quic_config, &mut next_client).await?;
                    }

                    // Send QUIC packets over UDP socket
                    Some(packet_data) = rx_quic_to_udp.recv() => {
                        socket.send_to(&packet_data.data, packet_data.dst).await?;
                        debug!("sent {} bytes on socket to {}", packet_data.data.len(), packet_data.dst);
                    }
                }
            }
        }
    }

    async fn handle_udp_packet(
        &self,
        buf: &mut [u8],
        len: usize,
        src_ip_socket: std::net::SocketAddr,
        src_scion_socket: scion_proto::address::SocketAddr,
        local_ip_socket: std::net::SocketAddr,
        local_scion_socket: scion_proto::address::SocketAddr,
        tx_quic_to_udp: &mpsc::Sender<UdpPacket>,
        quic_config: &mut quiche::Config,
        next_client: &mut u32,
    ) -> Result<()> {
        // Parse the QUIC packet header to identify connection
        let hdr = match quiche::Header::from_slice(&mut buf[..len], quiche::MAX_CONN_ID_LEN) {
            Ok(v) => v,
            Err(e) => {
                warn!("failed to parse header: {:?}", e);
                return Ok(());
            }
        };

        let conn_id = ring::hmac::sign(&self.conn_id_seed, &hdr.dcid);
        let conn_id = &conn_id.as_ref()[..quiche::MAX_CONN_ID_LEN];
        let conn_id = conn_id.to_vec().into();

        // Check if this is an existing connection (by dcid or derived conn_id)
        let client_conn_sender = {
            let connections_lock = self.connections.lock().await;
            connections_lock
                .get(&hdr.dcid)
                .or_else(|| connections_lock.get(&conn_id))
                .cloned()
        };
        if let Some(client_conn) = client_conn_sender {
            // Forward to existing connection task
            match client_conn.try_send(UdpPacket {
                data: buf[..len].to_vec(),
                src: src_scion_socket,
                dst: local_scion_socket,
            }) {
                Ok(_) => {}
                Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                    debug!(
                        "Connection channel full, dropping packet for connection {:?}",
                        hdr.dcid
                    );
                }
                Err(e) => {
                    warn!(
                        "Failed to send packet to connection {:?}: {}, shutting down",
                        hdr.dcid, e
                    );
                    // TODO: properly shut down the connection
                }
            }
        } else if hdr.ty == quiche::Type::Initial {
            let mut out = [0; MAX_DATAGRAM_SIZE];

            // New connection - create connection ID
            if !quiche::version_is_supported(hdr.version) {
                debug!("Doing version negotiation");

                let len = quiche::negotiate_version(&hdr.scid, &hdr.dcid, &mut out)?;
                let out = &out[..len];

                let packet = UdpPacket {
                    data: out.to_vec(),
                    src: local_scion_socket,
                    dst: src_scion_socket,
                };

                // We use try_send here to avoid a deadlock
                match tx_quic_to_udp.try_send(packet) {
                    Ok(_) => {}
                    Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                        trace!("QUIC to UDP channel full, dropping version negotiation packet");
                    }
                    Err(e) => {
                        warn!("Failed to send version negotiation packet: {}", e);
                    }
                }
                return Ok(());
            }

            let mut scid = [0; quiche::MAX_CONN_ID_LEN];
            scid.copy_from_slice(&conn_id);
            let scid = quiche::ConnectionId::from_ref(&scid);

            // Token is always present in Initial packets.
            let token = hdr
                .token
                .as_ref()
                .ok_or(anyhow!("Token should be available."))?;

            // Do stateless retry if the client didn't send a token.
            if token.is_empty() {
                debug!("Doing stateless retry");

                let new_token = self.mint_token(&hdr, &src_ip_socket);

                let len = quiche::retry(
                    &hdr.scid,
                    &hdr.dcid,
                    &scid,
                    &new_token,
                    hdr.version,
                    &mut out,
                )?;

                let out = &out[..len];

                let packet = UdpPacket {
                    data: out.to_vec(),
                    src: local_scion_socket,
                    dst: src_scion_socket,
                };

                // We use try_send here to avoid a deadlock
                match tx_quic_to_udp.try_send(packet) {
                    Ok(_) => {}
                    Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                        trace!("QUIC to UDP channel full, dropping retry packet");
                    }
                    Err(e) => {
                        warn!("Failed to send retry packet: {}", e);
                    }
                }
                return Ok(());
            }

            let odcid = self.validate_token(&src_ip_socket, token);

            // The token was not valid, meaning the retry failed, so
            // drop the packet.
            if odcid.is_none() {
                warn!("Invalid address validation token");
                return Ok(());
            }

            if scid.len() != hdr.dcid.len() {
                warn!("Invalid destination connection ID");
                return Ok(());
            }

            // Reuse the source connection ID we sent in the Retry packet,
            // instead of changing it again.
            let scid = hdr.dcid.clone();

            debug!(
                "New connection: dcid={:?} scid={:?} src={}",
                hdr.dcid, scid, src_scion_socket
            );

            // Create QUIC connection
            let mut conn = match quiche::accept(
                &scid,
                odcid.as_ref(),
                local_ip_socket,
                src_ip_socket,
                quic_config,
            ) {
                Ok(c) => c,
                Err(e) => {
                    warn!("failed to create connection: {:?}", e);
                    return Ok(());
                }
            };

            // Process the initial packet
            let recv_info = quiche::RecvInfo {
                from: src_ip_socket,
                to: local_ip_socket,
            };

            match conn.recv(&mut buf[..len], recv_info) {
                Ok(len) => {
                    debug!("processed initial packet {} bytes", len);
                }
                Err(e) => {
                    warn!("failed to process initial packet: {:?}", e);
                    return Ok(());
                }
            }

            // Create channel for this connection
            let (tx_to_connection, rx_from_main) =
                mpsc::channel::<UdpPacket>(CLIENT_CHANNEL_CAPACITY);

            // Allocate TUN name for this client
            let tun_name = format!("tun{}", next_client);
            *next_client += 1;

            // Store connection info
            let client_conn = Connection::new(
                conn,
                scid.clone().into_owned(),
                local_scion_socket.isd_asn(),
                src_scion_socket.isd_asn(),
                rx_from_main,
                tx_quic_to_udp.clone(),
                tun_name,
                self.config.tun_mtu,
                self.available_addresses.clone(),
                self.config.routes.clone(),
            );
            self.connections
                .lock()
                .await
                .insert(scid.clone().into_owned(), tx_to_connection);

            // Spawn task for this connection
            let scid_owned = scid.clone().into_owned();
            let connections_clone = self.connections.clone();
            tokio::spawn(async move {
                if let Err(e) = client_conn
                    .handle_client_connection()
                    .instrument(tracing::info_span!("connection", scid = ?scid_owned))
                    .await
                {
                    error!("connection {:?} error: {:?}", scid_owned, e);
                }
                connections_clone.lock().await.remove(&scid_owned);
            });
        } else {
            debug!("packet for unknown connection with dcid {:?}", hdr.dcid);
        }
        Ok(())
    }

    fn mint_token(&self, hdr: &quiche::Header, src: &SocketAddr) -> Vec<u8> {
        let mut token = Vec::new();

        token.extend_from_slice(TOKEN_PREFIX);

        let addr = match src.ip() {
            std::net::IpAddr::V4(a) => a.octets().to_vec(),
            std::net::IpAddr::V6(a) => a.octets().to_vec(),
        };

        token.extend_from_slice(&addr);
        token.extend_from_slice(&hdr.dcid);

        let tag = ring::hmac::sign(&self.token_key, &token);
        token.extend_from_slice(tag.as_ref());

        token
    }

    fn validate_token<'a>(
        &self,
        src: &SocketAddr,
        token: &'a [u8],
    ) -> Option<quiche::ConnectionId<'a>> {
        if token.len() < TOKEN_PREFIX.len() {
            return None;
        }

        if &token[..TOKEN_PREFIX.len()] != TOKEN_PREFIX {
            return None;
        }

        let addr = match src.ip() {
            std::net::IpAddr::V4(a) => a.octets().to_vec(),
            std::net::IpAddr::V6(a) => a.octets().to_vec(),
        };

        if token[TOKEN_PREFIX.len()..].len() < addr.len()
            || &token[TOKEN_PREFIX.len()..TOKEN_PREFIX.len() + addr.len()] != addr.as_slice()
        {
            return None;
        }

        if token.len() < TOKEN_PREFIX.len() + addr.len() + HMAC_TAG_LEN {
            return None;
        }

        let (data, tag) = token.split_at(token.len() - HMAC_TAG_LEN);
        if ring::hmac::verify(&self.token_key, data, tag).is_err() {
            return None;
        }

        let dcid_start = TOKEN_PREFIX.len() + addr.len();
        let dcid_end = token.len() - HMAC_TAG_LEN;

        Some(quiche::ConnectionId::from_ref(&token[dcid_start..dcid_end]))
    }
}
