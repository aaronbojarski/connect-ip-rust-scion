pub mod connection;

use anyhow::Result;
use ipnet::IpNet;
use ring::rand::SystemRandom;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::sync::mpsc;
use tracing::warn;
use tracing::{debug, error, info, trace};

use crate::net::UdpPacket;
use crate::net::quic::MAX_DATAGRAM_SIZE;
use crate::proxy::connection::Connection;

const TOKEN_PREFIX: &[u8] = b"connect-ip-rust-scion";
const MAIN_CHANNEL_CAPACITY: usize = 10000;
const CLIENT_CHANNEL_CAPACITY: usize = 1000;

pub struct ProxyConfig {
    pub listen: SocketAddr,
    pub ca_cert_path: std::path::PathBuf,
    pub cert_path: std::path::PathBuf,
    pub key_path: std::path::PathBuf,
    pub routes: Vec<IpNet>,
    pub address_pool: Vec<IpNet>,
}

pub struct Proxy {
    config: ProxyConfig,
    token_key: ring::hmac::Key,
}

impl Proxy {
    pub fn new(config: ProxyConfig) -> Self {
        Proxy {
            config: config,
            token_key: ring::hmac::Key::generate(ring::hmac::HMAC_SHA256, &SystemRandom::new())
                .unwrap(),
        }
    }

    #[tokio::main]
    pub async fn run(&self) -> Result<()> {
        let mut quic_config = crate::net::quic::configure_quic(
            &self.config.ca_cert_path,
            &self.config.cert_path,
            &self.config.key_path,
        )?;

        let socket = tokio::net::UdpSocket::bind(self.config.listen).await?;
        let local_addr = socket.local_addr()?;
        info!("listening on {}", local_addr);

        // Channel for sending UDP packets
        let (tx_quic_to_udp, mut rx_quic_to_udp) =
            mpsc::channel::<UdpPacket>(MAIN_CHANNEL_CAPACITY);

        // Track active connections
        let connections: Arc<
            Mutex<HashMap<quiche::ConnectionId<'static>, mpsc::Sender<UdpPacket>>>,
        > = Arc::new(Mutex::new(HashMap::new()));

        let rng = SystemRandom::new();
        let conn_id_seed = ring::hmac::Key::generate(ring::hmac::HMAC_SHA256, &rng).unwrap();

        let available_addresses = Arc::new(Mutex::new(self.config.address_pool.clone()));

        let mut buf = [0; 65535];
        let mut out = [0; MAX_DATAGRAM_SIZE];
        let mut next_client = 0u32;

        // Main loop: handle UDP socket
        loop {
            tokio::select! {
                // Receive datagram from UDP socket
                Ok((len, src)) = socket.recv_from(&mut buf) => {
                    // Parse the QUIC packet header to identify connection
                    let hdr = match quiche::Header::from_slice(&mut buf[..len], quiche::MAX_CONN_ID_LEN) {
                        Ok(v) => v,
                        Err(e) => {
                            debug!("failed to parse header: {:?}", e);
                            continue;
                        }
                    };

                    let conn_id = ring::hmac::sign(&conn_id_seed, &hdr.dcid);
                    let conn_id = &conn_id.as_ref()[..quiche::MAX_CONN_ID_LEN];
                    let conn_id = conn_id.to_vec().into();

                    // Check if this is an existing connection (by dcid or derived conn_id)
                    let client_conn_sender = {
                        let connections_lock = connections.lock().await;
                        connections_lock.get(&hdr.dcid).or_else(|| connections_lock.get(&conn_id)).cloned()
                    };
                    if let Some(client_conn) = client_conn_sender {
                        // Forward to existing connection task
                        let _ = client_conn.send(UdpPacket {
                            data: buf[..len].to_vec(),
                            src,
                            dst: local_addr,
                        }).await;
                    } else if hdr.ty == quiche::Type::Initial {
                        // New connection - create connection ID

                         if !quiche::version_is_supported(hdr.version) {
                            debug!("Doing version negotiation");

                            let len =
                                quiche::negotiate_version(&hdr.scid, &hdr.dcid, &mut out)
                                    .unwrap();

                            let out = &out[..len];

                            if let Err(e) = socket.send_to(out, src).await {
                                error!("send() failed: {e:?}");
                            }
                            continue;
                        }

                        let mut scid = [0; quiche::MAX_CONN_ID_LEN];
                        scid.copy_from_slice(&conn_id);
                        let scid = quiche::ConnectionId::from_ref(&scid);

                         // Token is always present in Initial packets.
                        let token = hdr.token.as_ref().unwrap();

                        // Do stateless retry if the client didn't send a token.
                        if token.is_empty() {
                            debug!("Doing stateless retry");

                            let new_token = self.mint_token(&hdr, &src);

                            let len = quiche::retry(
                                &hdr.scid,
                                &hdr.dcid,
                                &scid,
                                &new_token,
                                hdr.version,
                                &mut out,
                            )
                            .unwrap();

                            let out = &out[..len];

                            if let Err(e) = socket.send_to(out, src).await {
                                error!("send() failed: {e:?}");
                            }
                            continue;
                        }

                        let odcid = self.validate_token(&src, token);

                        // The token was not valid, meaning the retry failed, so
                        // drop the packet.
                        if odcid.is_none() {
                            warn!("Invalid address validation token");
                            continue;
                        }

                        if scid.len() != hdr.dcid.len() {
                            warn!("Invalid destination connection ID");
                            continue;
                        }

                        // Reuse the source connection ID we sent in the Retry packet,
                        // instead of changing it again.
                        let scid = hdr.dcid.clone();

                        debug!("New connection: dcid={:?} scid={:?} src={}", hdr.dcid, scid, src);

                        // Create QUIC connection
                        let mut conn = match quiche::accept(&scid, odcid.as_ref(), local_addr, src, &mut quic_config) {
                            Ok(c) => c,
                            Err(e) => {
                                warn!("failed to create connection: {:?}", e);
                                continue;
                            }
                        };

                        // Process the initial packet
                        let recv_info = quiche::RecvInfo {
                            from: src,
                            to: local_addr,
                        };

                        match conn.recv(&mut buf[..len], recv_info) {
                            Ok(len) => {
                                debug!("processed initial packet {} bytes", len);
                            }
                            Err(e) => {
                                warn!("failed to process initial packet: {:?}", e);
                                continue;
                            }
                        }

                        // Send response packets
                        loop {
                            let (write, send_info) = match conn.send(&mut buf) {
                                Ok(v) => v,
                                Err(quiche::Error::Done) => break,
                                Err(e) => {
                                    error!("send failed: {:?}", e);
                                    break;
                                }
                            };

                            if let Err(e) = socket.send_to(&buf[..write], send_info.to).await {
                                error!("send() failed: {e:?}");
                            }
                        }

                        // Create channel for this connection
                        let (tx_to_connection, rx_from_main) = mpsc::channel::<UdpPacket>(CLIENT_CHANNEL_CAPACITY);

                        // Allocate TUN name for this client
                        let tun_name = format!("tun{}", next_client);
                        next_client += 1;

                        // Store connection info
                        let client_conn =
                            Connection::new(
                                conn,
                                scid.clone().into_owned(),
                                src,
                                rx_from_main,
                                tx_quic_to_udp.clone(),
                                tun_name,
                                available_addresses.clone(),
                                self.config.routes.clone(),
                            );
                        connections.lock().await.insert(scid.clone().into_owned(), tx_to_connection);

                        // Spawn task for this connection
                        let scid_owned = scid.clone().into_owned();
                        let connections_clone = connections.clone();
                        tokio::spawn(async move {
                            if let Err(e) = client_conn.handle_client_connection().await {
                                error!("connection {:?} error: {:?}", scid_owned, e);
                            }
                            connections_clone.lock().await.remove(&scid_owned);
                        });
                    } else {
                        debug!("packet for unknown connection with dcid {:?}", hdr.dcid);
                    }
                }

                // Send QUIC packets over UDP socket
                Some(packet_data) = rx_quic_to_udp.recv() => {
                    let sent_len = socket.send_to(&packet_data.data, packet_data.dst).await?;
                    trace!("sent {} bytes to {}", sent_len, packet_data.dst);
                }
            }
        }
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

        if token.len() < TOKEN_PREFIX.len() + addr.len() + 32 {
            return None;
        }

        let (data, tag) = token.split_at(token.len() - 32);

        if ring::hmac::verify(&self.token_key, data, tag).is_err() {
            return None;
        }

        let dcid_start = TOKEN_PREFIX.len() + addr.len();
        let dcid_end = token.len() - 32;

        Some(quiche::ConnectionId::from_ref(&token[dcid_start..dcid_end]))
    }
}
