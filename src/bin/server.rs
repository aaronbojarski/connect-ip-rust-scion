use std::{
    ascii, env, fs, io, net::SocketAddr, str, sync::Arc, collections::HashMap
};

use anyhow::{Context, Result, anyhow, bail};
use clap::Parser;
use pnet::packet::{ipv4::Ipv4Packet, Packet};
use pnet_datalink::Channel;
use quinn::crypto::rustls::QuicServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::sync::mpsc::{self, Sender, Receiver};
use tokio::sync::Mutex;
use tracing::{error, info, info_span, warn};
use tracing_futures::Instrument as _;

const ALPN_QUIC_HTTP: &[&[u8]] = &[b"h3"];

type ConnectionId = usize;
type QueueSet = Arc<Mutex<HashMap<ConnectionId, Sender<Vec<u8>>>>>;

#[derive(Parser, Debug)]
#[clap(name = "server")]
struct Opt {
    /// Address to listen on
    #[clap(long = "listen", default_value = "127.0.0.1:4433")]
    listen: SocketAddr,
    /// Maximum number of concurrent connections to allow
    #[clap(long = "connection-limit")]
    connection_limit: Option<usize>,
}

fn main() {
    tracing_subscriber::fmt().init();
    let opt = Opt::parse();
    let code = {
        if let Err(e) = run(opt) {
            eprintln!("ERROR: {e}");
            1
        } else {
            0
        }
    };
    ::std::process::exit(code);
}

#[tokio::main]
async fn run(options: Opt) -> Result<()> {
    let (certs, key) = {
        let cwd = env::current_dir()?;
        let cert_path = cwd.join("cert.der");
        let key_path = cwd.join("key.der");
        let (cert, key) = match fs::read(&cert_path).and_then(|x| Ok((x, fs::read(&key_path)?))) {
            Ok((cert, key)) => (
                CertificateDer::from(cert),
                PrivateKeyDer::try_from(key).map_err(anyhow::Error::msg)?,
            ),
            Err(ref e) if e.kind() == io::ErrorKind::NotFound => {
                info!("generating self-signed certificate");
                let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
                let key = PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der());
                let cert = cert.cert.into();
                fs::create_dir_all(cwd).context("failed to create certificate directory")?;
                fs::write(&cert_path, &cert).context("failed to write certificate")?;
                fs::write(&key_path, key.secret_pkcs8_der())
                    .context("failed to write private key")?;
                (cert, key.into())
            }
            Err(e) => {
                bail!("failed to read certificate: {}", e);
            }
        };

        (vec![cert], key)
    };

    let mut server_crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    server_crypto.alpn_protocols = ALPN_QUIC_HTTP.iter().map(|&x| x.into()).collect();

    let mut server_config =
        quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(server_crypto)?));
    let transport_config = Arc::get_mut(&mut server_config.transport).unwrap();
    transport_config.max_concurrent_uni_streams(0_u8.into());

    let endpoint = quinn::Endpoint::server(server_config, options.listen)?;
    info!("listening on {}", endpoint.local_addr()?);

    // Create queue set for distributing packets to connections
    let queue_set: QueueSet = Arc::new(Mutex::new(HashMap::new()));
    
    // Create channel for sending packets from connections to the pnet socket
    let (outbound_tx, outbound_rx) = mpsc::channel::<Vec<u8>>(1000);

    // Spawn IP packet handler task
    let queue_set_clone = queue_set.clone();
    tokio::spawn(async move {
        if let Err(e) = handle_ip_packets(queue_set_clone, outbound_rx, Some("proxy10".to_string())).await {
            error!("IP packet handler failed: {}", e);
        }
    }.instrument(info_span!("ip_packet_handler")));

    let mut connection_id: ConnectionId = 0;
    while let Some(conn) = endpoint.accept().await {
        if options
            .connection_limit
            .is_some_and(|n| endpoint.open_connections() >= n)
        {
            info!("refusing due to open connection limit");
            conn.refuse();
        } else {
            info!("accepting connection");
            let current_id = connection_id;
            connection_id += 1;
            
            let queue_set_clone = queue_set.clone();
            let outbound_tx_clone = outbound_tx.clone();
            
            let fut = handle_connection(conn, current_id, queue_set_clone, outbound_tx_clone);
            tokio::spawn(async move {
                if let Err(e) = fut.await {
                    error!("connection failed: {reason}", reason = e.to_string())
                }
            });
        }
    }

    Ok(())
}

async fn handle_ip_packets(
    queue_set: QueueSet,
    mut outbound_rx: Receiver<Vec<u8>>,
    interface_name: Option<String>
) -> Result<()> {
    info!("starting IP packet handler");
    
    // Get the network interface
    let interface = if let Some(name) = interface_name {
        info!("looking for interface: {}", name);
        pnet_datalink::interfaces()
            .into_iter()
            .find(|iface| iface.name == name)
            .ok_or_else(|| anyhow!("interface '{}' not found", name))?
    } else {
        info!("no interface specified, using default");
        pnet_datalink::interfaces()
            .into_iter()
            .find(|iface| !iface.is_loopback() && iface.is_up())
            .ok_or_else(|| anyhow!("no suitable network interface found"))?
    };
    
    info!("using interface: {} ({})", interface.name, 
        interface.ips.iter()
            .map(|ip| ip.to_string())
            .collect::<Vec<_>>()
            .join(", ")
    );
    
    // Create datalink channel bound to specific interface
    let (mut tx, mut rx) = match pnet_datalink::channel(&interface, Default::default()) {
        Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => return Err(anyhow!("unsupported channel type")),
        Err(e) => {
            error!("failed to create datalink channel: {}", e);
            warn!("Make sure to run the server with sudo/root privileges");
            return Err(anyhow!("failed to create datalink channel: {}", e));
        }
    };

    info!("datalink channel created successfully on interface {}", interface.name);

    // Spawn task to receive packets and distribute to connections
    let queue_set_clone = queue_set.clone();
    let inbound_handle = tokio::task::spawn_blocking(move || {
        use pnet::packet::ethernet::{EthernetPacket, EtherTypes};
        
        info!("started listening for packets on interface");
        
        loop {
            match rx.next() {
                Ok(packet) => {
                    if let Some(ethernet) = EthernetPacket::new(packet) {
                        // Filter for IPv4 packets
                        if ethernet.get_ethertype() == EtherTypes::Ipv4 {
                            if let Some(ipv4) = Ipv4Packet::new(ethernet.payload()) {
                                let packet_data = ipv4.packet().to_vec();
                                info!("received IPv4 packet: {} bytes", packet_data.len());
                                
                                // Distribute to all connections
                                let queue_set = queue_set_clone.clone();
                                let handle = tokio::runtime::Handle::current();
                                handle.spawn(async move {
                                    let queues = queue_set.lock().await;
                                    if queues.is_empty() {
                                        warn!("no active connections to forward packet to");
                                    }
                                    for (conn_id, sender) in queues.iter() {
                                        info!("forwarding packet to connection {}", conn_id);
                                        if let Err(e) = sender.send(packet_data.clone()).await {
                                            error!("failed to send packet to connection {}: {}", conn_id, e);
                                        } else {
                                            info!("forwarded packet to connection {}", conn_id);
                                        }
                                    }
                                });
                            }
                        }
                    }
                }
                Err(e) => {
                    error!("error receiving packet: {}", e);
                    break;
                }
            }
        }
    });

    // Handle outbound packets from connections
    let outbound_handle = tokio::task::spawn_blocking(move || {
        use pnet::packet::ethernet::{MutableEthernetPacket, EtherTypes};
        use pnet::util::MacAddr;
        
        let handle = tokio::runtime::Handle::current();
        
        info!("started outbound packet handler");
        
        while let Some(packet) = handle.block_on(outbound_rx.recv()) {
            info!("processing outbound IP packet: {} bytes", packet.len());
            
            if let Some(ipv4_packet) = Ipv4Packet::new(&packet) {
                let dest = ipv4_packet.get_destination();
                let src = ipv4_packet.get_source();
                info!("sending IP packet: {} -> {}, {} bytes", src, dest, packet.len());
                
                // Create Ethernet frame (you'll need proper MAC addresses)
                // This is a simplified version - you may need ARP resolution
                let mut ethernet_buffer = vec![0u8; 14 + packet.len()];
                let mut ethernet = MutableEthernetPacket::new(&mut ethernet_buffer).unwrap();
                
                // Set MAC addresses (these are placeholders - adjust as needed)
                ethernet.set_destination(MacAddr::broadcast());
                ethernet.set_source(MacAddr::zero());
                ethernet.set_ethertype(EtherTypes::Ipv4);
                ethernet.set_payload(&packet);
                
                match tx.send_to(ethernet.packet(), None) {
                    Some(Ok(())) => {
                        info!("successfully sent packet");
                    }
                    Some(Err(e)) => {
                        error!("failed to send packet: {}", e);
                    }
                    None => {
                        error!("failed to send packet: buffer full");
                    }
                }
            } else {
                warn!("invalid IPv4 packet, dropping");
            }
        }
        
        info!("outbound packet handler exiting");
    });

    // Wait for either task to complete
    tokio::select! {
        result = inbound_handle => {
            error!("inbound packet handler exited: {:?}", result);
        }
        result = outbound_handle => {
            error!("outbound packet handler exited: {:?}", result);
        }
    }

    Ok(())
}

async fn handle_connection(
    conn: quinn::Incoming,
    connection_id: ConnectionId,
    queue_set: QueueSet,
    outbound_tx: Sender<Vec<u8>>
) -> Result<()> {
    let connection = conn.await?;
    let span = info_span!(
        "connection",
        id = connection_id,
        remote = %connection.remote_address(),
        protocol = %connection
            .handshake_data()
            .unwrap()
            .downcast::<quinn::crypto::rustls::HandshakeData>().unwrap()
            .protocol
            .map_or_else(|| "<none>".into(), |x| String::from_utf8_lossy(&x).into_owned())
    );
    async {
        info!("established");

        let (datagram_tx, mut datagram_rx) = mpsc::channel::<Vec<u8>>(100);
        let (inbound_tx, mut inbound_rx) = mpsc::channel::<Vec<u8>>(100);

        // Register this connection in the queue set
        {
            let mut queues = queue_set.lock().await;
            queues.insert(connection_id, inbound_tx);
        }

        // Each stream initiated by the client constitutes a new request.
        loop {
            let stream = connection.accept_bi().await;
            let stream = match stream {
                Err(quinn::ConnectionError::ApplicationClosed { .. }) => {
                    info!("connection closed");
                    // Cleanup: remove from queue set
                    let mut queues = queue_set.lock().await;
                    queues.remove(&connection_id);
                    return Ok(());
                }
                Err(e) => {
                    let mut queues = queue_set.lock().await;
                    queues.remove(&connection_id);
                    return Err(e);
                }
                Ok(s) => s,
            };
            let fut = handle_request(stream);
            tokio::spawn(
                async move {
                    if let Err(e) = fut.await {
                        error!("failed: {reason}", reason = e.to_string());
                    }
                }
                .instrument(info_span!("request")),
            );
            
            // After handling the request, start listening for datagrams
            let conn_clone = connection.clone();
            let datagram_tx_clone = datagram_tx.clone();
            tokio::spawn(
                async move {
                    if let Err(e) = handle_datagrams(conn_clone, datagram_tx_clone).await {
                        error!("datagram handler failed: {}", e);
                    }
                }.instrument(info_span!("datagram_handler")),
            );
            
            // Forward datagrams from connection to outbound queue
            let outbound_tx_clone = outbound_tx.clone();
            tokio::spawn(async move {
                while let Some(packet) = datagram_rx.recv().await {
                    info!("forwarding datagram to IP: {} bytes", packet.len());
                    if let Err(e) = outbound_tx_clone.send(packet).await {
                        error!("failed to forward packet: {}", e);
                        break;
                    }
                }
            });
            
            // Forward packets from inbound queue to connection datagrams
            let conn_clone = connection.clone();
            tokio::spawn(async move {
                while let Some(packet) = inbound_rx.recv().await {
                    info!("sending packet as datagram: {} bytes", packet.len());
                    if let Err(e) = conn_clone.send_datagram(packet.into()) {
                        error!("failed to send datagram: {}", e);
                        break;
                    }
                }
            });
            
            return Ok(());
        }
    }
    .instrument(span)
    .await?;
    Ok(())
}
async fn handle_request(
    (mut send, mut recv): (quinn::SendStream, quinn::RecvStream),
) -> Result<()> {
    let req = recv
        .read_to_end(64 * 1024)
        .await
        .map_err(|e| anyhow!("failed reading request: {}", e))?;
    let mut escaped = String::new();
    for &x in &req[..] {
        let part = ascii::escape_default(x).collect::<Vec<_>>();
        escaped.push_str(str::from_utf8(&part).unwrap());
    }
    info!(content = %escaped);
    info!("handled request");

    let resp = b"10.248.3.13";
    send.write_all(resp)
        .await
        .map_err(|e| anyhow!("failed to send response: {}", e))?;

    // Gracefully terminate the stream
    send.finish().unwrap();
    info!("complete");
    Ok(())
}

async fn handle_datagrams(connection: quinn::Connection, tx: Sender::<Vec<u8>>) -> Result<()> {
    info!("starting datagram listener");
    loop {
        match connection.read_datagram().await {
            Ok(data) => {
                info!("received datagram: {} bytes", data.len());
                if tx.send(data.to_vec()).await.is_err() {
                    error!("failed to send datagram to queue");
                    break;
                }
            }
            Err(e) => {
                error!("datagram read error: {}", e);
                return Err(anyhow!("datagram read failed: {}", e));
            }
        }
    }
    Ok(())
}