use std::net::Ipv4Addr;
use std::{collections::HashMap, env, fs, io, net::SocketAddr, sync::Arc};

use anyhow::{Context, Result, anyhow, bail};
use clap::Parser;
use connect_ip_rust_scion::tun;
use pnet::packet::ipv4::Ipv4Packet;
use quinn::crypto::rustls::QuicServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::sync::Mutex;
use tokio::sync::mpsc::{self, Receiver, Sender};
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

    let server_config =
        quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(server_crypto)?));

    let endpoint = quinn::Endpoint::server(server_config, options.listen)?;
    info!("listening on {}", endpoint.local_addr()?);

    // Create queue set for distributing packets to connections
    let queue_set: QueueSet = Arc::new(Mutex::new(HashMap::new()));

    // Create channel for sending packets from connections to the pnet socket
    let (outbound_tx, outbound_rx) = mpsc::channel::<Vec<u8>>(1000);

    // Spawn IP packet handler task
    let queue_set_clone = queue_set.clone();
    tokio::spawn(
        async move {
            if let Err(e) = handle_ip_packets(queue_set_clone, outbound_rx).await {
                error!("IP packet handler failed: {}", e);
            }
        }
        .instrument(info_span!("ip_packet_handler")),
    );

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

async fn handle_ip_packets(queue_set: QueueSet, mut outbound_rx: Receiver<Vec<u8>>) -> Result<()> {
    info!("starting IP packet handler");

    let (tx_to_tun, rx_in_tun) = mpsc::channel::<Vec<u8>>(100);
    let (tx_from_tun, mut rx_from_tun) = mpsc::channel::<Vec<u8>>(100);

    let mut tun = tun::Tun::new("tun0", "10.248.1.7".parse::<Ipv4Addr>()?, 1500);
    tun.start(tx_from_tun, rx_in_tun).await?;

    // Spawn task to receive packets from TUN and distribute to connections
    let queue_set_clone = queue_set.clone();
    let inbound_handle = tokio::spawn(async move {
        info!("started listening for packets from TUN interface");

        while let Some(packet) = rx_from_tun.recv().await {
            if let Some(ipv4) = Ipv4Packet::new(&packet) {
                let src = ipv4.get_source();
                let dest = ipv4.get_destination();
                info!(
                    "received IP packet from TUN: {} -> {}, {} bytes",
                    src,
                    dest,
                    packet.len()
                );

                // Distribute to all connections
                let queues = queue_set_clone.lock().await;
                if queues.is_empty() {
                    warn!("no active connections to forward packet to");
                } else {
                    for (conn_id, sender) in queues.iter() {
                        info!("forwarding packet to connection {}", conn_id);
                        if let Err(e) = sender.send(packet.clone()).await {
                            error!("failed to send packet to connection {}: {}", conn_id, e);
                        } else {
                            info!("forwarded packet to connection {}", conn_id);
                        }
                    }
                }
            } else {
                warn!("received invalid IPv4 packet from TUN");
            }
        }

        info!("inbound packet handler exiting");
    });

    // Handle outbound packets from connections and send to TUN
    let outbound_handle = tokio::spawn(async move {
        info!("started outbound packet handler");

        while let Some(packet) = outbound_rx.recv().await {
            info!("processing outbound IP packet: {} bytes", packet.len());

            if let Some(ipv4_packet) = Ipv4Packet::new(&packet) {
                let dest = ipv4_packet.get_destination();
                let src = ipv4_packet.get_source();
                info!(
                    "sending IP packet to TUN: {} -> {}, {} bytes",
                    src,
                    dest,
                    packet.len()
                );

                if let Err(e) = tx_to_tun.send(packet).await {
                    error!("failed to send packet to TUN: {}", e);
                    break;
                }
                info!("successfully sent packet to TUN");
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
    outbound_tx: Sender<Vec<u8>>,
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

        let (inbound_tx, mut inbound_rx) = mpsc::channel::<Vec<u8>>(100);

        // Register this connection in the queue set
        {
            let mut queues = queue_set.lock().await;
            queues.insert(connection_id, inbound_tx);
        }

        // Clone connection for datagrams before passing to h3
        let conn_for_datagrams = connection.clone();

        // Create HTTP/3 connection
        let mut h3_conn = h3::server::Connection::new(h3_quinn::Connection::new(connection))
            .await
            .unwrap();
        info!("HTTP/3 connection established");

        // Handle the HTTP/3 request for address negotiation
        if let Some(resolver) = h3_conn
            .accept()
            .await
            .map_err(|e| anyhow!("h3 accept failed: {}", e))?
        {
            let (req, mut stream) = resolver.resolve_request().await?;
            info!("received HTTP/3 request");

            // TODO:
            // 1. Parse and check request
            // 2. Send around capsules until addresses are set
            // 3. Start datagram handling
            // 4. Keep stream open for further communication if needed

            // Check the fields of the request
            info!("Request method: {:?}", req.method());
            info!("Request URI: {:?}", req.uri());
            for (name, value) in req.headers() {
                info!("Header: {:?}: {:?}", name, value);
            }

            // Send response with allocated IP address
            let response = http::Response::builder()
                .status(http::StatusCode::OK)
                .body(())
                .unwrap();

            stream
                .send_response(response)
                .await
                .map_err(|e| anyhow!("failed to send response: {}", e))?;

            //stream.recv_data().await.map_err(|e| anyhow!("failed to receive data: {}", e))?;

            stream
                .send_data(bytes::Bytes::from("10.248.2.180"))
                .await
                .map_err(|e| anyhow!("failed to send data: {}", e))?;

            info!("sent IP address allocation response");
        } else {
            info!("no HTTP/3 request received on connection");
            return Ok(());
        }

        // Now use the cloned connection for datagrams
        let (datagram_tx, mut datagram_rx) = mpsc::channel::<Vec<u8>>(100);

        // Spawn datagram receiver
        let conn_clone = conn_for_datagrams.clone();
        let recv_handle = tokio::spawn(
            async move {
                loop {
                    match conn_clone.read_datagram().await {
                        Ok(data) => {
                            info!("received datagram: {} bytes", data.len());
                            if datagram_tx.send(data.to_vec()).await.is_err() {
                                error!("datagram queue closed");
                                break;
                            }
                        }
                        Err(e) => {
                            error!("datagram read error: {}", e);
                            break;
                        }
                    }
                }
            }
            .instrument(info_span!("datagram_receiver")),
        );

        // Forward datagrams from connection to outbound queue
        let outbound_tx_clone = outbound_tx.clone();
        let forward_handle = tokio::spawn(async move {
            while let Some(packet) = datagram_rx.recv().await {
                info!("forwarding datagram to IP: {} bytes", packet.len());
                if let Err(e) = outbound_tx_clone.send(packet).await {
                    error!("failed to forward packet: {}", e);
                    break;
                }
            }
        });

        // Forward packets from inbound queue to connection datagrams
        let conn_clone = conn_for_datagrams.clone();
        let send_handle = tokio::spawn(async move {
            while let Some(packet) = inbound_rx.recv().await {
                info!("sending packet as datagram: {} bytes", packet.len());
                if let Err(e) = conn_clone.send_datagram(packet.into()) {
                    error!("failed to send datagram: {}", e);
                    break;
                }
            }
        });

        // Wait for connection to close
        conn_for_datagrams.closed().await;
        info!("connection closed");

        // Cleanup
        let mut queues = queue_set.lock().await;
        queues.remove(&connection_id);
        drop(queues);

        // Cancel spawned tasks
        recv_handle.abort();
        forward_handle.abort();
        send_handle.abort();

        Ok::<(), anyhow::Error>(())
    }
    .instrument(span)
    .await?;
    Ok(())
}
