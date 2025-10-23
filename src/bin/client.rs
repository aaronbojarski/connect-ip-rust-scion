use std::{
    env, fs, io, net::{SocketAddr, ToSocketAddrs},  sync::Arc
};

use anyhow::{Result, anyhow};
use clap::Parser;
use connect_ip_rust_scion::tun;
use quinn::crypto::rustls::QuicClientConfig;
use rustls::pki_types::CertificateDer;
use tokio::sync::mpsc;
use tracing::{error, info};
use url::Url;

const ALPN_QUIC_HTTP: &[&[u8]] = &[b"h3"];

/// HTTP/0.9 over QUIC client
#[derive(Parser, Debug)]
#[clap(name = "client")]
struct Opt {
    url: Url,

    /// Override hostname used for certificate verification
    #[clap(long = "host")]
    host: Option<String>,

    /// Address to bind on
    #[clap(long = "bind", default_value = "0.0.0.0:0")]
    bind: SocketAddr,
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
    let endpoint = configure_endpoint(options.bind).await?;
    let url = options.url;
    let url_host = "10.248.100.11";
    let remote = (url_host, url.port().unwrap_or(4433))
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| anyhow!("couldn't resolve to an address"))?;

    let host = options.host.as_deref().unwrap_or(url_host);

    info!("connecting to {host} at {remote}");
    let conn = endpoint
        .connect(remote, host)?
        .await
        .map_err(|e| anyhow!("failed to connect: {}", e))?;
    info!("connected");

    let (mut send, mut recv) = conn
        .open_bi()
        .await
        .map_err(|e| anyhow!("failed to open stream: {}", e))?;
    let request = format!("GET {}\r\n", url.path());
    send.write_all(request.as_bytes())
        .await
        .map_err(|e| anyhow!("failed to send request: {}", e))?;
    send.finish().unwrap();
    info!("request sent");
    let resp = recv
        .read_to_end(usize::MAX)
        .await
        .map_err(|e| anyhow!("failed to read response: {}", e))?;
    info!("response received");

    // convert the received bytes to an IPv4 address
    let received_address = String::from_utf8(resp)
        .map_err(|e| anyhow!("failed to parse response as UTF-8: {}", e))?;

    let (tx_to_tun, rx_in_tun) = mpsc::channel::<Vec<u8>>(100);
    let (tx_from_tun, mut rx_from_tun) = mpsc::channel::<Vec<u8>>(100);
    
    let mut tun = tun::Tun::new("tun0", received_address.parse()?, 1500);
    tun.start(tx_from_tun, rx_in_tun).await?;

    // Main loop: handle QUIC datagrams
    loop {
        tokio::select! {
            // Receive datagram from QUIC and forward to TUN
            Ok(packet_data) = conn.read_datagram() => {
                tx_to_tun.send(packet_data.to_vec()).await?;
            }
            // Receive packet from TUN and send via QUIC
            Some(packet_data) = rx_from_tun.recv() => {
                conn.send_datagram(packet_data.into())?;
            }
        }
    }

    // TODO: Graceful shutdown
    // conn.close(0u32.into(), b"done");

    // Give the server a fair chance to receive the close packet
    // endpoint.wait_idle().await;

    // Ok(())
}

async fn configure_endpoint(socket_addr: SocketAddr) -> Result<quinn::Endpoint> {
    let mut roots = rustls::RootCertStore::empty();
    let cwd = env::current_dir()?;
    match fs::read(cwd.join("cert.der")) {
        Ok(cert) => {
            roots.add(CertificateDer::from(cert))?;
        }
        Err(ref e) if e.kind() == io::ErrorKind::NotFound => {
            info!("local server certificate not found");
        }
        Err(e) => {
            error!("failed to open local server certificate: {}", e);
        }
    }

    let mut client_crypto = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();

    client_crypto.alpn_protocols = ALPN_QUIC_HTTP.iter().map(|&x| x.into()).collect();

    let client_config =
        quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(client_crypto)?));
    let mut endpoint = quinn::Endpoint::client(socket_addr)?;
    endpoint.set_default_client_config(client_config);

    Ok(endpoint)
}
