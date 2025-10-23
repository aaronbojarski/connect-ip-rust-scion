//! This example demonstrates an HTTP client that requests files from a server.
//!
//! Checkout the `README.md` for guidance.

use std::{
    env, fs, io, net::{SocketAddr, ToSocketAddrs},  sync::Arc, time::{Duration, Instant}
};

use anyhow::{Result, anyhow};
use clap::Parser;
use quinn::crypto::rustls::QuicClientConfig;
use rustls::pki_types::CertificateDer;
use tokio::sync::mpsc;
use tracing::{error, info};
use url::Url;

use tun_rs::DeviceBuilder;

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
    let endpoint = connect_to_server(options.bind).await?;
    let url = options.url;
    let url_host = "10.248.100.11";
    let remote = (url_host, url.port().unwrap_or(4433))
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| anyhow!("couldn't resolve to an address"))?;

    let host = options.host.as_deref().unwrap_or(url_host);

    info!("connecting to {host} at {remote}");
    let start = Instant::now();
    let conn = endpoint
        .connect(remote, host)?
        .await
        .map_err(|e| anyhow!("failed to connect: {}", e))?;
    info!("connected at {:?}", start.elapsed());

    let (mut send, mut recv) = conn
        .open_bi()
        .await
        .map_err(|e| anyhow!("failed to open stream: {}", e))?;
    let request = format!("GET {}\r\n", url.path());
    send.write_all(request.as_bytes())
        .await
        .map_err(|e| anyhow!("failed to send request: {}", e))?;
    send.finish().unwrap();
    let response_start = Instant::now();
    info!("request sent at {:?}", response_start - start);
    let resp = recv
        .read_to_end(usize::MAX)
        .await
        .map_err(|e| anyhow!("failed to read response: {}", e))?;
    let duration = response_start.elapsed();
    info!(
        "response received in {:?} - {} KiB/s",
        duration,
        (&resp).len() as f32 / (duration_secs(&duration) * 1024.0)
    );

    // convert the received bytes to an IPv4 address
    let received_address = String::from_utf8(resp)
        .map_err(|e| anyhow!("failed to parse response as UTF-8: {}", e))?;

    let (tx_to_tun, mut rx_in_tun) = mpsc::channel::<Vec<u8>>(100);
    let (tx_from_tun, mut rx_from_tun) = mpsc::channel::<Vec<u8>>(100);
    
    tokio::spawn(async move {
        let result: Result<()> = async {
            let dev = DeviceBuilder::new()
                .ipv4(received_address, 24, None)
                .build_async()?;

            let mut buf = vec![0; 65536];
            loop {
                tokio::select! {
                    // Read from TUN device and send to main task
                    len = dev.recv(&mut buf) => {
                        let len = len?;
                        let packet_data = buf[..len].to_vec();
                        println!("TUN -> QUIC: {:?}", packet_data);
                        tx_from_tun.send(packet_data).await
                            .map_err(|_| anyhow!("failed to send packet from TUN"))?;
                    }
                    // Receive from main task and write to TUN device
                    Some(packet) = rx_in_tun.recv() => {
                        println!("QUIC -> TUN: {:?}", packet);
                        dev.send(&packet).await.map_err(|_| anyhow!("failed to send packet to TUN"))?;
                    }
                }
            }
        }.await;
        
        if let Err(e) = result {
            error!("TUN device task failed: {}", e);
        }
    });

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

async fn connect_to_server(socket_addr: SocketAddr) -> Result<quinn::Endpoint> {
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

fn duration_secs(x: &Duration) -> f32 {
    x.as_secs() as f32 + x.subsec_nanos() as f32 * 1e-9
}