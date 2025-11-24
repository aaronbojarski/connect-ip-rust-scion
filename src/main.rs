use anyhow::anyhow;
use clap::{Args, Parser, Subcommand};
use ipnet::IpNet;
use std::path::PathBuf;
use url::Url;

#[derive(Parser, Debug)]
#[clap(
    name = "connect-ip-rust-scion",
    about = "Run the CONNECT-IP proxy or client",
    subcommand_required = true,
    arg_required_else_help = true
)]
struct Cli {
    #[clap(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    Proxy(ProxyOpt),
    Client(ClientOpt),
}

#[derive(Args, Debug)]
struct ProxyOpt {
    /// Address to listen on
    #[clap(long, default_value = "[0-0,127.0.0.1]:4433")]
    listen: scion_proto::address::SocketAddr,

    /// Address of the endhost API to connect to for scion path resolution. Required when using SCION.
    #[clap(long = "endhost-api")]
    endhost_api_address: Option<Url>,

    /// CA certificate used to verify peers
    #[clap(long = "ca-cert", value_name = "FILE", default_value = "ca-cert.pem")]
    ca_cert_path: PathBuf,

    /// Certificate presented to clients
    #[clap(long = "cert", value_name = "FILE", default_value = "proxy-cert.pem")]
    cert_path: PathBuf,

    /// Private key for the presented certificate
    #[clap(long = "key", value_name = "FILE", default_value = "proxy-key.pem")]
    key_path: PathBuf,

    /// Routes to advertise to clients
    #[clap(long, required = true)]
    routes: Vec<IpNet>,

    /// Address pool to assign addresses to clients from
    #[clap(long, required = true)]
    address_pool: Vec<IpNet>,

    /// Tracing level (trace, debug, info, warn, error)
    #[clap(long = "log", default_value = "info")]
    log_level: tracing::Level,
}

#[derive(Args, Debug)]
struct ClientOpt {
    /// Address of proxy to connect to (e.g. [0-0,proxy.example.com]:4433)
    remote: scion_proto::address::SocketAddr,

    /// Override hostname used for certificate verification (defaults to the host from --url)
    #[clap(long = "host")]
    host: Option<String>,

    /// Local address to bind to
    #[clap(long = "bind", default_value = "[0-0,0.0.0.0]:0")]
    bind: scion_proto::address::SocketAddr,

    /// Address of the endhost API to connect to for scion path resolution. Required when using SCION.
    #[clap(long = "endhost-api")]
    endhost_api_address: Option<Url>,

    /// Path to the Snap token file for authentication with the endhost API
    #[clap(long = "snap-token", value_name = "FILE")]
    snap_token_path: Option<PathBuf>,

    /// Routes to advertise to the proxy (repeat --routes for each CIDR, e.g. 192.0.2.0/24)
    #[clap(long)]
    routes: Vec<IpNet>,

    /// Address pool to assign addresses to the proxy from (repeat --address-pool for each CIDR, e.g. 192.0.1.0/24)
    #[clap(long)]
    address_pool: Vec<IpNet>,

    /// CA certificate used to verify the proxy
    #[clap(long = "ca-cert", value_name = "FILE", default_value = "ca-cert.pem")]
    ca_cert_path: PathBuf,

    /// Client certificate presented to the proxy
    #[clap(long = "cert", value_name = "FILE", default_value = "client-cert.pem")]
    cert_path: PathBuf,

    /// Private key for the client certificate
    #[clap(long = "key", value_name = "FILE", default_value = "client-key.pem")]
    key_path: PathBuf,

    /// Name of the TUN interface to create
    #[clap(long = "tun", default_value = "tun0")]
    tun_name: String,

    /// Tracing level (trace, debug, info, warn, error)
    #[clap(long = "log", default_value = "info")]
    log_level: tracing::Level,
}

fn main() -> Result<(), anyhow::Error> {
    let cli = Cli::parse();
    let result = match cli.command {
        Command::Proxy(opt) => run_proxy(opt),
        Command::Client(opt) => run_client(opt),
    };
    if let Err(ref err) = result {
        tracing::error!(error = %err, "command failed");
    }
    result
}

#[tokio::main]
async fn run_proxy(opt: ProxyOpt) -> Result<(), anyhow::Error> {
    tracing_subscriber::fmt()
        .with_max_level(opt.log_level)
        .try_init()
        .map_err(|err| anyhow!("failed to init tracing: {err}"))?;
    let config = connect_ip_rust_scion::proxy::ProxyConfig {
        listen: opt.listen,
        endhost_api_address: opt.endhost_api_address,
        ca_cert_path: opt.ca_cert_path,
        cert_path: opt.cert_path,
        key_path: opt.key_path,
        routes: opt.routes,
        address_pool: opt.address_pool,
    };
    let proxy = connect_ip_rust_scion::proxy::Proxy::new(config);
    proxy.run().await?;
    Ok(())
}

#[tokio::main]
async fn run_client(opt: ClientOpt) -> Result<(), anyhow::Error> {
    tracing_subscriber::fmt()
        .with_max_level(opt.log_level)
        .try_init()
        .map_err(|err| anyhow!("failed to init tracing: {err}"))?;
    let config = connect_ip_rust_scion::client::ClientConfig {
        bind: opt.bind,
        remote: opt.remote,
        host: opt.host,
        endhost_api_address: opt.endhost_api_address,
        snap_token_path: opt.snap_token_path,
        ca_cert_path: opt.ca_cert_path,
        cert_path: opt.cert_path,
        key_path: opt.key_path,
        routes: opt.routes,
        address_pool: opt.address_pool,
        tun_name: opt.tun_name,
    };
    let client = connect_ip_rust_scion::client::Client::new(config);
    client.run().await?;
    Ok(())
}
