use clap::{Args, Parser, Subcommand};
use ipnet::IpNet;
use std::{net::SocketAddr, path::PathBuf};
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
    #[clap(long, default_value = "127.0.0.1:4433")]
    listen: SocketAddr,

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
    /// URL of proxy to connect to (must include scheme and port, e.g. https://host:4433)
    url: Url,

    /// Override hostname used for certificate verification (defaults to the host from --url)
    #[clap(long = "host")]
    host: Option<String>,

    /// Local address to bind to
    #[clap(long = "bind", default_value = "0.0.0.0:0")]
    bind: SocketAddr,

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

fn main() {
    let cli = Cli::parse();
    let exit_code = match cli.command {
        Command::Proxy(opt) => run_proxy(opt),
        Command::Client(opt) => run_client(opt),
    };
    ::std::process::exit(exit_code);
}

fn run_proxy(opt: ProxyOpt) -> i32 {
    tracing_subscriber::fmt()
        .with_max_level(opt.log_level)
        .init();
    let config = connect_ip_rust_scion::proxy::ProxyConfig {
        listen: opt.listen,
        ca_cert_path: opt.ca_cert_path,
        cert_path: opt.cert_path,
        key_path: opt.key_path,
        routes: opt.routes,
        address_pool: opt.address_pool,
    };
    let proxy = connect_ip_rust_scion::proxy::Proxy::new(config);
    if let Err(e) = proxy.run() {
        eprintln!("ERROR: {e}");
        1
    } else {
        0
    }
}

fn run_client(opt: ClientOpt) -> i32 {
    tracing_subscriber::fmt()
        .with_max_level(opt.log_level)
        .init();
    let config = connect_ip_rust_scion::client::ClientConfig {
        bind: opt.bind,
        url: opt.url,
        ca_cert_path: opt.ca_cert_path,
        cert_path: opt.cert_path,
        key_path: opt.key_path,
        routes: opt.routes,
        address_pool: opt.address_pool,
        tun_name: opt.tun_name,
    };
    let client = connect_ip_rust_scion::client::Client::new(config);
    if let Err(e) = client.run() {
        eprintln!("ERROR: {e}");
        1
    } else {
        0
    }
}
