use clap::{Args, Parser, Subcommand};
use ipnet::IpNet;
use std::{env, net::SocketAddr};
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

    /// Routes to advertise to clients
    #[clap(long)]
    routes: Vec<IpNet>,

    /// Address pool to assign addresses to clients from
    #[clap(long)]
    address_pool: Vec<IpNet>,

    /// Tracing level (trace, debug, info, warn, error)
    #[clap(long = "log", default_value = "info")]
    log_level: tracing::Level,
}

#[derive(Args, Debug)]
struct ClientOpt {
    /// URL of proxy to connect to
    url: Url,

    /// Override hostname used for certificate verification
    #[clap(long = "host")]
    host: Option<String>,

    /// Local address to bind to
    #[clap(long = "bind", default_value = "0.0.0.0:0")]
    bind: SocketAddr,

    /// Routes to advertise to the proxy
    #[clap(long)]
    routes: Vec<IpNet>,

    /// Address pool to assign addresses to the proxy from
    #[clap(long)]
    address_pool: Vec<IpNet>,

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
    let cwd = env::current_dir().unwrap();
    let config = connect_ip_rust_scion::proxy::ProxyConfig {
        listen: opt.listen,
        ca_cert_path: cwd.join("ca-cert.pem"),
        cert_path: cwd.join("proxy-cert.pem"),
        key_path: cwd.join("proxy-key.pem"),
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
    let cwd = env::current_dir().unwrap();
    let config = connect_ip_rust_scion::client::ClientConfig {
        bind: opt.bind,
        url: opt.url,
        ca_cert_path: cwd.join("ca-cert.pem"),
        cert_path: cwd.join("client-cert.pem"),
        key_path: cwd.join("client-key.pem"),
        routes: opt.routes,
        address_pool: opt.address_pool,
        tun_name: "tun0".to_string(),
    };
    let client = connect_ip_rust_scion::client::Client::new(config);
    if let Err(e) = client.run() {
        eprintln!("ERROR: {e}");
        1
    } else {
        0
    }
}
