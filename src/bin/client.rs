use clap::Parser;
use ipnet::IpNet;
use std::net::SocketAddr;
use url::Url;

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

    /// Routes to advertise to the proxy
    #[clap(long)]
    routes: Vec<IpNet>,

    /// Address pool to assign from
    #[clap(long)]
    address_pool: Vec<IpNet>,

    /// Tracing level (trace, debug, info, warn, error)
    #[clap(long = "log", default_value = "info")]
    log_level: tracing::Level,
}

fn main() {
    let opt = Opt::parse();

    tracing_subscriber::fmt()
        .with_max_level(opt.log_level)
        .init();

    let config = connect_ip_rust_scion::client::ClientConfig {
        bind: opt.bind,
        url: opt.url.clone(),
        cert_path: std::path::PathBuf::new(),
        key_path: std::path::PathBuf::new(),
        routes: opt.routes,
        address_pool: opt.address_pool,
        tun_name: "tun0".to_string(),
    };
    let client = connect_ip_rust_scion::client::Client::new(config);
    let code = if let Err(e) = client.run() {
        eprintln!("ERROR: {e}");
        1
    } else {
        0
    };
    ::std::process::exit(code);
}
