use clap::Parser;
use ipnet::IpNet;
use std::{env, net::SocketAddr};

#[derive(Parser, Debug)]
#[clap(name = "proxy", about = "A CONNECT-IP proxy server")]
struct Opt {
    /// Address to listen on
    #[clap(long, default_value = "127.0.0.1:4433")]
    listen: SocketAddr,

    /// Routes to advertise to clients
    #[clap(long)]
    routes: Vec<IpNet>,

    /// Address pool to assign from
    #[clap(long)]
    address_pool: Vec<IpNet>,
}

fn main() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();
    let opt = Opt::parse();
    let cwd = env::current_dir().unwrap();
    let config = connect_ip_rust_scion::proxy::ProxyConfig {
        listen: opt.listen,
        cert_path: cwd.join("cert.pem"),
        key_path: cwd.join("key.pem"),
        routes: opt.routes,
        address_pool: opt.address_pool,
    };
    let proxy = connect_ip_rust_scion::proxy::Proxy::new(config);
    let code = {
        if let Err(e) = proxy.run() {
            eprintln!("ERROR: {e}");
            1
        } else {
            0
        }
    };
    ::std::process::exit(code);
}
