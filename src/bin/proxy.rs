use clap::Parser;
use ipnet::IpNet;
use std::{
    env,
    net::{IpAddr, Ipv4Addr, SocketAddr},
};

#[derive(Parser, Debug)]
#[clap(name = "proxy", about = "A CONNECT-IP proxy server")]
struct Opt {
    /// Address to listen on
    #[clap(long = "listen", default_value = "127.0.0.1:4433")]
    listen: SocketAddr,
}

fn main() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .init();
    let opt = Opt::parse();
    let cwd = env::current_dir().unwrap();
    let config = connect_ip_rust_scion::proxy::ProxyConfig {
        listen: opt.listen,
        cert_path: cwd.join("cert.pem"),
        key_path: cwd.join("key.pem"),
        routes: vec![IpNet::new(IpAddr::V4(Ipv4Addr::new(10, 248, 2, 0)), 24).unwrap()],
        address_pool: vec![IpNet::new(IpAddr::V4(Ipv4Addr::new(10, 248, 2, 128)), 25).unwrap()],
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
