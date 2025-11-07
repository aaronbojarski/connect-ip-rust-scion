use clap::Parser;
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
}

fn main() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .init();
    let opt = Opt::parse();
    let code =
        if let Err(e) = connect_ip_rust_scion::client::run(opt.url, opt.bind, "tun0".to_string()) {
            eprintln!("ERROR: {e}");
            1
        } else {
            0
        };
    ::std::process::exit(code);
}
