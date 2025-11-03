use clap::Parser;
use std::net::SocketAddr;

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
    let code = {
        if let Err(e) = connect_ip_rust_scion::proxy::run(opt.listen) {
            eprintln!("ERROR: {e}");
            1
        } else {
            0
        }
    };
    ::std::process::exit(code);
}
