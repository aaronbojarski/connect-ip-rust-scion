use anyhow::anyhow;
use clap::Parser;
use connect_ip_rust_scion::config::{
    Cli, ClientOpt, Command, ProxyOpt, combine_client_config, combine_proxy_config,
    load_client_config_from_file, load_proxy_config_from_file,
};

fn main() -> Result<(), anyhow::Error> {
    install_rustls_crypto_provider()?;
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
    let config_file = opt
        .config_path
        .as_ref()
        .map(|config_path| {
            load_proxy_config_from_file(config_path)
                .map_err(|e| anyhow!("Failed to load config from {:?}: {}", config_path, e))
        })
        .transpose()?;

    let (config, log_level) = combine_proxy_config(opt, config_file)
        .map_err(|e| anyhow!("Invalid Config Parameters: {}", e))?;

    tracing_subscriber::fmt()
        .with_max_level(log_level)
        .try_init()
        .map_err(|err| anyhow!("failed to init tracing: {err}"))?;

    let mut proxy = connect_ip_rust_scion::proxy::Proxy::new(config)?;
    proxy.run().await?;
    Ok(())
}

#[tokio::main]
async fn run_client(opt: ClientOpt) -> Result<(), anyhow::Error> {
    let config_file = opt
        .config_path
        .as_ref()
        .map(|config_path| {
            load_client_config_from_file(config_path)
                .map_err(|e| anyhow!("Failed to load config from {:?}: {}", config_path, e))
        })
        .transpose()?;

    let (config, log_level) = combine_client_config(opt, config_file)
        .map_err(|e| anyhow!("Invalid Config Parameters: {}", e))?;

    tracing_subscriber::fmt()
        .with_max_level(log_level)
        .try_init()
        .map_err(|err| anyhow!("failed to init tracing: {err}"))?;

    let client = connect_ip_rust_scion::client::Client::new(config);
    client.run().await?;
    Ok(())
}

fn install_rustls_crypto_provider() -> Result<(), anyhow::Error> {
    rustls::crypto::CryptoProvider::install_default(rustls::crypto::ring::default_provider())
        .map_err(|err| anyhow!("failed to install rustls ring CryptoProvider: {err:?}"))
}
