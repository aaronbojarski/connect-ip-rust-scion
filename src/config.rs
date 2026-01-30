use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;

use clap::{Args, Parser, Subcommand};
use ipnet::IpNet;
use scion_proto::path::policy::acl::AclPolicy;
use serde::{Deserialize, Serialize};
use url::Url;

pub const DEFAULT_TUN_NAME: &str = "tun0";
pub const DEFAULT_TUN_MTU: u16 = 1500;

#[derive(Parser, Debug)]
#[clap(
    name = "connect-ip-rust-scion",
    about = "Run the CONNECT-IP proxy or client",
    subcommand_required = true,
    arg_required_else_help = true
)]
pub struct Cli {
    #[clap(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    Proxy(ProxyOpt),
    Client(ClientOpt),
}

#[derive(Args, Debug)]
pub struct ProxyOpt {
    /// Config file path
    #[clap(long = "config", value_name = "FILE")]
    pub config_path: Option<PathBuf>,

    /// Address to listen on
    #[clap(long)]
    listen: Option<scion_proto::address::SocketAddr>,

    /// Address of the endhost API to connect to for scion path resolution. Required when using SCION.
    #[clap(long = "endhost-api")]
    endhost_api_address: Option<Url>,

    /// Path to the Snap token file for authentication with the endhost API
    #[clap(long = "snap-token", value_name = "FILE")]
    snap_token_path: Option<PathBuf>,

    /// ACL policy to filter SCION paths
    #[clap(long = "acl", allow_hyphen_values = true)]
    acl: Option<AclPolicy>,

    /// CA certificate used to verify peers
    #[clap(long = "ca-cert", value_name = "FILE")]
    ca_cert_path: Option<PathBuf>,

    /// Certificate presented to clients
    #[clap(long = "cert", value_name = "FILE")]
    cert_path: Option<PathBuf>,

    /// Private key for the presented certificate
    #[clap(long = "key", value_name = "FILE")]
    key_path: Option<PathBuf>,

    /// Routes to advertise to clients
    #[clap(long)]
    routes: Vec<IpNet>,

    /// Address pool to assign addresses to clients from
    #[clap(long)]
    address_pool: Vec<IpNet>,

    /// MTU for the interface
    #[clap(long)]
    mtu: Option<u16>,

    /// Tracing level (trace, debug, info, warn, error)
    #[clap(long = "log")]
    log_level: Option<tracing::Level>,
}

#[derive(Args, Debug)]
pub struct ClientOpt {
    /// Config file path
    #[clap(long = "config", value_name = "FILE")]
    pub config_path: Option<PathBuf>,

    /// Address of proxy to connect to (e.g. [0-0,proxy.example.com]:4433)
    #[clap(long)]
    remote: Option<scion_proto::address::SocketAddr>,

    /// Hostname used for certificate verification
    #[clap(long = "host")]
    host: Option<String>,

    /// Local address to bind to
    #[clap(long = "bind")]
    bind: Option<scion_proto::address::SocketAddr>,

    /// Address of the endhost API to connect to for scion path resolution. Required when using SCION.
    #[clap(long = "endhost-api")]
    endhost_api_address: Option<Url>,

    /// Path to the Snap token file for authentication with the endhost API
    #[clap(long = "snap-token", value_name = "FILE")]
    snap_token_path: Option<PathBuf>,

    /// ACL policy to filter SCION paths
    #[clap(long = "acl", allow_hyphen_values = true)]
    acl: Option<AclPolicy>,

    /// Routes to advertise to the proxy (repeat --routes for each CIDR, e.g. 192.0.2.0/24)
    #[clap(long)]
    routes: Vec<IpNet>,

    /// Address pool to assign addresses to the proxy from (repeat --address-pool for each CIDR, e.g. 192.0.1.0/24)
    #[clap(long)]
    address_pool: Vec<IpNet>,

    /// CA certificate used to verify the proxy
    #[clap(long = "ca-cert", value_name = "FILE")]
    ca_cert_path: Option<PathBuf>,

    /// Client certificate presented to the proxy
    #[clap(long = "cert", value_name = "FILE")]
    cert_path: Option<PathBuf>,

    /// Private key for the client certificate
    #[clap(long = "key", value_name = "FILE")]
    key_path: Option<PathBuf>,

    /// Name of the TUN interface to create
    #[clap(long = "tun")]
    tun_name: Option<String>,

    /// MTU for the interface
    #[clap(long)]
    mtu: Option<u16>,

    /// Tracing level (trace, debug, info, warn, error)
    #[clap(long = "log")]
    log_level: Option<tracing::Level>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfiguredClient {
    pub name: String,
    pub address: IpNet,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProxyConfigFile {
    /// Address to listen on
    pub listen: Option<String>,

    /// Address of the endhost API to connect to for scion path resolution.
    pub endhost_api_address: Option<String>,

    /// Path to the Snap token file for authentication with the endhost API
    pub snap_token_path: Option<PathBuf>,

    /// ACL policy to filter SCION paths
    pub acl_policy: Option<String>,

    /// CA certificate used to verify the client
    pub ca_cert_path: Option<PathBuf>,

    /// Server certificate presented to the client
    pub cert_path: Option<PathBuf>,

    /// Private key for the server certificate
    pub key_path: Option<PathBuf>,

    /// Name of the TUN interface to create
    pub tun_name: Option<String>,

    /// MTU for the interface
    pub mtu: Option<u16>,

    /// Address pool to assign addresses to clients from
    pub address_pool: Option<Vec<IpNet>>,

    /// Routes to advertise to clients
    pub routes: Option<Vec<IpNet>>,

    /// Clients with configured static addresses
    pub configured_clients: Option<Vec<ConfiguredClient>>,

    /// Tracing level (trace, debug, info, warn, error)
    pub log_level: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientConfigFile {
    /// Address of proxy to connect to.
    pub remote: Option<String>,

    /// Hostname used for certificate verification
    pub host: Option<String>,

    /// Local address to bind to
    pub bind: Option<String>,

    /// Address of the endhost API to connect to for scion path resolution.
    pub endhost_api_address: Option<String>,

    /// Path to the Snap token file for authentication with the endhost API
    pub snap_token_path: Option<PathBuf>,

    /// ACL policy to filter SCION paths
    pub acl_policy: Option<String>,

    /// CA certificate used to verify the proxy
    pub ca_cert_path: Option<PathBuf>,

    /// Client certificate presented to the proxy
    pub cert_path: Option<PathBuf>,

    /// Private key for the client certificate
    pub key_path: Option<PathBuf>,

    /// Name of the TUN interface to create
    pub tun_name: Option<String>,

    /// MTU for the interface
    pub mtu: Option<u16>,

    /// Address pool to assign addresses to clients from
    pub address_pool: Option<Vec<IpNet>>,

    /// Routes to advertise to clients
    pub routes: Option<Vec<IpNet>>,

    /// Tracing level (trace, debug, info, warn, error)
    pub log_level: Option<String>,
}

pub fn load_proxy_config_from_file(path: &PathBuf) -> anyhow::Result<ProxyConfigFile> {
    let config_data = std::fs::read_to_string(path)?;
    let config: ProxyConfigFile = serde_json::from_str(&config_data)?;
    Ok(config)
}

pub fn combine_proxy_config(
    cli_config: ProxyOpt,
    file_config: Option<ProxyConfigFile>,
) -> anyhow::Result<(crate::proxy::ProxyConfig, tracing::Level)> {
    let file_config = file_config.as_ref();

    let listen = cli_config
        .listen
        .or_else(|| {
            file_config.and_then(|config| {
                config.listen.as_ref().and_then(|s| {
                    s.parse()
                        .map_err(|e| anyhow::anyhow!("invalid listen address in config file: {e}"))
                        .ok()
                })
            })
        })
        .ok_or_else(|| anyhow::anyhow!("No listen address provided."))?;

    let endhost_api_address = cli_config.endhost_api_address.or_else(|| {
        file_config.and_then(|config| {
            config.endhost_api_address.as_ref().and_then(|s| {
                s.parse()
                    .map_err(|e| anyhow::anyhow!("invalid endhost API address in config file: {e}"))
                    .ok()
            })
        })
    });

    let snap_token_path = cli_config
        .snap_token_path
        .or_else(|| file_config.and_then(|config| config.snap_token_path.clone()));

    let acl_policy = cli_config.acl.or_else(|| {
        file_config.and_then(|config| {
            config
                .acl_policy
                .as_ref()
                .and_then(|policy| AclPolicy::from_str(policy).ok())
        })
    });

    let ca_cert_path = cli_config
        .ca_cert_path
        .clone()
        .or_else(|| file_config.and_then(|config| config.ca_cert_path.clone()))
        .ok_or_else(|| anyhow::anyhow!("No CA Certificate path provided."))?;

    let cert_path = cli_config
        .cert_path
        .clone()
        .or_else(|| file_config.and_then(|config| config.cert_path.clone()))
        .ok_or_else(|| anyhow::anyhow!("No Certificate path provided."))?;

    let key_path = cli_config
        .key_path
        .clone()
        .or_else(|| file_config.and_then(|config| config.key_path.clone()))
        .ok_or_else(|| anyhow::anyhow!("No Key path provided."))?;

    let routes = (!cli_config.routes.is_empty())
        .then(|| cli_config.routes.clone())
        .or_else(|| file_config.and_then(|config| config.routes.clone()))
        .unwrap_or_default();

    let address_pool = (!cli_config.address_pool.is_empty())
        .then(|| cli_config.address_pool.clone())
        .or_else(|| file_config.and_then(|config| config.address_pool.clone()))
        .unwrap_or_default();

    let configured_clients = if let Some(config) = file_config
        && let Some(clients) = &config.configured_clients
    {
        let mut map = std::collections::HashMap::new();
        for client in clients {
            if address_pool
                .iter()
                .any(|pool| pool.contains(&client.address.addr()))
            {
                return Err(anyhow::anyhow!(
                    "Configured client address {} for client '{}' must not be part of the address pool.",
                    client.address,
                    client.name
                ));
            }
            map.insert(client.name.clone(), client.address);
        }
        map
    } else {
        std::collections::HashMap::new()
    };

    let mtu = cli_config
        .mtu
        .or_else(|| file_config.and_then(|config| config.mtu))
        .unwrap_or(DEFAULT_TUN_MTU);

    let log_level = cli_config
        .log_level
        .or_else(|| {
            file_config
                .and_then(|config| config.log_level.as_ref())
                .and_then(|s| tracing::Level::from_str(s).ok())
        })
        .unwrap_or(tracing::Level::INFO);

    Ok((
        crate::proxy::ProxyConfig {
            listen,
            endhost_api_address,
            snap_token_path,
            acl_policy,
            ca_cert_path,
            cert_path,
            key_path,
            routes,
            address_pool,
            configured_clients: Arc::new(configured_clients),
            tun_mtu: mtu,
        },
        log_level,
    ))
}

pub fn load_client_config_from_file(path: &PathBuf) -> anyhow::Result<ClientConfigFile> {
    let config_data = std::fs::read_to_string(path)?;
    let config: ClientConfigFile = serde_json::from_str(&config_data)?;
    Ok(config)
}

pub fn combine_client_config(
    cli_config: ClientOpt,
    file_config: Option<ClientConfigFile>,
) -> anyhow::Result<(crate::client::ClientConfig, tracing::Level)> {
    let file_config = file_config.as_ref();

    let remote = cli_config
        .remote
        .or_else(|| {
            file_config.and_then(|config| {
                config.remote.as_ref().and_then(|s| {
                    s.parse()
                        .map_err(|e| anyhow::anyhow!("invalid remote address in config file: {e}"))
                        .ok()
                })
            })
        })
        .ok_or_else(|| anyhow::anyhow!("No remote address provided."))?;

    let host = cli_config
        .host
        .or_else(|| file_config.and_then(|config| config.host.clone()));

    let listen = cli_config.bind.or_else(|| {
        file_config.and_then(|config| {
            config.bind.as_ref().and_then(|s| {
                s.parse()
                    .map_err(|e| anyhow::anyhow!("invalid listen address in config file: {e}"))
                    .ok()
            })
        })
    });

    let endhost_api_address = cli_config.endhost_api_address.or_else(|| {
        file_config.and_then(|config| {
            config.endhost_api_address.as_ref().and_then(|s| {
                s.parse()
                    .map_err(|e| anyhow::anyhow!("invalid endhost API address in config file: {e}"))
                    .ok()
            })
        })
    });

    let snap_token_path = cli_config
        .snap_token_path
        .or_else(|| file_config.and_then(|config| config.snap_token_path.clone()));

    let acl_policy = cli_config.acl.or_else(|| {
        file_config.and_then(|config| {
            config
                .acl_policy
                .as_ref()
                .and_then(|policy| AclPolicy::from_str(policy).ok())
        })
    });

    let ca_cert_path = cli_config
        .ca_cert_path
        .clone()
        .or_else(|| file_config.and_then(|config| config.ca_cert_path.clone()))
        .ok_or_else(|| anyhow::anyhow!("No CA Certificate path provided."))?;

    let cert_path = cli_config
        .cert_path
        .clone()
        .or_else(|| file_config.and_then(|config| config.cert_path.clone()))
        .ok_or_else(|| anyhow::anyhow!("No Certificate path provided."))?;

    let key_path = cli_config
        .key_path
        .clone()
        .or_else(|| file_config.and_then(|config| config.key_path.clone()))
        .ok_or_else(|| anyhow::anyhow!("No Key path provided."))?;

    let routes = (!cli_config.routes.is_empty())
        .then(|| cli_config.routes.clone())
        .or_else(|| file_config.and_then(|config| config.routes.clone()))
        .unwrap_or_default();

    let address_pool = (!cli_config.address_pool.is_empty())
        .then(|| cli_config.address_pool.clone())
        .or_else(|| file_config.and_then(|config| config.address_pool.clone()))
        .unwrap_or_default();

    let mtu = cli_config
        .mtu
        .or_else(|| file_config.and_then(|config| config.mtu))
        .unwrap_or(DEFAULT_TUN_MTU);

    let tun_name = cli_config
        .tun_name
        .or_else(|| file_config.and_then(|config| config.tun_name.clone()))
        .unwrap_or(DEFAULT_TUN_NAME.to_string());

    let log_level = cli_config
        .log_level
        .or_else(|| {
            file_config
                .and_then(|config| config.log_level.as_ref())
                .and_then(|s| tracing::Level::from_str(s).ok())
        })
        .unwrap_or(tracing::Level::INFO);

    Ok((
        crate::client::ClientConfig {
            bind: listen,
            remote,
            host,
            endhost_api_address,
            snap_token_path,
            acl_policy,
            ca_cert_path,
            cert_path,
            key_path,
            routes,
            address_pool,
            tun_mtu: mtu,
            tun_name,
        },
        log_level,
    ))
}
