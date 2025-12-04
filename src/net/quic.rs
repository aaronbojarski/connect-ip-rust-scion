use anyhow::{Result, anyhow};
use tracing::info;

pub const MAX_DATAGRAM_SIZE: usize = 1200;
pub const KEEPALIVE_INTERVAL: u64 = 5000; // in milliseconds
pub const DEFAULT_TIMEOUT: u64 = 30_000; // in milliseconds

pub fn configure_quic(
    ca_cert_path: &std::path::Path,
    cert_path: &std::path::Path,
    key_path: &std::path::Path,
) -> Result<quiche::Config> {
    let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION)?;

    info!("Loading cert from {}", cert_path.display());
    info!("Loading key from {}", key_path.display());
    info!("Loading CA cert from {}", ca_cert_path.display());

    config.verify_peer(true);
    config.load_cert_chain_from_pem_file(
        cert_path
            .to_str()
            .ok_or_else(|| anyhow!("Invalid certificate path"))?,
    )?;
    config.load_priv_key_from_pem_file(
        key_path
            .to_str()
            .ok_or_else(|| anyhow!("Invalid key path"))?,
    )?;
    config.load_verify_locations_from_file(
        ca_cert_path
            .to_str()
            .ok_or_else(|| anyhow!("Invalid CA certificate path"))?,
    )?;

    config.set_application_protos(quiche::h3::APPLICATION_PROTOCOL)?;
    config.set_max_idle_timeout(DEFAULT_TIMEOUT);
    config.set_max_recv_udp_payload_size(MAX_DATAGRAM_SIZE);
    config.set_max_send_udp_payload_size(MAX_DATAGRAM_SIZE);
    config.set_initial_max_data(10_000_000);
    config.set_initial_max_stream_data_bidi_local(1_000_000);
    config.set_initial_max_stream_data_bidi_remote(1_000_000);
    config.set_initial_max_stream_data_uni(1_000_000);
    config.set_initial_max_streams_bidi(1);
    config.set_initial_max_streams_uni(1);
    config.set_disable_active_migration(true);
    config.enable_early_data();
    config.enable_dgram(true, 1000, 200);

    Ok(config)
}
