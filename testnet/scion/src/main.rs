use std::{net::SocketAddr, time::SystemTime};

use anyhow::Context;
use ipnet::IpNet;
use pocketscion::{
    io_config,
    network::scion::topology::{ScionAs, ScionTopology},
    runtime::{PocketScionRuntime, PocketScionRuntimeBuilder},
    state::SharedPocketScionState,
};
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;
use scion_proto::address::IsdAsn;
use snap_tokens::snap_token::dummy_snap_token;
use tracing::level_filters::LevelFilter;

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    tracing_subscriber::fmt()
        .with_max_level(LevelFilter::INFO)
        .init();

    // Config
    let pocket_scion = PocketScionConfig {
        topology: example_topology()?,
        scion_access_points: vec![
            SnapConfig {
                name: "server_snap".to_string(),
                listening_addr: "10.248.101.21:10001".parse()?,
                data_planes: vec![DataPlaneConfig {
                    listening_addr: "10.248.101.21:10002".parse()?,
                    isd_as: "2-2".parse()?,
                    address_range: vec!["10.1.0.0/24".parse()?],
                }],
            },
            SnapConfig {
                name: "client_snap".to_string(),
                listening_addr: "10.248.100.20:10003".parse()?,
                data_planes: vec![DataPlaneConfig {
                    listening_addr: "10.248.100.20:10004".parse()?,
                    isd_as: "1-12".parse()?,
                    address_range: vec!["10.2.0.0/24".parse()?],
                }],
            },
        ],
    };

    //##############################################
    // Start Pocket SCION

    let _pocket_scion_runtime = {
        tracing::info!("Starting Pocket SCION runtime...");

        // Pocket SCIONs state is separated from IO Configuration to allow sharing the state
        // between multiple runtimes/machines/systems e.g. for testing purposes.
        let mut system_state = SharedPocketScionState::new(SystemTime::now());
        let io_config = io_config::SharedPocketScionIoConfig::new();

        // Set the topology
        system_state.set_topology(pocket_scion.topology.clone());

        // Create SCION Network Access Points (SNAPs)
        for snap in &pocket_scion.scion_access_points {
            // Add a new SNAP to the system state
            let snap_id = system_state.add_snap();

            // Then add an IO config to declare how this control plane can be reached
            io_config.set_snap_control_addr(snap_id, snap.listening_addr);

            for data_plane in &snap.data_planes {
                // Add the SNAP data plane to the system state
                let dataplane_id = system_state.add_snap_data_plane(
                    snap_id,
                    data_plane.isd_as,
                    data_plane.address_range.clone(),
                    ChaCha8Rng::seed_from_u64(10),
                );

                // Add an IO config
                io_config.set_snap_data_plane_addr(dataplane_id, data_plane.listening_addr);
            }
        }

        // Finally we create the PocketScionRuntime
        let rt: PocketScionRuntime = PocketScionRuntimeBuilder::new()
            .with_system_state(system_state.into_state())
            .with_io_config(io_config.into_state())
            .with_mgmt_listen_addr(std::net::SocketAddr::from(([127, 0, 0, 1], 8082)))
            .start()
            .await
            .context("error starting Pocket SCION runtime")?;

        tracing::info!("Pocket SCION runtime started");

        rt
    };

    tracing::info!("Example SCION testnet setup complete.");
    tracing::info!("Dummy SNAP token: {}", dummy_snap_token());
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(60)).await;
    }

    Ok(())
}

/// Defines a Network Topology to be simulated through Pocket SCION.
pub fn example_topology() -> anyhow::Result<ScionTopology> {
    let mut topo = ScionTopology::new();

    topo.add_as(ScionAs::new_core("1-1".parse()?))?
        .add_as(ScionAs::new("1-2".parse()?))?
        .add_as(ScionAs::new("1-3".parse()?))?
        .add_as(ScionAs::new("1-4".parse()?))?
        .add_as(ScionAs::new_core("1-11".parse()?))?
        .add_as(ScionAs::new("1-12".parse()?))?
        .add_as(ScionAs::new_core("1-21".parse()?))?
        .add_as(ScionAs::new_core("2-1".parse()?))?
        .add_as(ScionAs::new("2-2".parse()?))?
        .add_as(ScionAs::new("2-3".parse()?))?
        .add_as(ScionAs::new("2-4".parse()?))?;

    // Core links
    topo.add_link("1-1#5 core 1-11#6".parse()?)?
        .add_link("1-1#32 core 1-21#17".parse()?)?
        .add_link("1-11#15 core 1-21#22".parse()?)?
        .add_link("1-21#23 core 2-1#24".parse()?)?
        .add_link("1-11#23 core 2-1#1".parse()?)?;

    // Single digit as links
    topo.add_link("1-1#1 down_to 1-2#2".parse()?)?
        .add_link("1-2#3 down_to 1-3#4".parse()?)?
        .add_link("1-3#15 down_to 1-4#16".parse()?)?
        .add_link("1-2#17 down_to 1-4#18".parse()?)?;

    // Double digit as links
    topo.add_link("1-11#7 down_to 1-12#8".parse()?)?
        .add_link("1-12#9 down_to 1-3#10".parse()?)?
        .add_link("1-12#19 down_to 1-4#20".parse()?)?
        .add_link("1-12#12 down_to 1-2#11 ".parse()?)?;

    // ISD2 links
    topo.add_link("2-1#2 down_to 2-2#3".parse()?)?
        .add_link("2-2#4 down_to 2-3#5".parse()?)?
        .add_link("2-3#6 down_to 2-4#7".parse()?)?;

    Ok(topo)
}

struct PocketScionConfig {
    /// The SCION network topology being simulated
    topology: ScionTopology,
    /// SCION Network Access Points (SNAP) for the server and client
    scion_access_points: Vec<SnapConfig>,
}

/// SCION Network Access Point (SNAP) configuration
struct SnapConfig {
    /// Example internal name of the SNAP
    name: String,
    /// Listening address for the SNAP's control plane
    listening_addr: SocketAddr,
    /// This SNAP's data planes
    data_planes: Vec<DataPlaneConfig>,
}

struct DataPlaneConfig {
    isd_as: IsdAsn,
    /// The LAN address this data plane should listen on
    listening_addr: SocketAddr,
    /// The (virtual) IP addresses this data plane can assign to its clients
    address_range: Vec<IpNet>,
}
