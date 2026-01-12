use std::process::Command;

use anyhow::{Context, Error};
use ipnet::IpNet;

// ============================================================================
// Linux implementation using `ip` command
// ============================================================================

#[cfg(target_os = "linux")]
/// Builds IP route command arguments based on IP version and operation
fn build_ip_route_args(destination: &IpNet, operation: &str) -> Vec<String> {
    match destination {
        IpNet::V4(_) => vec!["route".to_string(), operation.to_string()],
        IpNet::V6(_) => vec!["-6".to_string(), "route".to_string(), operation.to_string()],
    }
}

#[cfg(target_os = "linux")]
/// Adds a routing table entry for the specified destination network.
///
/// Checks if the route already exists before adding it. Uses the `ip` command
/// to configure the system routing table.
///
/// # Arguments
/// * `destination` - The destination network for the route
/// * `dev` - The network device/interface name (e.g., "tun0")
///
/// # Returns
/// * `Ok(true)` - Route was added successfully
/// * `Ok(false)` - Route already exists
/// * `Err(_)` - Failed to execute the ip command or command returned an error
pub fn add_route(destination: &IpNet, dev: &str) -> Result<bool, Error> {
    let existing_routes = {
        let mut cmd = Command::new("ip");
        let args = build_ip_route_args(destination, "show");
        cmd.args(args);
        let dest = destination.to_string();
        cmd.arg(&dest).args(["dev", dev]);
        run_command(cmd)?
    };

    if !existing_routes.stdout.is_empty() {
        return Ok(false);
    }

    let mut add_cmd = Command::new("ip");
    let args = build_ip_route_args(destination, "add");
    add_cmd.args(args);
    let dest = destination.to_string();
    add_cmd.arg(&dest).args(["dev", dev]);
    run_command(add_cmd)?;
    Ok(true)
}

#[cfg(target_os = "linux")]
/// Removes a routing table entry for the specified destination network.
///
/// Uses the `ip` command to remove the route from the system routing table.
///
/// # Arguments
/// * `destination` - The destination network of the route to remove
/// * `dev` - The network device/interface name (e.g., "tun0")
///
/// # Returns
/// * `Ok(())` - Route was removed successfully
/// * `Err(_)` - Failed to execute the ip command or command returned an error
pub fn remove_route(destination: &IpNet, dev: &str) -> Result<(), Error> {
    let mut del_cmd = Command::new("ip");
    let args = build_ip_route_args(destination, "del");
    del_cmd.args(args);
    let dest = destination.to_string();
    del_cmd.arg(&dest).args(["dev", dev]);
    run_command(del_cmd)?;
    Ok(())
}

// ============================================================================
// Windows implementation using `route` command
// ============================================================================

#[cfg(target_os = "windows")]
/// Parses the output of `route print` to find the interface index for a given interface name.
///
/// The output contains an interface list section like:
/// ```
/// Interface List
///  12...........................tun0 Tunnel
///  15...00 15 5d 01 23 45 ......Ethernet Adapter
/// ```
///
/// # Arguments
/// * `interface_name` - The name of the interface to find (e.g., "tun0")
///
/// # Returns
/// * `Ok(Some(index))` - Interface index found
/// * `Ok(None)` - Interface name not found
/// * `Err(_)` - Failed to execute route print command
fn get_interface_index(interface_name: &str) -> Result<Option<String>, Error> {
    let mut print_cmd = Command::new("route");
    print_cmd.args(["print", "IF"]);
    let output = run_command(print_cmd)?;
    let output_str = String::from_utf8_lossy(&output.stdout);

    // Parse the interface list section
    for line in output_str.lines() {
        if line.contains(interface_name) {
            // Extract the interface index (number before "...")
            let index_str = line
                .trim()
                .split(".")
                .next()
                .ok_or_else(|| anyhow::anyhow!("Failed to parse interface index"))?;
            return Ok(Some(index_str.to_string()));
        }
    }

    Ok(None)
}

#[cfg(target_os = "windows")]
/// Adds a routing table entry for the specified destination network.
///
/// Checks if the route already exists before adding it. Uses the `route` command
/// to configure the system routing table.
///
/// # Arguments
/// * `destination` - The destination network for the route
/// * `dev` - The network device/interface name (e.g., "tun0")
///
/// # Returns
/// * `Ok(true)` - Route was added successfully
/// * `Ok(false)` - Route already exists
/// * `Err(_)` - Failed to execute the route command or command returned an error
pub fn add_route(destination: &IpNet, dev: &str) -> Result<bool, Error> {
    // Get interface index from name
    let interface_index = get_interface_index(dev)?
        .ok_or_else(|| anyhow::anyhow!("Interface '{}' not found", dev))?;

    // Check if route already exists
    let mut print_cmd = Command::new("route");
    print_cmd.args(["print"]);
    let output = run_command(print_cmd)?;
    let output_str = String::from_utf8_lossy(&output.stdout);

    let dest_str = destination.network().to_string();
    if output_str.contains(&dest_str) {
        return Ok(false);
    }

    // Add the route
    let mut add_cmd = Command::new("route");
    add_cmd.arg("add");

    match destination {
        IpNet::V4(net) => {
            add_cmd.arg(net.network().to_string());
            add_cmd.arg("mask");
            add_cmd.arg(net.netmask().to_string());
            add_cmd.arg("0.0.0.0"); // Gateway (use 0.0.0.0 for direct interface routing)
            add_cmd.args(["IF", &interface_index]);
        }
        IpNet::V6(net) => {
            add_cmd.arg(format!("{}/{}", net.network(), net.prefix_len()));
            add_cmd.args(["IF", &interface_index]);
        }
    }

    run_command(add_cmd)?;
    Ok(true)
}

#[cfg(target_os = "windows")]
/// Removes a routing table entry for the specified destination network.
///
/// Uses the `route` command to remove the route from the system routing table.
///
/// # Arguments
/// * `destination` - The destination network of the route to remove
/// * `dev` - The network device/interface name (unused on Windows, kept for API compatibility)
///
/// # Returns
/// * `Ok(())` - Route was removed successfully
/// * `Err(_)` - Failed to execute the route command or command returned an error
pub fn remove_route(destination: &IpNet, _dev: &str) -> Result<(), Error> {
    let mut del_cmd = Command::new("route");
    del_cmd.arg("delete");

    match destination {
        IpNet::V4(net) => {
            del_cmd.arg(net.network().to_string());
        }
        IpNet::V6(net) => {
            del_cmd.arg(format!("{}/{}", net.network(), net.prefix_len()));
        }
    }

    run_command(del_cmd)?;
    Ok(())
}

// ============================================================================
// Common helper function
// ============================================================================

fn run_command(mut cmd: Command) -> Result<std::process::Output, Error> {
    let program = cmd.get_program().to_string_lossy();
    let args = cmd
        .get_args()
        .map(|a| a.to_string_lossy())
        .collect::<Vec<_>>();
    let display_cmd = format!("{} {}", program, args.join(" ")).trim().to_string();

    let output = cmd
        .output()
        .with_context(|| format!("failed to execute `{}`", display_cmd))?;

    if !output.status.success() {
        return Err(anyhow::anyhow!(
            "`{}` exited with {}.\nstderr: {}\nstdout: {}",
            display_cmd,
            output.status,
            String::from_utf8_lossy(&output.stderr),
            String::from_utf8_lossy(&output.stdout)
        ));
    }

    Ok(output)
}
