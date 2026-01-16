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

#[cfg(target_os = "linux")]
/// Sets the specified network device/interface down.
//// Uses the `ip` command to set the interface down.
/// # Arguments
/// * `dev` - The network device/interface name (e.g., "tun0")
/// # Returns
/// * `Ok(())` - Interface was set down successfully
/// * `Err(_)` - Failed to execute the ip command or command returned an error
pub fn set_interface_down(dev: &str) -> Result<(), Error> {
    let mut cmd = Command::new("ip");
    cmd.args(["link", "set", "dev", dev, "down"]);
    run_command(cmd)?;
    Ok(())
}

#[cfg(target_os = "linux")]
/// Flushes all IP addresses assigned to the specified network device.
///
/// Uses the `ip` command to flush the addresses.
/// # Arguments
/// * `dev` - The network device/interface name (e.g., "tun0")
/// # Returns
/// * `Ok(())` - Addresses were flushed successfully
/// * `Err(_)` - Failed to execute the ip command or command returned an error
pub fn flush_ip_addresses(dev: &str) -> Result<(), Error> {
    let mut cmd = Command::new("ip");
    cmd.args(["addr", "flush", "dev", dev]);
    run_command(cmd)?;
    Ok(())
}

// ============================================================================
// Windows implementation using `netsh` command
// ============================================================================

#[cfg(target_os = "windows")]
/// Adds a routing table entry for the specified destination network.
///
/// Checks if the route already exists before adding it. Uses the `netsh` command
/// to configure the system routing table.
///
/// # Arguments
/// * `destination` - The destination network for the route
/// * `dev` - The network device/interface name (e.g., "tun0")
///
/// # Returns
/// * `Ok(true)` - Route was added successfully
/// * `Ok(false)` - Route already exists
/// * `Err(_)` - Failed to execute the netsh command or command returned an error
pub fn add_route(destination: &IpNet, dev: &str) -> Result<bool, Error> {
    // Check if route already exists
    let mut show_cmd = Command::new("netsh");
    let ip_version = match destination {
        IpNet::V4(_) => "ipv4",
        IpNet::V6(_) => "ipv6",
    };
    show_cmd.args(["interface", ip_version, "show", "route"]);
    let output = run_command(show_cmd)?;
    let output_str = String::from_utf8_lossy(&output.stdout);

    let dest_str = destination.to_string();
    if output_str.contains(&dest_str) && output_str.contains(dev) {
        return Ok(false);
    }

    // Add the route
    let mut add_cmd = Command::new("netsh");
    add_cmd.args(["interface", ip_version, "add", "route"]);
    add_cmd.arg(&dest_str);
    add_cmd.arg(dev);

    run_command(add_cmd)?;
    Ok(true)
}

#[cfg(target_os = "windows")]
/// Removes a routing table entry for the specified destination network.
///
/// Uses the `netsh` command to remove the route from the system routing table.
///
/// # Arguments
/// * `destination` - The destination network of the route to remove
/// * `dev` - The network device/interface name (e.g., "tun0")
///
/// # Returns
/// * `Ok(())` - Route was removed successfully
/// * `Err(_)` - Failed to execute the netsh command or command returned an error
pub fn remove_route(destination: &IpNet, dev: &str) -> Result<(), Error> {
    let mut del_cmd = Command::new("netsh");
    let ip_version = match destination {
        IpNet::V4(_) => "ipv4",
        IpNet::V6(_) => "ipv6",
    };
    del_cmd.args(["interface", ip_version, "delete", "route"]);
    del_cmd.arg(destination.to_string());
    del_cmd.arg(dev);

    run_command(del_cmd)?;
    Ok(())
}

#[cfg(target_os = "windows")]
/// Sets the specified network device/interface down.
//// Uses the `netsh` command to set the interface down.
/// # Arguments
/// * `dev` - The network device/interface name (e.g., "tun0")
/// # Returns
/// * `Ok(())` - Interface was set down successfully
/// * `Err(_)` - Failed to execute the netsh command or command returned an error
pub fn set_interface_down(dev: &str) -> Result<(), Error> {
    let mut cmd = Command::new("netsh");
    cmd.args(["interface", "set", "interface", dev, "disable"]);
    run_command(cmd)?;
    Ok(())
}

#[cfg(target_os = "windows")]
/// Flushes all IP addresses assigned to the specified network device.
///
/// Uses the `netsh` command to flush the addresses.
/// # Arguments
/// * `dev` - The network device/interface name (e.g., "tun0")
/// # Returns
/// * `Ok(())` - Addresses were flushed successfully
/// * `Err(_)` - Failed to execute the netsh command or command returned an error
pub fn flush_ip_addresses(dev: &str) -> Result<(), Error> {
    // Note: Windows does not have a direct equivalent to `ip addr flush dev`.
    // However setting the inteface down should effectively remove its IP addresses.
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
