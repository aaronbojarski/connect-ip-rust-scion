pub mod quic;
pub mod tun;

use anyhow::Error;
use ipnet::IpNet;
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    process::Command,
    sync::Arc,
};
use tokio::sync::Mutex;

pub const ZERO_IPV4_ADDRESS: IpAddr = IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0));
pub const ZERO_IPV6_ADDRESS: IpAddr = IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0));

pub fn is_zero_address(ip_net: &IpNet) -> bool {
    match ip_net.addr() {
        IpAddr::V4(addr) => addr == ZERO_IPV4_ADDRESS,
        IpAddr::V6(addr) => addr == ZERO_IPV6_ADDRESS,
    }
}

pub fn is_ipv4(ip_net: &IpNet) -> bool {
    matches!(ip_net, IpNet::V4(_))
}

pub fn is_ipv6(ip_net: &IpNet) -> bool {
    matches!(ip_net, IpNet::V6(_))
}

pub struct UdpPacket {
    pub src: scion_proto::address::SocketAddr,
    pub dst: scion_proto::address::SocketAddr,
    pub data: Vec<u8>,
}

pub fn ip_range_to_net(start: IpAddr, end: IpAddr) -> Result<IpNet, Error> {
    match (start, end) {
        (IpAddr::V4(start_v4), IpAddr::V4(end_v4)) => {
            let start_u32 = u32::from(start_v4);
            let end_u32 = u32::from(end_v4);

            let diff = end_u32.wrapping_sub(start_u32);
            let prefix_len = diff.leading_zeros() as u8;

            IpNet::new(start, prefix_len).map_err(|e| anyhow::anyhow!("Invalid IP network: {}", e))
        }
        (IpAddr::V6(start_v6), IpAddr::V6(end_v6)) => {
            let start_u128 = u128::from(start_v6);
            let end_u128 = u128::from(end_v6);

            let diff = end_u128.wrapping_sub(start_u128);
            let prefix_len = diff.leading_zeros() as u8;

            IpNet::new(start, prefix_len).map_err(|e| anyhow::anyhow!("Invalid IP network: {}", e))
        }
        _ => Err(anyhow::anyhow!("IP addresses must be of the same version")),
    }
}

pub async fn get_next_avail_subnet(
    available_nets: &Arc<Mutex<Vec<IpNet>>>,
    ipv4: bool,
    prefix_len: u8,
) -> Option<IpNet> {
    let mut available_nets = available_nets.lock().await;

    for net in available_nets.iter() {
        match (ipv4, net) {
            (true, IpNet::V4(_)) | (false, IpNet::V6(_)) => {}
            _ => continue,
        }
        if net.prefix_len() <= prefix_len {
            let net_clone = net.clone();
            let subnets = net.subnets(prefix_len).ok()?;
            let first_subnet = subnets.into_iter().next()?;

            // Remove the allocated subnet from the candidate net
            let remaining_nets: Vec<IpNet> = net
                .subnets(prefix_len)
                .ok()?
                .filter(|n| *n != first_subnet)
                .collect();

            // Update available_nets
            available_nets.retain(|n| n != &net_clone);
            available_nets.extend(remaining_nets);
            *available_nets = IpNet::aggregate(&available_nets);

            return Some(first_subnet);
        }
    }

    None
}

pub async fn return_subnet(available_nets: &Arc<Mutex<Vec<IpNet>>>, subnet: IpNet) {
    let mut available_nets = available_nets.lock().await;
    available_nets.push(subnet);
    *available_nets = IpNet::aggregate(&available_nets);
}

pub async fn get_specific_subnet(
    available_nets: &Arc<Mutex<Vec<IpNet>>>,
    desired_subnet: IpNet,
) -> Option<IpNet> {
    let mut available_nets = available_nets.lock().await;

    for net in available_nets.iter() {
        if net.contains(&desired_subnet.network())
            && net.prefix_len() <= desired_subnet.prefix_len()
        {
            // Remove the allocated subnet from the candidate net
            let remaining_nets: Vec<IpNet> = net
                .subnets(desired_subnet.prefix_len())
                .ok()?
                .filter(|n| *n != desired_subnet)
                .collect();

            // Update available_nets
            let net_clone = net.clone();
            available_nets.retain(|n| n != &net_clone);
            available_nets.extend(remaining_nets);
            *available_nets = IpNet::aggregate(&available_nets);

            return Some(desired_subnet);
        }
    }

    None
}

pub fn add_route(destination: &IpNet, dev: String) -> Result<bool, Error> {
    // check if the route already exists
    let existing_routes = match destination {
        IpNet::V4(_) => Command::new("ip")
            .args(&["route", "show", &destination.to_string(), "dev", &dev])
            .output()?,
        IpNet::V6(_) => Command::new("ip")
            .args(&["-6", "route", "show", &destination.to_string(), "dev", &dev])
            .output()?,
    };

    if !existing_routes.stdout.is_empty() {
        return Ok(false);
    }

    let status = match destination {
        IpNet::V4(_) => Command::new("ip")
            .args(&["route", "add", &destination.to_string(), "dev", &dev])
            .status()?,
        IpNet::V6(_) => Command::new("ip")
            .args(&["-6", "route", "add", &destination.to_string(), "dev", &dev])
            .status()?,
    };

    if status.success() {
        Ok(true)
    } else {
        Err(anyhow::anyhow!("ExitStatus: {}", status))
    }
}

pub fn remove_route(destination: &IpNet, dev: String) -> Result<(), Error> {
    let status = match destination {
        IpNet::V4(_) => Command::new("ip")
            .args(&["route", "del", &destination.to_string(), "dev", &dev])
            .status()?,
        IpNet::V6(_) => Command::new("ip")
            .args(&["-6", "route", "del", &destination.to_string(), "dev", &dev])
            .status()?,
    };

    if status.success() {
        Ok(())
    } else {
        Err(anyhow::anyhow!("ExitStatus: {}", status))
    }
}

pub fn check_packet_src_dst(
    packet_src: IpAddr,
    packet_dst: IpAddr,
    allowed_src_1: &Vec<IpNet>,
    allowed_src_2: &Vec<IpNet>,
    allowed_dst_1: &Vec<IpNet>,
    allowed_dst_2: &Vec<IpNet>,
) -> bool {
    let src_valid = allowed_src_1.iter().any(|net| net.contains(&packet_src))
        || allowed_src_2.iter().any(|net| net.contains(&packet_src));

    let dst_valid = allowed_dst_1.iter().any(|net| net.contains(&packet_dst))
        || allowed_dst_2.iter().any(|net| net.contains(&packet_dst));

    src_valid && dst_valid
}
