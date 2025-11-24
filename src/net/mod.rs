pub mod quic;
pub mod tun;

use anyhow::{Context, Error};
use ipnet::IpNet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::process::Command;
use std::sync::Arc;
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
    // TODO: currently we assume that start and end define a valid CIDR block. This should be validated or handled properly.
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
    let mut pool = available_nets.lock().await;
    let mut idx = 0;

    while idx < pool.len() {
        let net = pool[idx];
        let family_matches = (ipv4 && is_ipv4(&net)) || (!ipv4 && is_ipv6(&net));
        if !family_matches || net.prefix_len() > prefix_len {
            idx += 1;
            continue;
        }

        let mut subnets = net.subnets(prefix_len).ok()?;
        let first = subnets.next()?;
        let rest: Vec<IpNet> = subnets.collect();

        pool.remove(idx);
        pool.splice(idx..idx, rest);
        *pool = IpNet::aggregate(&pool);

        return Some(first);
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
    let mut pool = available_nets.lock().await;
    let mut idx = 0;

    while idx < pool.len() {
        let net = pool[idx];
        if !net.contains(&desired_subnet) {
            idx += 1;
            continue;
        }

        let rest: Vec<IpNet> = net
            .subnets(desired_subnet.prefix_len())
            .ok()?
            .filter(|n| *n != desired_subnet)
            .collect();

        pool.remove(idx);
        pool.splice(idx..idx, rest);
        *pool = IpNet::aggregate(&pool);

        return Some(desired_subnet);
    }

    None
}

pub fn add_route(destination: &IpNet, dev: &str) -> Result<bool, Error> {
    let existing_routes = {
        let mut cmd = Command::new("ip");
        match destination {
            IpNet::V4(_) => {
                cmd.args(["route", "show"]);
            }
            IpNet::V6(_) => {
                cmd.args(["-6", "route", "show"]);
            }
        };
        let dest = destination.to_string();
        cmd.arg(&dest).args(["dev", dev]);
        run_ip_command(cmd)?
    };

    if !existing_routes.stdout.is_empty() {
        return Ok(false);
    }

    let mut add_cmd = Command::new("ip");
    match destination {
        IpNet::V4(_) => {
            add_cmd.args(["route", "add"]);
        }
        IpNet::V6(_) => {
            add_cmd.args(["-6", "route", "add"]);
        }
    };
    let dest = destination.to_string();
    add_cmd.arg(&dest).args(["dev", dev]);
    run_ip_command(add_cmd)?;
    Ok(true)
}

pub fn remove_route(destination: &IpNet, dev: &str) -> Result<(), Error> {
    let mut del_cmd = Command::new("ip");
    match destination {
        IpNet::V4(_) => {
            del_cmd.args(["route", "del"]);
        }
        IpNet::V6(_) => {
            del_cmd.args(["-6", "route", "del"]);
        }
    };
    let dest = destination.to_string();
    del_cmd.arg(&dest).args(["dev", dev]);
    run_ip_command(del_cmd)?;
    Ok(())
}

fn run_ip_command(mut cmd: Command) -> Result<std::process::Output, Error> {
    let program = cmd.get_program().to_string_lossy().into_owned();
    let args = cmd
        .get_args()
        .map(|a| a.to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    let display_cmd = if args.is_empty() {
        program.clone()
    } else {
        format!("{} {}", program, args.join(" "))
    };

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

pub fn check_packet_src_dst(
    packet_src: IpAddr,
    packet_dst: IpAddr,
    allowed_src_1: &[IpNet],
    allowed_src_2: &[IpNet],
    allowed_dst_1: &[IpNet],
    allowed_dst_2: &[IpNet],
) -> bool {
    let src_valid = allowed_src_1
        .iter()
        .chain(allowed_src_2.iter())
        .any(|net| net.contains(&packet_src));

    let dst_valid = allowed_dst_1
        .iter()
        .chain(allowed_dst_2.iter())
        .any(|net| net.contains(&packet_dst));

    src_valid && dst_valid
}
