pub mod icmp;
pub mod quic;
pub mod route;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use anyhow::Error;
use ipnet::IpNet;
use tokio::sync::Mutex;
use tracing::debug;

use crate::net::icmp::IcmpType;

/// IP version selector for network operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpVersion {
    V4,
    V6,
}

impl IpVersion {
    pub fn matches(&self, net: &IpNet) -> bool {
        matches!(
            (self, net),
            (IpVersion::V4, IpNet::V4(_)) | (IpVersion::V6, IpNet::V6(_))
        )
    }
}

impl From<&IpNet> for IpVersion {
    fn from(net: &IpNet) -> Self {
        match net {
            IpNet::V4(_) => IpVersion::V4,
            IpNet::V6(_) => IpVersion::V6,
        }
    }
}

pub const ZERO_IPV4_ADDRESS: IpAddr = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
pub const ZERO_IPV6_ADDRESS: IpAddr = IpAddr::V6(Ipv6Addr::UNSPECIFIED);

/// Checks if the given network is an unspecified (zero) address.
///
/// # Returns
/// `true` if the address is 0.0.0.0 (IPv4) or :: (IPv6), `false` otherwise
pub fn is_zero_address(ip_net: &IpNet) -> bool {
    ip_net.addr().is_unspecified()
}

/// Represents a UDP packet with SCION addressing.
///
/// Contains source and destination SCION addresses along with the packet payload.
pub struct UdpPacket {
    pub src: scion_proto::address::SocketAddr,
    pub dst: scion_proto::address::SocketAddr,
    pub data: Vec<u8>,
}

/// Converts an IP range to a CIDR network.
///
/// Calculates the appropriate prefix length based on the difference between
/// the start and end addresses.
///
/// # Arguments
/// * `start` - The starting IP address of the range
/// * `end` - The ending IP address of the range
///
/// # Returns
/// A `Result` containing the IP network or an error if:
/// - The addresses are of different versions (IPv4 vs IPv6)
/// - The resulting prefix length is invalid
///
/// # Limitations
/// Currently assumes that start and end define a valid CIDR block.
/// This should be validated in future versions.
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

/// Allocates the next available subnet from a pool of IP networks.
///
/// Searches through the available network pool for a subnet that matches
/// the requested IP version and can accommodate the specified prefix length.
/// The allocated subnet is removed from the pool, and any remaining space
/// is returned to the pool as smaller subnets.
///
/// # Arguments
/// * `available_nets` - Shared pool of available IP networks
/// * `ip_version` - The IP version (V4 or V6) to allocate
/// * `prefix_len` - The desired prefix length for the subnet
///
/// # Returns
/// `Some(IpNet)` if a suitable subnet is found, `None` if no subnet is available
pub async fn get_next_avail_subnet(
    available_nets: Arc<Mutex<Vec<IpNet>>>,
    ip_version: IpVersion,
    prefix_len: u8,
) -> Option<IpNet> {
    let mut pool = available_nets.lock().await;
    let mut idx = 0;

    while idx < pool.len() {
        let net = pool[idx];
        if !ip_version.matches(&net) || net.prefix_len() > prefix_len {
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

/// Returns a subnet to the pool of available IP networks.
///
/// Adds the subnet back to the available networks pool and aggregates
/// adjacent networks to optimize the pool.
///
/// # Arguments
/// * `available_nets` - Shared pool of available IP networks
/// * `subnet` - The subnet to return to the pool
pub async fn return_subnet(available_nets: &Arc<Mutex<Vec<IpNet>>>, subnet: IpNet) {
    let mut available_nets = available_nets.lock().await;
    available_nets.push(subnet);
    *available_nets = IpNet::aggregate(&available_nets);
}

/// Allocates a specific subnet from the pool of available IP networks.
///
/// Searches for a network in the pool that contains the desired subnet,
/// removes the desired subnet, and returns any remaining space to the pool.
///
/// # Arguments
/// * `available_nets` - Shared pool of available IP networks
/// * `desired_subnet` - The specific subnet to allocate
///
/// # Returns
/// `Some(IpNet)` if the desired subnet is available, `None` if it cannot be allocated
pub async fn get_specific_subnet(
    available_nets: Arc<Mutex<Vec<IpNet>>>,
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

#[derive(Debug)]
pub enum ForwardingDecision {
    Forward,
    Drop,
    RespondWithIcmp(IcmpType),
}

/// Validates packet source and destination addresses against allowed networks.
///
/// Checks if both the source and destination addresses of a packet fall within
/// the allowed network ranges. Returns a forwarding decision based on the validation.
///
/// # Arguments
/// * `packet_src` - Source IP address of the packet
/// * `packet_dst` - Destination IP address of the packet
/// * `allowed_src_1` - First set of allowed source networks
/// * `allowed_src_2` - Second set of allowed source networks
/// * `allowed_dst_1` - First set of allowed destination networks
/// * `allowed_dst_2` - Second set of allowed destination networks
///
/// # Returns
/// * `ForwardingDecision::Forward` - Both source and destination are valid
/// * `ForwardingDecision::RespondWithIcmp(SourceRouteFailed)` - Invalid source address
/// * `ForwardingDecision::RespondWithIcmp(DestinationUnreachable)` - Invalid destination address
pub fn check_packet_src_dst(
    packet_src: IpAddr,
    packet_dst: IpAddr,
    allowed_src_1: &[IpNet],
    allowed_src_2: &[IpNet],
    allowed_dst_1: &[IpNet],
    allowed_dst_2: &[IpNet],
) -> ForwardingDecision {
    let src_valid = allowed_src_1
        .iter()
        .chain(allowed_src_2.iter())
        .any(|net| net.contains(&packet_src));

    let dst_valid = allowed_dst_1
        .iter()
        .chain(allowed_dst_2.iter())
        .any(|net| net.contains(&packet_dst));

    if src_valid && dst_valid {
        ForwardingDecision::Forward
    } else if !src_valid {
        debug!("source address {} not allowed", packet_src);
        ForwardingDecision::RespondWithIcmp(IcmpType::SourceRouteFailed)
    } else {
        debug!("destination address {} not allowed", packet_dst);
        ForwardingDecision::RespondWithIcmp(IcmpType::DestinationUnreachable)
    }
}
