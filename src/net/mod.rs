pub mod tun;

use anyhow::Error;
use ipnet::IpNet;
use std::net::{IpAddr, SocketAddr};

pub struct UdpPacket {
    pub data: Vec<u8>,
    pub src: SocketAddr,
    pub dst: SocketAddr,
}

pub fn ip_range_to_net(start: IpAddr, end: IpAddr) -> Result<IpNet, Error> {
    match (start, end) {
        (IpAddr::V4(start_v4), IpAddr::V4(end_v4)) => {
            let start_u32 = u32::from(start_v4);
            let end_u32 = u32::from(end_v4);

            let diff = end_u32.wrapping_sub(start_u32);

            let prefix_len = if diff == 0 {
                32
            } else {
                32 - (diff + 1).leading_zeros() as u8
            };

            IpNet::new(start, prefix_len).map_err(|e| anyhow::anyhow!("Invalid IP network: {}", e))
        }
        (IpAddr::V6(start_v6), IpAddr::V6(end_v6)) => {
            let start_u128 = u128::from(start_v6);
            let end_u128 = u128::from(end_v6);

            let diff = end_u128.wrapping_sub(start_u128);

            let prefix_len = if diff == 0 {
                128
            } else {
                128 - (diff + 1).leading_zeros() as u8
            };

            IpNet::new(start, prefix_len).map_err(|e| anyhow::anyhow!("Invalid IP network: {}", e))
        }
        _ => Err(anyhow::anyhow!("IP addresses must be of the same version")),
    }
}
