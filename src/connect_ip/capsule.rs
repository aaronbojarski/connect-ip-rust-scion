use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use anyhow::Error as AnyhowError;
use ipnet::IpNet;
use thiserror::Error;

use crate::net::ip_range_to_net;

#[derive(Debug, Error)]
pub enum CapsuleError {
    #[error("unknown capsule type {0}")]
    UnknownCapsuleType(u64),
    #[error("invalid IP version {0}")]
    InvalidIpVersion(u8),
    #[error("start and end IP addresses must be of the same version")]
    IpVersionMismatch,
    #[error(transparent)]
    Buffer(#[from] octets::BufferTooShortError),
    #[error(transparent)]
    PrefixLen(#[from] ipnet::PrefixLenError),
    #[error(transparent)]
    RouteConversion(#[from] AnyhowError),
}

pub type CapsuleResult<T> = Result<T, CapsuleError>;

// Capsule types
#[derive(Clone, Debug)]
pub enum CapsuleType {
    Datagram = 0x00,
    AddressAssign = 0x01,
    AddressRequest = 0x02,
    RouteAdvertisement = 0x03,
}

#[derive(Clone, Debug)]
pub enum Capsule {
    Datagram(DatagramCapsule),
    AddressAssign(AddressAssignCapsule),
    AddressRequest(AddressRequestCapsule),
    RouteAdvertisement(RouteAdvertisementCapsule),
}

impl Capsule {
    /// Parse a capsule from octets
    pub fn parse(octets: &mut octets::Octets) -> CapsuleResult<Capsule> {
        let capsule_type = octets.get_varint()?;

        let capsule_type = match capsule_type {
            0x00 => CapsuleType::Datagram,
            0x01 => CapsuleType::AddressAssign,
            0x02 => CapsuleType::AddressRequest,
            0x03 => CapsuleType::RouteAdvertisement,
            _ => return Err(CapsuleError::UnknownCapsuleType(capsule_type)),
        };

        let length = octets.get_varint()?;
        let payload_bytes = octets.get_bytes(length as usize)?;
        let mut payload_octets = octets::Octets::with_slice(payload_bytes.buf());

        let capsule = match capsule_type {
            CapsuleType::Datagram => {
                Capsule::Datagram(DatagramCapsule::parse(&mut payload_octets)?)
            }
            CapsuleType::AddressAssign => {
                Capsule::AddressAssign(AddressAssignCapsule::parse(&mut payload_octets)?)
            }
            CapsuleType::AddressRequest => {
                Capsule::AddressRequest(AddressRequestCapsule::parse(&mut payload_octets)?)
            }
            CapsuleType::RouteAdvertisement => {
                Capsule::RouteAdvertisement(RouteAdvertisementCapsule::parse(&mut payload_octets)?)
            }
        };

        Ok(capsule)
    }

    /// Append the capsule to octets
    pub fn append(&self, octets: &mut octets::OctetsMut) -> CapsuleResult<()> {
        match self {
            Capsule::Datagram(capsule) => {
                octets.put_varint(CapsuleType::Datagram as u64)?;
                let len = capsule.wire_len();
                octets.put_varint(len as u64)?;
                capsule.append(octets)?;
            }
            Capsule::AddressAssign(capsule) => {
                octets.put_varint(CapsuleType::AddressAssign as u64)?;
                let len = capsule.wire_len();
                octets.put_varint(len as u64)?;
                capsule.append(octets)?;
            }
            Capsule::AddressRequest(capsule) => {
                octets.put_varint(CapsuleType::AddressRequest as u64)?;
                let len = capsule.wire_len();
                octets.put_varint(len as u64)?;
                capsule.append(octets)?;
            }
            Capsule::RouteAdvertisement(capsule) => {
                octets.put_varint(CapsuleType::RouteAdvertisement as u64)?;
                let len = capsule.wire_len();
                octets.put_varint(len as u64)?;
                capsule.append(octets)?;
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct DatagramCapsule {
    pub data: Vec<u8>,
}

impl DatagramCapsule {
    /// Parse a DatagramCapsule from octets
    pub fn parse(octets: &mut octets::Octets) -> CapsuleResult<DatagramCapsule> {
        let data = octets.get_bytes(octets.cap())?.to_vec();
        Ok(DatagramCapsule { data })
    }

    /// Append the DatagramCapsule to octets
    pub fn append(&self, octets: &mut octets::OctetsMut) -> CapsuleResult<()> {
        octets.put_bytes(&self.data)?;
        Ok(())
    }

    /// Calculate the wire length of the DatagramCapsule
    pub fn wire_len(&self) -> usize {
        self.data.len()
    }
}

#[derive(Clone, Debug)]
pub struct AssignedAddress {
    pub request_id: u64,
    pub ip_net: IpNet,
}

impl AssignedAddress {
    /// Parse an AssignedAddress from octets
    pub fn parse(octets: &mut octets::Octets) -> CapsuleResult<AssignedAddress> {
        let request_id = octets.get_varint()?;

        let ip_version = octets.get_u8()?;

        let address = if ip_version == 4 {
            let addr_bytes = octets.get_u32()?;
            IpAddr::V4(Ipv4Addr::from(addr_bytes))
        } else if ip_version == 6 {
            let addr_bytes = octets.get_bytes(16)?;
            let mut bytes = [0u8; 16];
            bytes.copy_from_slice(addr_bytes.as_ref());
            IpAddr::V6(Ipv6Addr::from(bytes))
        } else {
            return Err(CapsuleError::InvalidIpVersion(ip_version));
        };

        let prefix_len = octets.get_u8()?;

        let ip_net = IpNet::new(address, prefix_len)?;

        Ok(AssignedAddress { request_id, ip_net })
    }

    /// Append the AssignedAddress to octets
    pub fn append(&self, octets: &mut octets::OctetsMut) -> CapsuleResult<()> {
        octets.put_varint(self.request_id)?;

        match self.ip_net.addr() {
            IpAddr::V4(addr) => {
                octets.put_u8(4)?;
                octets.put_bytes(&addr.octets())?;
            }
            IpAddr::V6(addr) => {
                octets.put_u8(6)?;
                octets.put_bytes(&addr.octets())?;
            }
        }

        octets.put_u8(self.ip_net.prefix_len())?;
        Ok(())
    }

    /// Calculate the wire length of the AssignedAddress
    pub fn wire_len(&self) -> usize {
        let addr_len = match self.ip_net.addr() {
            IpAddr::V4(_) => 4,
            IpAddr::V6(_) => 16,
        };
        octets::varint_len(self.request_id) + 1 + addr_len + 1
    }
}

#[derive(Clone, Debug)]
pub struct AddressAssignCapsule {
    pub addresses: Vec<AssignedAddress>,
}

impl AddressAssignCapsule {
    /// Parse an AddressAssignCapsule from octets
    pub fn parse(octets: &mut octets::Octets) -> CapsuleResult<AddressAssignCapsule> {
        let mut addresses = Vec::new();
        while octets.cap() > 0 {
            let address = AssignedAddress::parse(octets)?;
            addresses.push(address);
        }
        Ok(AddressAssignCapsule { addresses })
    }

    /// Append the AddressAssignCapsule to octets
    pub fn append(&self, octets: &mut octets::OctetsMut) -> CapsuleResult<()> {
        for address in &self.addresses {
            address.append(octets)?;
        }
        Ok(())
    }

    /// Calculate the wire length of the AddressAssignCapsule
    pub fn wire_len(&self) -> usize {
        self.addresses.iter().map(|addr| addr.wire_len()).sum()
    }
}

#[derive(Clone, Debug)]
pub struct RequestedAddress {
    pub request_id: u64,
    pub ip_net: IpNet,
}

impl RequestedAddress {
    /// Parse a RequestedAddress from octets
    pub fn parse(octets: &mut octets::Octets) -> CapsuleResult<RequestedAddress> {
        let request_id = octets.get_varint()?;

        let ip_version = octets.get_u8()?;

        let address = if ip_version == 4 {
            let addr_bytes = octets.get_u32()?;
            IpAddr::V4(Ipv4Addr::from(addr_bytes))
        } else if ip_version == 6 {
            let addr_bytes = octets.get_bytes(16)?;
            let mut bytes = [0u8; 16];
            bytes.copy_from_slice(addr_bytes.as_ref());
            IpAddr::V6(Ipv6Addr::from(bytes))
        } else {
            return Err(CapsuleError::InvalidIpVersion(ip_version));
        };

        let prefix_len = octets.get_u8()?;

        let ip_net = IpNet::new(address, prefix_len)?;

        Ok(RequestedAddress { request_id, ip_net })
    }

    /// Append the RequestedAddress to octets
    pub fn append(&self, octets: &mut octets::OctetsMut) -> CapsuleResult<()> {
        octets.put_varint(self.request_id)?;

        match self.ip_net.addr() {
            IpAddr::V4(addr) => {
                octets.put_u8(4)?;
                octets.put_bytes(&addr.octets())?;
            }
            IpAddr::V6(addr) => {
                octets.put_u8(6)?;
                octets.put_bytes(&addr.octets())?;
            }
        }

        octets.put_u8(self.ip_net.prefix_len())?;
        Ok(())
    }

    /// Calculate the wire length of the RequestedAddress
    pub fn wire_len(&self) -> usize {
        let addr_len = match self.ip_net.addr() {
            IpAddr::V4(_) => 4,
            IpAddr::V6(_) => 16,
        };
        octets::varint_len(self.request_id) + 1 + addr_len + 1
    }
}

#[derive(Clone, Debug)]
pub struct AddressRequestCapsule {
    pub addresses: Vec<RequestedAddress>,
}

impl AddressRequestCapsule {
    /// Parse an AddressRequestCapsule from octets
    pub fn parse(octets: &mut octets::Octets) -> CapsuleResult<AddressRequestCapsule> {
        let mut addresses = Vec::new();
        while octets.cap() > 0 {
            let address = RequestedAddress::parse(octets)?;
            addresses.push(address);
        }
        Ok(AddressRequestCapsule { addresses })
    }

    /// Append the AddressRequestCapsule to octets
    pub fn append(&self, octets: &mut octets::OctetsMut) -> CapsuleResult<()> {
        for address in &self.addresses {
            address.append(octets)?;
        }
        Ok(())
    }

    /// Calculate the wire length of the AddressRequestCapsule
    pub fn wire_len(&self) -> usize {
        self.addresses.iter().map(|addr| addr.wire_len()).sum()
    }
}

#[derive(Clone, Debug)]
pub struct RouteAdvertisement {
    pub ip_net: IpNet,
    pub proto: u8,
}

impl RouteAdvertisement {
    /// Parse a RouteAdvertisement from octets
    pub fn parse(octets: &mut octets::Octets) -> CapsuleResult<RouteAdvertisement> {
        let ip_version = octets.get_u8()?;

        let (start, end) = if ip_version == 4 {
            let start_bytes = octets.get_u32()?;
            let end_bytes = octets.get_u32()?;
            (
                IpAddr::V4(Ipv4Addr::from(start_bytes)),
                IpAddr::V4(Ipv4Addr::from(end_bytes)),
            )
        } else if ip_version == 6 {
            let start_bytes = octets.get_bytes(16)?;
            let end_bytes = octets.get_bytes(16)?;
            let mut start_arr = [0u8; 16];
            start_arr.copy_from_slice(start_bytes.buf());
            let mut end_arr = [0u8; 16];
            end_arr.copy_from_slice(end_bytes.buf());
            (
                IpAddr::V6(Ipv6Addr::from(start_arr)),
                IpAddr::V6(Ipv6Addr::from(end_arr)),
            )
        } else {
            return Err(CapsuleError::InvalidIpVersion(ip_version));
        };

        let proto = octets.get_u8()?;

        let ip_net = ip_range_to_net(start, end).map_err(CapsuleError::RouteConversion)?;

        Ok(RouteAdvertisement { ip_net, proto })
    }

    /// Append the RouteAdvertisement to octets
    pub fn append(&self, octets: &mut octets::OctetsMut) -> CapsuleResult<()> {
        let start = self.ip_net.network();
        let end = self.ip_net.broadcast();
        match (start, end) {
            (IpAddr::V4(start_addr), IpAddr::V4(end_addr)) => {
                octets.put_u8(4)?;
                octets.put_bytes(&start_addr.octets())?;
                octets.put_bytes(&end_addr.octets())?;
            }
            (IpAddr::V6(start_addr), IpAddr::V6(end_addr)) => {
                octets.put_u8(6)?;
                octets.put_bytes(&start_addr.octets())?;
                octets.put_bytes(&end_addr.octets())?;
            }
            _ => {
                return Err(CapsuleError::IpVersionMismatch);
            }
        }

        octets.put_u8(self.proto)?;
        Ok(())
    }

    /// Calculate the wire length of the RouteAdvertisement
    pub fn wire_len(&self) -> usize {
        let addr_len = match self.ip_net.addr() {
            IpAddr::V4(_) => 4,
            IpAddr::V6(_) => 16,
        };
        1 + addr_len * 2 + 1
    }
}

#[derive(Clone, Debug)]
pub struct RouteAdvertisementCapsule {
    pub routes: Vec<RouteAdvertisement>,
}

impl RouteAdvertisementCapsule {
    /// Parse a RouteAdvertisementCapsule from octets
    pub fn parse(octets: &mut octets::Octets) -> CapsuleResult<RouteAdvertisementCapsule> {
        let mut routes = Vec::new();
        while octets.cap() > 0 {
            let route = RouteAdvertisement::parse(octets)?;
            routes.push(route);
        }
        Ok(RouteAdvertisementCapsule { routes })
    }

    /// Append the RouteAdvertisementCapsule to octets
    pub fn append(&self, octets: &mut octets::OctetsMut) -> CapsuleResult<()> {
        for route in &self.routes {
            route.append(octets)?;
        }
        Ok(())
    }

    /// Calculate the wire length of the RouteAdvertisementCapsule
    pub fn wire_len(&self) -> usize {
        self.routes.iter().map(|route| route.wire_len()).sum()
    }
}

// test parsing and writing of capsules
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_address_assign_capsule() {
        let addresses = vec![
            AssignedAddress {
                request_id: 1,
                ip_net: IpNet::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 24).unwrap(),
            },
            AssignedAddress {
                request_id: 2,
                ip_net: IpNet::new(IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)), 64)
                    .unwrap(),
            },
        ];
        let capsule = AddressAssignCapsule {
            addresses: addresses.clone(),
        };
        let mut buf = vec![0u8; 1000];
        let mut octets_mut = octets::OctetsMut::with_slice(&mut buf);
        capsule.append(&mut octets_mut).unwrap();

        let written = octets_mut.off();
        let mut octets = octets::Octets::with_slice(&buf[..written]);
        let parsed_capsule = AddressAssignCapsule::parse(&mut octets).unwrap();
        assert_eq!(parsed_capsule.addresses.len(), addresses.len());
        for (parsed, original) in parsed_capsule.addresses.iter().zip(addresses.iter()) {
            assert_eq!(parsed.request_id, original.request_id);
            assert_eq!(parsed.ip_net, original.ip_net);
        }
    }

    #[test]
    fn test_address_request_capsule() {
        let addresses = vec![
            RequestedAddress {
                request_id: 1,
                ip_net: IpNet::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 16).unwrap(),
            },
            RequestedAddress {
                request_id: 2,
                ip_net: IpNet::new(
                    IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
                    48,
                )
                .unwrap(),
            },
        ];
        let capsule = AddressRequestCapsule {
            addresses: addresses.clone(),
        };
        let mut buf = vec![0u8; 1000];
        let mut octets_mut = octets::OctetsMut::with_slice(&mut buf);
        capsule.append(&mut octets_mut).unwrap();

        let written = octets_mut.off();
        let mut octets = octets::Octets::with_slice(&buf[..written]);
        let parsed_capsule = AddressRequestCapsule::parse(&mut octets).unwrap();
        assert_eq!(parsed_capsule.addresses.len(), addresses.len());
        for (parsed, original) in parsed_capsule.addresses.iter().zip(addresses.iter()) {
            assert_eq!(parsed.request_id, original.request_id);
            assert_eq!(parsed.ip_net, original.ip_net);
        }
    }

    #[test]
    fn test_route_advertisement_capsule() {
        let routes = vec![
            RouteAdvertisement {
                ip_net: IpNet::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 0)), 24).unwrap(),
                proto: 17,
            },
            RouteAdvertisement {
                ip_net: IpNet::new(
                    IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0)),
                    48,
                )
                .unwrap(),
                proto: 6,
            },
        ];
        let capsule = RouteAdvertisementCapsule {
            routes: routes.clone(),
        };
        let mut buf = vec![0u8; 1000];
        let mut octets_mut = octets::OctetsMut::with_slice(&mut buf);
        capsule.append(&mut octets_mut).unwrap();

        let written = octets_mut.off();
        let mut octets = octets::Octets::with_slice(&buf[..written]);
        let parsed_capsule = RouteAdvertisementCapsule::parse(&mut octets).unwrap();
        assert_eq!(parsed_capsule.routes.len(), routes.len());
        for (parsed, original) in parsed_capsule.routes.iter().zip(routes.iter()) {
            assert_eq!(parsed.ip_net, original.ip_net);
            assert_eq!(parsed.proto, original.proto);
        }
    }

    #[test]
    fn test_capsule_parsing_and_writing() {
        let capsule = Capsule::AddressAssign(AddressAssignCapsule {
            addresses: vec![AssignedAddress {
                request_id: 42,
                ip_net: IpNet::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 24).unwrap(),
            }],
        });

        let mut buf = vec![0u8; 1000];
        let mut octets_mut = octets::OctetsMut::with_slice(&mut buf);
        capsule.append(&mut octets_mut).unwrap();
        let written = octets_mut.off();
        let mut octets = octets::Octets::with_slice(&buf[..written]);
        let parsed_capsule = Capsule::parse(&mut octets).unwrap();

        match parsed_capsule {
            Capsule::AddressAssign(assign_capsule) => {
                assert_eq!(assign_capsule.addresses.len(), 1);
                let addr = &assign_capsule.addresses[0];
                assert_eq!(addr.request_id, 42);
                assert_eq!(addr.ip_net.addr(), IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)));
                assert_eq!(addr.ip_net.prefix_len(), 24);
            }
            _ => panic!("Expected AddressAssign capsule"),
        }
    }
}
