use std::net::IpAddr;

use anyhow::Error;
use ipnet::IpNet;

use crate::net::ip_range_to_net;

// Capsule types
#[derive(Clone, Debug)]
pub enum CapsuleType {
    AddressAssign = 0x01,
    AddressRequest = 0x02,
    RouteAdvertisement = 0x03,
}

#[derive(Clone, Debug)]
pub enum Capsule {
    AddressAssign(AddressAssignCapsule),
    AddressRequest(AddressRequestCapsule),
    RouteAdvertisement(RouteAdvertisementCapsule),
}

impl Capsule {
    pub fn parse(octets: &mut octets::Octets) -> Result<Capsule, Error> {
        let capsule_type = octets.get_varint()?;

        let capsule_type = match capsule_type {
            0x01 => CapsuleType::AddressAssign,
            0x02 => CapsuleType::AddressRequest,
            0x03 => CapsuleType::RouteAdvertisement,
            _ => return Err(anyhow::anyhow!("Unknown capsule type")),
        };

        let length = octets.get_varint()?;
        let payload_bytes = octets.get_bytes(length as usize)?;
        let mut payload_octets = octets::Octets::with_slice(payload_bytes.buf());

        let capsule = match capsule_type {
            CapsuleType::AddressAssign => {
                let addr_capsule = AddressAssignCapsule::parse(&mut payload_octets)?;
                Capsule::AddressAssign(addr_capsule)
            }
            CapsuleType::AddressRequest => {
                let addr_capsule = AddressRequestCapsule::parse(&mut payload_octets)?;
                Capsule::AddressRequest(addr_capsule)
            }
            CapsuleType::RouteAdvertisement => {
                let addr_capsule = RouteAdvertisementCapsule::parse(&mut payload_octets)?;
                Capsule::RouteAdvertisement(addr_capsule)
            }
        };

        Ok(capsule)
    }

    pub fn append(&self, octets: &mut octets::OctetsMut) -> Result<(), Error> {
        match self {
            Capsule::AddressAssign(capsule) => {
                octets.put_varint(CapsuleType::AddressAssign as u64)?;
                let len = capsule.len();
                octets.put_varint(len as u64)?;
                capsule.append(octets)?;
            }
            Capsule::AddressRequest(capsule) => {
                octets.put_varint(CapsuleType::AddressRequest as u64)?;
                let len = capsule.len();
                octets.put_varint(len as u64)?;
                capsule.append(octets)?;
            }
            Capsule::RouteAdvertisement(capsule) => {
                octets.put_varint(CapsuleType::RouteAdvertisement as u64)?;
                let len = capsule.len();
                octets.put_varint(len as u64)?;
                capsule.append(octets)?;
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct AssignedAddress {
    pub request_id: u64,
    pub ip_net: IpNet,
}

impl AssignedAddress {
    pub fn parse(octets: &mut octets::Octets) -> Result<AssignedAddress, Error> {
        let request_id = octets.get_varint()?;

        let ip_version = octets.get_u8()?;

        let address = if ip_version == 4 {
            let addr_bytes = octets.get_u32()?;
            IpAddr::V4(std::net::Ipv4Addr::from(addr_bytes.to_be_bytes()))
        } else if ip_version == 6 {
            let addr_bytes = octets.get_bytes(16)?;
            let mut bytes = [0u8; 16];
            bytes.copy_from_slice(addr_bytes.as_ref());
            IpAddr::V6(std::net::Ipv6Addr::from(bytes))
        } else {
            return Err(anyhow::anyhow!("Invalid IP version"));
        };

        let prefix_len = octets.get_u8()?;

        let ip_net = IpNet::new(address, prefix_len)?;

        Ok(AssignedAddress { request_id, ip_net })
    }

    pub fn append(&self, octets: &mut octets::OctetsMut) -> Result<(), Error> {
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

    pub fn len(&self) -> usize {
        let addr_len = match self.ip_net.addr() {
            IpAddr::V4(_) => 4,
            IpAddr::V6(_) => 16,
        };
        1 + addr_len + 1 + octets::varint_len(self.request_id)
    }
}

#[derive(Clone, Debug)]
pub struct AddressAssignCapsule {
    pub addresses: Vec<AssignedAddress>,
}

impl AddressAssignCapsule {
    pub fn new(addresses: Vec<AssignedAddress>) -> Self {
        AddressAssignCapsule { addresses }
    }

    pub fn parse(octets: &mut octets::Octets) -> Result<AddressAssignCapsule, Error> {
        let mut addresses = Vec::new();
        while octets.cap() > 0 {
            let address = AssignedAddress::parse(octets)?;
            addresses.push(address);
        }
        Ok(AddressAssignCapsule { addresses })
    }

    pub fn append(&self, octets: &mut octets::OctetsMut) -> Result<(), Error> {
        for address in &self.addresses {
            address.append(octets)?;
        }
        Ok(())
    }

    pub fn len(&self) -> usize {
        self.addresses.iter().map(|addr| addr.len()).sum()
    }
}

#[derive(Clone, Debug)]
pub struct RequestedAddress {
    pub request_id: u64,
    pub ip_net: IpNet,
}

impl RequestedAddress {
    pub fn parse(octets: &mut octets::Octets) -> Result<RequestedAddress, Error> {
        let request_id = octets.get_varint()?;

        let ip_version = octets.get_u8()?;

        let address = if ip_version == 4 {
            let addr_bytes = octets.get_u32()?;
            IpAddr::V4(std::net::Ipv4Addr::from(addr_bytes))
        } else if ip_version == 6 {
            let addr_bytes = octets.get_bytes(16)?;
            let mut bytes = [0u8; 16];
            bytes.copy_from_slice(addr_bytes.as_ref());
            IpAddr::V6(std::net::Ipv6Addr::from(bytes))
        } else {
            return Err(anyhow::anyhow!("Invalid IP version"));
        };

        let prefix_len = octets.get_u8()?;

        let ip_net = IpNet::new(address, prefix_len)?;

        Ok(RequestedAddress { request_id, ip_net })
    }

    pub fn append(&self, octets: &mut octets::OctetsMut) -> Result<(), Error> {
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

    pub fn len(&self) -> usize {
        let addr_len = match self.ip_net.addr() {
            IpAddr::V4(_) => 4,
            IpAddr::V6(_) => 16,
        };
        1 + addr_len + 1 + octets::varint_len(self.request_id)
    }
}

#[derive(Clone, Debug)]
pub struct AddressRequestCapsule {
    pub addresses: Vec<RequestedAddress>,
}

impl AddressRequestCapsule {
    pub fn parse(octets: &mut octets::Octets) -> Result<AddressRequestCapsule, Error> {
        let mut addresses = Vec::new();
        while octets.cap() > 0 {
            let address = RequestedAddress::parse(octets)?;
            addresses.push(address);
        }
        Ok(AddressRequestCapsule { addresses })
    }

    pub fn append(&self, octets: &mut octets::OctetsMut) -> Result<(), Error> {
        for address in &self.addresses {
            address.append(octets)?;
        }
        Ok(())
    }

    pub fn len(&self) -> usize {
        self.addresses.iter().map(|addr| addr.len()).sum()
    }
}

#[derive(Clone, Debug)]
pub struct RouteAdvertisement {
    pub ip_net: IpNet,
    pub proto: u8,
}

impl RouteAdvertisement {
    pub fn parse(octets: &mut octets::Octets) -> Result<RouteAdvertisement, Error> {
        let ip_version = octets.get_u8()?;

        let (start, end) = if ip_version == 4 {
            let start_bytes = octets.get_u32()?;
            let end_bytes = octets.get_u32()?;
            (
                IpAddr::V4(std::net::Ipv4Addr::from(start_bytes.to_be_bytes())),
                IpAddr::V4(std::net::Ipv4Addr::from(end_bytes.to_be_bytes())),
            )
        } else if ip_version == 6 {
            let start_bytes = octets.get_bytes(16)?;
            let end_bytes = octets.get_bytes(16)?;
            let mut start_arr = [0u8; 16];
            start_arr.copy_from_slice(start_bytes.buf());
            let mut end_arr = [0u8; 16];
            end_arr.copy_from_slice(end_bytes.buf());
            (
                IpAddr::V6(std::net::Ipv6Addr::from(start_arr)),
                IpAddr::V6(std::net::Ipv6Addr::from(end_arr)),
            )
        } else {
            return Err(anyhow::anyhow!("Invalid IP version"));
        };

        let proto = octets.get_u8()?;

        let ip_net = ip_range_to_net(start, end)?;

        Ok(RouteAdvertisement { ip_net, proto })
    }

    pub fn append(&self, octets: &mut octets::OctetsMut) -> Result<(), Error> {
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
                return Err(anyhow::anyhow!(
                    "Start and end IP addresses must be of the same version"
                ));
            }
        }

        octets.put_u8(self.proto)?;
        Ok(())
    }

    pub fn len(&self) -> usize {
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
    pub fn parse(octets: &mut octets::Octets) -> Result<RouteAdvertisementCapsule, Error> {
        let mut routes = Vec::new();
        while octets.cap() > 0 {
            let route = RouteAdvertisement::parse(octets)?;
            routes.push(route);
        }
        Ok(RouteAdvertisementCapsule { routes })
    }

    pub fn append(&self, octets: &mut octets::OctetsMut) -> Result<(), Error> {
        for route in &self.routes {
            route.append(octets)?;
        }
        Ok(())
    }

    pub fn len(&self) -> usize {
        self.routes.iter().map(|route| route.len()).sum()
    }
}

// test parsing and writing of capsules
#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};
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
        let capsule = AddressAssignCapsule::new(addresses.clone());
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

        let mut buf = vec![0u8; 100];
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
