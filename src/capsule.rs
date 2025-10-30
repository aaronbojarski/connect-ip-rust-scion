use std::net::IpAddr;

use anyhow::Error;

// Capsule types
#[derive(Clone)]
pub enum CapsuleType {
    AddressAssign = 0x01,
    AddressRequest = 0x02,
    RouteAdvertisement = 0x03,
}

#[derive(Clone)]
pub struct Capsule {
    pub capsule_type: CapsuleType,
    pub payload: Vec<u8>,
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

        let payload = octets.get_bytes_with_varint_length()?.to_vec();

        Ok(Capsule {
            capsule_type,
            payload,
        })
    }

    pub fn append(&self, octets: &mut octets::OctetsMut) -> Result<(), Error> {
        octets.put_varint(self.capsule_type.clone() as u64)?;
        octets.put_varint(self.payload.len() as u64)?;
        octets.put_bytes(&self.payload)?;
        Ok(())
    }
}

#[derive(Clone)]
pub struct AssignedAddress {
    pub request_id: u64,
    pub address: IpAddr,
    pub prefix_len: u8,
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

        Ok(AssignedAddress {
            request_id,
            address,
            prefix_len,
        })
    }

    pub fn append(&self, octets: &mut octets::OctetsMut) -> Result<(), Error> {
        octets.put_varint(self.request_id)?;

        match self.address {
            IpAddr::V4(addr) => {
                octets.put_u8(4)?;
                octets.put_bytes(&addr.octets())?;
            }
            IpAddr::V6(addr) => {
                octets.put_u8(6)?;
                octets.put_bytes(&addr.octets())?;
            }
        }

        octets.put_u8(self.prefix_len)?;
        Ok(())
    }
}

#[derive(Clone)]
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
}

#[derive(Clone)]
pub struct RequestedAddress {
    pub request_id: u64,
    pub address: IpAddr,
    pub prefix_len: u8,
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

        Ok(RequestedAddress {
            request_id,
            address,
            prefix_len,
        })
    }

    pub fn append(&self, octets: &mut octets::OctetsMut) -> Result<(), Error> {
        octets.put_varint(self.request_id)?;

        match self.address {
            IpAddr::V4(addr) => {
                octets.put_u8(4)?;
                octets.put_bytes(&addr.octets())?;
            }
            IpAddr::V6(addr) => {
                octets.put_u8(6)?;
                octets.put_bytes(&addr.octets())?;
            }
        }

        octets.put_u8(self.prefix_len)?;
        Ok(())
    }
}

#[derive(Clone)]
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
}

#[derive(Clone)]
pub struct RouteAdvertisement {
    pub start: IpAddr,
    pub end: IpAddr,
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

        Ok(RouteAdvertisement { start, end, proto })
    }

    pub fn append(&self, octets: &mut octets::OctetsMut) -> Result<(), Error> {
        match (self.start, self.end) {
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
}

#[derive(Clone)]
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
                address: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
                prefix_len: 24,
            },
            AssignedAddress {
                request_id: 2,
                address: IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)),
                prefix_len: 64,
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
            assert_eq!(parsed.address, original.address);
            assert_eq!(parsed.prefix_len, original.prefix_len);
        }
    }

    #[test]
    fn test_address_request_capsule() {
        let addresses = vec![
            RequestedAddress {
                request_id: 1,
                address: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                prefix_len: 16,
            },
            RequestedAddress {
                request_id: 2,
                address: IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
                prefix_len: 48,
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
            assert_eq!(parsed.address, original.address);
            assert_eq!(parsed.prefix_len, original.prefix_len);
        }
    }

    #[test]
    fn test_route_advertisement_capsule() {
        let routes = vec![
            RouteAdvertisement {
                start: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 0)),
                end: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 255)),
                proto: 17,
            },
            RouteAdvertisement {
                start: IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0)),
                end: IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 255)),
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
            assert_eq!(parsed.start, original.start);
            assert_eq!(parsed.end, original.end);
            assert_eq!(parsed.proto, original.proto);
        }
    }

    #[test]
    fn test_capsule_parsing_and_writing() {
        let capsule = Capsule {
            capsule_type: CapsuleType::AddressAssign,
            payload: vec![1, 2, 3, 4, 5],
        };
        let mut buf = vec![0u8; 100];
        let mut octets_mut = octets::OctetsMut::with_slice(&mut buf);
        capsule.append(&mut octets_mut).unwrap();
        let written = octets_mut.off();
        let mut octets = octets::Octets::with_slice(&buf[..written]);
        let parsed_capsule = Capsule::parse(&mut octets).unwrap();
        assert_eq!(
            parsed_capsule.capsule_type as u8,
            capsule.capsule_type as u8
        );
        assert_eq!(parsed_capsule.payload, capsule.payload);
    }
}
