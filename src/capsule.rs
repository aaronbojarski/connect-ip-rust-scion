use std::{io::Cursor, net::IpAddr};

use bytes::Buf;
use quinn::VarInt;
use quinn_proto::coding::Codec;

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
    pub fn parse(cursor: &mut Cursor<&Vec<u8>>) -> Result<Capsule, &'static str> {
        let capsule_type: VarInt = VarInt::decode(cursor).unwrap();
        let length: VarInt = VarInt::decode(cursor).unwrap();

        if cursor.remaining() < length.into_inner() as usize {
            return Err("Insufficient data for capsule payload");
        }

        let mut payload = vec![0u8; length.into_inner() as usize];
        cursor.copy_to_slice(&mut payload);

        let capsule_type = match capsule_type.into_inner() {
            0x01 => CapsuleType::AddressAssign,
            0x02 => CapsuleType::AddressRequest,
            0x03 => CapsuleType::RouteAdvertisement,
            _ => return Err("Unknown capsule type"),
        };

        Ok(Capsule {
            capsule_type,
            payload,
        })
    }

    pub fn append(&self, buf: &mut Vec<u8>) {
        VarInt::from_u64(self.capsule_type.clone() as u64)
            .unwrap()
            .encode(buf);
        VarInt::from_u64(self.payload.len() as u64)
            .unwrap()
            .encode(buf);
        buf.extend_from_slice(&self.payload);
    }
}

#[derive(Clone)]
pub struct AssignedAddress {
    pub request_id: u64,
    pub address: IpAddr,
    pub prefix_len: u8,
}

impl AssignedAddress {
    pub fn parse(cursor: &mut Cursor<&Vec<u8>>) -> Result<AssignedAddress, &'static str> {
        let request_id: VarInt = VarInt::decode(cursor).unwrap();

        let ip_version = cursor.get_u8();
        if cursor.remaining() < if ip_version == 4 { 4 } else { 16 } {
            return Err("Insufficient data for IP address");
        }

        let address = if ip_version == 4 {
            let octets: [u8; 4] = cursor.get_u32().to_be_bytes();
            IpAddr::V4(std::net::Ipv4Addr::from(octets))
        } else if ip_version == 6 {
            let segments: [u8; 16] = cursor.get_u128().to_be_bytes();
            IpAddr::V6(std::net::Ipv6Addr::from(segments))
        } else {
            return Err("Invalid IP version");
        };

        if cursor.remaining() < 1 {
            return Err("Insufficient data for prefix length");
        }

        let prefix_len = cursor.get_u8();

        Ok(AssignedAddress {
            request_id: request_id.into_inner(),
            address: address,
            prefix_len: prefix_len,
        })
    }

    pub fn append(&self, buf: &mut Vec<u8>) {
        VarInt::from_u64(self.request_id).unwrap().encode(buf);

        match self.address {
            IpAddr::V4(addr) => {
                buf.push(4);
                buf.extend_from_slice(&addr.octets());
            }
            IpAddr::V6(addr) => {
                buf.push(6);
                buf.extend_from_slice(&addr.octets());
            }
        }

        buf.push(self.prefix_len);
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

    pub fn parse(cursor: &mut Cursor<&Vec<u8>>) -> Result<AddressAssignCapsule, &'static str> {
        let mut addresses = Vec::new();
        while cursor.has_remaining() {
            let address = AssignedAddress::parse(cursor)?;
            addresses.push(address);
        }
        Ok(AddressAssignCapsule { addresses })
    }

    pub fn append(&self, buf: &mut Vec<u8>) {
        for address in &self.addresses {
            address.append(buf);
        }
    }
}

#[derive(Clone)]
pub struct RequestedAddress {
    pub request_id: u64,
    pub address: IpAddr,
    pub prefix_len: u8,
}

impl RequestedAddress {
    pub fn parse(cursor: &mut Cursor<&Vec<u8>>) -> RequestedAddress {
        let request_id: VarInt = VarInt::decode(cursor).unwrap();

        let ip_version = cursor.get_u8();
        if cursor.remaining() < if ip_version == 4 { 4 } else { 16 } {
            panic!("Insufficient data for IP address");
        }
        let address = if ip_version == 4 {
            let octets: [u8; 4] = cursor.get_u32().to_be_bytes();
            IpAddr::V4(std::net::Ipv4Addr::from(octets))
        } else if ip_version == 6 {
            let segments: [u8; 16] = cursor.get_u128().to_be_bytes();
            IpAddr::V6(std::net::Ipv6Addr::from(segments))
        } else {
            panic!("Invalid IP address length");
        };

        if cursor.remaining() < 1 {
            panic!("Insufficient data for prefix length");
        }

        let prefix_len = cursor.get_u8();

        RequestedAddress {
            request_id: request_id.into_inner(),
            address: address,
            prefix_len: prefix_len,
        }
    }

    pub fn append(&self, buf: &mut Vec<u8>) {
        VarInt::from_u64(self.request_id).unwrap().encode(buf);

        match self.address {
            IpAddr::V4(addr) => {
                buf.push(4);
                buf.extend_from_slice(&addr.octets());
            }
            IpAddr::V6(addr) => {
                buf.push(6);
                buf.extend_from_slice(&addr.octets());
            }
        }

        buf.push(self.prefix_len);
    }
}

#[derive(Clone)]
pub struct AddressRequestCapsule {
    pub addresses: Vec<RequestedAddress>,
}

impl AddressRequestCapsule {
    pub fn parse(cursor: &mut Cursor<&Vec<u8>>) -> Result<AddressRequestCapsule, &'static str> {
        let mut addresses = Vec::new();
        while cursor.has_remaining() {
            let address = RequestedAddress::parse(cursor);
            addresses.push(address);
        }
        Ok(AddressRequestCapsule { addresses })
    }

    pub fn append(&self, buf: &mut Vec<u8>) {
        for address in &self.addresses {
            address.append(buf);
        }
    }
}

#[derive(Clone)]
pub struct RouteAdvertisement {
    pub start: IpAddr,
    pub end: IpAddr,
    pub proto: u8,
}

impl RouteAdvertisement {
    pub fn parse(cursor: &mut Cursor<&Vec<u8>>) -> Result<RouteAdvertisement, &'static str> {
        let ip_version = cursor.get_u8();
        if cursor.remaining() < if ip_version == 4 { 2 * 4 } else { 2 * 16 } {
            return Err("Insufficient data for start IP address");
        }
        let (start, end) = if ip_version == 4 {
            let octets_start: [u8; 4] = cursor.get_u32().to_be_bytes();
            let octets_end: [u8; 4] = cursor.get_u32().to_be_bytes();
            (
                IpAddr::V4(std::net::Ipv4Addr::from(octets_start)),
                IpAddr::V4(std::net::Ipv4Addr::from(octets_end)),
            )
        } else if ip_version == 6 {
            let segments_start: [u8; 16] = cursor.get_u128().to_be_bytes();
            let segments_end: [u8; 16] = cursor.get_u128().to_be_bytes();
            (
                IpAddr::V6(std::net::Ipv6Addr::from(segments_start)),
                IpAddr::V6(std::net::Ipv6Addr::from(segments_end)),
            )
        } else {
            return Err("Invalid IP address length for start address");
        };

        if cursor.remaining() < 1 {
            return Err("Insufficient data for protocol");
        }
        let proto = cursor.get_u8();

        Ok(RouteAdvertisement { start, end, proto })
    }

    pub fn append(&self, buf: &mut Vec<u8>) {
        match self.start {
            IpAddr::V4(addr) => {
                buf.push(4);
                buf.extend_from_slice(&addr.octets());
            }
            IpAddr::V6(addr) => {
                buf.push(6);
                buf.extend_from_slice(&addr.octets());
            }
        }

        match self.end {
            IpAddr::V4(addr) => {
                buf.extend_from_slice(&addr.octets());
            }
            IpAddr::V6(addr) => {
                buf.extend_from_slice(&addr.octets());
            }
        }

        buf.push(self.proto);
    }
}

#[derive(Clone)]
pub struct RouteAdvertisementCapsule {
    pub routes: Vec<RouteAdvertisement>,
}

impl RouteAdvertisementCapsule {
    pub fn parse(cursor: &mut Cursor<&Vec<u8>>) -> Result<RouteAdvertisementCapsule, &'static str> {
        let mut routes = Vec::new();
        while cursor.has_remaining() {
            let route = RouteAdvertisement::parse(cursor)?;
            routes.push(route);
        }
        Ok(RouteAdvertisementCapsule { routes })
    }

    pub fn append(&self, buf: &mut Vec<u8>) {
        for route in &self.routes {
            route.append(buf);
        }
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
        let mut buf = Vec::new();
        capsule.append(&mut buf);

        let mut cursor = Cursor::new(&buf);
        let parsed_capsule = AddressAssignCapsule::parse(&mut cursor).unwrap();
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
        let mut buf = Vec::new();
        capsule.append(&mut buf);
        let mut cursor = Cursor::new(&buf);
        let parsed_capsule = AddressRequestCapsule::parse(&mut cursor).unwrap();
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
        let mut buf = Vec::new();
        capsule.append(&mut buf);
        let mut cursor = Cursor::new(&buf);
        let parsed_capsule = RouteAdvertisementCapsule::parse(&mut cursor).unwrap();
        assert_eq!(parsed_capsule.routes.len(), routes.len());
        for (parsed, original) in parsed_capsule.routes.iter().zip(routes.iter()) {
            assert_eq!(parsed.start, original.start);
            assert_eq!(parsed.end, original.end);
            assert_eq!(parsed.proto, original.proto);
        }
    }
}
