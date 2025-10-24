use std::{io::Cursor, net::IpAddr};

use bytes::Buf;
use quinn::VarInt;
use quinn_proto::coding::Codec;

// Capsule types
pub enum CapsuleType {
    AddressAssign = 0x01,
    AddressRequest = 0x02,
    RouteAdvertisement = 0x03,
}

pub struct Capsule {
    pub capsule_type: CapsuleType,
    pub length: u64,
    pub payload: Vec<u8>,
}

pub struct AssignedAddress {
    pub request_id: u64,
    pub address: IpAddr,
    pub prefix_len: u8,
}

pub struct AddressAssignCapsule {
    pub addresses: Vec<AssignedAddress>,
}

impl AddressAssignCapsule {
    pub fn new(addresses: Vec<AssignedAddress>) -> Self {
        AddressAssignCapsule { addresses }
    }

    pub fn parse_address_assign_capsule(data: &[u8]) -> Self {
        let mut cursor = Cursor::new(data);
        let mut addresses = Vec::new();
        while cursor.has_remaining() {
            let address = parse_address(&mut cursor);
            addresses.push(address);
        }
        AddressAssignCapsule { addresses }
    }
}

pub fn parse_address(cursor: &mut Cursor<&[u8]>) -> AssignedAddress {
    let request_id: VarInt = VarInt::decode(cursor).unwrap();

    let ip_version = cursor.get_u8();
    let address = if ip_version == 4 {
        let octets: [u8; 4] = cursor.get_u32().to_be_bytes();
        IpAddr::V4(std::net::Ipv4Addr::from(octets))
    } else if ip_version == 6 {
        let segments: [u8; 16] = cursor.get_u128().to_be_bytes();
        IpAddr::V6(std::net::Ipv6Addr::from(segments))
    } else {
        panic!("Invalid IP address length");
    };

    let prefix_len = cursor.get_u8();

    AssignedAddress {
        request_id: request_id.into_inner(),
        address: address,
        prefix_len: prefix_len,
    }
}

pub struct RequestedAddress {
    pub request_id: u64,
    pub address: IpAddr,
    pub prefix_len: u8,
}

pub struct AddressRequestCapsule {
    pub addresses: Vec<RequestedAddress>,
}

pub struct RouteAdvertisement {
    pub start: IpAddr,
    pub end: IpAddr,
    pub proto: u8,
}

pub struct RouteAdvertisementCapsule {
    pub routes: Vec<RouteAdvertisement>,
}
