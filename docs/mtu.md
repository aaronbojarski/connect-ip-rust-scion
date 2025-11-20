# MTU Considerations
When using Connect-IP over SCION, it is important to consider the Maximum Transmission Unit (MTU). While connect-ip-rust-scion allows to tunnel arbitrary IP traffic, the effective MTU for tunneled packets is influenced by the underlying SCION transport and additional headers used for encapsulation.

## Assuptions
This document assumes the following:
- The underlying network path has an MTU of 1500 bytes.
- The SCION path has at most 10 hops. This results in a SCION header size of at most 180 bytes.
    - SCION Common Header: 12 bytes
    - SCION Address Header: 32 bytes (with IPv6 addresses)
    - SCION Path Header: 136 bytes (assuming 10 hops)
        - Meta Header: 4 bytes
        - Info Fields: 12 bytes (3 Info Fields)
        - Hop Fields: 120 bytes (10 Hop Fields)
- The QUIC layer adds an overhead of 36 bytes.
    - UDP Header: 8 bytes
    - QUIC Header: 12 bytes
    - AEAD: 16 bytes
- The Connect-IP datagram overhead is 4 bytes.
    - Datagram: 2 bytes
    - Quarter Stream ID: 1 byte (max 8 bytes, but varint and in practice small)
    - Context ID: 1 byte (max 8 bytes, but varint and in practice has value equal 0)

### Type 1: UDP Underlay
The UDP underlay adds an additional overhead of (at most) 48 bytes.
- IP Header: 20 bytes (IPv4) or 40 bytes (IPv6)
- UDP Header: 8 bytes

### Type 2: SNAP Underlay
The SNAP underlay adds an additional overhead of (at most) 78 bytes.
- IP Header: 20 bytes (IPv4) or 40 bytes (IPv6)
- QUIC adds an overhead of 38 bytes.
    - UDP Header: 8 bytes
    - QUIC Header: 12 bytes
    - AEAD: 16 bytes
    - Datagram: 2 bytes


## MTU Calculation
In theory this results in the following MTU calculations:

| Underlay Type | Calculation                   | Resulting MTU  |
|---------------|-------------------------------|----------------|
| UDP           | 1500 - 180 - 36 - 4 - 48      | 1232 bytes     |
| SNAP          | 1500 - 180 - 36 - 4 - 78      | 1202 bytes     |


## IPv6 Issue
IPv6 has a minimum MTU requirement of 1280 bytes. Given the above calculations, tunneling IPv6 packets over Connect-IP using SCION is not feasible with the assumed MTU of 1500 bytes for the underlying SCION transport.