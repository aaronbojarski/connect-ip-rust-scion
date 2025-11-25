# MTU Considerations
When using Connect-IP over SCION, it is important to consider the Maximum Transmission Unit (MTU) for tunneled packets. While connect-ip-rust-scion allows to tunnel arbitrary IP traffic, the effective MTU for tunneled packets is influenced by the underlying SCION transport and additional headers used for encapsulation.

## Assumptions
We make the following assumptions:
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

In practice, the QUIC datagram size is often chosen to be smaller than the theoretical maximum to avoid fragmentation.


## IPv6 Issue
IPv6 has a minimum MTU requirement of 1280 bytes. Given the above calculations, tunneling IPv6 packets over Connect-IP using SCION is not feasible with the assumed MTU of 1500 bytes for the underlying SCION transport. 

### Solution 1: Drop IPv6 Support
One solution is to drop IPv6 support entirely and only support IPv4 traffic. This would allow us to keep using QUIC datagrams for tunneling, but would limit the MTU on the tun interfaces to about 1200 bytes. Furthermore, this would limit the usability in some scenarios where IPv6 connectivity is required.

### Solution 2: Use QUIC Streams
Another solution is to use QUIC streams instead of datagrams for tunneling IP traffic. This would allow for larger MTUs on the tun interfaces, as the QUIC streams can then handle fragmentation and reassembly internally. However, this would introduce additional overhead and potential performance implications due to the increased complexity and potential for head-of-line blocking.

### Solution 2b: Tunnel only IPv6 over QUIC Streams
A variant of Solution 2 is to only tunnel IPv6 traffic over QUIC streams, while still tunneling IPv4 traffic over QUIC datagrams. It is however not clear yet, how to set the MTU on the tun interfaces in this case, as both IPv4 and IPv6 traffic would be present on the same interface.

### Solution 3: Fragmentation at the Connect-IP Layer
A third solution is to implement fragmentation and reassembly at the Connect-IP layer. This would allow for larger MTUs on the tun interfaces, as the Connect-IP layer could handle fragmentation and reassembly of IP packets. We could for example split packets larger than a certain size into multiple datagrams and keep a small (FIFO) buffer for reassembling packets on the receiving side.

### Solution 4: Let the user choose the MTU
A fourth solution is to let the user choose the MTU for the tun interfaces. We can then choose to send IPv4 packets over QUIC datagrams if possible or fall back to QUIC streams for larger packets. IPv6 packets would always be sent over QUIC streams. 

### Solution 5: Larger Underlay MTU
A fifth solution is to use an underlying SCION transport with a larger MTU. This can be done in some scenarios, but will not be available everywhere.
