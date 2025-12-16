# MTU Considerations
The Connect-IP RFC suggests to use QUIC datagrams for tunneling IP traffic, when using HTTP/3. This works well in many scenarios, as QUIC datagrams allow for low-latency transmission of packets without the overhead of stream management. However, QUIC datagrams have size limitations that can impact the effective MTU for tunneled packets. This is especially relevant when using Connect-IP over SCION, as the SCION headers add additional overhead that further reduces the effective MTU.

The calculations below show that when using Connect-IP over SCION with QUIC datagrams, the effective MTU for tunneled packets can be significantly lower than the typical MTU of 1500 bytes. This can lead to fragmentation of larger packets, which can negatively impact performance and compatibility with certain applications. The main issue is that IPv6 has a minimum MTU requirement of 1280 bytes, which cannot be met when tunneling over QUIC datagrams in SCION with the stated assumptions. 

We therefore decided to let the user choose the MTU that he requires on the TUN interface. Depending on the chosen value, we either use QUIC datagrams for tunneling (if the MTU is small enough, in this case IPv6 support is dropped) or QUIC streams (if the MTU is too large for datagrams). This allows for the most flexibility and good better performance in different deployment scenarios.

Several other solutions were considered, which are discussed below.

# Overhead Calculation
## Assumptions
We make the following assumptions:
- The underlay network path has an MTU of 1500 bytes.
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
IPv6 has a minimum MTU requirement of 1280 bytes. Given the above calculations, tunneling IPv6 packets over QUIC datagrams is not feasible over SCION with the assumed MTU of 1500 bytes for the underlying SCION transport. This issue of insufficient MTU for IPv6 packets is also discussed in the Connect-IP RFC. The RFC suggests that implementations may choose to drop IPv6 support if the effective MTU for tunneled packets is below 1280 bytes. This is a significant limitation, as it restricts the use of Connect-IP tunnels to IPv4 traffic only in such scenarios. Since this scenario is always the case when using SCION, we considered several solutions to address this issue.

### Solution 1: Drop IPv6 Support
Drop IPv6 support entirely and only support IPv4 traffic. This would allow us to keep using QUIC datagrams for tunneling, but would limit the MTU on the tun interfaces to about 1200 bytes. Furthermore, this would limit the usability in some scenarios where IPv6 connectivity is required.

### Solution 2: Use QUIC Streams
Tunnel traffic over QUIC streams instead of datagrams. This would allow for larger MTUs on the tun interfaces, as the QUIC streams can then handle fragmentation and reassembly internally. However, this would introduce additional overhead and potential performance implications due to the increased complexity and potential for head-of-line blocking.

### Solution 2b: Tunnel only IPv6 over QUIC Streams
A variant of Solution 2 is to only tunnel IPv6 traffic over QUIC streams, while still tunneling IPv4 traffic over QUIC datagrams. It is however not clear yet, how to set the MTU on the tun interfaces in this case, as both IPv4 and IPv6 traffic would be present on the same interface.

### Solution 3: Fragmentation at the Connect-IP Layer
The fragmentation and reassembly could be implemented at the Connect-IP layer. This would allow for larger MTUs on the tun interfaces, as the Connect-IP layer could handle fragmentation and reassembly of IP packets. We could for example split packets larger than a certain size into multiple datagrams and keep a small (FIFO) buffer for reassembling packets on the receiving side. The downside is that this deviates drastically from the Connect-IP RFC.

### Solution 4: Let the user choose the MTU
The user chooses the MTU for the tun interfaces. We can then send IPv4 packets over QUIC datagrams if possible or fall back to QUIC streams for larger packets. IPv6 packets would always be sent over QUIC streams.

### Solution 5: Larger Underlay MTU
Use an underlying SCION transport with a larger MTU. This can be done in some scenarios, but will not be available everywhere.


## Chosen Solution
We decided to implement Solution 4, as it provides the most flexibility for different deployment scenarios.

1. The user chooses an MTU on the tun device (default 1500 bytes).
2. Client establishes a QUIC connection to the server.
3. Client sends http3 request to server. This includes the MTU value.
4. If MTU > 1150 bytes, client and server use streams.
5. If MTU <= 1150 bytes, client and server use datagrams and drop IPv6 support.
