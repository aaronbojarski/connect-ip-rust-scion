# Client side decision for streams or datagrams
1. The user chooses an MTU on the tun device (default 1500 bytes).
2. Client establishes a QUIC connection to the server.
3. Client sends http3 request to server. This includes the MTU value.
4. If MTU > 1000 bytes, client and server use streams.
5. If MTU <= 1000 bytes, client and server use datagrams and drop IPv6 support.