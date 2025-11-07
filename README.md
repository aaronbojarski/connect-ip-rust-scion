# connect-ip-rust-scion

## Building
To build the project, use cargo.
```bash
cargo build --bin proxy --bin client
```

## Running tests
To run the unit tests, use cargo test.
```bash
cargo test
```

## Running example in test network
To start the test network, run the `testnet.sh` script.
```bash
sudo bash ./testnet.sh up
```

The proxy requires a valid certificate to run. A self-signed certificate can be generated using the following command.
```bash
openssl req -x509 -newkey rsa:4096 -keyout key.der -outform DER -out cert.der -outform DER -days 365 -nodes -subj "/CN=localhost"
```

Then start the server the corresponding namespace.
```bash
sudo ip netns exec proxy_ns ./target/debug/proxy --listen 10.248.100.11:4433
```

Then start the client in another terminal.
```bash
sudo ip netns exec client_ns ./target/debug/client https://10.248.100.11:4433 --host localhost
```

Enable packet forwading in the server and client namespaces.
```bash
sudo ip netns exec client_ns sysctl -w net.ipv4.ip_forward=1
sudo ip netns exec proxy_ns sysctl -w net.ipv4.ip_forward=1
```

Connectivity can be tested by pinging from the client host via the tun interface to the host connected to the servers subnet.
```bash
sudo ip netns exec client_ns ping -I tun0 10.248.2.1
```

It is also possible to ping from one endhost to the other.
```bash
sudo ip netns exec eh0ns ping 10.248.2.1
```

## TODO:
- improve QUIC implementation
    - check connection establishment
    - add retry logic
    - certificates
    - access logic (authentication/authorization)
- improve http3
    - use correct quarter stream id for datagrams
    - request on new stream
    - add checks on IP packets (src/dst addresses)
- scion integration
    - switch socket
    - translate addresses
