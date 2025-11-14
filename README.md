# connect-ip-rust-scion

## Building
To build the project, use cargo.
```bash
cargo build
```

## Usage
### Routes and address pools
- `--routes` accepts CIDR prefixes (repeat the flag for multiple values). These prefixes will be advertised to the other end of the tunnel.
- `--address-pool` accepts CIDR ranges (repeat the flag for multiple values). These ranges will be used to allocate tunnel addresses. Provide enough space for every peer.

At least one route and one address pool must be provided for the proxy. For the client this is only necessary for site-to-site setups.

Example:

```
connect-ip-rust-scion proxy \
  --listen 127.0.0.1:4433 \
  --routes 10.0.0.0/24 --routes 10.0.1.0/24 \
  --address-pool 10.1.0.0/24
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
sudo ip netns exec proxy_ns ./target/debug/connect-ip-rust-scion proxy --listen 10.248.100.11:4433 --routes 10.248.2.0/24 --address-pool 10.248.2.128/25
```

Then start the client in another terminal.
```bash
sudo ip netns exec client_ns ./target/debug/connect-ip-rust-scion client https://10.248.100.11:4433 --host localhost --routes 10.248.1.0/24 --address-pool 10.248.1.128/25
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
- scion integration
    - switch socket
    - translate addresses
