# connect-ip-rust-scion

connect-ip-rust-scion is an implementation of Connect-IP ([RFC 9484](https://www.rfc-editor.org/rfc/rfc9484)) in Rust using SCION as the underlying transport protocol. It provides a client and a proxy component to establish secure tunnels over SCION networks. It allows tunnerling of arbitrary IP traffic over SCION.

This project used the scion-sdk. It does therefore not require the scion-daemon to be running.

## Building
To build the project, use cargo.
```bash
cargo build
```

## Running tests
To run the unit tests, use cargo test.
```bash
cargo test
```

## Usage
### Routes and address pools
- `--routes` accepts CIDR prefixes (repeat the flag for multiple values). These prefixes will be advertised to the other end of the tunnel.
- `--address-pool` accepts CIDR ranges (repeat the flag for multiple values). These ranges will be used to allocate addresses to peers. Provide enough space for every peer.

At least one route and one address pool must be provided for the proxy. For the client this is only necessary for site-to-site setups.

Example:

```
connect-ip-rust-scion proxy \
  --listen [0-0,127.0.0.1]:4433 \
  --routes 10.0.0.0/24 --routes 10.0.1.0/24 \
  --address-pool 10.1.0.0/24
```


## Running example in test network
To start the test network, run the `testnet.sh` script.
```bash
sudo bash ./testnet.sh up
```

All necessary certificats can be generated with the `generate_certs.sh` script.
```bash
bash ./generate_certs.sh
```

Then start the server the corresponding namespace.
```bash
sudo ip netns exec proxy_ns ./target/debug/connect-ip-rust-scion proxy --listen [0-0,10.248.100.11]:4433 --routes 10.248.2.0/24 --address-pool 10.248.2.128/25
```

Then start the client in another terminal.
```bash
sudo ip netns exec client_ns ./target/debug/connect-ip-rust-scion client [0-0,10.248.100.11]:4433 --host localhost --routes 10.248.1.0/24 --address-pool 10.248.1.128/25
```

Enable packet forwading in the server and client namespaces.
```bash
sudo ip netns exec client_ns sysctl -w net.ipv4.ip_forward=1
sudo ip netns exec proxy_ns sysctl -w net.ipv4.ip_forward=1
```

Connectivity can be tested by pinging from the client host via the tun interface to the host connected to the proxys subnet.
```bash
sudo ip netns exec client_ns ping -I tun0 10.248.2.1
```

It is also possible to ping from one endhost to the other.
```bash
sudo ip netns exec eh0ns ping 10.248.2.1
sudo ip netns exec eh1ns ping 10.248.1.1
```

Finally, the test network can be torn down.
```bash
sudo bash ./testnet.sh down
```

## TODO:
- SCION
  - Path selection
  - SNAP on server side
- Connect-IP
  - Better error handling
  - MTU
