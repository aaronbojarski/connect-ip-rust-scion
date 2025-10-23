# connect-ip-rust-scion

## Starting Test Network
NOTE that currently all addresses and routes are hardcoded. This will need to be changed soon.

To start the test network, run the `testnet.sh` script.

```bash
sudo bash ./testnet.sh up
```

Then start the server the corresponding namespace.
```bash
sudo ip netns exec proxy_ns ./target/debug/server --listen 10.248.100.11:4433
```

Then start the client in another terminal.
```bash
sudo ip netns exec client_ns ./target/debug/client https://10.248.100.11:4433 --host localhost
```

Connectivity can be tested by pinging from the client host via the tun interface to the host connected to the servers subnet.
```bash
sudo ip netns exec client_ns ping -I tun0 10.248.2.1
```