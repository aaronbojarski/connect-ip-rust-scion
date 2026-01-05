# Test Network Setup

To start the SCION test network, run the `testnet.sh` script.
```bash
sudo bash ./testnet/scion/testnet.sh up
```

We use the [pocketscion-configurator](https://github.com/aaronbojarski/pocketscion-configurator) to set up the pocketscion instance inside the `pocketscion_ns` namespace. First, fetch and build the configurator or use the prebuilt binary.
```bash
cd testnet/scion
curl -LO https://github.com/aaronbojarski/pocketscion-configurator/releases/download/v0.1.1/pocketscion-configurator-x86-64-deb.tar.gz
tar -xvf pocketscion-configurator-x86-64-deb.tar.gz
sudo ip netns exec pocketscion_ns ./pocketscion-configurator --config ./pocketscion_config.json
cd ../..
```

All necessary certificats can be generated with the `generate_certs.sh` script.
```bash
cd testnet
bash ./generate_certs.sh
cd ..
```

Then start the server the corresponding namespace.
```bash
sudo ip netns exec proxy_ns ./target/debug/connect-ip-rust-scion proxy --listen [2-3,10.248.200.10]:4433 --routes 10.248.2.0/24 --address-pool 10.248.2.128/25 --ca-cert ./testnet/ca-cert.pem --cert ./testnet/proxy-cert.pem --key ./testnet/proxy-key.pem --endhost-api http://10.248.200.20:10231
```

Then start the client in another terminal.
```bash
sudo ip netns exec client_ns ./target/debug/connect-ip-rust-scion client [2-3,10.248.200.10]:4433 --host localhost --routes 10.248.1.0/24 --address-pool 10.248.1.128/25 --ca-cert ./testnet/ca-cert.pem --cert ./testnet/client-cert.pem --key ./testnet/client-key.pem --endhost-api http://10.248.100.20:10143 --snap-token ./testnet/scion/snap.token
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
sudo bash ./testnet/scion/testnet.sh down
```