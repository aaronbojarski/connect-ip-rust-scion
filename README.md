# connect-ip-rust-scion

connect-ip-rust-scion is an implementation of Connect-IP ([RFC 9484](https://www.rfc-editor.org/rfc/rfc9484)) in Rust using SCION as the underlying transport protocol. It provides a client and a proxy component to establish secure tunnels over SCION networks. It allows tunneling of arbitrary IP traffic securely over SCION. It is based on [quiche](https://github.com/cloudflare/quiche) and the [scion-sdk](https://github.com/Anapaya/scion-sdk).


## SCION
[SCION](https://www.scion.org/) is a next-generation internet architecture that provides high security, availability, and path control.

This project uses the [scion-sdk](https://github.com/Anapaya/scion-sdk) for handling SCION networking. It does therefore not require the scion-daemon to be running.

(For testing purposes it is also possible to run Connect-IP over IP. While this is working, it is not the intended use of this project and might be deprecated in the future.)


## Building and testing
Building the project requires Rust and Cargo to be installed. The project can be built using cargo.
```console
cargo build
```
This will produce the `connect-ip-rust-scion` binary in the `target/debug` directory.

Unit tests can also be run using cargo.
```console
cargo test
```


## Usage
The `connect-ip-rust-scion` binary provides two subcommands: `proxy` and `client`. Both require sudo privileges for the configuration of the tun interface.

### Proxy
The proxy subcommand starts the Connect-IP proxy server. It listens for incoming client connections and forwards traffic between the SCION network and the tun interface.
```console
sudo ./connect-ip-rust-scion proxy --listen [SCION_ADDRESS]:PORT --endhost-api ENDHOST_API_ADDRESS --routes ROUTES --address-pool ADDRESS_POOL
```
The proxy requires the following parameters:
- `--listen [SCION_ADDRESS]:PORT`: The SCION address and port to listen on.
- `--endhost-api ENDHOST_API_ADDRESS`: The address of the endhost API to discover SCION underlays, addresses and routes.
- `--routes ROUTES`: A CIDR notation of the routes to be announced to clients. Multiple routes can be specified by repeating the option.
- `--address-pool ADDRESS_POOL`: A CIDR notation of the address pool to allocate client addresses from. Multiple pools can be specified by repeating the option.

All other options can be viewed by running with the `--help` flag.

### Client
The client subcommand starts the Connect-IP client. It connects to the proxy server and forwards traffic between the tun interface and the SCION network.
```console
sudo ./connect-ip-rust-scion client [SCION_PROXY_ADDRESS]:PORT --endhost-api ENDHOST_API_ADDRESS --routes ROUTES --address-pool ADDRESS_POOL
```
The client requires the following parameters:
- `[SCION_PROXY_ADDRESS]:PORT`: The SCION address and port of the proxy server.
- `--endhost-api ENDHOST_API_ADDRESS`: The address of the endhost API to discover SCION underlays, addresses and routes.
- `--snap-token SNAP_TOKEN`: (optional) The SNAP token to use for authentication with the endhost API service.

For site-to-site connections, the client also requires:
- `--routes ROUTES`: A CIDR notation of the routes to be announced to the proxy. Multiple routes can be specified by repeating the option.
- `--address-pool ADDRESS_POOL`: A CIDR notation of the address pool to allocate addresses from. Multiple pools can be specified by repeating the option.

All other options can be viewed by running with the `--help` flag.

### Running over IP
To run the client and proxy over IP instead of SCION the wildcard ISD-AS `0-0` can be used as SCION address. The address would then be `[0-0,IP_ADDRESS]`. In that case the `--endhost-api` and `--snap-token` options are not required.


## Test Network
Test network setups for local testing are provided in the `testnet` directory. 
- [`./testnet/ip`](./testnet/ip) contains a setup based on network namespaces to allow running the IP version of the client and proxy.
- [`./testnet/scion`](./testnet/scion) contains a setup based on `pocketscion` and network namespaces to run the SCION version of the client and proxy.


## Acknowledgements
This project took inspiration from the following implementations. We thank the authors for their great work!
- [connect-ip-go](https://github.com/quic-go/connect-ip-go)
- [pasque](https://github.com/PasiSa/pasque)


## TODO:
- Code Improvements
  - Documentation (especially public APIs)
  - Better error handling
    - use custom error types when possible
    - handle errors more gracefully when allowed

- SCION Integration
  - Update sdk version once SNAP is done
  - Check if path can be selected when connectivity is not working

- Setup
  - Provide systemd service files for client and proxy
