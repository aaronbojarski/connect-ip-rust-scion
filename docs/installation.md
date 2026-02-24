# Installation and Configuration
This document describes the installation and configuration of a simple (machine-to-machine) deployment of connect-ip-rust-scion. For more complicated network scenarios we refer to [deployment.md](deployment.md).

## Prerequisites
Before deploying connect-ip-rust-scion, ensure that the following prerequisites are met.
- SCION Connectivity
    - Endhost API must be reachable by the client and proxy.
    - Each endpoint that is connected via SNAP must have a valid token. This usually concerns client endpoints, but can also be relevant for proxies in some scenarios.
    - Endpoints that use the UDP underlay (i.e. not SNAP) and are in an AS that does not support dispatcherless operation must have the shim dispatcher installed and running. One notable AS where this is currently the case is AS 64-2:0:9 (ETH Zurich). The dispatcher can be found in the [releases of the scionproto repository](https://github.com/scionproto/scion/releases/tag/v0.14.0) and the installation is described in the [SCION documentation](https://docs.scion.org/en/latest/manuals/install.html).
- Deployment machines
    - Necessary permissions to create and manage TUN interfaces (sudo).


## Installation
The installation of connect-ip-rust-scion can be done via pre-built binaries or by building from source.

### Pre-built Binaries
Pre-built binaries for the latest release can be found in the [releases section of the Git repository](https://github.com/aaronbojarski/connect-ip-rust-scion/releases). Download the appropriate binary for your platform and extract it.

### Building from Source
To build connect-ip-rust-scion from source, clone the repository and use Cargo to build the binary. This requires Rust, Cargo, and Protoc to be installed on your system.
```bash
cargo build --release
```
The compiled binaries will be located in the `target/release` directory.

For building on Windows, additional steps are required. They are outlined in [windows.md](windows.md).


## Configuration
### Certificates
For secure QUIC connections, TLS certificates are required for both clients and proxies. You can generate the necessary certificates with the `./testnet/generate_certs.sh` script. This will create a self-signed CA certificate and use it to sign certificates for the client and proxy.

Running `bash ./testnet/generate_certs.sh` will generate the files `ca-cert.pem`, `proxy-cert.pem`, `proxy-key.pem`, `client-cert.pem`, and `client-key.pem` in the current directory. The generated proxy and client certificates have the Common Name "CIRS-Proxy" and "CIRS-Client" respectively.

### Proxy
The proxy can also be configured using command line arguments or a config file.

The following shows a minimal config file for the proxy (`proxy-config.json`):
```json
{
    "listen": "PROXY_ADDRESS:4433",
    "endhost_api_address": "http://LOCAL_ENDHOST_API_ADDRESS:12345",
    "ca_cert_path": "/etc/cirs/ca-cert.pem",
    "cert_path": "/etc/cirs/proxy-cert.pem",
    "key_path": "/etc/cirs/proxy-key.pem",
    "address_pool": [
        "10.248.2.128/25"
    ],
    "configured_clients": [
        {
            "name": "CIRS-Client",
            "address": "10.248.2.1/32"
        }
    ],
    "log_level": "info"
}
```

This config file assumes that all certificates and the key are located in `/etc/cirs/`. The `listen` field specifies the address that the proxy will listen on for incoming connections from clients. It must be of the form `[ISD-AS,IP]:Port`. The `endhost_api_address` field specifies the address of the Endhost API that the proxy will use to fetch routes and addresses. The `configured_clients` field allows for pre-configuring specific clients with a fixed IP address. In this example, a client with the Common Name "CIRS-Client" will always be assigned the IP address `10.248.1.128`. (The mentioned certificate generation script can be used to create a client certificate with the appropriate CN). The `address_pool` field specifies an IP subnet from which the proxy will assign an address to clients in case they are not pre-configured.

### Client
The client can be configured using command line arguments or a config file. 

The following shows a minimal config file for the client (`client-config.json`):
```json
{
    "remote": "PROXY_ADDRESS:4433",
    "host": "CIRS-Proxy",
    "endhost_api_address": "http://LOCAL_ENDHOST_API_ADDRESS:12345",
    "snap_token_path": "/etc/cirs/snap.token",
    "ca_cert_path": "/etc/cirs/ca-cert.pem",
    "cert_path": "/etc/cirs/client-cert.pem",
    "key_path": "/etc/cirs/client-key.pem",
    "address_pool": [
        "10.248.1.1/32"
    ],
    "log_level": "info"
}
```

This config file also assumes that all certificates, the key, and the SNAP token are located in `/etc/cirs/`. The `remote` field specifies the address of the proxy to connect to. It must be of the form `[ISD-AS,IP]:Port`. The `host` field specifies the hostname that the client will use when connecting to the proxy. The `endhost_api_address` field specifies the address of the Endhost API (or SNAP) that the client will use to fetch routes. The `snap_token_path` field specifies the path to a file containing a valid SNAP token with permissions to access the SNAP. The `address_pool` field specifies an IP subnet from which the client will assign an address to the proxy. This is optional and can be left out if the client does not need to assign an address to the proxy.


## Usage
### Proxy
```
./connect-ip-rust-scion proxy --config proxy-config.json
```

### Client
```
./connect-ip-rust-scion client --config client-config.json
```


## Systemd Service
To run the client and proxy as systemd services, we provide service files in the `deployment` directory. They assume that the binary is located in `/usr/local/bin` and the config files in `/etc/cirs`.

After installing the service files (at `/etc/systemd/system/`), the services can be started with.
```bash
sudo systemctl start connect-ip-scion-proxy.service
```

```bash
sudo systemctl start connect-ip-scion-client.service
```


## Example Application: SSH over Connect-IP
Once a tunnel is established, you can SSH into the remote network. For example, if the client assigned the IP address `10.248.0.1` to the proxy, you can SSH into the proxy machine with.
```bash
ssh user@10.248.1.1
```
