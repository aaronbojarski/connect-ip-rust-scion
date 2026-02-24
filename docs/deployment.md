# Deployment
This document provides some guidance on deploying the connect-ip-rust-scion implementation in different network scenarios. Installation and configuration instructions can be found in [installation.md](installation.md).

## Remote Client
### Network Configuration
In this deployment scenario, the client is located in a remote network (e.g., home or office) and connects to a proxy located in a SCION-enabled network. The client requires a single IP address for communicating with the network behind the proxy. The client has no further network behind it, so it does not announce any routes. It also does not need to assign an address to the proxy. The proxy assigns an IP address to the client from a predefined subnet (e.g. 10.0.0.128/25) and announces the necessary routes to its local network (e.g. 10.0.0.0/24).

```
                                                    ┌─────────────────────────┐
                                                    │   Local Network         │
                                                    │   10.0.0.0/24           │
                                                    │                         │
                                                    │  ┌────────┐  ┌────────┐ │
                                                    │  │ Host A │  │ Host B │ │
                                                    │  │10.0.0.2│  │10.0.0.3│ │
                                                    │  └────────┘  └────────┘ │
                                                    └──────────┬──────────────┘
                                                               │
                                                               │
┌──────────────────┐    Connect-IP over QUIC/UDP/SCION    ┌────┴─────┐
│  Remote Client   │◄────────────────────────────────────►│  Proxy   │
│                  │                                      │          │
│  Assigned IP:    │                                      └──────────┘
│  10.0.0.130      │                              Routes announced: 10.0.0.0/24
│                  │                              Address pool:     10.0.0.128/25
└──────────────────┘
```

The client can then reach resources in the local network behind the proxy using the assigned IP address.

## Site to Site
### Network Configuration
In this deployment scenario, two sites with their own local networks are connected via SCION. Site A runs a client and Site B runs a proxy that establishes a Connect-IP tunnel. The proxy assigns an IP address to the client and announces routes to its local network, while the client announces routes to its local network, enabling hosts in either site to communicate with hosts in the other site. Client and Proxy get addresses assigned from each other's address pools. This can be beneficial for devices that require a local IP address in the remote network's subnet.

```
┌─────────────────────────┐                                          ┌─────────────────────────┐
│   Site A Local Network  │                                          │   Site B Local Network  │
│   192.168.1.0/24        │                                          │   10.0.0.0/24           │
│                         │                                          │                         │
│  ┌────────┐  ┌────────┐ │                                          │  ┌────────┐  ┌────────┐ │
│  │ Host A1│  │ Host A2│ │                                          │  │ Host B1│  │ Host B2│ │
│  │.1.10   │  │.1.20   │ │                                          │  │.0.10   │  │.0.20   │ │
│  └────────┘  └────────┘ │                                          │  └────────┘  └────────┘ │
└──────────┬──────────────┘                                          └──────────┬──────────────┘
           │                                                                    │
           │                                                                    │
      ┌────┴─────┐               Connect-IP over QUIC/UDP/SCION            ┌────┴─────┐
      │ Client A │◄───────────────────────────────────────────────────────►│ Proxy B  │
      │          │                                                         │          │
      └──────────┘                                                         └──────────┘
   Routes: 192.168.1.0/24                                              Routes: 10.0.0.0/24
   Address pool: 192.168.1.128/25                                      Address pool: 10.0.0.128/25

   IP assigned from peer: 10.0.0.130                                   IP assigned from peer: 192.168.1.131
```

In this configuration, hosts in Site A (192.168.1.0/24) can communicate with hosts in Site B (10.0.0.0/24) through the Connect-IP tunnel established between Client A and Proxy B. Obviously, the Hosts need to use the correct gateway addresses for routing traffic through the tunnel.
