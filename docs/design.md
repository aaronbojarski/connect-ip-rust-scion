# Software Design
This document outlines the design principles and architecture of the connect-ip-rust-scion implementation. It covers the key components, their interactions, and the rationale behind design decisions.


## Async
The implementation leverages Rust's async/await capabilities with the `tokio` runtime to handle concurrent operations efficiently. This design is particularly important for the proxy, which needs to handle multiple client connections simultaneously. By implementing each connection as a separate asynchronous task, expensive cryptographic operations are isolated to individual tasks and don't block other connections. This task-based architecture also leads to more readable and maintainable code, especially for the integration of quiche's event loop, as each connection can manage its own state and event handling independently. 


## Modules
The project is organized into several modules. Here we just want to give a brief overview.
- **`connect_ip`**: implements the data handling of connect-ip. This includes the capsules processing and state keeping for address assignments, route announcements, and the encapsulation and decapsulation of tunneled IP packets. The module is fully transport-agnostic and can in theory be used with any underlying http/3 implementation. It was however, developed with quiche in mind and has only ever been used with it. How to integrate with quiche and its event loop can be seen in the client and proxy implementations.
- **`net`**: implements various networking utilities and abstractions used throughout the project. This includes IP address and subnet management, packet address validation, and the handling of TUN interfaces.
- **`client`**: implements the main client functionality. The module contains both the (UDP) socket management and the connect-ip logic for the client side of the connect-ip tunnel. This includes connection establishment, the quiche event loop integration, and the handling of incoming and outgoing packets.
- **`proxy`**: implements the main proxy functionality. Similar to the client module, it contains the (UDP) socket management and the connect-ip logic for the proxy side of the connect-ip tunnel. The main difference is that the proxy listens for http/3 requests and can handle multiple client connections simultaneously.


## Proxy Architecture
The proxy consists of one main task that is listening for incoming UDP packets. If a packet is received for a known client connection, it is forwarded to the respective client handler task on a dedicated queue. If the packet is an initial QUIC packet for a new connection, a new client handler task is spawned to manage the connection. Each client handler task manages its own connect-ip state and TUN interface, allowing for concurrent handling of multiple clients. Whenever a client needs to send a (QUIC) packet, it is forwarded to the main UDP listener task which sends it out on the network.

```
┌─────────────────────┐
│   Main Proxy Task   │           ┌────────────────────┐           ┌──────────┐
│                     │───[RxQ]──►│ Client Connection  │           │   TUN 1  │
│  UDP Receiver/      │           │      Handler 1     ├──[Queue]─►│          │
│  Sender +           │           │                    │           │          │◄─► Local Network (IP)
│  Packet Router      │  ┌─[TxQ]──│  Connect-IP State  │◄─[Queue]──┤          │
│                     │  |        └────────────────────┘           └──────────┘
│                     │◄─┤
│                     │  |        ┌────────────────────┐           ┌──────────┐
│                     │  └─[TxQ]──│ Client Connection  │           │   TUN 2  │
│                     │           │      Handler 2     ├──[Queue]─►│          │
│                     │───[RxQ]──►│                    │           │          │◄─► Local Network (IP)
│                     │           │  Connect-IP State  │◄─[Queue]──┤          │
└─────────────────────┘           └────────────────────┘           └──────────┘
         ▲                                 ...
         |
         ▼
Public Network (QUIC/UDP/SCION)
```


## Client Architecture
The client design is similar to that of the proxy. While the client does not necessarily need the separation of tasks for performance reasons, it was designed this way to keep the code structure consistent between client and proxy. The main client task manages the UDP socket and forwards incoming packets to the connect-ip handler task. The connect-ip handler manages the connect-ip state and the TUN handler task manages the TUN interface. Outgoing (QUIC) packets from the connect-ip handler are sent to the main client task for transmission over the network.

```
┌─────────────────────┐
│     Main Client     │           ┌─────────────────────┐           ┌──────────┐
│                     │───[RxQ]──►│  Connect-IP Handler │           │   TUN    │
│  UDP Receiver/      │           │                     ├──[Queue]─►│          │◄─► Local Network (IP)
│  Sender +           │◄──[TxQ]───┤  Connect-IP State   │◄─[Queue]──┤          │
│  Packet Router      │           └─────────────────────┘           └──────────┘
│                     │
└─────────────────────┘
         ▲
         |
         ▼
Public Network (QUIC/UDP/SCION)
```
