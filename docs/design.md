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

### TUN Interface Handling
Each client connection handler sets up its own TUN interface and spawns a dedicated task to manage it. This design choice was taken with a lot of consideration. The alternative would have been to have a shared TUN interface for all connections, with a dedicated task reading from the TUN and forwarding packets to the correct connection handler based on the destination address. We compared both designs based on several criteria.

- **State Management**: Separate TUN interfaces allow for simpler state management. This is especially important for handling connection teardowns and reconnections. With separate TUN interfaces, once a connection is closed, its associated TUN interface can be cleanly shut down without affecting other connections. With a shared TUN interface, additional logic is required to keep track of active connections and their addresses and routes.
- **Simplicity**: A shared TUN interface introduces significant complexity in routing packets to the correct client connection. With separate TUN interfaces the routing is handled by the OS. Each TUN interface only receives packets destined for the addresses assigned to that specific connection, simplifying the packet processing logic.
- **Performance**: We believe the OS routing logic to be quite performant. Our own routing implementation would likely decrease overall performance. (We actually implemented a prototype of the shared TUN interface design and found that we can achieve decent routing performance. However, the complexity increased significantly.)
- **Memory Usage**: A shared TUN interface requires less memory, as there would be only one interface and associated buffers. We have not measured the actual memory usage difference.
- **Connect-IP Compatibility**: A shared TUN interface is not suitable for all Connect-IP modes. The protocol allows clients to assign addresses to the proxy. With a shared TUN interface, all theses addresses are assigned to a single interface. There is then no natural way for applications to use the tun interface directly. While we could handle the routing based on destination address, the source address selection would not be straightforward. An application would select one of the available addresses on the interface. This address might not belong to the intended client connection, leading to packets being dropped by the proxy. By having separate TUN interfaces per connection, each interface only has the addresses assigned to that specific client connection, ensuring correct source address selection.
- **Administration**: A single TUN interface is simpler to manage from a system administration perspective. Having thousands of TUN interfaces on a system might be unconventional and not liked by system administrators.

Overall we believe that the benefits of having separate TUN interfaces per connection outweigh the drawbacks. The design simplifies state management and packet processing, aligns well with the connect-ip protocol's capabilities, and leverages the OS's routing efficiency. Lets hope system administrators will not mind too much.


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

### Task Separation
The separation of tasks in the client serves to maintain a clean architecture that mirrors the proxy. This separation would not be strictly necessary for performance, as the client handles only a single connection. However, by maintaining this structure, the code remains consistent and easier to understand. Furthermore, the use of the queues between the tasks allows for a natural way to process multiple packets at once. This can be useful to improve efficency when small IP packets are proccessed that can fit into a single QUIC packet. The tokio and tun implementations do not support batching receives natively, but by using queues we can read multiple packets from the TUN or UDP socket and then process them in a batch in the connect-ip handler.
