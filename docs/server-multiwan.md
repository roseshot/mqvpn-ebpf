# Server multi-WAN MPQUIC addresses

Server exposes multiple physical underlay addresses over **one HTTP/3/QUIC
listener and one authenticated VPN session**. It must not spin up an
independent QUIC listener for every public IP: connection IDs and MPQUIC
paths belong to one common listener.

## Four WAN example

```yaml
listen: "0.0.0.0:8443"
wans:
  - interface: wan0
    ip: 192.0.2.1
  - interface: wan1
    ip: 198.51.100.1
  - interface: wan2
    ip: 203.0.113.1
  - interface: wan3
    ip: 192.0.2.5
instances:
  - name: lab
    server_name: vpn.example.com
    tun: mq0
    address: 10.77.0.1/30
    mtu: 1500
    max_frame: 1514
    peers: /etc/mqvpn/peers.yaml
    cert: /etc/mqvpn/server.crt
    key: /etc/mqvpn/server.key
    client_ca: /etc/mqvpn/ca.crt
```

The listed WAN IPs must be assigned to the listed local interfaces.
The server binds the **wildcard listen address** and advertises its
available Server addresses using the negotiated MPQUIC `ADD_ADDRESS`
extension. IPs are always on the configured QUIC port; configuring
separate listen ports for individual WANs is not supported by this
single-listener architecture. Clients must be able to route to each
advertised destination. NAT/load-balancers must preserve a
connection-ID-compatible path back to the same Server process.

`wans` is the only supported explicit Server underlay list. If it is
omitted, automatic MTU discovery uses the default route or local bind
interface. Server WAN entries are validated, and changing WAN addresses or the
shared listener requires a daemon restart rather than reconfiguring
an existing live connection unsafely.

For static Client-to-Server pairing:

```yaml
server: vpn.example.com:8443
connect_ip: 192.0.2.1
transport: quic
wans:
  - source_ip: 192.0.2.2
    interface: wan0
    server_ip: 192.0.2.1
  - source_ip: 198.51.100.2
    interface: wan1
    server_ip: 198.51.100.1
  - source_ip: 203.0.113.2
    interface: wan2
    server_ip: 203.0.113.1
  - source_ip: 192.0.2.6
    interface: wan3
    server_ip: 192.0.2.5
```

Alternatively, Client can set `use_server_wans: true` (or
`--use-server-wans=true`) and omit secondary `server_ip` values.
Client then uses authenticated Server `ADD_ADDRESS` announcements,
assigning the available remote addresses to its WAN paths in
announcement order. It is the operator's responsibility to configure
source-specific routes so each chosen pair is reachable.

**Important operational difference:** Client same-destination
WAN paths use `SO_BINDTODEVICE` per UDP socket. The Client's
multi-remote-address mode uses `mp-quic-go`'s `MultiSocketManager`
to select the desired source IP for each QUIC path; the Linux routing
table/policy rules must still route that source to the desired Server
address via the correct WAN interface. Neither Server nor Client
automatically configures policy routes, firewall or NAT.

Configuration list length has no mqvpn-defined constant. The pinned
`mp-quic-go v0.3.1` dependency supports at most **64 concurrently
active paths**; other protocol and OS resource constraints may apply.
TCP fallback continues to use only the primary WAN.

## CI

```bash
make release
sudo bash tests/integration/overlay-netns.sh wan4
```

The `wan4` scenario uses four independent Client/Server veth pairs.
It requires all additional QUIC paths to validate against **different
Server IPs**, applies a different `tc netem` profile to each physical
path and confirms actual transmitted bytes on all eight WAN egresses.
It also runs full-duplex simulated SIP/RTP/RTCP traffic. The same
combined network integration job retains VXLAN, TCP/UDP and WAN-loss
scenarios, and separately checks randomized **1–8 WAN per Client**
five-site BGP/OSPF convergence, all eight bidirectional adjacencies,
20/20 learned remote FIB routes and 20/20 cross-site pings per protocol.
See [Five-site routing](five-site-routing.md).
