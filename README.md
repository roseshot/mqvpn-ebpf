# mqvpn-ebpf — routed point-to-multipoint MASQUE tunnel

A Linux VPN prototype for an **mGRE-like single L3 interface** while preserving
the standard **MASQUE CONNECT-ETHERNET** wire protocol over encrypted HTTP/3,
QUIC DATAGRAM and Multipath QUIC.

**Server: ONE TUN device with ONE interface IP, MANY independent clients.**
No shared Linux bridge or L2 broadcast domain. The N200/I226 1–2.5 Gbit/s
target remains unmeasured; AF_XDP is not wired to the current UDP backend.

## Topology and packet flow

    Server: mq0 TUN 10.77.0.1/24
        |
        +--- CONNECT-ETHERNET/MPQUIC peer A --- mq0 TUN 10.77.0.2/24
        |                                          LAN 192.168.20.0/24
        |
        +--- CONNECT-ETHERNET/MPQUIC peer B --- mq0 TUN 10.77.0.3/24
                                                   LAN 192.168.30.0/24

    Linux route -> TUN IP packet -> L3/Ethernet shim -> CONNECT-ETHERNET
                -> QUIC DATAGRAM / MPQUIC (two WAN Paths per client)

Incoming: QUIC DATAGRAM -> Context ID 0 Ethernet frame -> extract IP packet
          -> verify authenticated peer's source prefix -> write to server TUN
          -> Linux IP stack / firewall / kernel forwarding.

Outgoing: Linux IP route emits packet on server mq0 -> choose destination
          peer by configured longest-prefix match -> one peer's MPQUIC stream.

**TUN** carries bare IP packets; CONNECT-ETHERNET still carries a full valid
Ethernet frame (synthetic locally administered MACs, EtherType and IP packet).
There is **no ARP/MAC learning/BUM flooding** across sites. This design uses
IP routing through the Linux main routing table, not XFRM policy-based VPN.

## Build

Linux amd64, Go 1.26+, iproute2 and /dev/net/tun. Root/CAP_NET_ADMIN
required to create persistent TUN interfaces. The client can bind UDP WAN
sockets using SO_BINDTODEVICE when --source-interface is provided.

~~~bash
go mod tidy
go build -o mqvpn-server ./cmd/mqvpn-server
go build -o mqvpn-client ./cmd/mqvpn-client
go test -race ./...
~~~

Legacy combined CLI remains available as mqvpn server|client.

### Test-only certificates

~~~bash
bash scripts/gen-dev-certs.sh certs vpn.local
openssl x509 -in certs/client.crt -outform DER | sha256sum
~~~

For multiple sites, use **distinct client certificates** per site. The server
maps the SHA-256 digest of each certificate's DER bytes to specific IP routes.
The --client-ca CA chain is validated independently. Keep client keys private.

## Explicit peer configuration (server only)

Create /etc/mqvpn/peers.json using the format in
[configs/peers.example.json](configs/peers.example.json). Replace each
certificate_sha256 with the output of the command above; remove whitespace.
Example:

~~~json
{
  "multicast_pps": 20,
  "peers": [
    {
      "id": "site-a",
      "certificate_sha256": "<64 hex characters from site A client cert DER>",
      "routes": ["10.77.0.2/32", "192.168.20.0/24"],
      "multicast_groups": ["224.0.0.251"]
    },
    {
      "id": "site-b",
      "certificate_sha256": "<64 hex characters from site B client cert DER>",
      "routes": ["10.77.0.3/32", "192.168.30.0/24"],
      "multicast_groups": ["224.0.0.251"]
    }
  ]
}
~~~

Unknown certificates receive HTTP 403. Overlapping routes across different
sites, duplicate fingerprints and default-route claims are rejected.
The routes list is **both** outbound destination selection AND an inbound
source-IP allowlist, blocking one site from impersonating another.

## Server (one interface)

~~~bash
sudo ./mqvpn-server \
  --listen :4433 \
  --tun mq0 --tunnel-ip 10.77.0.1/24 --tunnel-mtu 1100 \
  --max-frame 1160 --peers /etc/mqvpn/peers.json \
  --cert certs/server.crt --key certs/server.key \
  --client-ca certs/ca.crt
~~~

The single mq0 has the connected route 10.77.0.0/24. For additional site
LANs, install ordinary Linux interface routes (NO per-application policy):

~~~bash
sudo ip route replace 192.168.20.0/24 dev mq0
sudo ip route replace 192.168.30.0/24 dev mq0

# To route packets from client A to client B via the server's L3 stack:
sudo sysctl -w net.ipv4.ip_forward=1
~~~

Keep a firewall between peers. Forwarding is handled by the Linux kernel and
its forwarding / firewall rules; the user-space hub is a next-hop demux only.
**Do not route the remote QUIC server's public underlay IP via mq0.**

## Client A (one or two WAN paths)

~~~bash
sudo ./mqvpn-client \
  --url https://vpn.local:4433/.well-known/masque/ethernet/ \
  --source-ip 192.0.2.10 --source-interface enp1s0 \
  --wan2-ip 198.51.100.10 --wan2-interface enp2s0 \
  --tun mq0 --tunnel-ip 10.77.0.2/24 --tunnel-mtu 1100 \
  --max-frame 1160 \
  --multicast-groups 224.0.0.251 --multicast-pps 20 \
  --ca certs/ca.crt --cert certs/client.crt --key certs/client.key

# In a separate terminal: ordinary destination-based routing:
sudo ip route replace 192.168.30.0/24 dev mq0
ping -I mq0 10.77.0.1
ping -I mq0 10.77.0.3
~~~

Replace sample WAN IPs and interface names with real settings. The client
still supports --source-ip / --source-interface and --wan2-ip /
--wan2-interface. SO_BINDTODEVICE chooses the physical WAN, but underlay
source routing must remain valid. This is separate from *inner* VPN routing.

## Multicast / mDNS without broadcast storms

Default: **all IP multicast is blocked**, and all L2 broadcasts/unknown
Ethernet traffic are not part of this L3 architecture.

For a multicast group to traverse the overlay:
- Each participating server peer entry must explicitly list it under
  multicast_groups.
- Each client must list it in --multicast-groups.
- Every source is rate-limited to multicast_pps / --multicast-pps (default 20).
- The server only replicates to connected subscribers to that exact group;
  it does not send to every connected site.
- For mDNS specifically, only UDP 5353 with IPv4 TTL 255 or IPv6 Hop
  Limit 255 is eligible; it retains link-local group addresses. Other L2
  broadcasts, ARP, DHCP and non-IP frames are never bridged.

To use mDNS **between applications bound to the VPN TUN interface** on the
IPv4 overlay, the host may need an explicit multicast route:

~~~bash
sudo ip route replace 224.0.0.251/32 dev mq0
~~~

**Important:** mDNS packets from an existing physical LAN do *not* magically
appear in a routed TUN. Cross-site *LAN* service discovery additionally
requires a site-local mDNS reflector or a service-aware proxy, bound to LAN
and mq0, with loop suppression and service filtering. Generic IP routing
cannot make 224.0.0.251 / ff02::fb behave as normal routed multicast.
This code does **not** implement that external LAN reflector yet. Site-local
multicast storms are not bridged; configured overlay multicast traffic is
bounded but can still create some traffic at subscribed sites.

IPv6 mDNS requires a sufficiently large tunnel MTU (>= 1280) AND sufficient
QUIC DATAGRAM/underlay PMTU. The default 1100 MTU supports IPv4 testing only.

## Deployment caveats

- MASQUE CONNECT-ETHERNET exchanges Ethernet frames; synthetic L2 headers
  are an application adaptation to expose a routed TUN locally, not a new
  CONNECT-ETHERNET wire protocol.
- The current QUIC DATAGRAM path cannot fragment oversized Ethernet frames.
  Default max-frame=1160 and TUN MTU=1100. Sending an overlarge frame drops
  it; a transparent 1500-MTU WAN is not guaranteed.
- No automatic IP route creation beyond the TUN connected route. Per-site
  LAN routes, site forwarding and multicast routes are administrator-managed.
- No AF_XDP RX/TX runtime backend, no automatic reconnect or dynamic BGP,
  no external LAN mDNS reflector or IGMP/MLD membership tracking.
- Site identity pinned to client certificate DER SHA-256. The static peer
  configuration must be reloaded by restarting the server.
- No full Cisco NHRP/DMVPN protocol or spoke-to-spoke shortcut negotiation.
  Traffic between spokes traverses the hub.
- Performance and real WAN failover remain unmeasured on N200/I226.
- Restarting from the previous TAP-based prototype: **delete the old TAP**
  before starting the TUN version (ip link delete dev mq0) after taking
  care not to affect a live network.

Protocol references:
- https://datatracker.ietf.org/doc/draft-ietf-masque-connect-ethernet/
- https://www.rfc-editor.org/rfc/rfc10069.html
- https://docs.kernel.org/networking/tuntap.html
