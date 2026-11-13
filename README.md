# mqvpn-ebpf — transparent routed P2MP tunnel

Experimental Go CONNECT-ETHERNET over encrypted HTTP/3 DATAGRAM + Multipath
QUIC. One VPN **instance** represents one IP-based P2MP virtual LAN:

    mq0 (server, 10.77.0.1/24)
      ↕ one shared Linux TUN
      ├── authenticated MPQUIC site A (10.77.0.2, 192.168.20.0/24)
      └── authenticated MPQUIC site B (10.77.0.3, 192.168.30.0/24)

Each server instance has a *single* IP-addressed TUN and accepts many
clients. The server process may host multiple independent instances
(mq0/UDP4433, mq1/UDP4434, etc.).

**This is a Layer-3 TUN overlay, not an Ethernet switch or Linux bridge.**
"VPN LAN" means all peers participate in the same logical IP subnet and
multicast/broadcast distribution domain, but Ethernet frames from the
physical LAN (ARP/DHCP/unknown L2 broadcasts) are **not** bridged.

## Transparent inner traffic: no daemon ACLs

The daemon establishes authenticated CONNECT-ETHERNET/MPQUIC sessions
and moves IP packets between Linux TUN and the corresponding QUIC stream.
It does not classify inner traffic by source IP, destination transport
port, protocol, mDNS content, TTL/HopLimit, or packet rate.

- **Unicast:** Linux decides whether to send a packet into TUN using its
  own routing table. The daemon resolves the destination IP to a remote
  session using the static peer-to-prefix map. This map is only next-hop
  selection, *not* a source-address allowlist or kernel routing table.
- **IP multicast and limited IP broadcast:** packets *received from the
  TUN* are replicated to every connected peer in the same VPN instance.
  Packets received from a peer are delivered to the server's TUN and to
  every other peer in the instance. No membership lists, group filters,
  mDNS-specific checks, TTL rewriting, or PPS rate limits are applied.
- **No cross-instance replication:** separate server instances do not
  share traffic. No physical-LAN L2 broadcast bridging occurs.

**Important operational consequence:** IP multicast/broadcast arriving
at the VPN TUN can now be replicated to *every* connected peer.
A broadcast/multicast flood *inside the VPN* can affect the entire VPN
instance. Control it with the host firewall, traffic-control/qdisc, network
multicast routing configuration, or an external multicast proxy—not with
mqvpn packet filters. This is intentional per transparent-tunnel semantics.

There is no IGMP/MLD membership discovery in mqvpn. The Linux networking
stack or a dedicated service controls multicast subscription/routing. To
carry local application-generated mDNS traffic over TUN, the OS must first
send those packets to TUN. Physical LAN discovery requires an external
mDNS reflector or service proxy; a TUN is not an Ethernet bridge.

Transport still rejects malformed L3 packets and frames larger than the
negotiated QUIC DATAGRAM / configured maximum Ethernet frame. This is a
protocol/MTU limitation, not a user-configurable inner traffic policy.

## The OS owns TUN addresses and all routing

Daemon never creates TUN devices, configures IP addresses/MTU, edits Linux
routes/rules, sets forwarding sysctls, manages multicast groups, or sets
firewall/TC rules. Configure the TUN and routes *before* starting mqvpn via
systemd-networkd, NetworkManager, iproute2, etc.

Example **server**:

~~~bash
sudo ip tuntap add dev mq0 mode tun
sudo ip address add 10.77.0.1/24 dev mq0
sudo ip link set dev mq0 mtu 1100 up
sudo ip route replace 192.168.20.0/24 dev mq0
sudo ip route replace 192.168.30.0/24 dev mq0
# Optional kernel routing between spokes:
sudo sysctl -w net.ipv4.ip_forward=1
~~~

Example **client A**:

~~~bash
sudo ip tuntap add dev mq0 mode tun
sudo ip address add 10.77.0.2/24 dev mq0
sudo ip link set dev mq0 mtu 1100 up
sudo ip route replace 192.168.30.0/24 dev mq0
~~~

If you want overlay multicast, configure the relevant Linux multicast
routes externally (if necessary) so packets reach mq0. No daemon changes
to the host routing or multicast control plane.

## Build

Linux amd64, Go 1.26+, /dev/net/tun, preconfigured UP TUN and permissions
to attach the TUN; SO_BINDTODEVICE may need additional permissions.

~~~bash
go mod tidy
go build -o mqvpn-server ./cmd/mqvpn-server
go build -o mqvpn-client ./cmd/mqvpn-client
go test -race ./...
~~~

The compatibility CLI (mqvpn server|client) is retained.

## Peer directory (session next-hop lookup)

Server file: /etc/mqvpn/peers.json, format in
[configs/peers.example.json](configs/peers.example.json).
Each peer has an **mTLS client certificate SHA-256 DER fingerprint**
and a list of destination IP prefixes sent to that client. mTLS is required
to authenticate tunnel sessions; inner IP packets receive no daemon ACLs.

~~~json
{
  "peers": [
    {
      "id": "site-a",
      "certificate_sha256": "<64-digit certificate SHA-256>",
      "routes": ["10.77.0.2/32", "192.168.20.0/24"]
    },
    {
      "id": "site-b",
      "certificate_sha256": "<different 64-digit SHA-256>",
      "routes": ["10.77.0.3/32", "192.168.30.0/24"]
    }
  ]
}
~~~

The field "routes" is an overlay **IP-to-session destination map**, not
kernel routes and not a source spoofing filter. A missing unicast mapping
cannot be delivered because there is no next-hop session to select.
Overlapping destination prefixes for different peers are rejected as
ambiguous. Administrators remain responsible for kernel firewall/source
validation if desired. This is separate from the VPN daemon.

The previous "multicast_groups" and "multicast_pps" peer configuration
fields are obsolete and have no effect; remove them from config files.

To get the SHA-256 fingerprint for a test client certificate:

~~~bash
openssl x509 -in certs/client.crt -outform DER | sha256sum
~~~

## Single-instance server

~~~bash
sudo ./mqvpn-server \
  --listen :4433 --tun mq0 \
  --peers /etc/mqvpn/peers.json \
  --cert /etc/mqvpn/server.crt \
  --key /etc/mqvpn/server.key \
  --client-ca /etc/mqvpn/ca.crt \
  --log-level info --log-format text
~~~

## Multi-instance server

[configs/server.instances.example.json](configs/server.instances.example.json)
shows one process listening on separate UDP ports and attaching to separate
pre-existing TUN devices. Each instance has its own certificates, peer
directory and traffic forwarding domain.

~~~bash
sudo ./mqvpn-server --config /etc/mqvpn/server.json \
  --log-level debug --log-format json
~~~

Instance startup fails if the TUN is unavailable. The server stops all
instances if one fails unexpectedly. Static peer map updates require a
process restart.

## Client (dual WAN)

~~~bash
sudo ./mqvpn-client \
  --url https://vpn.local:4433/.well-known/masque/ethernet/ \
  --source-ip 192.0.2.10 --source-interface enp1s0 \
  --wan2-ip 198.51.100.10 --wan2-interface enp2s0 \
  --tun mq0 --max-frame 1160 \
  --ca /etc/mqvpn/ca.crt \
  --cert /etc/mqvpn/client.crt --key /etc/mqvpn/client.key \
  --log-level debug
~~~

WAN source-interface options constrain the **outer** QUIC UDP paths via
SO_BINDTODEVICE; Linux network administration is responsible for valid WAN
source routes. The *inner* VPN still uses normal destination-based routing.

The old --multicast-groups and --multicast-pps CLI flags are removed.
Traffic is forwarded without inner multicast/packet rate policies.

## Current limitations

- 1–2.5 Gbps Intel N200/I226 performance target is **not** measured.
- AF_XDP Zero-Copy is not wired into Go; experimental XDP code exists.
- QUIC DATAGRAM cannot transport Ethernet frames exceeding path PMTU;
  default maximum frame=1160; default Linux TUN MTU in examples=1100.
  IPv6 requires MTU >=1280 and sufficient QUIC underlay PMTU.
- Full Cisco DMVPN/NHRP discovery/spoke-to-spoke direct paths, BGP and
  dynamic peer learning are not implemented.
- No LAN L2 bridging, no IGMP/MLD processing, no LAN mDNS reflector.
- VPN-wide IP multicast/broadcast amplification can occur. This is a
  shared IP overlay, not multicast isolation between sites.

Protocol specifications:
- https://datatracker.ietf.org/doc/draft-ietf-masque-connect-ethernet/
- https://www.rfc-editor.org/rfc/rfc10069.html
