# mqvpn-ebpf

Experimental **route-based point-to-multipoint** MASQUE CONNECT-ETHERNET
over encrypted HTTP/3 DATAGRAM + MPQUIC. Each VPN instance presents **one
pre-existing, IP-addressed Linux TUN**, shared by its authenticated peers.
There is no TAP bridge, Ethernet broadcast flooding, plain QUIC mode, or
implemented AF_XDP userspace backend.

## Separation of responsibilities

**Linux / network administrator owns network configuration.** The mqvpn
daemon does **not** create or persist TUN devices, assign addresses, set MTU,
install or delete IP routes, enable forwarding, modify ip rules, join IP
multicast groups, or program kernel multicast routing/IGMP/MLD.

Use systemd-networkd, NetworkManager, iproute2 or your own network management
service to prepare each TUN and normal kernel routes **before** starting
mqvpn. Daemon startup fails if its TUN does not exist, is DOWN or lacks an
IP address.

The application still needs a **static authenticated peer-to-prefix
forwarding map** to choose a remote MPQUIC session when Linux sends an IP
packet to a single shared TUN. These entries are overlay destination
selectors and ingress source-address authorizations, **not Linux routes**.
This is inherent to a single-interface point-to-multipoint overlay.

The existing optional multicast relay in p2mp is likewise a **bounded
data-plane forwarding mechanism** for explicitly configured peer groups,
not management of kernel multicast memberships/routes. Configured IP
multicast may be relayed, but there is no IGMP/MLD subscriber discovery and
no LAN mDNS reflector. Site LAN mDNS needs a separate, carefully isolated
mDNS reflector/service proxy; Linux or that external agent owns host
multicast configuration.

## Linux interface and route preparation

Example for the first server instance:

~~~bash
sudo ip tuntap add dev mq0 mode tun
sudo ip address add 10.77.0.1/24 dev mq0
sudo ip link set dev mq0 mtu 1100 up
sudo ip route replace 192.168.20.0/24 dev mq0
sudo ip route replace 192.168.30.0/24 dev mq0

# Optional: kernel routed forwarding between sites.
sudo sysctl -w net.ipv4.ip_forward=1
~~~

For a second instance, separately configure mq1 with **another** tunnel
network and routes; do not reuse an interface in two instances.

Client-side TUN example (site A):

~~~bash
sudo ip tuntap add dev mq0 mode tun
sudo ip address add 10.77.0.2/24 dev mq0
sudo ip link set dev mq0 mtu 1100 up
sudo ip route replace 192.168.30.0/24 dev mq0
~~~

These are **administrator commands**, never executed by mqvpn. Make them
persistent in your host network configuration. The tunnel IP and routes
exist independently from the daemon's lifetime; it only opens /dev/net/tun.

## Build

Requires Linux amd64, Go 1.26+, a preconfigured TUN (/dev/net/tun) and
permission to open it (typically CAP_NET_ADMIN). Bind-to-device for WAN
paths may also require privilege.

~~~bash
go mod tidy
go build -o mqvpn-server ./cmd/mqvpn-server
go build -o mqvpn-client ./cmd/mqvpn-client
go test -race ./...
~~~

The combined command mqvpn server|client remains available.

## Single server instance

~~~bash
sudo ./mqvpn-server \
  --listen :4433 --tun mq0 \
  --peers /etc/mqvpn/peers.json \
  --cert /etc/mqvpn/server.crt \
  --key /etc/mqvpn/server.key \
  --client-ca /etc/mqvpn/ca.crt \
  --log-level info --log-format text
~~~

No --tunnel-ip or --tunnel-mtu flags are accepted. They belong to the OS
network configuration, not the tunnel daemon.

The server verifies client TLS certificates and pins their DER SHA-256
fingerprints to allowed site IP prefixes. The peer configuration format
remains in [configs/peers.example.json](configs/peers.example.json).
Overlapping peer prefixes across sites are rejected. Prefixes cover IP
destination selection and anti-spoofing inside this one VPN instance.

## Multi-instance server (one daemon process)

Create the file
[configs/server.instances.example.json](configs/server.instances.example.json)
with entries such as:

~~~json
{
  "instances": [
    {
      "name": "edge-a",
      "listen": "0.0.0.0:4433",
      "tun": "mq0",
      "peers": "/etc/mqvpn/peers-a.json",
      "cert": "/etc/mqvpn/tls/a.crt",
      "key": "/etc/mqvpn/tls/a.key",
      "client_ca": "/etc/mqvpn/tls/a-ca.crt"
    },
    {
      "name": "edge-b",
      "listen": "0.0.0.0:4434",
      "tun": "mq1",
      "peers": "/etc/mqvpn/peers-b.json",
      "cert": "/etc/mqvpn/tls/b.crt",
      "key": "/etc/mqvpn/tls/b.key",
      "client_ca": "/etc/mqvpn/tls/b-ca.crt"
    }
  ]
}
~~~

Start both instances:

~~~bash
sudo ./mqvpn-server --config /etc/mqvpn/server.json \
  --log-level debug --log-format json
~~~

Each instance has independent TLS credentials, peer authorization, QUIC
listener, path handling, TUN and metrics. Log records include its instance
name and TUN. A failure of one instance shuts down the other instances
(clean fail-fast), rather than silently operating with partial coverage.
A single daemon currently requires **distinct UDP ports and TUN names**
per instance; no UDP listener sharing or live config reload is implemented.

## Client

~~~bash
sudo ./mqvpn-client \
  --url https://vpn.local:4433/.well-known/masque/ethernet/ \
  --source-ip 192.0.2.10 --source-interface enp1s0 \
  --wan2-ip 198.51.100.10 --wan2-interface enp2s0 \
  --tun mq0 \
  --max-frame 1160 \
  --ca /etc/mqvpn/ca.crt \
  --cert /etc/mqvpn/client.crt --key /etc/mqvpn/client.key \
  --log-level debug
~~~

The local mq0 IP address, MTU, routes and any multicast routes must already
exist. --source-interface / --wan2-interface bind the **underlay WAN UDP
sockets** using SO_BINDTODEVICE; per-WAN source/policy routing required by
your WAN topology remains the Linux administrator's responsibility.
They do not implement a policy-based tunnel for inner VPN traffic.

## Structured slog logging

Global flags accepted on both CLIs and on mqvpn subcommands:

- --log-level debug|info|warn|error (default info)
- --log-format text|json (default text)
- MQVPN_LOG_LEVEL and MQVPN_LOG_FORMAT set defaults; CLI flags override them

Example for systemd/journald:

~~~bash
MQVPN_LOG_LEVEL=warn MQVPN_LOG_FORMAT=json \
  ./mqvpn-server --config /etc/mqvpn/server.json
~~~

Debug includes QUIC DATAGRAM drops and path diagnostics; info includes
instance/session lifecycle. All levels use Go slog structured fields.

## Multicast boundary

The daemon **does not set up kernel multicast routes or subscriptions**.
The optional overlay multicast forwarding logic only replicates packets
that Linux has already delivered through the TUN, and only to the peer
groups explicitly listed in peers.json and the client --multicast-groups
flag. An ingress rate limiter bounds flooding. mDNS group 224.0.0.251
requires UDP port 5353 and TTL 255. Ordinary L2 broadcast and unknown
unicast are never flooded.

For applications on the VPN TUN, the network administrator may need an
explicit route to 224.0.0.251/32 via mq0, or a site-local mDNS reflector;
the daemon will not install either. Cross-site LAN mDNS discovery is not
provided by IP multicast routing alone, and external reflectors must have
their own loop and traffic limits.

## Current limitations

- The N200 + Intel I226-V/LM 1–2.5 Gbps performance objective is unverified.
- No AF_XDP production I/O backend; bpf/xdp_mqvpn.c is only a prototype.
- HTTP/3 DATAGRAM cannot fragment full Ethernet frames. Current defaults:
  tunnel IP MTU 1100 managed by Linux, max Ethernet frame 1160 in daemon.
  Standard IPv6 link MTU 1280 needs a sufficiently large path PMTU.
- No NHRP, direct spoke-to-spoke shortcuts, dynamic routing protocol,
  IGMP/MLD membership tracking, or automatic reconnect.
- Peer mapping and multicast allowlists are static (restart to reload).
  Linux policy decisions, route management and kernel multicast tables
  remain entirely outside mqvpn.

Protocols:
- https://datatracker.ietf.org/doc/draft-ietf-masque-connect-ethernet/
- https://www.rfc-editor.org/rfc/rfc10069.html
- https://docs.kernel.org/networking/tuntap.html
