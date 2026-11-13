# mqvpn-ebpf

Go, `CGO_ENABLED=0`, Linux: **MASQUE CONNECT-ETHERNET** over encrypted
HTTP/3 DATAGRAM + MPQUIC. One Server daemon exposes **ONE UDP listener**
to many independent, isolated route-based P2MP VPN LANs.

**Configuration format: YAML only.** Server and Peer configuration must be
`.yaml` or `.yml`. The server has no JSON loader, no single-instance CLI
fallback, and no combined `mqvpn server|client` executable. Build the
independent `mqvpn-server` and `mqvpn-client` commands.

## Shared UDP listener and per-instance TLS SNI

Each instance has:
- a unique `server_name` (DNS name used as **TLS SNI**, not an IP literal);
- one externally configured IP-addressed TUN;
- its own TLS certificate, verified client CA and Peer destination map;
- its own P2MP sessions, so overlaps between instances are allowed.

All instances share the **top-level `listen: "0.0.0.0:4433"`**. The server
accepts QUIC handshakes on this one UDP socket. TLS SNI determines which
instance certificate and client CA are used; the same SNI also selects
which P2MP hub handles the CONNECT-ETHERNET request. HTTP/3 authority must
match the SNI. Unknown or missing SNI is refused; there is no default
tenant that could accidentally receive another VPN's traffic.

~~~yaml
# /etc/mqvpn/server.yaml
listen: "0.0.0.0:4433"
instances:
  - name: customer-a
    server_name: customer-a.vpn.example.com
    tun: mq0
    peers: /etc/mqvpn/peers-a.yaml
    cert: /etc/mqvpn/tls/a.crt
    key: /etc/mqvpn/tls/a.key
    client_ca: /etc/mqvpn/tls/a-clients.crt

  - name: customer-b
    server_name: customer-b.vpn.example.com
    tun: mq1
    peers: /etc/mqvpn/peers-b.yaml
    cert: /etc/mqvpn/tls/b.crt
    key: /etc/mqvpn/tls/b.key
    client_ca: /etc/mqvpn/tls/b-clients.crt
~~~

Both DNS hostnames must resolve to the **same server IP**; both certificates
must have their respective `server_name` in DNS SAN. Per-instance mTLS
client CAs and Peer certificate fingerprint lists are kept separate.
Clients target different hostnames but the **same UDP port**:

~~~bash
mqvpn-client \
  --url https://customer-a.vpn.example.com:4433/.well-known/masque/ethernet/ \
  --tun mq0 --source-ip 192.0.2.10 --source-interface enp1s0 \
  --ca /etc/mqvpn/a-ca.crt \
  --cert /etc/mqvpn/a-client.crt --key /etc/mqvpn/a-client.key

mqvpn-client \
  --url https://customer-b.vpn.example.com:4433/.well-known/masque/ethernet/ \
  --tun mq0 --source-ip 192.0.2.10 --source-interface enp1s0 \
  --ca /etc/mqvpn/b-ca.crt \
  --cert /etc/mqvpn/b-client.crt --key /etc/mqvpn/b-client.key
~~~

On separate client hosts, local `mq0` names may be the same. If both
VPN instances are deployed on one client Linux host, use separate local
TUNs and network routing domains as appropriate.

## Overlapping subnets and host routing

`customer-a` and `customer-b` may both use `10.77.0.0/24` tunnel
addresses and `192.168.20.0/24` routed LANs. They have separate
`mq0` / `mq1` interfaces and **separate session destination tables**.
Their respective Peer YAML files may specify identical `routes`:

~~~yaml
peers:
  - id: site-1
    certificate_sha256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    routes: [10.77.0.2/32, 192.168.20.0/24]
~~~

These Peer `routes` select the QUIC session from **within** the
corresponding VPN instance; they do not modify Linux routes or filter
inner IP packets. Different clients inside the *same instance* cannot
claim ambiguous overlapping destination prefixes.

Linux overlapping subnets must be separated by VRF or network namespace,
configured **outside mqvpn**. See
[VRF route-based setup](docs/overlapping-subnets-vrf.md). The daemon never
creates TUN devices, changes IP addresses, routes, multicast memberships,
`ip rule`, firewall or routing tables.

This remains a Layer-3 IP VPN LAN, not an Ethernet bridge. IP broadcast /
multicast traffic entering one instance's TUN is replicated only within
that instance. Physical LAN Ethernet broadcasts are not bridged, and
the daemon imposes no inner traffic ACLs, mDNS filters or PPS limits.

## Server CLI, YAML hot reload

~~~bash
CGO_ENABLED=0 go build -mod=mod -o mqvpn-server ./cmd/mqvpn-server
CGO_ENABLED=0 go build -mod=mod -o mqvpn-client ./cmd/mqvpn-client

mqvpn-server validate --config /etc/mqvpn/server.yaml

mqvpn-server --config /etc/mqvpn/server.yaml \
  --reload-interval 2s --log-level info --log-format json

mqvpn-server instance list --config /etc/mqvpn/server.yaml

mqvpn-server instance upsert --config /etc/mqvpn/server.yaml \
  --name customer-c --server-name customer-c.vpn.example.com \
  --tun mq2 --peers /etc/mqvpn/peers-c.yaml \
  --cert /etc/mqvpn/tls/c.crt --key /etc/mqvpn/tls/c.key \
  --client-ca /etc/mqvpn/tls/c-clients.crt

mqvpn-server instance delete --config /etc/mqvpn/server.yaml \
  --name customer-c

mqvpn-server reload --pid <daemon-pid>
~~~

CLI edits YAML using an atomic rewrite with original owner/mode preserved.
YAML validation rejects unknown fields/duplicate keys/multiple documents,
invalid certificates and SNI collisions. A failed parse or certificate
check keeps running instances active.

**Hot reload preserves the ONE shared UDP socket.** Adding/removing
instances updates the SNI registry and starts/stops only the affected TUN
hub. Peer destination-prefix updates preserve unchanged MPQUIC sessions.
Rotating an instance's TLS identity, TUN or max-frame restarts only
that hub, leaving the shared UDP socket and other instances running.
Existing session closures follow the hub's lifecycle. **Changing the
top-level `listen` address requires restarting the daemon** (a UDP socket
cannot safely be rebound in place).

## Optional XDP (not AF_XDP Zero-Copy)

If enabled, one XDP dispatcher per physical WAN NIC recognizes the **one
shared outer UDP port**, not any private VPN subnet or tenant's identity.
HTTP/3 QUIC/TLS/SNI performs tenant selection after the handshake.
The existing XSKMAP is intentionally empty, so matched packets use
`XDP_PASS` into the working kernel UDP socket. AF_XDP UMEM/rings and
a QUIC PacketConn replacement are not implemented.

~~~yaml
xdp:
  interfaces: [enp1s0, enp2s0]
  object: /usr/lib/mqvpn/xdp_mqvpn.o
  mode: driver
~~~

Install `clang`, `llvm`, `libbpf-dev` and `linux-libc-dev` to run
`make bpf`; production Go binaries remain CGO-free.
See [XDP control plane](docs/xdp-multi-instance.md).

## Limitations

- SNI-based tenant demux requires DNS, per-instance server SAN, and
  unique `server_name`. Distinct TLS identities can share one UDP port.
- Peer session selection is static; hot reload does not implement NHRP.
- IPv4 TUN example MTU: 1100; CONNECT-ETHERNET over QUIC DATAGRAM cannot
  fragment oversized Ethernet frames. Standard IPv6 needs >=1280 and
  sufficient underlay PMTU.
- No LAN L2 bridge or mDNS reflector, no full AF_XDP Zero-Copy backend,
  no measured N200/I226 throughput, no real multi-tenant E2E test yet.

Protocol reference: https://datatracker.ietf.org/doc/draft-ietf-masque-connect-ethernet/
