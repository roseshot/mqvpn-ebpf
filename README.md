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
- one daemon-created (or attached) Linux TUN with configured local IP/CIDR, MTU and UP state;
- its own TLS certificate, verified client CA and Peer destination map;
- its own P2MP sessions, so overlaps between instances are allowed.

All instances use **UDP/443 by default**. The optional top-level
`listen: "0.0.0.0:443"` overrides the bind address and port; omitting
`listen` binds to `0.0.0.0:443`. The server
accepts QUIC handshakes on this one UDP socket. TLS SNI determines which
instance certificate and client CA are used; the same SNI also selects
which P2MP hub handles the CONNECT-ETHERNET request. HTTP/3 authority must
match the SNI. Unknown or missing SNI is refused; there is no default
tenant that could accidentally receive another VPN's traffic.

~~~yaml
# /etc/mqvpn/server.yaml
# listen is optional (default 0.0.0.0:443, UDP)
instances:
  - name: customer-a
    server_name: customer-a.vpn.example.com
    tun: mq0
    address: 10.77.0.1/24
    mtu: 1100
    peers: /etc/mqvpn/peers-a.yaml
    cert: /etc/mqvpn/tls/a.crt
    key: /etc/mqvpn/tls/a.key
    client_ca: /etc/mqvpn/tls/a-clients.crt

  - name: customer-b
    server_name: customer-b.vpn.example.com
    tun: mq1
    address: 10.77.0.1/24  # same subnet; configure separate VRF externally
    mtu: 1100
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
  --url https://customer-a.vpn.example.com:443/.well-known/masque/ethernet/ \
  --tun mq0 --tun-address 10.77.0.2/24 --tun-mtu 1100 --source-ip 192.0.2.10 --source-interface enp1s0 \
  --ca /etc/mqvpn/a-ca.crt \
  --cert /etc/mqvpn/a-client.crt --key /etc/mqvpn/a-client.key

mqvpn-client \
  --url https://customer-b.vpn.example.com:443/.well-known/masque/ethernet/ \
  --tun mq0 --source-ip 192.0.2.10 --source-interface enp1s0 \
  --ca /etc/mqvpn/b-ca.crt \
  --cert /etc/mqvpn/b-client.crt --key /etc/mqvpn/b-client.key
~~~

### Client connection IP versus authenticated tenant domain

Clients can use a DNS name or an explicit server IP without changing the
one-port Server configuration. **TLS SNI and HTTP/3 authority always
refer to the selected Instance DNS name**, even when UDP dials a literal
IP. TLS certificate chain and DNS SAN verification remain enabled.

**DNS endpoint** (normal DNS resolution):

~~~bash
mqvpn-client \
  --url https://customer-a.vpn.example.com:443/.well-known/masque/ethernet/ \
  --source-ip 192.0.2.10 --source-interface enp1s0 \
  --tun mq0 --tun-address 10.77.0.2/24 --ca /etc/mqvpn/a-ca.crt \
  --cert /etc/mqvpn/a-client.crt --key /etc/mqvpn/a-client.key
~~~

**Pinned IP + tenant domain** (no DNS lookup for the remote endpoint):

~~~bash
mqvpn-client \
  --url https://customer-a.vpn.example.com:443/.well-known/masque/ethernet/ \
  --connect-ip 198.51.100.10 \
  --source-ip 192.0.2.10 --source-interface enp1s0 \
  --tun mq0 --tun-address 10.77.0.2/24 --ca /etc/mqvpn/a-ca.crt \
  --cert /etc/mqvpn/a-client.crt --key /etc/mqvpn/a-client.key
~~~

**Literal IP URL + explicit tenant domain**:

~~~bash
mqvpn-client \
  --url https://198.51.100.10:443/.well-known/masque/ethernet/ \
  --server-name customer-a.vpn.example.com \
  --source-ip 192.0.2.10 --source-interface enp1s0 \
  --tun mq0 --tun-address 10.77.0.2/24 --ca /etc/mqvpn/a-ca.crt \
  --cert /etc/mqvpn/a-client.crt --key /etc/mqvpn/a-client.key
~~~

IPv6 literals are also accepted (bracket the IPv6 address in the URL).
IP-only connections without an authenticated tenant DNS name are rejected:
all VPN instances use the same UDP port, so SNI is needed to select the
correct instance and client CA. The explicit IP chooses only the QUIC UDP
destination; it does not override TLS identity or VPN TUN routes.

On separate client hosts, local `mq0` names may be the same. If both
VPN instances are deployed on one client Linux host, use separate local
TUNs and network routing domains as appropriate.

**TCP Fallback is not implemented yet.** When implemented, its intended
default will be TCP/443 while the existing HTTP/3/MPQUIC listener remains
on UDP/443; TCP and UDP can use the same numeric port independently.
Binding port 443 normally requires root or CAP_NET_BIND_SERVICE. Configure
firewall ingress for UDP/443 now; TCP/443 is only needed after the
fallback transport exists.

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
[VRF route-based setup](docs/overlapping-subnets-vrf.md). The daemon **creates or attaches TUN**, assigns its configured local
IP/CIDR and MTU, and brings it UP. It sets Linux
`IFA_F_NOPREFIXROUTE` to suppress automatic connected-prefix route
installation. It does **not** install routes, `ip rule`, VRFs, namespace
assignments, forwarding, multicast routes or firewall rules. The kernel
may still create mandatory local-address routing entries.

This remains a Layer-3 IP VPN LAN, not an Ethernet bridge. IP broadcast /
multicast traffic entering one instance's TUN is replicated only within
that instance. Physical LAN Ethernet broadcasts are not bridged, and
the daemon imposes no inner traffic ACLs, mDNS filters or PPS limits.

## Daemon-managed TUN setup — IP, MTU and UP only

Both Server and Client now create the named Linux L3 TUN on startup (or
attach to an existing TUN) and configure its **explicit host IP/CIDR**.
The Server YAML instance requires `address`, e.g.
`address: 10.77.0.1/24`; `mtu` defaults to 1100. The Client
requires `--tun-address 10.77.0.2/24` and accepts
`--tun-mtu 1100`. No TUN IP is inferred from a Peer route map.

The setup order is: **TUNSETIFF → set MTU → assign IP/CIDR using
IFA_F_NOPREFIXROUTE → set UP → verify address, MTU and UP**. This is
implemented by Go with Linux rtnetlink, no shell commands and no CGO.
The daemon does not invoke route, policy-rule, VRF, network-namespace,
firewall, multicast-route or forwarding operations.

The kernel still manages its local-address FIB entries. In particular,
`IFA_F_NOPREFIXROUTE` prevents **automatic connected-prefix routes**
from being installed when the address is assigned. To reach routed
sites, the Linux administrator **must install appropriate routes** or
manage network routing via their own service. The daemon does not
do it on their behalf. Existing TUNs are not purged of other addresses;
the configured IP is added/replaced. Newly created nonpersistent
TUNs exist while the daemon holds their file descriptor.

Linux needs `/dev/net/tun` and `CAP_NET_ADMIN` to create/configure
interfaces, even though UDP/TCP port 443 may additionally require
`CAP_NET_BIND_SERVICE`. A manually precreated persistent TUN is still
supported for administrators who must attach it to a VRF *before*
the daemon starts. The daemon then configures the IP/MTU/UP state.
See [overlapping-subnet VRFs](docs/overlapping-subnets-vrf.md).

IPv6 addresses require an MTU >= 1280 and `max_frame >= mtu+14`
for the synthetic Ethernet header. A QUIC path also needs adequate
path MTU to carry the encapsulated datagram; this is not automatic
fragmentation or PMTU discovery by the daemon.

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
  --tun mq2 --address 10.77.2.1/24 --mtu 1100 \
  --peers /etc/mqvpn/peers-c.yaml \
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

## TCP fallback (optional, default TCP/443)

UDP/443 **MPQUIC + HTTP/3 DATAGRAM** remains the primary transport. When
the QUIC initial handshake cannot complete before the configured UDP
deadline, the client in `auto` mode falls back to **TLS 1.3 + HTTP/1.1
Upgrade `connect-ethernet` + RFC 9297 DATAGRAM Capsules** on TCP/443.
This is the HTTP/1.1 protocol defined by the October 2026
CONNECT-ETHERNET draft, **not HTTP/2 Extended CONNECT**.

Server-side YAML (opt-in so deploying on a host with an existing TCP/443
service does not fail unexpectedly):

~~~yaml
# Top-level, next to instances:
tcp_fallback:
  enabled: true
  # listen: "0.0.0.0:443"  # optional; defaults to TCP/443
~~~

Both listeners have the **same numeric default port 443**, but use separate
protocols and sockets: UDP/443 for MPQUIC and TCP/443 for TLS fallback.
They use the same SNI tenant registry, client CA, fingerprint authorization,
TUN and peer mapping. Changes to the TCP listener enabled/address settings
require a daemon restart; instance peer map changes continue to hot-reload.
The host must permit TCP/443 ingress as well as UDP/443.

Client (automatic by default):

~~~bash
mqvpn-client \
  --url https://customer-a.vpn.example.com/.well-known/masque/ethernet/ \
  --transport auto --udp-dial-timeout 5s \
  --tun mq0 --source-interface enp1s0 \
  --ca /etc/mqvpn/a-ca.crt \
  --cert /etc/mqvpn/a-client.crt --key /etc/mqvpn/a-client.key
~~~

An independent `--tcp-port` flag defaults to 443 even if the QUIC URL
specifies a different UDP port. Use it when Server `tcp_fallback.listen`
is configured to a nonstandard TCP port.

Choose `--transport quic` to disable fallback, or `--transport tcp` to
force TCP without an initial QUIC attempt. Both the pinned-IP
(`--connect-ip`) and the literal-IP URL + `--server-name` forms
are supported. TLS certificate validation and tenant SNI remain mandatory.

**Safe downgrade boundary:** automatic fallback occurs **only on initial
QUIC dial timeout**, not on TLS certificate errors, mTLS rejection, bad
CONNECT responses, or other post-handshake application errors. There is no
simultaneous UDP/TCP peer session, no seamless mid-session failover or
automatic failback probing yet. Forced TCP uses **primary WAN only**;
auto fallback also uses primary WAN and logs if WAN2 is configured.

The TCP transport is reliable and ordered and can suffer head-of-line
blocking (especially for tunneled TCP). It does not use MPQUIC multi-path
or the optional XDP acceleration. The data carried remains the same
Context-ID-0 synthetic Ethernet frame from the existing L3 TUN shim.
No inner packet ACL, multicast filter, or kernel route
configuration is added by fallback. The common TUN setup creates or
attaches the device and assigns only its configured address/MTU/UP state.

See [docs/tcp-fallback.md](docs/tcp-fallback.md).

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

## Pull-request CI

The GitHub Actions `Go` workflow runs on PRs targeting `main`, direct
pushes to `main`, or manual dispatch. Feature-branch push events no longer
cause duplicate PR checks. Three independent jobs run in parallel:
**Native Go (CGO=0)** (build, tests, vet), **Race detector** (CGO enabled),
and **eBPF ELF** (Clang compilation). The Go cache key uses `go.mod`.
Superseded PR runs are canceled; CI permissions are read-only.

The unconditional Dependabot auto-merge policy remains unchanged.

## Limitations

- SNI-based tenant demux requires DNS, per-instance server SAN, and
  unique `server_name`. Distinct TLS identities can share one UDP port.
- Peer session selection is static; hot reload does not implement NHRP.
- IPv4 TUN default MTU: 1100; CONNECT-ETHERNET over QUIC DATAGRAM cannot
  fragment oversized Ethernet frames. Standard IPv6 needs >=1280 and
  sufficient underlay PMTU.
- No HTTP/2 TCP fallback or automatic mid-session failback; no LAN L2 bridge or mDNS reflector, no full AF_XDP Zero-Copy backend,
  no measured N200/I226 throughput, no real multi-tenant E2E test yet.

Protocol reference: https://datatracker.ietf.org/doc/draft-ietf-masque-connect-ethernet/
