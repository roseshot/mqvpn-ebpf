# mqvpn-ebpf

Go, `CGO_ENABLED=0`, Linux: **MASQUE CONNECT-ETHERNET** over encrypted
HTTP/3 DATAGRAM + MPQUIC. One Server daemon exposes **ONE UDP listener**
to many independent, isolated route-based P2MP VPN LANs.

**Configuration format: YAML only.** Server, Client (optional daemon file),
and Peer configuration use `.yaml` or `.yml`. The server has no JSON loader
or single-instance CLI fallback. Build the independent `mqvpn-server` and
`mqvpn-client` commands. Client CLI flags remain available for overrides.

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
    peers: /etc/mqvpn/peers-a.yaml
    cert: /etc/mqvpn/tls/a.crt
    key: /etc/mqvpn/tls/a.key
    client_ca: /etc/mqvpn/tls/a-clients.crt

  - name: customer-b
    server_name: customer-b.vpn.example.com
    tun: mq1
    address: 10.77.0.1/24  # same subnet; configure separate VRF externally
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
  --tun mq0 --tun-address 10.77.0.2/24 --source-ip 192.0.2.10 --source-interface enp1s0 \
  --ca /etc/mqvpn/a-ca.crt \
  --cert /etc/mqvpn/a-client.crt --key /etc/mqvpn/a-client.key

mqvpn-client \
  --url https://customer-b.vpn.example.com:443/.well-known/masque/ethernet/ \
  --tun mq0 --tun-address 10.77.0.2/24 \
  --source-ip 192.0.2.10 --source-interface enp1s0 \
  --ca /etc/mqvpn/b-ca.crt \
  --cert /etc/mqvpn/b-client.crt --key /etc/mqvpn/b-client.key
~~~

## Simple Client daemon configuration

A Client needs just five YAML values. The standard MASQUE path, UDP/TCP
ports, TUN name (`mq0`), WAN source selection, MTU/frame budget, transport
fallback and bundled TCX eBPF policy are all automatic.

~~~yaml
# /etc/mqvpn/client.yaml
server: customer-a.vpn.example.com
address: 10.77.0.2/24
ca: /etc/mqvpn/a-ca.crt
cert: /etc/mqvpn/a-client.crt
key: /etc/mqvpn/a-client.key
~~~

~~~bash
mqvpn-client --config /etc/mqvpn/client.yaml
~~~

For one-off CLI usage, the equivalent short form is:

~~~bash
mqvpn-client --server customer-a.vpn.example.com --tun-address 10.77.0.2/24 \
  --ca /etc/mqvpn/a-ca.crt --cert /etc/mqvpn/a-client.crt \
  --key /etc/mqvpn/a-client.key
~~~

The Client chooses the primary WAN source from the kernel route to the
resolved remote IP, without adding routes. On unusual policy routing/VRF,
set `source_interface` and optionally `source_ip` in YAML, or use
`--source-interface` / `--source-ip` explicitly. Secondary WAN paths
still require `wan2_interface` or `wan2_ip`.

`server` accepts `domain.example.com`, `domain.example.com:8443`, or
an HTTPS URL with a custom path. DNS identity remains mandatory for mTLS
and tenant SNI. To connect to a pinned endpoint, use `connect_ip` while
keeping `server` as the authenticated tenant domain:

~~~yaml
server: customer-a.vpn.example.com
connect_ip: 198.51.100.10
address: 10.77.0.2/24
ca: /etc/mqvpn/a-ca.crt
cert: /etc/mqvpn/a-client.crt
key: /etc/mqvpn/a-client.key
~~~

Legacy `--url`, `--server-name`, `--connect-ip` and all advanced
flags remain supported. An IP-literal URL still requires an explicit
tenant `server_name`; certificate/hostname validation is unchanged.
CLI flags override values from `--config`. See
[Client configuration reference](docs/client-config.md).

On separate client hosts, local `mq0` names may be the same. Multiple
VPN instances on one host still need separate TUNs/routing domains.

**TCP fallback** is attempted on the initial QUIC timeout by default
when the server has enabled TCP fallback; forced TCP uses the primary WAN
only. The transport never downgrades on authentication failures.

## Server-assigned Tunnel IP leases (optional)

The Server can dynamically assign a client TUN IPv4/IPv6 host address from
an instance-specific pool **only after mTLS Peer authorization**. The
assigned CIDR is returned in the authenticated HTTP/3 CONNECT 200 or
HTTP/1.1 Upgrade 101 `Mqvpn-Tunnel-Address` response header; Client
configures the TUN **after** receiving and validating it.

Configure `tunnel_pool` to match the instance's TUN connected prefix:

~~~yaml
instances:
  - name: customer-a
    server_name: customer-a.vpn.example.com
    tun: mq0
    address: 10.77.0.1/24
    tunnel_pool: 10.77.0.0/24
    peers: /etc/mqvpn/peers-a.yaml
    cert: /etc/mqvpn/tls/a.crt
    key: /etc/mqvpn/tls/a.key
    client_ca: /etc/mqvpn/tls/ca.crt
~~~

In the instance's peer YAML, allow individual authenticated sites to
request a lease (other Peers remain static):

~~~yaml
peers:
  - id: site-a
    certificate_sha256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    dynamic_tunnel_ip: true
    routes: [192.168.20.0/24] # optional LAN; no overlap with tunnel_pool
~~~

For the matching Client, omit `address` (or use `address: auto`) in
`client.yaml`. Its remaining required values are `server`, `ca`,
`cert`, and `key`. To retain a static address, provide
`address: 10.77.0.2/24` as before; no negotiation happens.

The pool excludes the Server's TUN IP, IPv4 network and broadcast
addresses, and reserves existing static host (/32 or /128) Peer destinations.
Broader overlapping static routes are rejected. Dynamic allocations remain
unique across concurrent sessions. A lease is released on disconnect
or Peer revocation. Leases are **session-scoped**, not persisted across
reconnect/restart and not an address reservation service. Each VPN
instance allocates independently, including when tenant subnets overlap.
Dynamic peers without a pool and clients requesting a lease from an
unauthorized Server are rejected. There is no DHCP, kernel route
installation, firewall policy or inner-source anti-spoofing added.
See [Client configuration](docs/client-config.md).

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
IP/CIDR and MTU, and brings it UP. The kernel **automatically adds the normal connected-prefix route**
(and local-address routes) when the daemon assigns IP/CIDR. The daemon
does **not** explicitly add custom routes, `ip rule`, VRFs, namespace
assignments, forwarding, multicast routes or firewall rules.

This remains a Layer-3 IP VPN LAN, not an Ethernet bridge. IP broadcast /
multicast traffic entering one instance's TUN is replicated only within
that instance. Physical LAN Ethernet broadcasts are not bridged, and
the daemon imposes no inner traffic ACLs, mDNS filters or PPS limits.

## Daemon-managed TUN setup — IP, MTU and UP only

Both Server and Client now create the named Linux L3 TUN on startup (or
attach to an existing TUN) and configure its **explicit host IP/CIDR**.
The Server YAML instance requires `address`, e.g.
`address: 10.77.0.1/24`; `mtu` defaults to WAN-aware automatic sizing capped at 1400. The Client accepts an explicit `--tun-address 10.77.0.2/24`
(static) or requests an authenticated Server lease by default when its
address is omitted. `--tun-mtu` remains an optional override. No TUN
IP is inferred from a Peer route map.

The setup order is: **TUNSETIFF → set MTU → assign IP/CIDR with
normal Linux address flags → set UP → verify address, MTU and UP**.
Linux automatically maintains the associated connected-prefix route.
This is implemented by Go with Linux rtnetlink, no shell commands and
no CGO.
The daemon does not invoke route, policy-rule, VRF, network-namespace,
firewall, multicast-route or forwarding operations.

The kernel manages both **connected-prefix routes** and local-address
routes when the TUN address is assigned. Other site prefixes outside
the configured connected subnet still require administrator-managed
routing. The daemon does not install them. Existing TUNs are not purged
of other addresses;
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

## Automatic WAN-aware MTU (1400 maximum by default)

The Server and Client determine their **local WAN link MTUs** before
starting each TUN. With the normal single-WAN IPv4 Internet link at
MTU 1500 the automatic TUN MTU is **1400**, and `max_frame` is **1414**.
The kernel-reported WAN MTU is a link property, not an observed
Internet end-to-end Path MTU. The auto planner reserves 100 bytes for
IPv4 WAN or 120 bytes for IPv6 WAN, including QUIC/MASQUE framing plus
a safety margin. It caps the resulting TUN MTU at 1400.

| WAN | WAN MTU | Auto TUN MTU | Auto `max_frame` |
| --- | ---: | ---: | ---: |
| IPv4 Ethernet | 1500 | 1400 | 1414 |
| IPv4 PPPoE | 1492 | 1392 | 1406 |
| IPv4 cellular | 1420 | 1320 | 1334 |
| IPv6 Ethernet | 1500 | 1380 | 1394 |

If MPQUIC has two WAN paths, use the **smaller** budget. With Server
`listen: "0.0.0.0:443"`, the daemon uses main-table IPv4 default
route NIC(s) unless you explicitly configure the top-level
`wan_interfaces` list. When the listener is bound to an exact IP,
the owning interface can be identified directly. Servers with multiple
WANs or unusual routing should explicitly list every physical WAN
interface that may receive VPN traffic:

~~~yaml
# Top-level YAML; optional but recommended on multi-WAN servers
wan_interfaces: [enp1s0, wwan0]
instances:
  - name: customer-a
    server_name: customer-a.vpn.example.com
    tun: mq0
    address: 10.77.0.1/24
    # mtu and max_frame omitted: calculate at runtime
    peers: /etc/mqvpn/peers-a.yaml
    cert: /etc/mqvpn/tls/a.crt
    key: /etc/mqvpn/tls/a.key
    client_ca: /etc/mqvpn/tls/a-ca.crt
~~~

Client automatically discovers the primary WAN source through the
kernel's route to the server; explicit `source_ip`/`source_interface`
selectors override this for multi-WAN or policy routing deployments.
Both WAN source link MTUs are inspected before opening the TUN.
TCP fallback uses the primary WAN. If the selected WAN interface
cannot be identified, automatic sizing fails rather than guessing.
Server polling/reload detects link-MTU changes and restarts affected
TUN sessions, but the Client does **not** dynamically resize an
established tunnel.

`max_frame` is derived as `TUN MTU + 14` (synthetic Ethernet), not
a fixed 1160-byte allowance. Manual `mtu` and `max_frame` remain
available and must be mutually compatible.

**This is not active PMTU discovery.** A downstream Internet hop can
have a smaller MTU than the local NIC; QUIC DATAGRAM size is also
bounded by negotiation and per-path DPLPMTUD. No guarantee is made
that a 1400-byte inner packet will fit immediately after handshake.
See [WAN MTU budgets and path constraints](docs/mtu-mss.md).

## MTU 1360 / TCP MSS 1360

`mtu: 1360` is supported **when the entire WAN path can carry the
resulting QUIC DATAGRAM**. Set `max_frame` to at least 1374 (1360 IP
payload + 14 synthetic Ethernet bytes), on both Client and Server:

~~~yaml
# In one Server instance, after tun / address:
mtu: 1360
max_frame: 1374
~~~

~~~bash
# Add to mqvpn-client:
--tun-mtu 1360 --max-frame 1374
~~~

**TUN MTU 1360 is not TCP MSS 1360.** Normal IPv4 TCP MSS is 1320,
and IPv6 TCP MSS is 1300 with this MTU. To *target* TCP MSS 1360,
the TUN MTU would need to be at least 1400 for IPv4 (max_frame 1414)
or 1420 for IPv6 (max_frame 1434). TCP options / PMTU can reduce
the effective value.

QUIC DATAGRAM frames cannot be fragmented, so 1360 is an **opt-in**
configuration, not a guarantee on dual-WAN paths or tunnels with a
smaller underlay PMTU. Do not force MSS or install mangle/routing rules
in the daemon. See [MTU and MSS sizing](docs/mtu-mss.md).

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
  --tun mq2 --address 10.77.2.1/24 \
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
mqvpn-client --config /etc/mqvpn/client.yaml
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

## TC eBPF TCP MSS Clamp and traffic statistics (default auto)

TCX eBPF on the L3 TUN can cap TCP MSS in SYN and SYN-ACK
without calling `tc`, `iptables`, `nftables`, or `os/exec`.
The Linux kernel must support **TCX (6.6+)**. Both ingress and egress
are attached to handle VPN traffic moving in either direction.
The TCX ELF is **embedded in both Go executables** and loaded directly
from memory. There is no runtime `.o` file, Clang or libbpf installation
requirement. Default `auto` attempts the bundled program, warning and
falling back to ordinary TUN forwarding only if the kernel or BPF
permissions do not support it. `required` fails instead; `off` disables it.

The default policy requires no TC YAML stanza. Per-instance overrides:

~~~yaml
instances:
  - name: customer-a
    server_name: customer-a.vpn.example.com
    tun: mq0
    address: 10.77.0.1/24
    tc:
      mode: auto  # off | auto | required; omitting tc also defaults auto
      mss_clamp: auto  # off | auto | numeric (e.g. "1280")
      stats: true
    peers: /etc/mqvpn/peers-a.yaml
    cert: /etc/mqvpn/tls/a-server.crt
    key: /etc/mqvpn/tls/a-server.key
    client_ca: /etc/mqvpn/tls/a-clients.crt
~~~

Client defaults to `--tc-mode auto --mss-clamp auto --tc-stats=true`.
QUIC and TCP fallback use the same bundled TCX program. An explicit
`tc.object: /path/to/tun_tc.o` or `--tc-object /path/to/tun_tc.o`
overrides the bundle; legacy explicit object settings without a mode
stay strict (`required`) for backward compatibility.
`tc: {mode: off}` disables TCX.

Auto MSS clamp uses the effective TUN MTU (not the raw WAN MTU):
for MTU 1400, IPv4 MSS is at most **1360** and IPv6 MSS is at
most **1340**. Explicit values only lower these ceilings.
Existing smaller peer MSS values stay unchanged. Only SYN/SYN-ACK
MSS options are modified; TCP payloads and other packets are passed.
Malformed IP/TCP options or fragmented IPv4/IPv6 packets are never
rewritten. BPF computes updated TCP checksums using a kernel helper;
if a checksum/write operation fails, the packet is dropped rather
than forwarded with corruption.

Separate per-CPU TUN counters include ingress/egress packets/bytes,
IPv4/IPv6, SYN, clamped, oversize observed and parser/checksum errors.
Counters are logged when a TUN instance closes. TC eBPF doesn't
install routes or change the kernel-generated connected-prefix route.

WAN XDP records per-CPU packet/byte/UDP port-match counters and always
passes traffic to the normal UDP socket. Its unused XSKMAP/redirect
placeholder has been deleted. The XDP counters are logged on shutdown. See
[TC eBPF data plane](docs/tc-ebpf.md).

## Optional XDP (not AF_XDP Zero-Copy)

If enabled, one XDP dispatcher per physical WAN NIC recognizes the **one
shared outer UDP port**, not any private VPN subnet or tenant's identity.
HTTP/3 QUIC/TLS/SNI performs tenant selection after the handshake.
The only supported XDP ELF has `xdp_mqvpn`, `instance_ports` and
`xdp_stats`; missing maps or the obsolete `xsks_map` are rejected.
Packets always take `XDP_PASS` into the Linux UDP socket.

~~~yaml
xdp:
  interfaces: [enp1s0, enp2s0]
  mode: driver  # XDP is opt-in; uses embedded ELF by default
~~~

The XDP ELF is also embedded in the **server** executable; XDP still
requires an explicit interface list, and never replaces the UDP socket.
Build normally with `CGO_ENABLED=0 go build` or use `make release` to
produce `bin/mqvpn-server` and `bin/mqvpn-client` including both BPF objects.
Clang/LLVM and development headers are needed only to regenerate the bundled
ELFs from C (`make bpf`), not to build Go binaries or deploy them.
See [XDP control plane](docs/xdp-multi-instance.md).

## Pure Go runtime and development tools

Server and Client use Go libraries and Linux socket/ioctl/Netlink APIs:
no subprocess-based network setup and no production `os/exec`. TUN
validation, TUN creation, Netlink IP/MTU/UP, WAN source selection and
UDP/TCP socket binding are separate packages/files. The Go architecture
test checks this restriction in production source.

**Development commands are allowed.** `scripts/gen-dev-certs.sh`
still uses OpenSSL for test-only certificates, and `make bpf` still uses
Clang/LLVM to build the BPF ELF; neither is invoked by the running
VPN daemon. See [runtime architecture](docs/runtime-architecture.md).

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
- TUN MTU defaults to WAN-aware sizing capped at 1400 and auto
  `max_frame=MTU+14`. Link MTU is not end-to-end PMTU: large DATAGRAMs
  still require per-path PMTU and peer support; IPv6 TUN needs MTU >=1280.
- No HTTP/2 TCP fallback or automatic mid-session failback; no LAN L2 bridge or mDNS reflector, no full AF_XDP Zero-Copy backend,
  no measured N200/I226 throughput, no real multi-tenant E2E test yet.

Protocol reference: https://datatracker.ietf.org/doc/draft-ietf-masque-connect-ethernet/
