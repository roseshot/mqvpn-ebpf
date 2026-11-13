# mqvpn-ebpf

Experimental **MASQUE CONNECT-ETHERNET** over HTTP/3 QUIC DATAGRAM and
Multipath QUIC. Linux server supports multiple independent, route-based,
point-to-multipoint (P2MP) VPN LANs within one daemon. Every instance has
one **preconfigured IP-addressed TUN**, one UDP listener, its own authenticated
clients, and an independent Peer → destination-prefix table.

**Configuration is YAML by default** (`.yaml` / `.yml`). Existing `.json`
server and peer configuration files remain readable for migration.

## Independent instances, including overlapping subnets

Two VPN LANs may both use **10.77.0.0/24** for their tunnel addresses and
**192.168.20.0/24** for their site LANs:

| Instance | TUN | Underlay port | VPN prefix | Remote LAN prefix |
| --- | --- | --- | --- | --- |
| customer-a | mq0 | UDP/4433 | 10.77.0.0/24 | 192.168.20.0/24 |
| customer-b | mq1 | UDP/4434 | 10.77.0.0/24 | 192.168.20.0/24 |

Each instance owns its own destination lookup and session set; the same IP
means a **different Peer depending on the instance**. Neither the P2MP hub
nor XDP shares inner prefix mappings across instances. Duplicate TUN names
or UDP listen ports remain prohibited. Within *one* instance, overlapping
destinations for two different Peers remain invalid because the next hop
would be ambiguous.

**Linux must separately isolate overlapping routing domains.** Putting two
identical subnet routes into one main routing table does not create isolated
VPNs. Configure a distinct Linux **VRF** (or network namespace) for each
TUN, using ordinary route-based tables. mqvpn does **not** create VRFs,
TUN devices, IP addresses, routes, multicast routes, firewall or policy rules.
See [VRF setup and isolation](docs/overlapping-subnets-vrf.md).

This is an IP VPN LAN on TUN, not an Ethernet bridge. VPN IP multicast /
limited broadcast entering the TUN is replicated within that **one
instance**; physical LAN L2 broadcasts are not bridged. No daemon packet
ACLs, mDNS filters, PPS limits or content inspection are imposed.

## Compile without CGO

Linux amd64, Go 1.26+, /dev/net/tun. Preconfigure the TUN and its routes
externally before starting. Runtime TLS 1.3/QUIC and the Go XDP control
plane do not require CGO.

~~~bash
CGO_ENABLED=0 go build -mod=mod -o mqvpn-server ./cmd/mqvpn-server
CGO_ENABLED=0 go build -mod=mod -o mqvpn-client ./cmd/mqvpn-client
CGO_ENABLED=0 go test -mod=mod ./...
~~~

Optional experimental XDP dispatcher is compiled separately with Clang:
`make bpf`. It currently provides dynamic multi-instance UDP port maps,
**not** an AF_XDP zero-copy packet backend. XSKMAP is intentionally empty
and the established transport still uses Linux UDP Socket. The N200/I226
1–2.5 Gbps goal has not been benchmarked.

## Multi-instance Server YAML

See [configs/server.instances.example.yaml](configs/server.instances.example.yaml).

~~~yaml
instances:
  - name: customer-a
    listen: "0.0.0.0:4433"
    tun: mq0
    peers: /etc/mqvpn/peers-a.yaml
    cert: /etc/mqvpn/tls/a-server.crt
    key: /etc/mqvpn/tls/a-server.key
    client_ca: /etc/mqvpn/tls/a-clients.crt

  - name: customer-b
    listen: "0.0.0.0:4434"
    tun: mq1
    peers: /etc/mqvpn/peers-b.yaml
    cert: /etc/mqvpn/tls/b-server.crt
    key: /etc/mqvpn/tls/b-server.key
    client_ca: /etc/mqvpn/tls/b-clients.crt
~~~

Peer examples (the second intentionally overlaps with the first):
[configs/peers.example.yaml](configs/peers.example.yaml) and
[configs/peers-b.example.yaml](configs/peers-b.example.yaml).

~~~yaml
# /etc/mqvpn/peers-a.yaml
peers:
  - id: site-a
    certificate_sha256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    routes:
      - 10.77.0.2/32
      - 192.168.20.0/24
~~~

`routes` is **only** the destination IP → MPQUIC session selector inside
this VPN instance, not a Linux route, a source-IP ACL, or a global prefix
registry. mTLS client certificate fingerprints distinguish client sessions.
All configured prefix maps stay private to the instance.

## YAML validation, CLI edits and hot reload

Strict YAML loading rejects unknown keys, duplicate keys, multiple documents,
malformed types and invalid Peer maps. Legacy JSON uses strict field checks.
Use `.yaml` or `.yml` for new deployments; an existing `.json` file can
still be managed without changing its format.

~~~bash
mqvpn-server validate --config /etc/mqvpn/server.yaml

mqvpn-server --config /etc/mqvpn/server.yaml \
  --reload-interval 2s --log-level info --log-format json

mqvpn-server instance list --config /etc/mqvpn/server.yaml

mqvpn-server instance upsert --config /etc/mqvpn/server.yaml \
  --name customer-c --listen 0.0.0.0:4435 --tun mq2 \
  --peers /etc/mqvpn/peers-c.yaml \
  --cert /etc/mqvpn/tls/c-server.crt \
  --key /etc/mqvpn/tls/c-server.key \
  --client-ca /etc/mqvpn/tls/c-clients.crt

mqvpn-server instance upsert --config /etc/mqvpn/server.yaml \
  --name customer-c --listen 0.0.0.0:4436

mqvpn-server instance delete --config /etc/mqvpn/server.yaml \
  --name customer-c

mqvpn-server reload --pid <server-pid>
~~~

The CLI validates referenced Peer/TLS files before an atomic config-file
rewrite, preserving permissions and ownership. The daemon watches the YAML
and referenced files, or handles SIGHUP. Invalid updates keep live instances
running. Peer destination updates do not restart unchanged QUIC sessions;
listener/TUN/TLS changes restart only their affected instance. A configuration
with zero instances is currently invalid.

Optional top-level XDP YAML, in the same file as `instances`:

~~~yaml
xdp:
  interfaces: [enp1s0, enp2s0]
  object: /usr/lib/mqvpn/xdp_mqvpn.o
  mode: driver
~~~

The XDP dispatcher maps **outer UDP destination ports** (4433, 4434, ...)
to the shared NIC XDP program, without looking into encrypted VPN IP data.
XDP is opt-in; see [docs/xdp-multi-instance.md](docs/xdp-multi-instance.md).

## Client / WAN binding

The independent client CLI remains unchanged: `--source-ip` and
`--source-interface` select WAN1, while `--wan2-ip` and
`--wan2-interface` select WAN2. Both client and server attach to
**pre-existing, UP, IP-addressed** TUNs.

~~~bash
mqvpn-client \
  --url https://vpn.local:4433/.well-known/masque/ethernet/ \
  --source-ip 192.0.2.10 --source-interface enp1s0 \
  --wan2-ip 198.51.100.10 --wan2-interface enp2s0 \
  --tun mq0 --max-frame 1160 \
  --ca /etc/mqvpn/ca.crt \
  --cert /etc/mqvpn/client.crt --key /etc/mqvpn/client.key
~~~

Multicast, inner traffic routing and firewall policy are controlled
externally by Linux. Underlay WAN source routing is likewise outside mqvpn.

## Limitations

- One TUN per instance; overlapping instances require OS VRF/netns isolation.
- No automatic LAN-to-LAN L2 bridging, IGMP/MLD, mDNS reflector or NHRP.
- No AF_XDP userspace UMEM/rings/Zero-Copy, no experimental performance claims.
- QUIC DATAGRAM frames cannot exceed path MTU; default max Ethernet frame is
  1160 bytes. Examples use an IPv4 TUN MTU of 1100; IPv6 requires >=1280
  and sufficient underlay PMTU.
- Full hardware I226/N200 P2MP multi-instance interoperability has not been
  validated on a production host.

Protocols: https://datatracker.ietf.org/doc/draft-ietf-masque-connect-ethernet/
and https://www.rfc-editor.org/rfc/rfc10069.html
