# Server-side high availability (HA)

The **Client does not select, discover, or manage Server cluster members**. A normal mqvpn Client continues to use one authenticated `server` name (and, optionally, its existing `connect_ip`). All HA election, health evaluation, ingress steering and service-address ownership are controlled by the **Server deployment**.

For versioned configuration/CRL distribution, fenced session ownership,
durable tunnel leases, and cross-node P2MP data forwarding, follow the
[HA cluster state synchronization contract](ha-cluster-state-sync.md).
**Those replication phases are planned, not live features of this release.**

**Cluster size is not fixed at two Servers.** The production design targets
a configurable **N-node Server pool** (N >= 2) with a separately sized,
quorum-backed control plane (typically 3 or 5 consensus voters). A two-node
diagram or HAProxy/Keepalived sample below is an *illustration*, not an
architectural limit. Adding more VPN Servers must preserve identical tenant
policy/CRL generations, one fenced owner per peer/IP, and secure cross-node
forwarding; none of those replication features is implemented yet. The
number of VPN Servers and the number of Raft voters must not be conflated.


This guide distinguishes **availability of a Server service** from **lossless continuity of an existing QUIC session**. Changing the backend of an encrypted session generally requires the existing Client to establish a fresh TLS/QUIC connection after its normal reconnect cycle. The latter is already implemented in the Client; no HA-specific Client code or YAML is added here.

## Choose the topology

| Topology | Public ingress | HA decision | Status/limitations |
| --- | --- | --- | --- |
| QUIC/UDP **active/standby** | One VIP to one active Server | Keepalived/VRRP, driven by the Server's local `/readyz` | Practical first deployment. Existing QUIC sessions don't migrate to a separate process. |
| TLS/TCP **active/standby** | One HAProxy TCP frontend | Health checks + HAProxy `backup` | New TCP sessions use standby after a primary outage. |
| TLS/TCP **active/active** | One HAProxy TCP frontend | Health checks + `roundrobin` per new connection | Independent Client sessions can be distributed across N backend Servers, not just two; cross-node P2MP forwarding still requires shared owner/routing state and is not supplied by HAProxy. |
| QUIC/UDP **active/active** | One QUIC-aware UDP L4 ingress / anycast | Stable **QUIC Connection ID** based backend ownership | **Architecture only, not yet verified for MPQUIC or implemented inside mqvpn.** A simple five-tuple/UDP proxy is not enough for changing WAN endpoints. |

## Non-negotiable cluster invariants

- All Servers serving the same public name present a trusted certificate with the **same DNS SAN** and the same tenant-isolated Client CA trust, CN/Peer mapping and **revocation policy**. The public Client's TLS identity never changes when the VIP moves.
- All Servers agree on tenant SNI, CONNECT path and relevant transport features, although they may have distinct physical interfaces and IPs.
- VIP ownership and return routing must remain symmetric. A QUIC Server sends replies **from the Server public endpoint that the Client expects**; a separate backend must not send replies directly from an unexpected private address. Use a VIP on the active node or a verified symmetric UDP L4 proxy with correct source-NAT handling.
- Server peer destination maps, Linux FIB routes, forwarding, VRF ownership and externally managed BGP/OSPF must converge on the **active peer owner**. Merely load-balancing QUIC or TCP sessions is not enough to enable forwarding between Clients on different backend hubs.
- Server tunnel-IP pools are **local and not replicated**. Start with static addresses or design a durable shared lease allocator before supporting automatic leases across nodes.
- Keepalived VRRP on a shared L2 requires a reliable failure domain and fencing/routing controls to prevent split-brain. For multi-AZ/subnet ingress use an external managed L4 ingress or BGP-based VIP advertisement instead.

## Node-local status is not replicated

Each Server is authoritative for observations of its **own** listener
bindings, TUN devices, WAN link/carrier, packet loss, routing/FIB state,
resource use and whether its *local* policy/CRL files were actually validated.
These transient observations must be collected locally and may differ across
N Servers. They are not consensus records and do not belong in Raft/etcd.

Only shared desired state and facts requiring a unique cluster-wide owner
need quorum: membership, policy/PKI/CRL manifest revisions, tunnel IP leases
and fenced peer ownership. A local health HTTP request must not block on an etcd/Raft read.
The Server samples required local TUN interfaces every two seconds,
independently of configuration reload polling, with no Store/etcd/Raft
request. The minimal [ClusterStore contract](ha-cluster-store.md) remains
unwired to distributed policy/ownership admission; there is no
preemptive background control-state cache.

The existing `/livez` and `/readyz` remain purely local. The
`/readyz` status also reflects each active local TUN's UP flag, configured
host IP and MTU, and required listener presence; a single failed WAN path
does not disable a multi-WAN node that can fail over. The probe loop also
runs when `--reload-interval=0`. Local readiness
**does not** mean that a new shared lease can be allocated or a revoked Client
can be admitted while isolated from quorum: those distributed decisions
require authoritative fencing and up-to-date committed policy. The
atomic local readiness bit is never a lease allocator or proof of immediate
CRL revocation.

## 1. Enable Server readiness checks

On **each Server**, add only this optional Server YAML section:

```yaml
listen: "0.0.0.0:8443"
ha:
  readiness_listen: "127.0.0.1:9090"
instances:
  - name: company
    server_name: vpn.example.com
    tun: mq0
    address: 10.77.0.1/24
    peers: /etc/mqvpn/peers.yaml
    cert: /etc/mqvpn/tls/server.crt
    key: /etc/mqvpn/tls/server.key
    client_ca: /etc/mqvpn/tls/clients-ca.crt
```

The HA listener is **off by default**, binds only to a literal loopback address (`127.0.0.1` or `::1`), and does **not** accept an unauthenticated public listen address. Its port cannot be changed by a live reload; restart the Server to rebind it.

```bash
./bin/mqvpn-server validate --config /etc/mqvpn/server.yaml
curl --fail --silent http://127.0.0.1:9090/livez
curl --fail --silent http://127.0.0.1:9090/readyz
```

| Probe | HTTP result | Meaning |
| --- | --- | --- |
| `GET /livez` | 200 | HTTP health listener is serving; basic liveness only |
| `GET /readyz` | 200 | Required instances are attached, each local TUN is UP with its configured host IP and MTU, and the shared UDP and configured TCP listeners are initialized |
| `GET /readyz` | 503 | Startup incomplete, required TUN absent/DOWN/misconfigured, or Server shutting down |
| Other path/method | 404 / 405 | Not a health endpoint |

**Limits:** TUN/listener state is sampled on the Server manager loop every 2 seconds and HTTP serves the last local atomic result. This check neither synchronizes per-node statistics nor detects WAN loss when alternate paths remain usable. Readiness is a **local operational check**, not a synthetic authenticated CONNECT, QUIC path probe, BGP FIB convergence check or proof that every tenant's traffic forwards. Use an external synthetic test and FIB check if your SLA needs them. This port must remain loopback-only; do not forward it as an unauthenticated public HTTP service.

## 2. Autonomous active/standby with Keepalived/VRRP

Every eligible Server can run mqvpn in standby-capable configuration, with one **movable** public UDP VIP. Keepalived, running on the **Server hosts**, monitors `/readyz` and moves the VIP. The mqvpn Client continues to target `vpn.example.com:8443` resolving to that VIP.

```text
                           vpn.example.com
                           192.0.2.100 (VIP)
                                 |
             Keepalived/VRRP owns exactly one active VIP
                   /                           \
       Server A 192.0.2.11            Server B 192.0.2.12
       mqvpn-server + FRR             mqvpn-server + FRR
       VIP current owner              warm standby
```

The following two-Server configuration is a minimal example; deployments may add more eligible VRRP nodes with distinct priorities and the same VIP, subject to split-brain prevention and fencing:

Use the included examples:
- [Primary Keepalived config](../configs/keepalived-mqvpn-primary.conf) — priority 150, same VRRP ID and VIP.
- [Standby Keepalived config](../configs/keepalived-mqvpn-standby.conf) — priority 100.
- [Local readiness probe](../scripts/mqvpn-ready.sh) — checks loopback `/readyz` using curl.

Install the probe at `/usr/local/libexec/mqvpn-ready`, executable by the Keepalived script user. Adapt physical interface, local and peer addresses, VIP, firewall, and routing for every participating Server node. Install Keepalived from your Linux distribution and validate with `keepalived -t -f /etc/keepalived/keepalived.conf` on each host.

VRRP `track_script` uses a **weight of zero**, putting a Server into FAULT after the configured number of failed health checks instead of merely reducing priority. The examples use `nopreempt` to avoid automatically stealing back the VIP after a recovered Server reappears; operators can arrange an explicit planned failback. Monitor split-brain and route convergence independently.

**MPQUIC warning:** This example has **one public UDP VIP**. It does not make the Server's other advertised `wans` addresses movable. If Clients use multiple Server destination WAN addresses, cluster every required public WAN VIP consistently (for example with a Keepalived VRRP synchronization group), and verify underlay source/return routing per WAN; otherwise a retained path can still point to the failed physical Server. Start with a single Server destination for an HA rollout until multi-WAN failover is validated.

A Server crash causes VRRP takeover, **not QUIC cryptographic session migration**. The existing Client will detect session failure according to its normal liveness behavior and reconnect to the same VIP. Packet loss and disruption to application sessions are possible. Faster, bounded failure detection needs a separately tested transport health/liveness design; never promise zero downtime from VIP movement alone.

## 3. External HAProxy for TLS/TCP fallback

HAProxy Community `mode tcp` can forward a byte stream without terminating the Client's mTLS, Server SNI or CONNECT upgrade. The Client must already use mqvpn's **TLS/TCP** transport; it does not need any HA-specific fields or backend list. A Client configured for QUIC/UDP **cannot** treat these examples as a transparent UDP proxy.

Use [HAProxy active/standby](../configs/haproxy-mqvpn-active-standby-tcp.cfg) or [HAProxy active/active](../configs/haproxy-mqvpn-active-active-tcp.cfg). They show Server-based TCP checks, passive TLS passthrough and conservative long-lived tunnel timeouts.

```bash
haproxy -c -f configs/haproxy-mqvpn-active-standby-tcp.cfg
haproxy -c -f configs/haproxy-mqvpn-active-active-tcp.cfg
```

For both examples, enable Server `tcp_fallback.enabled: true` and update backend IPs/ports. Basic TCP health checks detect only accepting sockets. Use management-network authenticated synthetic CONNECT tests if a stronger readiness signal is required; do not expose the local readiness port over an untrusted network.

**HAProxy Community does not provide generic UDP load balancing through `mode tcp`.** Its `quic4@` frontends terminate QUIC/TLS and thus are not automatically compatible with transparent end-to-end mqvpn mTLS/MASQUE proxying. HAProxy Enterprise offers a distinct UDP module; validate QUIC-CID affinity and MPQUIC behavior separately before treating that as supported.

## 4. Active/active for QUIC: what remains to be built

The Client must continue to see **one** service name/VIP. Multiple backend Servers may handle different Client sessions, but a QUIC load balancer must keep each connection on the Server that has its cryptographic and P2MP session state. MPQUIC can create paths on multiple source and destination IPs, so **hashing by UDP five-tuple can split one connection across different backends**.

A complete solution needs a CID-aware routing/control plane (for example, the IETF QUIC-LB model), authenticated tenant mapping on every node, a cross-node owner/routing data plane for Client-to-Client P2MP packets, and coordinated or externally durable lease management. Neither Envoy's generic four-tuple UDP proxy nor HAProxy Community's ordinary TCP mode alone meets all of those requirements.

For current mqvpn releases, consider **active/standby QUIC with a VIP** the conservative native-wire deployment. Treat cross-node QUIC active/active as a separate milestone requiring MPQUIC, NAT rebinding, peer revocation and FRR five-site integration tests before promising production support.

## Operational validation plan

1. Start N >= 2 Servers (begin with two for a basic VIP smoke test, then validate three and five) with the same authenticated Server TLS identity, consistent peer policies and separate physical host/IP resources.
2. Keep the existing Client configuration **unchanged**; DNS resolves to one VIP or ingress endpoint.
3. Check local `/readyz` on all N Servers, confirm only one VRRP VIP owner or that the selected LB backend is healthy. After Phase B/C, also require committed policy/CRL revision and fenced peer ownership.
4. Verify authenticated CONNECT, Linux tunnel interface and site-to-site traffic.
5. Kill the active Server, observe VIP/ingress transition across more than one standby, and measure tunnel reconnection without changing the Client's destination or trust settings.
6. Validate N-node route-owner convergence, Client certificate revocation on *every* node, no duplicate dynamic IP leases, membership drain/rejoin, and clean failback under repeated failures and minority/majority partitions (once the replication phases exist).

### Reference implementations

- [Keepalived configuration reference](https://keepalived.org/documentation/keepalived-conf/) — VRRP, script health checks, failover conditions.
- [HAProxy UDP capability](https://www.haproxy.com/solutions/udp-load-balancing) and [HAProxy health checks](https://www.haproxy.com/documentation/haproxy-configuration-tutorials/reliability/health-checks/).
- [Envoy UDP proxy](https://www.envoyproxy.io/docs/envoy/latest/configuration/listeners/udp_filters/udp_proxy.html) — four-tuple session affinity and its limitations.
- [strongSwan cluster HA](https://docs.strongswan.org/docs/latest/features/highAvailability.html) — actual cross-node encrypted-session synchronization.
- [RFC 9308 `11](https://www.rfc-editor.org/rfc/rfc9308.html#section-11) — QUIC backend state and Connection ID load-balancing.
