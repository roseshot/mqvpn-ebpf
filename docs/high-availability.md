# High availability: native Server pools and HAProxy

mqvpn supports two ways to select a **Server backend** for a Client's authenticated VPN session. These controls sit *above* MPQUIC's multi-WAN paths: a backend is a separate Server daemon; a WAN is one underlay path within a single QUIC connection.

| Mode | Client-managed (`ha.controller: client`) | External (`ha.controller: haproxy`) |
| --- | --- | --- |
| `active_standby` | Prefer the first Server IP; rotate to another backend if the connection fails, with reconnect backoff | HAProxy forwards TLS/TCP sessions to the primary backend, marks it down after failed health checks, and uses a `backup` Server |
| `active_active` | Distribute **different Clients** deterministically across active Server IPs using a hash of the Client certificate DER; rotate a Client's backend after session loss | HAProxy balances new TLS/TCP connections across all healthy Server nodes |

**What this is not:** One Client does **not** simultaneously connect to two independent Servers and write two TUNs. It owns *one* authenticated QUIC/TCP VPN session at any time, completing TUN, pushed-route, TCX and DNS cleanup before switching. There is no seamless packet-level takeover, server state replication, automatic BGP/OSPF election, or shared tunnel lease allocation. If you require active/active *traffic spreading for one Client*, use **MPQUIC multiple WANs on one Server**, or design and test an explicit independent-TUN/ECMP deployment instead of duplicating a session unsafely.

## Preparation: what the Server cluster must agree on

Before enabling HA, each backend must:

1. Present a certificate trusted by the same Client CA and containing the **same** DNS/IP SAN configured under the Client's `server` field. Distinct physical IPs do not change TLS identity. A Client **must not** bypass certificate verification for availability.
2. Authorize the same Client certificate fingerprints and equivalent destination prefixes in each tenant's `peers` file. Auth failures abort native HA selection rather than trying a weaker backend.
3. Expose a compatible MASQUE CONNECT endpoint, tunnel subnet, MTU and negotiated features. With static addressing, the same Client TUN IP should be valid on every backend.
4. Ensure Linux routing, firewall, forwarding and—if used—FRRouting route advertisements deliver *both directions* of traffic to the currently active Server. The cluster needs external routing or VIP ownership; mqvpn does not synchronize multiple Server hubs.
5. Handle any stateful services, dynamically leased tunnel addresses, or pinned pushed routes explicitly. Leases are local to a Server instance and are not distributed across nodes.

## Option A: autonomous Client management

For active/standby, configure the Client:

```yaml
server: vpn.example.com:8443  # TLS identity, shared across the Servers
address: 10.77.0.2/24
ca: /etc/mqvpn/ca.crt
cert: /etc/mqvpn/site1.crt
key: /etc/mqvpn/site1.key
transport: quic
reconnect: true
ha:
  mode: active_standby
  controller: client
  backends:
    - 192.0.2.10    # preferred primary UDP/8443
    - 198.51.100.10 # backup UDP/8443
```

The initial QUIC session dials the first Server. On connection failure, the Client finishes the failed session's cleanup, waits according to its existing 1–30 s exponential reconnect backoff, then tries the next IP. After all backends fail, it cycles again. Any primary disconnect (including a clean end-of-session) chooses the next standby Server. A cleanly closed or long-lived **standby** session resets active/standby preference to the first Server *for its next reconnect*. It does **not** preempt a healthy backup session to probe primary.

For active/active across a **fleet of Clients**, change only the mode:

```yaml
ha:
  mode: active_active
  controller: client
  backends: [192.0.2.10, 198.51.100.10]
```

Each Client picks its first backend using a stable SHA-256 hash of its certificate DER. Different Clients can therefore use both Servers concurrently. Subsequent disconnects advance to the next backend. A hash distributes Clients approximately, not uniformly by traffic volume; two Clients may legitimately choose the same node. A backend outage is detected when the Client's session or handshake fails; the Client does not actively probe idle backends while healthy.

A native backend list accepts **2–16 distinct unicast IP literals**. `connect_ip` cannot also be specified: the per-backend addresses already pin the physical destination. Each selection keeps the same authenticated `server` DNS identity, CONNECT path and mTLS credentials. To pair additional **WAN** paths with different IPs advertised by the currently selected Server, set `use_server_wans: true` and remove fixed `wans[].server_ip` values; those otherwise belong to one Server and are rejected in native HA mode.

Equivalent Client flags:

```bash
./bin/mqvpn-client --server vpn.example.com:8443 \
  --ha-mode active_standby --ha-controller client \
  --ha-backend 192.0.2.10 --ha-backend 198.51.100.10 \
  --tun-address 10.77.0.2/24 \
  --ca /etc/mqvpn/ca.crt --cert /etc/mqvpn/site1.crt --key /etc/mqvpn/site1.key
```

Repeated `--ha-backend` flags **replace** a YAML `ha.backends` list. `--ha-mode` and `--ha-controller` override the respective YAML values. `reconnect: false` is rejected when HA is enabled because switching would not be possible.

## Option B: HAProxy-managed TLS/TCP entry

Use a **transparent layer-four TCP proxy** so the original Server-side TLS 1.3 mutual authentication, ALPN `http/1.1`, HTTP Upgrade and peer fingerprint checks stay end-to-end. This is a TCP fallback transport, **not** a transparent QUIC/UDP load balancer.

On the Client, use the virtual address (VIP) of HAProxy:

```yaml
server: vpn.example.com
connect_ip: 192.0.2.100  # HAProxy TCP VIP, not a backend IP
address: 10.77.0.2/24
ca: /etc/mqvpn/ca.crt
cert: /etc/mqvpn/site1.crt
key: /etc/mqvpn/site1.key
transport: tcp
tcp_port: 443
reconnect: true
ha:
  mode: active_standby # or active_active
  controller: haproxy
```

Each backend Server must have its own `tcp_fallback.enabled: true` and be reachable from HAProxy. The Client maintains a single connection to the stable VIP and reconnects after failure; **HAProxy decides** which Server receives each new TCP connection.

Two ready-to-adapt HAProxy Community examples are included:
- [Active/standby TCP](../configs/haproxy-ha-active-standby.cfg): `server backup ... backup` with health checks.
- [Active/active TCP](../configs/haproxy-ha-active-active.cfg): `balance roundrobin` among non-backup Servers.

Validate them with `haproxy -c -f <file>`. The TCP health check detects listening sockets, **not** whether CONNECT, tenant TLS/SNI, P2MP routing and tunnel forwarding are fully healthy. For production, add an authenticated end-to-end synthetic probe in external monitoring rather than treating a successful TCP connect as service readiness. Use a sufficiently long TCP timeout for a persistent VPN session.

**QUIC/UDP caveat:** HAProxy Community's standard `mode tcp` is not a generic UDP relay, and an HTTP/3 `quic4@` frontend **terminates** QUIC/TLS instead of simply forwarding mqvpn's authenticated tunnel. HAProxy Enterprise has a separate UDP load-balancing module, but compatibility with a particular MASQUE/MPQUIC connection-ID and path-migration design needs independent verification. For native encrypted QUIC HA, prefer the **Client-managed backend IP list** or a purpose-built L4 UDP/QUIC-aware balancer supporting stable connection affinity and appropriate health checks. Do not deploy an example `quic4@` termination frontend as a drop-in replacement for mTLS passthrough.

See [HAProxy UDP product behavior](https://www.haproxy.com/solutions/udp-load-balancing), [TCP health checks](https://www.haproxy.com/documentation/haproxy-configuration-tutorials/reliability/health-checks/) and [HAProxy HTTP/3 termination](https://www.haproxy.com/documentation/haproxy-configuration-tutorials/protocol-support/http/).

## Failure, failback and security guarantees

| Event | Expected behavior |
| --- | --- |
| Initial QUIC dial times out | Client-managed HA tries TCP fallback on **the same selected backend** if `transport: auto` allows it; on session failure it moves to another backend at the next retry |
| Established Server stops responding | Existing QUIC idle/keepalive handling eventually closes the session; the reconnect supervisor tears down TUN/routing and selects another backend |
| A Client certificate is not trusted, Server certificate name is wrong, or CONNECT is explicitly denied | Fail closed on identifiable TLS verification or CONNECT authorization errors; **no backend rotation** |
| A Server comes back | It becomes eligible when the Client next reconnects; active/standby prefers the first backend after a stable session has ended |
| HAProxy TCP primary fails | HAProxy health checks remove it from **new** TCP sessions; existing disconnected Client connections must reconnect |
| All backends fail | Client retries with capped exponential backoff and reports the current backend in structured logs |
| Session cleanup fails | The supervisor stops; it never starts a second session with potentially stale routes/TUN/DNS state |

Failover may change assigned tunnel addresses, disrupt existing UDP/TCP application flows, and lose in-flight datagrams. Server-side sessions and leases are **not** replicated. Both controllers need explicit network/RIB/FIB management for an active cluster.

## Verification

```bash
go test ./internal/app -run 'TestHA|TestPlanClientHA|TestClientHA'
make test
make release
sudo bash tests/integration/client-ha-netns.sh
haproxy -c -f configs/haproxy-ha-active-standby.cfg
haproxy -c -f configs/haproxy-ha-active-active.cfg
```

The namespace test runs **two separate Server daemons** sharing an authenticated tenant identity, terminates the primary and requires the Client to reestablish a working QUIC/TUN path to the standby. It needs Linux network namespaces, TUN, OpenSSL and root. It is a functional smoke test, not a measured recovery-time SLA.

Inspect Client logs for `HA backend selected`, `backend_index` and the selected destination. In production, monitor the authenticated CONNECT success rate, backend outages, reconnect count, route ownership and actual tunnel data—not just TCP port reachability.
