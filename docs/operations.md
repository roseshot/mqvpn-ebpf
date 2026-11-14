# Operate and troubleshoot mqvpn

This guide is for a Linux operator who has deployed a Server and at least one Client. If you have not yet established a session, start with the [two-host tutorial](getting-started.md).

## Know what each layer is responsible for

A working deployment has several independent layers:

1. **Underlay:** physical WAN reachability to the Server's UDP listener. With MPQUIC, each source/destination WAN pair needs viable Linux routing.
2. **Authentication:** a Server certificate whose DNS/IP SAN matches `server`, trusted Client CA material, and a Client fingerprint listed in the selected Server tenant's `peers` YAML.
3. **Overlay:** authenticated QUIC/HTTP3 CONNECT, a usable `mq0` TUN on both sides, a reachable peer destination map, and matching MTU/frame budgets.
4. **LAN routing:** Linux FIB routes and forwarding policy for any networks *behind* the VPN peers. FRRouting can provide OSPF/BGP; mqvpn does not auto-configure these protocols.

A successful QUIC handshake is not proof that a peer's destination routes or Linux forwarding work.

## Check a running session

On the Server:

```bash
ip link show mq0
ip -4 addr show dev mq0
ip route show dev mq0
ss -lun | grep ':8443'  # if the Server was configured for UDP/8443
```

On the Client:

```bash
ip link show mq0
ip -4 addr show dev mq0
ip route get 10.77.0.1
ping -c 3 10.77.0.1
```

Replace the addresses, interface and port with your own configuration. Prefer `ip route get DESTINATION from SOURCE` when troubleshooting multi-WAN routing or asymmetric return paths.

Use structured logs when investigating:

```bash
./bin/mqvpn-server --log-format json --log-level debug \
  --config /etc/mqvpn/server.yaml
./bin/mqvpn-client --log-format json --log-level debug \
  --config /etc/mqvpn/client.yaml
```

Logs go to **stderr**, and may contain sensitive network topology and peer information. Redact them before sharing. Never enable or publish test TLS key logging in production.

## Troubleshooting by symptom

| What you see | Likely layer | What to check next |
| --- | --- | --- |
| UDP dial or QUIC handshake times out | Underlay | Server's `listen` address, UDP firewall/port, actual `connect_ip` and source routing; see [TCP fallback](tcp-fallback.md) |
| Certificate validation fails | Identity | TLS name versus Server certificate DNS/IP SAN, `ca` file, clock and mTLS peer certificate |
| CONNECT rejected or peer unauthorized | P2MP authorization | Tenant SNI/Host, `client_ca`, exact Client DER certificate SHA-256 in `peers`, peer destination overlap |
| `mq0` missing or cannot be configured | Linux TUN | `/dev/net/tun`, capabilities, TUN name collision, interface MTU; see [TUN lifecycle](tun-lifecycle.md) |
| Client can ping Server TUN but not another site | Linux routing / peer mapping | Remote peer `routes` ownership, Server `ip_forward`, kernel routes and forwarding/firewall rules |
| Additional WAN paths do not validate | MPQUIC underlay | Each `--wan` source IP/interface and Server destination, source-policy routes, interface UP state; see [Multi-WAN](server-multiwan.md) |
| Assured traffic does not choose a specific WAN | QoS design | QoS queue class changes order, **not** per-datagram MPQUIC WAN selection; see [QoS](qos-queues.md) |
| Voice takes multiple WANs | Sticky configuration | Enable `sticky_voip` on the Client, mark media DSCP EF 46, verify companion QUIC and WAN health; see [Sticky voice](voip-sticky.md) |
| TCP fallback never starts | Transport policy | Server must enable it; automatic fallback is limited to an initial QUIC handshake timeout and uses only one WAN |
| DNS changes do not appear | Authenticated DNS push | Server `push_dns`; Client `accept_dns`/`dns_routes`; functional `systemd-resolved` or `resolvconf` |
| Large inner packets fail under loss | PMTU / fragmentation | WAN MTU, effective TUN MTU, `max_frame`, optional `frag-v1`; see [MTU/MSS](mtu-mss.md) |
| FRR neighbors stay Idle or routes are absent | Dynamic routing | FRR neighbor state, BGP/OSPF interface and source addresses, kernel route installation, P2MP peer authorization; see [Five-site routing](five-site-routing.md) |

## Verify multi-WAN paths

A Client's WAN list is ordered: the first path completes the authenticated handshake, and the other paths are explicitly probed. For each underlay:

```bash
ip addr show dev wan0
ip route get SERVER_WAN_IP from CLIENT_SOURCE_IP
ip -s link show dev wan0
```

Run the commands for each chosen WAN. The Server must advertise or allow the corresponding destination, and return traffic must follow a viable route to the source IP. MQVPN does not install custom `ip rule` or multipath policy routing rules.

For performance diagnostics, distinguish **configured** WANs, **validated QUIC paths**, and **actual traffic-bearing paths**. A connection-wide low-latency scheduler can legitimately leave a slower validated path unused until conditions change.

## Troubleshoot routing and FRR

A peer entry like `routes: [192.168.20.0/24]` controls which P2MP session the Server selects. It does not create an OS-level route or permit forwarding automatically.

For two remote LANs to reach one another:

1. Confirm the peer certificate and its destination prefixes are authorized.
2. Check the Linux FIB at each Client and on the Server, including return routes.
3. Enable Linux forwarding where transit traffic is expected; review firewall and source-policy routing.
4. If using BGP/OSPF, verify neighbors are **Established/Full** *and* the expected prefixes appear in the Linux FIB.
5. Test directed host-to-host traffic from both sides, not just a local TUN ping.

The [five-site integration test](five-site-routing.md) checks eight bidirectional FRR adjacencies, 20 learned routes and 20 directed pings for **each** of BGP and OSPF. The WAN count per Client is randomly chosen from 1–8 with a logged seed for reproduction. Passing CI is evidence for that lab topology, not a guarantee for arbitrary production routers.

## Reload without losing track of state

Validate Server configuration before a planned reload:

```bash
./bin/mqvpn-server validate --config /etc/mqvpn/server.yaml
./bin/mqvpn-server reload --pid SERVER_PID
```

Read the Server's logs after the reload request. Peer authorization and instance data can be refreshed; changing the shared listener address, physical WAN addresses or TCP fallback listener requires a process restart rather than in-session socket migration. The Client reconnects by default; a new session redoes its authentication and may obtain a different dynamic tunnel IP.

## Run a controlled regression

```bash
make test
make release
# Root + Linux networking tools required:
sudo bash tests/integration/overlay-netns.sh udp
# FRR official packages + root required:
sudo env WAN_SEED=20261115 bash tests/integration/five-site-frr.sh bgp
sudo env WAN_SEED=20261115 bash tests/integration/five-site-frr.sh ospf
```

The five-site script sets up temporary FRR namespaced configuration files and checks for clean `vtysh` output. A missing `vtysh.conf` warning, a non-Established BGP peer, a non-Full OSPF neighbor or an absent FIB route must fail the test—not be silenced.

For test prerequisites and coverage, see [Overlay tests](overlay-tests.md), [Five-site FRR](five-site-routing.md), and [Wire confidentiality](wire-encryption-tests.md).
