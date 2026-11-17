# MPQUIC path scheduling and four-WAN VoIP latency regression

[Documentation index](README.md) · [Transport, routing, and traffic policy](README.md#transport-routing-and-traffic-policy)

> **Document scope:** **Transport policy guide** for connection-wide MPQUIC scheduling. `low_latency` is a path selection heuristic, not per-RTP-flow steering or an SLA.

`mqvpn-ebpf` supports two **connection-wide** MPQUIC path policies:

| Policy | Config value | Effect |
|---|---|---|
| Existing default | `round_robin` | Spreads QUIC packets across usable WAN paths. Suitable for load distribution but can heavily reorder RTP when WAN RTTs differ. |
| Optional | `low_latency` | Uses the upstream `mp-quic-go` LowLatencyScheduler: prefers the path with the lowest measured smoothed RTT that can send. If congested or potentially failed, it can choose a remaining usable path. |

Apply **independently on both Server and Client** to control QUIC traffic
in each sending direction. They need not choose the same policy, but for
bidirectional VoIP tests we configure both to `low_latency`.

Server `server.yaml` (global shared QUIC listener):

```yaml
listen: "0.0.0.0:8443"
path_scheduler: low_latency
wans:
  - {interface: wan0, ip: 192.0.2.1}
  - {interface: wan1, ip: 198.51.100.1}
  - {interface: wan2, ip: 203.0.113.1}
  - {interface: wan3, ip: 192.0.2.5}
instances:
  # Existing VPN instance(s) with cert, key, peers, TUN, etc.
```

Client `client.yaml`:

```yaml
server: vpn.ci.example:8443
connect_ip: 192.0.2.1
transport: quic
path_scheduler: low_latency
use_server_wans: true
wans:
  - {source_ip: 192.0.2.2, interface: wan0, server_ip: 192.0.2.1}
  - {source_ip: 198.51.100.2, interface: wan1, server_ip: 198.51.100.1}
  - {source_ip: 203.0.113.2, interface: wan2, server_ip: 203.0.113.1}
  - {source_ip: 192.0.2.6, interface: wan3, server_ip: 192.0.2.5}
```

Or select `mqvpn-client --path-scheduler low_latency` with the existing
QUIC/TUN/identity/WAN flags. Omitting the field selects the
`round_robin` policy. Unknown policy values are rejected.
The Server policy is configured at listener creation: changes require a
daemon restart to preserve already-established QUIC sessions.

## Linux integration test

```bash
sudo bash tests/integration/overlay-netns.sh wan4         # original RR baseline
sudo bash tests/integration/overlay-netns.sh wan4-latency # new low-RTT mode
```

Both modes use the same 4 independent Linux veth WAN pairs and 4 Server
destination IPs. Each egress is shaped with `tc netem`:

| WAN | One-way delay and jitter | Loss | Rate |
|---|---|---|---|
| wan0 | 10±2 ms | 0% | 50 Mbit/s |
| wan1 | 35±8 ms | 0.5% | 20 Mbit/s |
| wan2 | 70±20 ms | 1% | 10 Mbit/s |
| wan3 | 120±40 ms | 3% | 5 Mbit/s |

The new test requires all four MPQUIC paths to validate, then runs
two synthetic full-duplex SIP/G.711 RTP/RTCP calls, recording both
directions' RTP delivered/lost, reordered, duplicates, RFC 3550-style
jitter and interarrival gaps (`WAN_QOE_JSON`).
The `latency` smoke-test profile caps reordered arrivals to **35 of
250 RTP packets per receiver**. This is a regression guard relative
to the previous Round Robin observation of 114–118 reordered arrivals;
it is not a production voice SLA or an assertion that every run will
have exactly the same packet loss.

In `low_latency` mode, lower-quality WANs are valid **standby
alternatives**; the script does not require equal traffic on all four,
unlike the original Round Robin integration test. The primary fast WAN
must transmit real packets. All historical CI tests, including
four-WAN round-robin, encryption, VXLAN 1450, TCP/UDP, VoIP, poor WAN and
FRR BGP remain active.

## Scope and limitations

The scheduler runs at **QUIC packet level**: it does *not* inspect
the encapsulated TUN packet, classify DSCP EF/SIP, or have a guaranteed
RTP-specific override. All traffic sharing the connection (including
TCP over TUN and bulk UDP) uses the same policy. The independent
high-priority queue for RTP/SIP in `internal/qos` remains intact.

The low-RTT policy can concentrate traffic on one WAN, so it is not
a bandwidth aggregation strategy. It chooses an alternate path only
when an available path is considered unavailable/congestion-limited.
Its selection is constrained by the underlying QUIC path state and
RTT measurements, not a guarantee of seamless service on every type
of link outage. Measure real-world RTP QoE before deploying it by
default. TLS, MPQUIC authentication, QUIC wire format and TUN frame
encapsulation are unchanged.

## Related documentation

- [Client configuration](client-config.md)
- [Server multi-WAN](server-multiwan.md)
- [Sticky voice](voip-sticky.md)
