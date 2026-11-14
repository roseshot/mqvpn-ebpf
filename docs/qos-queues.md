# QoS-aware forwarding and bounded queues

QoS classification is shared by both the Client TUN sender and Server P2MP
return traffic. It is scheduling, **not an ACL**: no traffic class is forbidden
from the VPN.

| Class | Markings / recognition | Queue size per sender | Service share when all lanes backlogged | Transport |
|---|---|---:|---:|---|
| Realtime | DSCP EF (46), SIP TCP/UDP 5060/5061 | 64 | 4/7 | Separate pinned single-WAN QUIC companion **if** `sticky_voip: true`; otherwise normal MPQUIC |
| Assured | DSCP AF11–AF43, CS5, CS6, CS7 | 96 | 2/7 | Bulk MPQUIC with configured connection-wide scheduler |
| Best effort | Everything else | 192 | 1/7 | Bulk MPQUIC with configured connection-wide scheduler |

The sender scans lanes according to a repeated **4:2:1 weighted sequence**.
Unused slots go to ready traffic immediately. Each queue has fixed capacity;
a full queue drops only packets in that class, without blocking other queues.
RTP/EF and SIP remain uncompressed even if zstd is negotiated. Other classes
retain the negotiated compression/framing settings.

## Choosing paths

For strict WAN affinity, configure `sticky_voip: true` with the intended WAN
order. EF/SIP use that pinned WAN with authenticated heartbeat failover and
never silently fall back to the bulk MPQUIC connection.

For bulk traffic (both assured and best effort), select
`path_scheduler: low_latency` on the Client and Server if fast-path preference
is desired. The upstream mp-quic-go packet scheduler is **connection-wide**:
it cannot see inner DSCP at path-selection time. Therefore it is *not*
possible to promise a different MPQUIC WAN for assured versus best-effort
datagrams on the same connection. The additional assured queue improves
service order and latency under local congestion, not per-packet WAN affinity.
The default path scheduler remains `round_robin` for backward compatibility.

OSPF/BGP traffic can use DSCP CS6 to select the assured queue without taking
the strict realtime transport; kernel or router QoS marking remains the
network administrator's responsibility. Inner IP and IPv6 extension headers
are validated before classifying SIP or DSCP.

## Verification

`go test ./internal/qos ./internal/p2mp` checks DSCP tiers, weighted queue
fairness, work conservation, and both directions of the transport separation.
The privileged four-WAN integration suite continues to exercise pinned EF/SIP
and connection-wide MPQUIC under shaped WANs.
