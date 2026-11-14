# Strict Sticky SIP / RTP / RTCP WAN affinity

Enable strict realtime WAN affinity with `sticky_voip: true` on the
**Client**, or `--sticky-voip`. The authenticated Server supports this
opt-in automatically; older Clients and all non-opted-in sessions retain
their original single-session behavior.

```yaml
server: vpn.example.com:8443
connect_ip: 192.0.2.1
transport: quic
sticky_voip: true
path_scheduler: round_robin   # normal traffic still distributes across WANs
wans:
  - {source_ip: 192.0.2.2, interface: wan0, server_ip: 192.0.2.1}
  - {source_ip: 198.51.100.2, interface: wan1, server_ip: 198.51.100.1}
  - {source_ip: 203.0.113.2, interface: wan2, server_ip: 203.0.113.1}
  - {source_ip: 192.0.2.6, interface: wan3, server_ip: 192.0.2.5}
```

### Transport separation

| Classified traffic | QUIC transport | Path selection |
|---|---|---|
| SIP signalling (TCP/UDP ports 5060/5061 within TUN) | Separate authenticated HTTP/3 CONNECT-ETHERNET realtime companion | One physical WAN; never round robin |
| DSCP EF (46), typically RTP and RTCP | Same dedicated realtime companion | One physical WAN; never round robin |
| Other IPv4/IPv6 TUN packets, including TCP and bulk UDP | Original authenticated MPQUIC session | Existing N-WAN scheduler (`round_robin` by default) |

The dedicated realtime connection uses only one UDP socket and deliberately
**does not enable Multipath QUIC**. The encrypted traffic can thus be
pinned to a single Linux source IP/interface and Server WAN address,
independently of the ordinary connection's multipath scheduler.
Both connections authenticate with the existing mTLS identity and the
same Server SNI, use independently negotiated CONNECT-ETHERNET
capabilities, and feed the same authorized Linux L3 TUN. The Server
accepts exactly one companion per explicitly sticky-enabled primary
session. A companion cannot replace the base P2MP session, allocate a
second tunnel lease, or bypass peer certificate authorization.

### Stable selection and failure

The first entry in `wans` is the preferred realtime WAN. It stays pinned
for its QUIC session lifetime, **even if another WAN's RTT briefly
improves**. When the realtime connection terminates due to a path
outage, the Client selects the **next configured WAN** and establishes
a new single-WAN mTLS companion. It does not move back merely because
the previous path recovers. If all WANs fail, retries cycle through the
configured list with bounded delay.

When a companion is unavailable, realtime packets are **dropped** rather
than secretly sent over the bulk MPQUIC connection. This preserves
strict affinity at the cost of a brief media/signalling outage during
failover. The realtime QUIC idle timeout is 8 s, so failover is not
instantaneous. The original bulk VPN connection remains independently
multipath-capable, including during realtime failover. WAN routes and
interface policy routing remain the network administrator's
responsibility.

The Server routes priority return traffic through the companion and
normal return traffic through the primary session. The two incoming
datagram streams have separate fragment reassemblers, preventing
session-local fragment ID collisions; TUN writes are serialized.

### QoS classification limitations

The `qos.Priority` classifier conservatively prioritizes DSCP EF 46
and SIP ports 5060/5061. RTP and RTCP often use dynamic UDP ports:
**those media flows must carry DSCP EF (46)** for strict affinity.
SIP signalling in the test uses port 5060. It does not parse SIP/SDP
dialog IDs to assign individual calls to independent WANs: currently
all classified realtime flows share **one sticky WAN per Client peer**.
Different calls cannot yet independently choose different realtime
WANs. The traffic class is sticky, not per-call WAN hashing.

This option requires QUIC; the single-WAN TCP fallback cannot offer
the same strict path affinity and is therefore not selected in sticky
mode. The normal `low_latency` policy remains independent and does
not itself guarantee application-specific stickiness.

### Privileged four-WAN CI test

```bash
sudo bash tests/integration/overlay-netns.sh wan4-sticky
```

The new test uses four independent Client↔Server veth pairs, distinct
Server IPs and independent `tc netem` profiles:

| WAN | One-way delay | Jitter | Packet loss | Rate |
|---|---|---|---|---|
| wan0 | 10 ms | 2 ms | 0% | 50 Mbit/s |
| wan1 | 35 ms | 8 ms | 0.5% | 20 Mbit/s |
| wan2 | 70 ms | 20 ms | 1% | 10 Mbit/s |
| wan3 | 120 ms | 40 ms | 3% | 5 Mbit/s |

It validates four active bulk MPQUIC paths, then verifies actual
single-WAN realtime QUIC from its **unique UDP source port** on both
the Client and Server captures, during two full-duplex SIP/G.711 RTP
calls. It applies 100% loss on WAN0 in both directions, waits for the
dedicated realtime connection to reattach on WAN1, and repeats two
calls. Across all eight PCAPs the test rejects any occurrence of
the realtime UDP source port on an unselected WAN. It simultaneously
requires ordinary MPQUIC traffic on WAN1/2/3 and validates SIP,
DSCP EF, RTP integrity, loss/reorder/jitter and RTCP exchange.

This is a transport-level **class affinity** regression test. It does
not certify real-world MOS, zero interruption during failover, or
per-call sticky path allocation. Security/encryption is independently
verified by the `crypto-wan4` and `crypto-tcp` tests.
