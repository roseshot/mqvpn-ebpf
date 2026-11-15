# Privileged VXLAN, TCP/UDP, SIP/RTP/RTCP and FRRouting over TUN tests

These opt-in GitHub Actions tests use actual `mqvpn-server` and
`mqvpn-client` binaries, an authenticated QUIC/HTTP/3 CONNECT-ETHERNET
tunnel, real Linux TUN interfaces, and independent network namespaces.
They are **not** unit tests that exchange mock TUN packets.

## Test topology

```
ns: mqvs*                                      ns: mqvc*
192.0.2.1/30 — wan0 === Linux veth === wan0 — 192.0.2.2/30
VPN Server  (UDP/8443 + mTLS) =======> Client (QUIC)
10.77.0.1/30 — mq0 ==== frag-v1 ===== mq0 — 10.77.0.2/30
       |                                      |
       +-- vx100 (VNI 100)   vx100 ---------+
       |   172.30.100.1      172.30.100.2   |
       +-- FRR 65001  =====  FRR 65002 -----+
           198.18.101.1/32  198.18.202.1/32
```

Both TUN MTUs are explicitly 1500, and both max_frame budgets are 1514.
The UDP WAN namespace link has no direct access to the overlay addresses.
Server and Client independently verify the same test-only CA. The peer
certificate fingerprint is in the Server peer routing policy.
No privileged test modifies the CI host's ordinary routes or interfaces;
namespaces, FRR runtime pathspaces and temporary certificates/configs are
removed by a cleanup trap.

### VXLAN over TUN

The VXLAN scenario creates a **real kernel VXLAN VNI 100** device on
each endpoint, explicitly sets the **VXLAN MTU to 1450 bytes**, with UDP
destination port 4789 and the peer's TUN IP as the remote VTEP. It checks:

1. Authenticated TUN control/data-plane readiness and 1500-byte MTU.
2. Kernel VXLAN L2 neighbor resolution (ARP) and ICMP both ways.
3. Full VXLAN MTU (1422-byte ICMP data + 8 ICMP + 20 IPv4 = **1450-byte**
   inner IP packet), in **both directions** with DF set. VXLAN IPv4
   encapsulation contributes 50 bytes, producing an exactly **1500-byte**
   outer TUN IPv4 packet, which exercises the VPN `frag-v1` extension.

### TCP and UDP data transport over TUN

The `tcp` and `udp` scenarios run real Python 3 standard-library sockets
inside each network namespace. Each scenario repeats with **Client and
Server swapped as listeners**, so it covers both directions independently.
No TCP connection or UDP datagram is sent directly over the WAN veth.

- **TCP:** transfers a deterministic 256 KiB payload and echoes it back,
  verifying byte-for-byte integrity on both legs. Real TCP segmentation,
  QUIC encapsulation and reassembly are exercised.
- **UDP:** checks exact datagram contents, sizes and sequence order for
  payloads of 64, 512, 1200 and **1472 bytes**. The last produces an
  inner IPv4/UDP datagram of **1500 bytes**, testing `frag-v1` with
  incompressible data. The listener echoes every datagram.

### Synthetic VoIP: SIP, RTP and RTCP over TUN

The `voip` scenario uses two independent test endpoints (no external PBX):

- Runs a minimal **SIP REGISTER → INVITE → BYE** exchange over UDP 5060.
  The INVITE includes a G.711 PCMU/8000 SDP offer.
- Runs **full-duplex RTP**: 100 packets per direction, 20 ms apart, each
  with 160 bytes of synthetic PCMU audio payload. Checks payload bytes,
  timestamp cadence, SSRC, sequence completeness, duplication and packet
  order. A missing frame fails the test.
- Marks RTP/RTCP with **DSCP EF (46)** and verifies the marking arrives
  at the receiver using Linux `IP_RECVTOS`.
- Computes a receive-side RFC 3550-style jitter estimate and interarrival
  gap; the local CI smoke test accepts up to 80 ms jitter and 200 ms
  maximum interarrival gap. **These are generous CI stability limits,
  not an end-user VoIP quality SLA or a Mean Opinion Score.**
- Exchanges and validates **RTCP Receiver Reports** (UDP port 40001).
  The test is run again with the SIP server role reversed.

This tests encapsulation and priority marking, **not actual telephony
hardware, PBX authentication, NAT traversal or audio intelligibility**.

### VoIP during concurrent TCP + UDP load (mixed)

The `mixed` scenario runs the same authenticated QUIC/TUN endpoints but
shapes **both WAN veth transmit interfaces to 20 Mbit/s** using Linux
`tc tbf` (64 KiB burst, up to 120 ms queue latency). Against each TUN
endpoint, it runs two concurrent iperf3 streams:

- **TCP:** 2 parallel bulk streams per direction, trying to use spare WAN capacity.
- **UDP:** paced at **4 Mbit/s per direction**, with 1200-byte application datagrams.

The test overlaps those four load processes with **two full-duplex
G.711/SIP/RTP/RTCP sessions**, reversing the SIP initiator between calls.
Every call must still pass RTP sequence, integrity, DSCP EF and RTCP
checks; the script also proves that the bulk generators remained active
for the complete voice test and that both TCP and UDP receivers saw
nontrivial traffic.

The QoS queue tests include `TestNextTierSustainedWeightedFairness`,
which checks the **4 realtime : 2 assured : 1 best-effort** service
ratio when all queues remain backlogged. These are *local queue*
weights; they do not select a different WAN for each DSCP class.
The integration test does *not* attempt to read that internal queue
or declare a MOS improvement. It checks application coexistence with
a shaped WAN, not QoS policy on external routers.

A shared CI runner cannot supply dependable real-world jitter, loss,
path failover, or audio intelligibility guarantees. It is deliberately
a reproducible smoke test; production acceptance needs external WAN
impairment and long-running measurements.

### Impaired Internet WAN using Linux tc netem

Two scenarios explicitly add delay, jitter, loss and a rate cap to the
**physical WAN-facing `wan0` egress interfaces in both namespaces**.
Netem is installed only **after** the genuine mTLS/QUIC TUN is established,
and never on the inner `mq0` TUN or VXLAN interfaces:

| Scenario | One-way average delay | Delay jitter (normal) | Independent random packet loss, per egress | Rate cap |
|---|---:|---:|---:|---:|
| `wan-regional` | 40 ms | 10 ms | 1% | 20 Mbit/s |
| `wan-poor` | 120 ms | 40 ms | 3% | 10 Mbit/s |

These values are **per WAN egress**, yielding approximate baseline RTTs
of 80 ms and 240 ms before scheduling/processing overhead. Traffic
passes through the encrypted QUIC/UDP tunnel, not a fake socket or a
simulated TUN. A bounded 120-packet netem queue avoids multi-second
buffering unrelated to the requested loss/jitter profile.

Under `wan-regional`, the test additionally launches continuous
bidirectional `iperf3` TCP (two streams per direction) and UDP
(3 Mbit/s per direction) for the duration of **two** synthetic
full-duplex SIP/RTP/RTCP calls. It checks that the generators stay
active, measures actual received bytes and reports TCP/UDP throughput
from `iperf3` JSON. `wan-poor` keeps the network impairment but
isolates SIP/RTP from competing bulk traffic.

Both scenarios run the test-only `wan_probe.py` endpoint on each side:
SIP UDP INVITE/ACK/BYE has bounded retries; each side sends 250
G.711 PCMU RTP packets at 20 ms intervals and checks DSCP EF (46).
Unlike the zero-loss smoke test, the receiver uses a fixed-time window,
so missing RTP packets are **counted**, not treated as an indefinite wait.
It prints parseable `WAN_QOE_JSON` containing delivered and missing
RTP packets, loss percentage, duplicates, reordered packets, RFC
3550-style jitter in milliseconds (8 kHz RTP clock), maximum
interarrival gap, SIP retransmits and RTCP receiver-report fields.
The RTCP report itself uses redundant sends to tolerate impairment.

QoE checks have loose smoke-test ceilings (regional 25% loss,
150 ms jitter, 1200 ms interarrival gap; poor 40% loss, 260 ms
jitter, 2000 ms gap), and merely detect catastrophic tunnel
breakage. **They are not acceptable production VoIP SLAs.**
Random loss is probabilistic: a sample may observe no losses, and
the displayed loss rate is for **inner RTP** after QUIC/IP encapsulation
and any fragmentation, not the netem outer packet-loss percentage.
The shape does not implement WAN per-path routing or prove audio
intelligibility. Results vary between GitHub-hosted CI machines.

Example local executions (privileged Linux, `tc`, `iperf3`, Python 3):

```bash
sudo bash tests/integration/overlay-netns.sh wan-regional
sudo bash tests/integration/overlay-netns.sh wan-poor
```

### Four independent WANs (MPQUIC)

The `wan4` test uses **four separate Linux veth WANs** between the
Server and Client namespaces, with distinct underlay source addresses:

| WAN | Client source | Server veth IP | One-way netem delay | Jitter | Random loss | Rate |
|---|---|---|---:|---:|---:|---:|
| wan0 | 192.0.2.2 | 192.0.2.1 | 10 ms | 2 ms | 0% | 50 Mbit/s |
| wan1 | 198.51.100.2 | 198.51.100.1 | 35 ms | 8 ms | 0.5% | 20 Mbit/s |
| wan2 | 203.0.113.2 | 203.0.113.1 | 70 ms | 20 ms | 1% | 10 Mbit/s |
| wan3 | 192.0.2.6 | 192.0.2.5 | 120 ms | 40 ms | 3% | 5 Mbit/s |

Every Client path dials the same authenticated Server address,
192.0.2.1:8443; additional interface-specific source IP policy tables
prevent Linux from silently routing secondary connections through
wan0. The Client uses four repeated `--wan IP@INTERFACE` options.

The test **requires all three additional MPQUIC AddPath/Probe steps
to succeed** before attaching `tc netem` to both egress endpoints of
each underlay. It then makes two full-duplex synthetic SIP/G.711 RTP
calls, checks receive-side loss, jitter, DSCP and RTCP reports, and
checks nonzero traffic counters for *all eight* WAN interface egress
qdiscs. This verifies that a single connection truly uses four paths,
rather than simply parsing four configuration entries.

~~~bash
sudo bash tests/integration/overlay-netns.sh wan4
~~~

See [Client WAN configuration](client-config.md) for the ordered WAN configuration and
the current **64 active-path ceiling inside the upstream MPQUIC
library**, which is separate from mqvpn's uncapped WAN-list parser.

## Run

GitHub Actions: the `overlay-integration` job in
[the Go workflow](../.github/workflows/go.yml) runs **VXLAN, TCP, UDP,
VoIP, four-WAN encryption and scheduling, shaped-WAN loads, and five-site
BGP/OSPF** on `ubuntu-24.04`. The signed FRR packages and Go binaries
are installed/built once per combined network job.

Locally, on an isolated Linux test host with root/CAP_NET_ADMIN and
`/dev/net/tun` (and `iproute2`, `iputils-ping`, OpenSSL, Python 3, iperf3):

```bash
make release
sudo bash tests/integration/overlay-netns.sh vxlan
sudo bash tests/integration/overlay-netns.sh tcp
sudo bash tests/integration/overlay-netns.sh udp
sudo bash tests/integration/overlay-netns.sh voip
sudo bash tests/integration/overlay-netns.sh mixed
sudo bash tests/integration/overlay-netns.sh wan-regional
sudo bash tests/integration/overlay-netns.sh wan-poor
sudo bash tests/integration/overlay-netns.sh wan4
sudo env WAN_SEED=20261115 bash tests/integration/five-site-frr.sh bgp
sudo env WAN_SEED=20261115 bash tests/integration/five-site-frr.sh ospf
```

FRR is required for BGP and OSPF tests. To install it from the official
stable channel, follow https://deb.frrouting.org/ and use
`FRRVER=frr-stable` with the signed package repository and
`apt install frr frr-pythontools`.

Network privileges and kernel VXLAN/TUN support are required. Failures
include process logs and route dumps before cleanup. On failure, do
not treat a TCP connection, ping of the underlay, or a static route as
sufficient proof: the tests intentionally require data delivery through
the actual authenticated VPN tunnel.

Notes: the FRR `frr-stable` channel intentionally floats to the latest
stable package. This protects testing against upstream packaging changes
but means CI results can change when the stable release updates.
