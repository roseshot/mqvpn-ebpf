# TUN MTU and TCP MSS sizing

[Documentation index](README.md) · [Transport, routing, and traffic policy](README.md#transport-routing-and-traffic-policy)

> **Document scope:** **Packet-size planning and verification guide** for Linux TUN and TCP MSS. WAN MTU, encoded MASQUE frames and QUIC DATAGRAM limits are distinct budgets.

The mqvpn data plane carries a complete IP packet from the L3 TUN in a
synthetic Ethernet frame for MASQUE CONNECT-ETHERNET.

## On this page

- [WAN-based automatic TUN sizing](#wan-based-automatic-tun-sizing)
- [Two different targets](#two-different-targets)
- [QUIC DATAGRAM and underlay PMTU](#quic-datagram-and-underlay-pmtu)
- [Example: 1360 TUN MTU](#example-1360-tun-mtu)
- [Validate on Linux](#validate-on-linux)

## WAN-based automatic TUN sizing

When `mtu` and `max_frame` are omitted, both daemons use the actual
**local WAN interface MTU** to calculate an initial conservative
TUN packet budget; maximum auto TUN MTU is **1400**.

~~~text
TUN MTU = min(1400, minimum of each WAN's link MTU minus reserve)
reserve = 100 B if outer WAN is IPv4
reserve = 120 B if outer WAN is IPv6
max_frame = TUN MTU + 14 B (synthetic Ethernet header)
~~~

This includes budget for outer IP, UDP, QUIC, HTTP/3, MASQUE and an
additional margin for variable-length headers. It is a conservative
startup heuristic, **not a measured end-to-end Internet PMTU**, QUIC
DATAGRAM maximum, or negotiated peer MTU.

| Local WAN interface | WAN MTU | Auto TUN MTU | Auto max_frame |
| --- | ---: | ---: | ---: |
| IPv4 Ethernet | 1500 | **1400** | **1414** |
| IPv4 PPPoE | 1492 | 1392 | 1406 |
| IPv4 4G/5G interface | 1420 | 1320 | 1334 |
| IPv6 Ethernet | 1500 | 1380 | 1394 |

All selected MPQUIC WANs contribute; the smallest budget wins.
On the Client the actual source IP and its owning Linux interface
determine which WAN MTUs are used. Forced TCP fallback uses only the
primary WAN. On the Server a specific bind IP identifies the local
interface; otherwise the main-table default route is consulted.
For servers with two or more WAN uplinks, explicitly provide:

~~~yaml
wans:
  - interface: enp1s0
    ip: 192.0.2.1
  - interface: enp2s0
    ip: 198.51.100.1
instances:
  - name: a
    server_name: a.example.com
    tun: mq0
    address: 10.77.0.1/24
    peers: /etc/mqvpn/peers-a.yaml
    cert: /etc/mqvpn/tls/a.crt
    key: /etc/mqvpn/tls/a.key
    client_ca: /etc/mqvpn/tls/a-ca.crt
~~~

If no WAN is identifiable, automatic sizing fails with an actionable
error instead of guessing or writing routes. TUN/IP/UP and the kernel
connected-prefix route remain unchanged. Omitted YAML MTU values stay
omitted so a Server reload can recalculate when WAN MTU changes; a
changed effective MTU restarts only the affected instance, not the
shared listener. Clients calculate at connection start and do not
resize an established QUIC connection.

An explicitly set \`mtu: 1360\` / \`--tun-mtu 1360\` bypasses WAN
link-based sizing; the related \`max_frame\` / \`--max-frame\` defaults to
\`MTU + 14\`. Explicit settings are **not proof of path support**.

## Two different targets

| Desired result | Inner IPv4 TUN MTU | Inner IPv6 TUN MTU | Minimum `max_frame` |
| --- | ---: | ---: | ---: |
| TUN MTU 1360 | 1360 | 1360 | 1374 |
| Inner TCP MSS 1360 | 1400 | 1420 | 1414 (IPv4) / 1434 (IPv6) |

TCP MSS is conventionally derived from the inner IP MTU:

- IPv4 without options: MSS = MTU - 20-byte IPv4 - 20-byte TCP;
- IPv6 without extension headers: MSS = MTU - 40-byte IPv6 - 20-byte TCP.

At inner MTU **1360** this means IPv4 MSS **1320**, IPv6 MSS **1300**.
An IPv4 inner MTU of **1400** permits MSS 1360. An IPv6 inner MTU of
**1420** permits MSS 1360. TCP options, per-route PMTU, advertised MSS
and packet policy can decrease effective MSS.

The daemon does **not** rewrite TCP MSS, `iptables`, `nftables`, `ip route`
or `ip rule`. For local TCP connections, the kernel chooses MSS based
on the outgoing route MTU. For forwarded TCP across LANs, ordinary
ICMP Fragmentation Needed / IPv6 Packet Too Big signaling and PMTU
discovery must work end to end; there is no hidden MSS clamp.

## QUIC DATAGRAM and underlay PMTU

The maximum MASQUE application DATAGRAM payload includes:

    inner IP (TUN MTU)
    + 14 bytes synthetic Ethernet
    + 1 byte Context ID 0
    + HTTP/3 stream identifier (variable length)
    + QUIC DATAGRAM frame header (variable length)
    + QUIC packet headers and cryptographic tag
    + UDP and outer IPv4/IPv6 headers

The Server and Client `max_frame` setting covers **Ethernet + inner IP**
only. It does NOT include Context ID, HTTP/3, QUIC or outer headers.

Therefore for MTU 1360 the minimum `max_frame` is **1374**. This is
necessary, but not sufficient: QUIC must negotiate enough DATAGRAM
capacity and **all active WAN paths** must support the resulting
outer packet without fragmentation. In a typical Ethernet-underlay path
with IP MTU 1500 this often fits, but PPPoE, VLAN tunnels, MPLS, WireGuard
and other extra encapsulation can reduce available PMTU.

QUIC RFC 9221 DATAGRAMs **cannot be automatically fragmented by QUIC**.
When both peers negotiate authenticated `Mqvpn-Framing: frag-v1`, the
VPN performs **application-layer fragmentation**: a large inner IP packet
(after optional stateless Zstd encoding) is split into several independent
CONNECT-ETHERNET DATAGRAM payloads of at most **1024 bytes**, each below
a conservative wire-size budget. The receiver reassembles them using an
authenticated per-session packet ID, with bounded memory and expiry.
Ordinary SIP/RTP small packets are neither compressed nor fragmented.

This is **not** QUIC retransmission or measured PMTU discovery. Loss of
any fragment loses the original inner packet, so sustained packet loss or
paths that cannot carry even the 1024-byte DATAGRAM payload can still
disrupt traffic. The initial version caps each frame at 16 fragments.
Sessions without `frag-v1` negotiation use unfragmented base framing
and must continue to obey actual DATAGRAM limits. Auto TUN MTU still
uses the local-WAN conservative heuristic and defaults to at most 1400;
selecting TUN MTU 1500 remains an **explicit** configuration choice.

Example after upgrading both ends: `mtu: 1500` and
`max_frame: 1514` on the Server, and
`--tun-mtu 1500 --max-frame 1514` on the Client.
See [fragmentation](fragmentation.md) for capacity, security and SIP notes.

## Example: 1360 TUN MTU

Server instance YAML:

~~~yaml
instances:
  - name: customer-a
    server_name: a.vpn.example.com
    tun: mq0
    address: 10.77.0.1/24
    mtu: 1360
    max_frame: 1374
    peers: /etc/mqvpn/peers-a.yaml
    cert: /etc/mqvpn/tls/a.crt
    key: /etc/mqvpn/tls/a.key
    client_ca: /etc/mqvpn/tls/a-ca.crt
~~~

Client:

~~~bash
mqvpn-client --server a.vpn.example.com \
  --tun mq0 --tun-address 10.77.0.2/24 \
  --tun-mtu 1360 --max-frame 1374 \
  --wan 192.0.2.2@enp1s0 \
  --ca /etc/mqvpn/ca.crt --cert /etc/mqvpn/client.crt \
  --key /etc/mqvpn/client.key
~~~

For MSS 1360 **IPv4**, change to `mtu: 1400`, `max_frame: 1414` on
the Server and matching `--tun-mtu 1400 --max-frame 1414` on Client.
For **IPv6**, `mtu: 1420`, `max_frame: 1434`. These higher profiles
need even more path PMTU and are not guaranteed safe on all WANs.

## Validate on Linux

The kernel's connected-prefix route is allowed to appear naturally:

~~~bash
ip -d addr show dev mq0
ip route show dev mq0
# If mq0 is in a VRF, inspect the corresponding VRF route table:
ip route show vrf vrf-a
~~~

For IPv4 underlay PMTU testing (from a WAN interface):

~~~bash
tracepath -n <SERVER_PUBLIC_IP>
# Or test a path using ICMP DF packets where permitted:
ping -M do -s 1472 <SERVER_PUBLIC_IP>  # 1500-byte IPv4 IP packet
~~~

An ICMP/ping check does not prove QUIC DATAGRAM size, path symmetry or
MPQUIC support; validate actual sustained bidirectional tunneled traffic
at the desired MTU, including after a WAN path switch.

References:
- https://www.rfc-editor.org/rfc/rfc9221
- https://www.rfc-editor.org/rfc/rfc9000

## Related documentation

- [DATAGRAM fragmentation](fragmentation.md)
- [TC eBPF and MSS clamp](tc-ebpf.md)
- [Operational troubleshooting](operations.md)
