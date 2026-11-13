# TUN MTU and TCP MSS sizing

The mqvpn data plane carries a complete IP packet from the L3 TUN in a
synthetic Ethernet frame for MASQUE CONNECT-ETHERNET.

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

QUIC RFC 9221 DATAGRAMs **cannot be fragmented into multiple frames**.
Path MTU discovery (DPLPMTUD) must have established a sufficiently
large packet size on the used MPQUIC path. The daemon doesn't currently
negotiate an inner TUN MTU from measured path PMTU or implement its own
DATAGRAM fragmentation / inner PMTU adaptation. An overlarge send can
be rejected/dropped, so don't force 1360 as a universal default.

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
mqvpn-client --url https://a.vpn.example.com/.well-known/masque/ethernet/ \
  --tun mq0 --tun-address 10.77.0.2/24 \
  --tun-mtu 1360 --max-frame 1374 \
  --source-interface enp1s0 \
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
