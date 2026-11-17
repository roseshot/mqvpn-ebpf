# Optional application-layer DATAGRAM fragmentation (frag-v1)

[Documentation index](README.md) · [Transport, routing, and traffic policy](README.md#transport-routing-and-traffic-policy)

> **Document scope:** **Negotiated MASQUE extension reference.** `frag-v1` can carry larger inner IP packets without promising per-path PMTU discovery or reliable fragment delivery.

The VPN supports TUN MTU 1500 over paths with smaller QUIC DATAGRAM limits
through an authenticated, optional `Mqvpn-Framing: frag-v1` extension.

## Wire contract

The Client sends `Mqvpn-Framing: frag-v1` in the mTLS-protected
CONNECT-ETHERNET request; a supporting Server echoes it in the success
response. Without the exact echo, both peers use the old unfragmented
CONNECT-ETHERNET framing. This applies to both QUIC/HTTP3 and TCP fallback.

A complete inner IP packet is first processed by the existing stateless
Zstd codec when CPU-eligible and worth compressing. The resulting
CONNECT-ETHERNET context-0 frame is sent unchanged when it fits the
**1024-byte** application payload budget. Larger frames are carried as
multiple new synthetic Ethernet frames with EtherType **0x88B6**:

    1 B MASQUE Context ID 0
    6 B synthetic destination MAC
    6 B synthetic source MAC
    2 B private Ethernet EtherType 0x88B6
    4 B session-local packet identifier (uint32, big endian)
    4 B original complete CONNECT-ETHERNET frame length (uint32)
    4 B fragment offset (uint32)
    N B original frame bytes at the specified offset

The fragment envelope is 27 bytes; each fragment carries at most
997 bytes of the original frame. A 1500-byte IPv4/IPv6 IP packet
requires two fragments if Zstd is off or does not help.
After reassembly, the complete frame passes through the existing
IP/Zstd frame decoder and TUN packet validation.

Each authenticated peer owns its own packet-ID sequence and reassembly
cache. The receive path allows out-of-order and exact duplicate
fragments, rejects partial overlaps or conflicting total sizes,
expires incomplete frames after 2 seconds (when new fragments arrive),
and caps pending records at 32 and retained fragment bytes at 2 MiB.
A frame requiring more than 16 fragments is rejected at send time.
These bounds protect the daemon against malformed or excess input.

## SIP / RTP

SIP UDP/TCP 5060/5061 and DSCP EF (46) RTP/RTCP retain the existing
higher-priority outgoing queue. Small RTP packets are sent as ordinary
uncompressed, unfragmented DATAGRAMs; they never wait for reassembly.
Normal bulk traffic is eligible for Zstd and fragmentation after its
queue turn. One large frame's fragments are sent consecutively, so
a bulk frame can still add minor send latency; profile under load.

## Setting TUN MTU 1500

Server instance:

~~~yaml
instances:
  - name: edge-a
    # ...other certificate, peer and TUN fields...
    mtu: 1500
    max_frame: 1514
~~~

Client:

~~~bash
mqvpn-client ... --tun-mtu 1500 --max-frame 1514
~~~

The WAN-local automatic TUN MTU is still capped at 1400, so the
1500-byte profile must be selected explicitly on each endpoint.

**Limitations:** Application fragmentation only limits payloads of
individual HTTP/3 DATAGRAM frames. It does not force the QUIC library
to send on a path whose PMTU is lower than the wire size of a
1024-byte application payload, and does not implement packet
retransmission. Loss of any fragment causes the full inner packet to
be dropped after timeout; this can degrade large-packet traffic.
There is no live DPLPMTUD integration, negotiated per-path fragment
budget, path pinning, or explicit resend request in this version.
Always test real SIP/RTP jitter and loss during sustained bulk
traffic, and on MPQUIC path switching.

References: RFC 9221, RFC 9297, MASQUE CONNECT-ETHERNET.

## Related documentation

- [MTU and MSS sizing](mtu-mss.md)
- [Adaptive DATAGRAM feedback](adaptive-datagram-voip.md)
- [Zstd compression](zstd-qos.md)
