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

### FRRouting eBGP peer on TUN

The BGP scenario uses **FRRouting's official signed stable Debian/Ubuntu
APT repository**, `https://deb.frrouting.org/frr`, channel
`frr-stable`, on an Ubuntu 24.04 GitHub runner.
It installs the **`frr` and `frr-pythontools` .deb packages**.
It does not install an Ubuntu archive FRR version, compile FRR from
source, or use an FRR container image.

Each namespace starts its own official `/usr/lib/frr/zebra` and
`/usr/lib/frr/bgpd`, using separate FRR `-N` pathspaces to isolate
sockets and PID files. ASN 65001 neighbors ASN 65002 over
10.77.0.1/30 ↔ 10.77.0.2/30 on the TUN. Both announce a /32 loopback:

- Server: 198.18.101.1/32
- Client: 198.18.202.1/32

The test waits for **both** remote prefixes to enter the Linux kernel
FIB with a next hop via `mq0`. This requires BGP session establishment,
route advertisement, zebra integration, and a working tunnel.
It then uses ICMP sourced from each loopback to verify forwarding
in **both** directions over the learned BGP routes. Only the local
loopback addresses are configured statically; no shortcut remote routes
are installed before BGP convergence.

## Run

GitHub Actions: the `overlay-integration` job in
`.github/workflows/go.yml` runs **VXLAN, TCP, UDP, VoIP and FRR BGP**
scenarios on `ubuntu-24.04`.

Locally, on an isolated Linux test host with root/CAP_NET_ADMIN and
`/dev/net/tun` (and `iproute2`, `iputils-ping`, OpenSSL, Python 3):

```bash
make release
sudo bash tests/integration/overlay-netns.sh vxlan
sudo bash tests/integration/overlay-netns.sh tcp
sudo bash tests/integration/overlay-netns.sh udp
sudo bash tests/integration/overlay-netns.sh voip
sudo bash tests/integration/overlay-netns.sh bgp
```

FRR is required only for the BGP test. To install it from the official
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
