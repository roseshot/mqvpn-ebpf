# Privileged VXLAN and FRRouting eBGP over TUN integration tests

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
each endpoint, with UDP destination port 4789 and the peer's TUN IP as
the remote VTEP. It checks:

1. Authenticated TUN control/data-plane readiness and 1500-byte MTU.
2. Kernel VXLAN L2 neighbor resolution (ARP) and ICMP both ways.
3. Large (1372-byte ICMP payload) IPv4 DF traffic through VXLAN,
   exercising VPN `frag-v1` when the encoded TUN packet exceeds
   the conservative DATAGRAM budget.

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
`.github/workflows/go.yml` runs both scenarios on `ubuntu-24.04`.

Locally, on an isolated Linux test host with root/CAP_NET_ADMIN and
`/dev/net/tun` (and `iproute2`, `iputils-ping`, OpenSSL):

```bash
make release
sudo bash tests/integration/overlay-netns.sh vxlan
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
