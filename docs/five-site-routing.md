# Five-site FRRouting integration

The privileged CI test uses **five isolated Linux network namespaces**:
one P2MP Server at `10.77.0.1/24` and four independently authenticated
Clients (`10.77.0.2` through `10.77.0.5`). Each Client has an independent
mTLS identity and randomly selects **1–8 MPQUIC WAN paths** from the Server's
eight distinct underlay interfaces. The Server uses one shared UDP/8443
listener and eight underlay bridges; Client bridge ports are isolated to
prevent direct Client-to-Client underlay communication. Every Client
selects its own randomized subset and handshake path, so WAN0 is not a
required or universally preferred uplink.

The four Client WAN counts are sampled *without replacement* from 1 through
8; WAN interface indices are then sampled independently. A recorded
`WAN_SEED` and the routing mode make the topology fully reproducible.
Before starting FRRouting, the test verifies `WAN_COUNT - 1` additional
QUIC paths have actually validated for every Client. Distinct randomized
seeds exercise different subsets on different CI runs.

Each node owns a `198.18.20x.1/32` Linux loopback address. Four Client
loopback destinations and tunnel host addresses are provisioned in the
Server's authenticated P2MP peer destination map so the overlay knows which
QUIC Client owns each IP. That P2MP delivery map is **not** a Linux FIB
route and does not replace BGP/OSPF route learning.

## Routing scenarios

Run from a Linux environment with `CAP_NET_ADMIN`, `tun`, built
`bin/mqvpn-server` / `bin/mqvpn-client`, and the official signed FRR
stable package containing `zebra`, `bgpd`, `ospfd`, and `vtysh`:

```bash
make release
sudo env WAN_SEED=20261115 bash tests/integration/five-site-frr.sh bgp
sudo env WAN_SEED=20261115 bash tests/integration/five-site-frr.sh ospf
```

For **BGP**, the Server uses AS65000, the Clients use distinct AS65101
through AS65104. Each advertises its own loopback via BGP. Server and
Clients converge over authenticated TUN sessions, and zebra installs the
four remote /32 routes at each site.

For **OSPF**, every site runs area 0 over its own mq0 interface using
point-to-multipoint semantics and a distinct router ID. A routing loopback
prefix is announced on each site. The Linux namespace on the Server enables
IP forwarding (including TUN ingress → TUN egress) and disables ICMP
redirects and reverse-path filtering for the test.

Each scenario first checks that each Client's sampled QUIC WAN count
is fully established. It then checks that all **20 directed remote loopback routes** in
the Linux FIB were installed by FRR (`proto bgp` or `proto ospf`), and
then performs **20 source-bound cross-site ICMP tests** across the encrypted
overlay. The test reports failures and daemon logs instead of silently
passing when neighbors or routes fail to converge. Certificates, namespaces
and FRR runtime sockets are test-only and cleaned up.

BGP/OSPF route advertisements and forwarding are handled by FRR and the
Linux IP stack. mqvpn remains a secure L3 transport: it does not parse
routing-protocol messages or inject static Linux routes to the 20 remote
test destinations.

## CI task consolidation

The existing `overlay-integration` GitHub Actions job now installs the
official signed FRRouting package, builds the binaries and initializes
TUN exactly once. It runs the existing independent encryption, four-WAN,
network load, VXLAN and voice scenarios followed by **five-site BGP and
OSPF**. The older two-site BGP CI step and duplicated standalone
five-site setup/build job were removed because the five-site tests
supersede them. The older two-site script remains usable manually.

GitHub Actions supplies `WAN_SEED` from `github.run_id`; the same run
can be repeated locally by using the printed seed. BGP and OSPF use
different deterministic subsets from that seed. Each run checks all
20 BGP and 20 OSPF learned routes and forwarding directions.
