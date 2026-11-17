# Five-site FRRouting integration

[Documentation index](README.md) · [Testing](README.md#testing)

> **Document scope:** **Unified five-site integration fixture.** Four authenticated Clients share one Server topology with concurrent BGP/OSPF, randomized MPQUIC paths and cross-Client application probes.

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

Each node owns a `198.18.20x.1/32` Linux loopback address. The unified
scenario also assigns a separate `198.18.21x.1/32` loopback per node for
OSPF, preventing an unrelated BGP route from hiding OSPF convergence failures. Four Client
loopback destinations and tunnel host addresses are provisioned in the
Server's authenticated P2MP peer destination map so the overlay knows which
QUIC Client owns each IP. That P2MP delivery map is **not** a Linux FIB
route and does not replace BGP/OSPF route learning.

## On this page

- [Unified five-site scenario](#unified-five-site-scenario)
- [One integration scenario entrypoint](#one-integration-scenario-entrypoint)
- [FRR per-namespace configuration and assertion hygiene](#frr-per-namespace-configuration-and-assertion-hygiene)

## Unified five-site scenario

Run from a Linux environment with `CAP_NET_ADMIN`, `tun`, built
`bin/mqvpn-server` / `bin/mqvpn-client`, and the official signed FRR
stable package containing `zebra`, `bgpd`, `ospfd`, and `vtysh`:

```bash
make release
sudo env WAN_SEED=20261115 bash tests/integration/five-site-frr.sh scenario
```

The `scenario` mode brings up the five VPN namespaces and four authenticated
Clients **once**, then runs BGP and OSPF concurrently on separate loopback
prefixes, followed by Client-to-Client TCP, UDP and SIP/RTP/RTCP probes.

For **BGP**, the Server uses AS65000, the Clients use distinct AS65101
through AS65104. Each advertises its own loopback via BGP. Server and
Clients converge over authenticated TUN sessions, and zebra installs the
four remote /32 routes at each site.

For **OSPF**, every site runs area 0 over its own mq0 interface using
point-to-multipoint semantics and a distinct router ID. A routing loopback
prefix is announced on each site. The Linux namespace on the Server enables
IP forwarding (including TUN ingress → TUN egress) and disables ICMP
redirects and reverse-path filtering for the test.

The unified scenario first checks that each Client's sampled QUIC WAN count
is fully established. It then checks that all **20 directed remote loopback routes** in
the Linux FIB were installed by FRR (`proto bgp` or `proto ospf`).
Additionally, it requires all four Server-to-Client and four Client-to-Server
BGP adjacencies to be `Established` **and** all eight OSPF adjacencies to be
`Full` in the same fixture. It then performs **20 source-bound cross-site
ICMP tests per routing protocol**, followed by real TCP integrity (256 KiB),
full-MTU UDP and full-duplex G.711/SIP/RTP/RTCP cross-Client checks across
the encrypted overlay. The test reports failures and daemon logs instead of silently
passing when neighbors or routes fail to converge. Certificates, namespaces
and FRR runtime sockets are test-only and cleaned up.

BGP/OSPF route advertisements and forwarding are handled by FRR and the
Linux IP stack. mqvpn remains a secure L3 transport: it does not parse
routing-protocol messages or inject static Linux routes to the 20 remote
test destinations.

## One integration scenario entrypoint

The complete privileged Linux CI integration suite has one entrypoint:

```bash
sudo env WAN_SEED=20261115 bash tests/integration/scenario.sh
```

It checks eBPF/TCX and kernel TUN behavior, wire confidentiality, four-WAN
failover/impairment, VXLAN, TCP/UDP/voice, and finally the combined five-site
BGP+OSPF fixture. Specialized two-site phases intentionally recreate their
own isolated namespaces to validate incompatible network conditions;
**BGP, OSPF, multi-WAN and cross-Client application probes share the same
five-site topology and certificate/session lifecycle**. This is one
fail-fast, seeded integration scenario rather than a list of independent
GitHub Actions test cases.

To troubleshoot a particular routing protocol without the complete scenario,
the focused `five-site-frr.sh bgp` and `five-site-frr.sh ospf` modes remain
available. CI runs only the combined `scenario` mode for this topology.

GitHub Actions provides `WAN_SEED` from `github.run_id`; the printed seed
supports local replay. Both routing protocols share one reproducible
randomized WAN selection in combined mode, but use disjoint route prefixes.
Each must independently converge, install 20 FIB destinations, bring up
eight adjacencies, and forward 20 directed packets across authenticated TUN.

## FRR per-namespace configuration and assertion hygiene

The test starts `zebra` and `bgpd` or `ospfd` under separate `-N`
namespaces using explicit generated per-daemon `-f` configurations.
**Only after the daemons have loaded those files and routing has converged**,
the script provisions each namespace's `/etc/frr/<namespace>/vtysh.conf`
and `frr.conf` as minimal FRR-valid comment files. Creating `frr.conf`
before daemon startup could enable integrated-configuration mode and cause
FRR to ignore the individual `-f` files. Test-only directories are
removed by the cleanup trap.

The script fails on any unexpected `vtysh` stderr instead of hiding it.
Its JSON output is parsed by `tests/integration/check_frr_neighbors.py`:
missing or Idle BGP peers, non-Full OSPF neighbors, and invalid JSON all
cause a failure. The helper has separate negative-case unit tests that CI
runs before the privileged five-site scenarios.

## Related documentation

- [Two-site overlay probes](overlay-tests.md)
- [Unified test entrypoint](README.md)
- [Route troubleshooting](operations.md)
