# Five-site FRRouting integration

The privileged CI test uses **five isolated Linux network namespaces**:
one P2MP Server at `10.77.0.1/24` and four independently authenticated
Clients (`10.77.0.2` through `10.77.0.5`). Each Client has a separate
mTLS identity and its own physically isolated /30 WAN veth pair to the
same Server UDP/8443 listener. Clients have no direct physical links.

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
sudo bash tests/integration/five-site-frr.sh bgp
sudo bash tests/integration/five-site-frr.sh ospf
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

Each scenario checks that all **20 directed remote loopback routes** in
the Linux FIB were installed by FRR (`proto bgp` or `proto ospf`), and
then performs **20 source-bound cross-site ICMP tests** across the encrypted
overlay. The test reports failures and daemon logs instead of silently
passing when neighbors or routes fail to converge. Certificates, namespaces
and FRR runtime sockets are test-only and cleaned up.

BGP/OSPF route advertisements and forwarding are handled by FRR and the
Linux IP stack. mqvpn remains a secure L3 transport: it does not parse
routing-protocol messages or inject static Linux routes to the 20 remote
test destinations.
