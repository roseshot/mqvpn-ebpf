# Daemon-managed Linux TUN lifecycle

Both `mqvpn-server` instances and `mqvpn-client` now have enough
information to create and initialize their own L3 TUN device.

### Server

~~~yaml
instances:
  - name: customer-a
    server_name: customer-a.vpn.example.com
    tun: mq0
    address: 10.77.0.1/24
    mtu: 1100
    peers: /etc/mqvpn/peers-a.yaml
    cert: /etc/mqvpn/tls/a.crt
    key: /etc/mqvpn/tls/a.key
    client_ca: /etc/mqvpn/tls/ca.crt
~~~

### Client

~~~bash
mqvpn-client --url https://customer-a.vpn.example.com/.well-known/masque/ethernet/ \
  --tun mq0 --tun-address 10.77.0.2/24 --tun-mtu 1100 \
  --source-interface enp1s0 \
  --ca /etc/mqvpn/ca.crt --cert /etc/mqvpn/client.crt \
  --key /etc/mqvpn/client.key
~~~

### Exactly what the daemon does

1. Validate TUN interface name and explicit host IP/CIDR/MTU.
2. Open `/dev/net/tun` with `TUNSETIFF(IFF_TUN|IFF_NO_PI)`, creating
   an ephemeral TUN if it is missing, or attaching if it already exists.
3. Set the configured MTU via Linux rtnetlink.
4. Add or replace the **specified IP address only** using RTM_NEWADDR
   with `IFA_F_NOPREFIXROUTE` to prevent the kernel from installing an
   automatic connected-prefix route.
5. Set the interface UP using rtnetlink.
6. Re-query and verify the IP address, MTU and UP bit before packet I/O.

The daemon does **not** create user-defined routes, VRFs, namespace
bindings, `ip rule`, firewall, forwarding entries or multicast routes
or manage routes in any other way. Kernel-maintained local-address
routes are a necessary side effect of owning an IP address; those are
not explicitly written by mqvpn.

The daemon also does not delete other IP addresses on a pre-existing
interface. To reconfigure cleanly, set new `address` and restart or
reload the affected instance; if the persistent TUN had other IPs,
the system administrator should remove them. The daemon leaves externally
configured network policy intact.

`CAP_NET_ADMIN` (and `/dev/net/tun` access) is needed to configure
the device; binding UDP/TCP 443 may require `CAP_NET_BIND_SERVICE`.

### Multi-instance overlapping subnets

When mq0 and mq1 both use 10.77.0.1/24, the administrator must keep them
in separate Linux routing domains (VRF/netns). If VRF binding must occur
*before* interface IP configuration, precreate persistent TUNs
(`ip tuntap add dev mq0 mode tun`, etc.) and assign each TUN to its
VRF; the daemon still configures the IP, MTU and UP state on attach.
Without VRFs, the daemon can create the TUN directly.
See [VRF setup](overlapping-subnets-vrf.md).

### IPv6 caveat

IPv6 needs MTU >= 1280, plus `max_frame >= mtu+14`, and enough
underlay path MTU to carry the encapsulated QUIC DATAGRAM. No
automatic fragmentation, routes or PMTU adaptation are installed.
