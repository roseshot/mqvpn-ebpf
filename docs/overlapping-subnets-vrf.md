# Overlapping VPN subnets using Linux VRF (route-based)

Each `mqvpn-server` instance owns one unique **TUN device** (mq0, mq1),
one UDP listener, a Peer directory and an independent in-memory P2MP
destination table. It is valid to use the **same inner IP addresses and
prefixes in different instances**. The daemon does not program Linux
routing or interface state.

## Why VRF is necessary

A single Linux main routing table cannot distinguish two independent
destinations both addressed `192.168.20.77` solely by their IP value.
Separate the two instances into their own **VRF routing tables**,
configured by the host administrator. This is destination-based routing
inside isolated routing domains, not application/IPsec policy-based VPN.

Example, on the server (administrative bootstrap, **not daemon code**):

~~~bash
sudo ip link add vrf-a type vrf table 1001
sudo ip link add vrf-b type vrf table 1002
sudo ip link set dev vrf-a up
sudo ip link set dev vrf-b up

sudo ip tuntap add dev mq0 mode tun
sudo ip tuntap add dev mq1 mode tun
sudo ip link set dev mq0 master vrf-a
sudo ip link set dev mq1 master vrf-b

sudo ip address add 10.77.0.1/24 dev mq0
sudo ip address add 10.77.0.1/24 dev mq1
sudo ip link set dev mq0 mtu 1100 up
sudo ip link set dev mq1 mtu 1100 up

# Two identical prefixes, but in different Linux FIB tables.
sudo ip route replace table 1001 192.168.20.0/24 dev mq0
sudo ip route replace table 1002 192.168.20.0/24 dev mq1

ip route show vrf vrf-a
ip route show vrf vrf-b
~~~

Server instance YAML:

~~~yaml
instances:
  - name: customer-a
    listen: "0.0.0.0:4433"
    tun: mq0
    peers: /etc/mqvpn/peers-a.yaml
    cert: /etc/mqvpn/tls/a.crt
    key: /etc/mqvpn/tls/a.key
    client_ca: /etc/mqvpn/tls/client-ca.crt
  - name: customer-b
    listen: "0.0.0.0:4434"
    tun: mq1
    peers: /etc/mqvpn/peers-b.yaml
    cert: /etc/mqvpn/tls/b.crt
    key: /etc/mqvpn/tls/b.key
    client_ca: /etc/mqvpn/tls/client-ca.crt
~~~

Each separate peer YAML may contain the **same destination routes**:

~~~yaml
peers:
  - id: site-1
    certificate_sha256: "<64-hex-DER-cert-fingerprint>"
    routes: [10.77.0.2/32, 192.168.20.0/24]
~~~

The same destination in customer-a maps to a session in customer-a; in
customer-b it maps to a different session in customer-b. No BPF key,
global prefix map or daemon policy is shared across the VPN LANs.

## Operational caveats

- Attach each corresponding LAN uplink or routed consumer to the correct
  VRF (or network namespace) too, if you want Linux to forward it via that
  domain. A VRF containing only the VPN TUN does not magically classify
  traffic arriving from LANs in the default VRF.
- QUIC **outer WAN listener sockets** remain in their usual host routing
  domain; the daemon only attaches to the existing TUN file descriptor.
- Avoid accidentally importing routes from one VRF into the other.
  Route leaking, NAT, firewall and multicast routing are host policy, not
  daemon responsibilities.
- Multipath WAN source/interface configuration remains separate from the
  inner VPN routing domains.
- Peer destination prefixes **within one instance** must still be
  unambiguous across its clients. Identical prefixes in different
  instances are valid.
- Configure persistent VRFs and TUNs using your OS networking service.
  These imperative commands illustrate manual setup only.

This is a route-based multi-instance VPN. It does not require the daemon
to install `ip rule` source/destination policy routing or inspect/filter
the inner flow.
