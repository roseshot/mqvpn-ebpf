# Overlapping VPN subnet isolation with Linux VRF

The server uses **one UDP/QUIC port** for multiple P2MP VPN LANs. TLS
`server_name` selects each tenant's mTLS identity, TUN and Peer session
table. The data plane is L3 TUN; mqvpn never configures host routes.

Different VPN instances can simultaneously carry `10.77.0.0/24` and
`192.168.20.0/24`. Linux must distinguish those overlapping destinations
using separate VRFs or network namespaces, not by a single main FIB.
Because the connected-prefix route now appears automatically, attach
each persistent TUN to its intended VRF **before** starting mqvpn.
Otherwise two identical kernel-generated routes may compete in main.

Example system administrator setup:

~~~bash
sudo ip link add vrf-a type vrf table 1001
sudo ip link add vrf-b type vrf table 1002
sudo ip link set vrf-a up
sudo ip link set vrf-b up

sudo ip tuntap add dev mq0 mode tun
sudo ip tuntap add dev mq1 mode tun
sudo ip link set dev mq0 master vrf-a
sudo ip link set dev mq1 master vrf-b

# No ip addr/MTU/up commands here: the daemon will set those.
# TUNs are precreated ONLY to let the administrator bind VRF masters first.
# For deployments without VRFs, the daemon can create the TUNs itself.

sudo ip route replace table 1001 192.168.20.0/24 dev mq0
sudo ip route replace table 1002 192.168.20.0/24 dev mq1
ip route show vrf vrf-a
ip route show vrf vrf-b
~~~

Make the LAN interfaces and their producers part of the correct VRF too;
simply adding two TUNs does not put all incoming LAN packets in the intended
routing table. Route leaking, firewall, multicast and WAN source routing
are administrator-controlled.

Use distinct `server_name` values for the shared HTTPS UDP port:

~~~yaml
# listen is optional; default UDP/443
instances:
  - name: customer-a
    server_name: customer-a.vpn.example.com
    tun: mq0
    address: 10.77.0.1/24
    mtu: 1100
    peers: /etc/mqvpn/peers-a.yaml
    cert: /etc/mqvpn/tls/a.crt
    key: /etc/mqvpn/tls/a.key
    client_ca: /etc/mqvpn/tls/a-ca.crt
  - name: customer-b
    server_name: customer-b.vpn.example.com
    tun: mq1
    address: 10.77.0.1/24
    mtu: 1100
    peers: /etc/mqvpn/peers-b.yaml
    cert: /etc/mqvpn/tls/b.crt
    key: /etc/mqvpn/tls/b.key
    client_ca: /etc/mqvpn/tls/b-ca.crt
~~~

Both DNS names must resolve to the same host and each certificate must have
its corresponding SNI in the DNS Subject Alternative Name.

The daemon creates or attaches TUNs and sets their IP/CIDR, MTU and UP
state. The Linux kernel **automatically installs the normal connected-prefix
route in the TUN's routing domain** as well as local-address routes.
The daemon does not create VRFs, change interface masters, explicitly
install custom `ip route` or `ip rule` entries, or configure forwarding
and multicast routing.
If you need VRF isolation, precreate persistent TUN devices and attach
them to their VRFs before starting the daemon. For ordinary single-domain
installations no manual TUN creation is necessary.
