# mqvpn-ebpf

Experimental Go MASQUE CONNECT-ETHERNET (draft -18) VPN over HTTP/3
DATAGRAM + encrypted Multipath QUIC. Dedicated client/server CLIs.
Target: Linux Intel N200 + I226-V/LM, 1–2.5 Gbps is a benchmark target,
not an achieved measurement.

**Transport is Linux UDP socket + TAP. AF_XDP is NOT connected to Go.**
The existing bpf/xdp_mqvpn.c is an experimental standalone XDP filter.

## GRE-like IP-addressed tunnel

CONNECT-ETHERNET transports Ethernet frames, so the kernel tunnel interface
is TAP, not GRE/TUN. It can still have an IP and its own connected route:

    Site A mq0 10.77.0.1/30 <-- CONNECT-ETHERNET/MPQUIC --> Site B mq0 10.77.0.2/30

The CLIs create or attach a **persistent** TAP, configure its tunnel CIDR,
MTU and bring it UP. It remains after exit until explicitly removed using
ip link delete dev mq0. **Do not enslave this TAP to a Linux bridge** in
addressed-tunnel mode; bridges should hold IP addresses on the bridge itself.

## Build

Requirements: Linux amd64, Go 1.26+, iproute2, /dev/net/tun and root or
CAP_NET_ADMIN. SO_BINDTODEVICE may require privileges.

~~~bash
go mod tidy
go build -o mqvpn-client ./cmd/mqvpn-client
go build -o mqvpn-server ./cmd/mqvpn-server
go test ./...
~~~

Legacy combined binary stays supported:

~~~bash
go build -o mqvpn ./cmd/mqvpn
./mqvpn client --help
./mqvpn server --help
~~~

## Development certificates (test only)

~~~bash
bash scripts/gen-dev-certs.sh certs vpn.local
~~~

Replace this seven-day development CA with independently managed production
credentials; never commit keys under certs/.

## Server: Site A

~~~bash
sudo ./mqvpn-server \
  --listen :4433 \
  --tap mq0 --tunnel-ip 10.77.0.1/30 --tunnel-mtu 1100 \
  --max-frame 1160 \
  --cert certs/server.crt --key certs/server.key \
  --client-ca certs/ca.crt
~~~

mTLS is required. The server accepts one active CONNECT-ETHERNET tunnel and
listens on all its UDP-facing interfaces, allowing client-initiated paths.

## Client: Site B

~~~bash
sudo ./mqvpn-client \
  --url https://vpn.local:4433/.well-known/masque/ethernet/ \
  --source-ip 192.0.2.10 --source-interface enp1s0 \
  --wan2-ip 198.51.100.10 --wan2-interface enp2s0 \
  --tap mq0 --tunnel-ip 10.77.0.2/30 --tunnel-mtu 1100 \
  --max-frame 1160 \
  --ca certs/ca.crt --cert certs/client.crt --key certs/client.key
~~~

Change the example WAN addresses to real IPs assigned to your I226 NICs.
The server hostname must resolve and match its certificate.

The primary path supports --source-ip and/or --source-interface.
The second path supports --wan2-ip and/or --wan2-interface.
If only an interface is provided, the program selects its source address
**only when exactly one IP of the remote host's address family is usable**;
with multiple addresses, you must specify an IP. Explicit IP + interface
are checked against netlink-visible interface addresses.

The program uses SO_BINDTODEVICE before binding each UDP socket and creates
separate sockets for WAN1/WAN2. Binding to a device **does not invent routes**:
ensure both underlay interfaces can reach the remote UDP address and configure
policy routes if needed. Verify from your host:

~~~bash
ip route get <gateway-ip> from <wan1-ip> oif enp1s0
ip route get <gateway-ip> from <wan2-ip> oif enp2s0
~~~

Backwards-compatible flags: --wan1, --wan2, --wan1-ip, --wan1-interface.
For single WAN, omit --wan2-ip and --wan2-interface.

## Test the tunnel IP and routing

~~~bash
# Site A
ip -br addr show dev mq0
ip route show dev mq0
ping -I mq0 10.77.0.2

# Site B
ip -br addr show dev mq0
ip route show dev mq0
ping -I mq0 10.77.0.1

# Optional: route a remote IPv4 LAN via the tunnel peer
sudo ip route replace 192.168.20.0/24 via 10.77.0.1 dev mq0
~~~

Ensure the outer QUIC server address never gets routed over mq0, and
configure forwarding/firewall rules separately for LAN-to-LAN routing.

## MTU and limitations

HTTP/3 QUIC DATAGRAM **does not fragment Ethernet frames**. The default
IP tunnel MTU is 1100 and max Ethernet frame 1160, intentionally conservative
for initial IPv4 testing over a typical WAN. An inner IP packet must fit
inside the full Ethernet frame plus CONNECT-ETHERNET, QUIC, UDP and outer IP
overhead. --max-frame is a local limit, not an advertised QUIC PMTU.

When too large, frames are dropped (no custom protocol fragmentation).
The CLI rejects --tunnel-mtu + 14 greater than --max-frame.
IPv6 requires link MTU >= 1280, which may be impossible to carry over
a 1500-byte QUIC DATAGRAM underlay without additional PMTU capacity.
No standard Capsule fallback is implemented.

AF_XDP/zero-copy, automatic reconnect, dynamic policy routing, link QoS,
full field hardening and N200 performance tests are not implemented yet.
The experimental XDP source is NOT attached by the running daemon.

References: https://datatracker.ietf.org/doc/draft-ietf-masque-connect-ethernet/
and https://github.com/qoke/mp-quic-go
