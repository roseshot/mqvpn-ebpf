# Multi-instance XDP dispatcher — opt-in control plane

One XDP program per physical WAN NIC. Linux UDP destination port selects
the server VPN instance. NIC RX queue index selects the AF_XDP socket.
Those are **different keys**; do not put instance IDs into XSKMAP.

    Intel I226 / igc NIC
       |
       +--- shared xdp_mqvpn dispatcher
             |
             +--- instance_ports: HASH [u16 host-order UDP dest port] -> u8
             |       4433 -> edge-a, 4434 -> edge-b, 4435 -> edge-c
             |
             +--- xsks_map: XSKMAP [u32 RX queue index] -> XSK socket fd
                     |
                     +--- default EMPTY -> always XDP_PASS
                     +--- future working AF_XDP socket -> XDP_REDIRECT

The Go package internal/xdp uses cilium/ebpf (no CGO) and exposes a
Controller to attach/detach NIC programs and to replace all desired
instance listener UDP ports on configuration hot reload. Adding or deleting
an instance does not require reattaching XDP. Other traffic, including
ARP, fragmented IPv4, IPv6 extension headers and non-instance UDP packets,
passes to the kernel stack without modification.

**The working transport remains the Linux UDP Socket backend.**
There is currently NO AF_XDP userspace socket, UMEM, RX/TX rings, raw UDP
checksum handling, or mp-quic-go PacketConn integration. Therefore XSKMAP
is never populated by the running application. The explicit BPF lookup of
XSKMAP prevents accidental packet redirection to an absent consumer.

### Build and enable

~~~bash
sudo apt-get install clang llvm libbpf-dev linux-libc-dev
make bpf
sudo install -D -m 0644 bpf/xdp_mqvpn.o /usr/lib/mqvpn/xdp_mqvpn.o
CGO_ENABLED=0 go build -mod=mod ./cmd/...
~~~

Example multi-instance server.yaml:

~~~yaml
xdp:
  interfaces: [enp1s0, enp2s0]
  object: /usr/lib/mqvpn/xdp_mqvpn.o
  mode: driver

instances:
  - name: vpn-a
    listen: "0.0.0.0:4433"
    tun: mq0
    peers: /etc/mqvpn/peers-a.yaml
    cert: /etc/mqvpn/tls/a.crt
    key: /etc/mqvpn/tls/a.key
    client_ca: /etc/mqvpn/tls/client-ca.crt
  - name: vpn-b
    listen: "0.0.0.0:4434"
    tun: mq1
    peers: /etc/mqvpn/peers-b.yaml
    cert: /etc/mqvpn/tls/b.crt
    key: /etc/mqvpn/tls/b.key
    client_ca: /etc/mqvpn/tls/client-ca.crt
~~~

XDP sees only the *outer UDP port*, so even when vpn-a and vpn-b
both carry 10.77.0.0/24 or 192.168.20.0/24 internally, their XDP
port bindings remain independent. Linux host routing for overlapping
TUN subnets should be isolated in externally managed VRFs.

Omit xdp completely to preserve existing UDP-only behavior. The dispatcher
is **opt-in**; test on dedicated NICs because another attached XDP program
may conflict with it. Program ELF/mode replacement on an attached NIC needs
a daemon restart, while adding/removing instance UDP ports is hot-reloadable.

### Limitations and future work

- Go AF_XDP socket creation, UMEM and ring allocation.
- Proper AF_XDP RX queue ownership and negotiated zero-copy verification.
- Raw WAN Ethernet/IP/UDP TX, checksums, neighbor and PMTU handling.
- MPQUIC PacketConn integration and per-instance QUIC demultiplexing.
- Real N200/I226 performance measurements.

Do not populate the XSKMAP without all of the above. A registered but
unserviced XSK will divert encrypted QUIC traffic away from kernel UDP
and interrupt the VPN. XDP pass-through by itself is not acceleration.

References:
https://docs.kernel.org/networking/af_xdp.html
https://github.com/cilium/ebpf
