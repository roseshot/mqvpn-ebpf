# TC eBPF: TUN TCP MSS clamp and per-interface statistics

The Linux L3 TUN is configured with IP/CIDR, MTU and UP using Go +
Netlink; Linux owns its connected-prefix route. TCX eBPF is an
**optional** addition on the TUN itself and requires kernel >=6.6.
All BPF program loading/attaching is pure Go via cilium/ebpf, not
a shell command.

## Build

Run **make bpf** (development-only Clang/LLVM). It produces:

- **bpf/xdp_mqvpn.o**: the existing WAN XDP dispatcher with per-CPU
  counters, including UDP listener matching and pass-through traffic.
- **bpf/tun_tc.o**: TUN TCX ingress and egress classifiers.

Deploy the new \`tun_tc.o\` with the daemon binary. No compilation
occurs at daemon runtime. Without a TC object setting, no TCX program
is attached; opting into TCX requires a kernel with TCX support.

## Server (per Instance)

~~~yaml
instances:
  - name: customer-a
    server_name: a.vpn.example.com
    tun: mq0
    address: 10.77.0.1/24
    tc:
      object: /usr/lib/mqvpn/tun_tc.o
      mss_clamp: auto
      stats: true
    peers: /etc/mqvpn/peers-a.yaml
    cert: /etc/mqvpn/tls/a.crt
    key: /etc/mqvpn/tls/a.key
    client_ca: /etc/mqvpn/tls/ca.crt
~~~

\`mss_clamp\` accepts \`off\`, \`auto\` and a numeric MSS from
256 to 65535. Even an explicit MSS is capped at the MTU-derived
maximum: IPv4 MTU minus 40 and IPv6 MTU minus 60. For example,
TUN MTU **1400** means MSS **1360** for IPv4 and **1340** for IPv6.

\`tc.stats: true\` enables a statistics-only deployment if
\`mss_clamp: off\`. The stats map is per CPU with a single independent
map instance per TUN, not shared between VPN tenants. Statistics
are logged at shutdown / instance reload; no peer IP/port ACLs
are introduced.

## Client

~~~bash
mqvpn-client --url https://a.vpn.example.com/.well-known/masque/ethernet/ \
  --tun mq0 --tun-address 10.77.0.2/24 \
  --source-interface enp1s0 \
  --tc-object /usr/lib/mqvpn/tun_tc.o --mss-clamp auto --tc-stats \
  --ca /etc/mqvpn/ca.crt --cert /etc/mqvpn/client.crt \
  --key /etc/mqvpn/client.key
~~~

Both QUIC/MPQUIC and HTTP/1.1 TCP fallback use the same TUN TCX
attachment. A TCX attach failure fails the opted-in instance or
client (no silently disabled clamp). Server hot reload restarts
only the instance when the TC config or ELF bytes change; the shared
UDP/443 and optional TCP/443 listeners remain running.

## Packet rules and limits

- TCX \`ingress\` processes packets written by Go to the TUN for Linux
  delivery. TCX \`egress\` processes packets Linux sends toward Go.
- L3 TUN data starts at IPv4 or IPv6, **without an Ethernet header**.
- Only TCP SYN / SYN-ACK with an existing MSS option are rewritten.
  MSS is only reduced, never increased, and the TCP checksum is updated.
- All non-TCP packets, non-SYN TCP, malformed TCP options and IP
  fragments are left unchanged. Known IPv6 extension headers are
  traversed with a bounded verifier-safe loop; ESP is not inspected.
- Oversize packets are **counted, not dropped** by this TC module.
  Linux TUN MTU and QUIC DATAGRAM size are separate constraints;
  this feature does not implement PMTU discovery or ICMP PTB.
- The kernel helper failure path drops the attempted packet to
  avoid passing corrupted TCP checksums. No other packet filter is added.
- IPv6 extension headers, TCP SYN options, and packet checksum behavior
  should still be validated with real production NICs/kernel versions.

WAN XDP is strictly statistics-only, always `XDP_PASS`, and has no
XSKMAP/AF_XDP redirect path. XDP statistics cover outer encrypted
packets; they cannot identify peer sessions or inner TCP MSS.
