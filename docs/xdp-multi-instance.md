# Shared-port XDP dispatcher

All Server VPN instances now share **one UDP/QUIC listener**, e.g. :443.
The BPF instance_ports map registers the **single shared outer UDP port**.
XDP has no visibility into TLS SNI or encrypted inner VPN traffic.

    Intel I226 WAN NIC
      -> XDP: UDP dest 443 registered?
           -> no XSK bound: XDP_PASS -> shared kernel UDP socket
           -> future XSK: XDP_REDIRECT to socket bound to RX queue
      -> one QUIC server
           -> TLS SNI customer-a.vpn.example.com -> customer-a TUN mq0
           -> TLS SNI customer-b.vpn.example.com -> customer-b TUN mq1

There is one native/generic XDP program per configured physical NIC, one
outer-port map and one XSKMAP keyed by RX queue. XDP does not demux by VPN
Instance; that is done by TLS SNI and HTTP/3 in Go. Hot-adding a VPN
instance on the same shared UDP port does not change the XDP port map.

Enable through the top-level Server YAML:

~~~yaml
# listen is optional; default UDP/443
xdp:
  interfaces: [enp1s0, enp2s0]
  object: /usr/lib/mqvpn/xdp_mqvpn.o
  mode: driver
instances:
  - name: vpn-a
    server_name: vpn-a.example.com
    tun: mq0
    peers: /etc/mqvpn/peers-a.yaml
    cert: /etc/mqvpn/tls/a.crt
    key: /etc/mqvpn/tls/a.key
    client_ca: /etc/mqvpn/tls/a-ca.crt
  - name: vpn-b
    server_name: vpn-b.example.com
    tun: mq1
    peers: /etc/mqvpn/peers-b.yaml
    cert: /etc/mqvpn/tls/b.crt
    key: /etc/mqvpn/tls/b.key
    client_ca: /etc/mqvpn/tls/b-ca.crt
~~~

~~~bash
sudo apt-get install clang llvm libbpf-dev linux-libc-dev
make bpf
sudo install -D -m 0644 bpf/xdp_mqvpn.o /usr/lib/mqvpn/xdp_mqvpn.o
CGO_ENABLED=0 go build -mod=mod ./cmd/...
~~~

**No AF_XDP RX/TX, UMEM or zero-copy backend exists today.** The program
keeps XSKMAP empty and returns XDP_PASS. Registering an XSK prematurely
would divert packets away from the working QUIC UDP socket.

No live N200/I226 throughput claim is made.
