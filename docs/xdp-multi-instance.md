# Shared-port WAN XDP statistics

[Documentation index](README.md) · [Linux data plane](README.md#linux-data-plane)

> **Document scope:** **Statistics-only WAN XDP reference.** XDP counts outer packets and passes them to the kernel; it does not forward, decrypt or classify individual VPN tenants.

All Server VPN instances share one UDP/QUIC listener (normally :443).
The optional XDP program counts incoming WAN packets and recognizes
UDP packets whose destination port is in the shared listener's
`instance_ports` map. XDP cannot inspect TLS SNI, tenant IDs, or
encrypted inner VPN packets.

## Packet path and object schema

~~~text
Physical WAN NIC
  -> XDP counters: total packets/bytes, VLAN headers, VPN UDP match
  -> XDP_PASS (always)
  -> Linux kernel UDP socket
  -> Go HTTP/3 + MPQUIC (TLS SNI selects the tenant/TUN)
~~~

Each WAN NIC owns a separate XDP object and BPF maps. Only the current
ELF schema is supported: `xdp_mqvpn` program, `instance_ports` map, and
`xdp_stats` per-CPU map. Objects without required maps or containing
the unsupported `xsks_map` are rejected *before* loading kernel BPF.
There is no AF_XDP redirect path or RX queue ownership.

## Configure WAN XDP

Configure the optional WAN XDP collector in the Server YAML:

~~~yaml
xdp:
  interfaces: [enp1s0, enp2s0]
  mode: driver  # bundled XDP ELF; object path optional
instances:
  - name: vpn-a
    server_name: vpn-a.example.com
    tun: mq0
    address: 10.77.0.1/24
    peers: /etc/mqvpn/peers-a.yaml
    cert: /etc/mqvpn/tls/a.crt
    key: /etc/mqvpn/tls/a.key
    client_ca: /etc/mqvpn/tls/a-ca.crt
  - name: vpn-b
    server_name: vpn-b.example.com
    tun: mq1
    address: 10.78.0.1/24
    peers: /etc/mqvpn/peers-b.yaml
    cert: /etc/mqvpn/tls/b.crt
    key: /etc/mqvpn/tls/b.key
    client_ca: /etc/mqvpn/tls/b-ca.crt
~~~

## Deployment and limits

The server executable includes the compiled XDP ELF by default; no
separate object needs to be deployed. XDP attaches only when `interfaces`
is configured. The optional `xdp.object: /path/to/xdp_mqvpn.o` overrides
the embedded ELF; changing an external override on a running dispatcher
still requires a server restart. After editing the C program, run
`make bpf` and commit the regenerated embedded object.

Statistics are logged at Server shutdown. XDP does not install
routes, filter incoming traffic, or replace the Go UDP transport.
The TCX MSS Clamp is a separate, optional TUN data-plane component.

## Related documentation

- [TC eBPF](tc-ebpf.md)
- [Server configuration](server-config.md)
- [Runtime architecture](runtime-architecture.md)
