# Configure the Server

The Server is an authenticated **P2MP routing hub**. It owns the UDP/QUIC listener, one Linux TUN per VPN instance and a map from allowed destination prefixes to authorized peer sessions.

If you are setting up your first instance, follow [Get started](getting-started.md) before adding options. This page explains the Server's current YAML configuration and its security boundaries.

## Basic configuration

```yaml
# /etc/mqvpn/server.yaml
listen: "0.0.0.0:8443"
instances:
  - name: company-a
    server_name: vpn.example.com
    tun: mq0
    address: 10.77.0.1/24
    peers: /etc/mqvpn/peers.yaml
    cert: /etc/mqvpn/tls/server.crt
    key: /etc/mqvpn/tls/server.key
    client_ca: /etc/mqvpn/tls/clients-ca.crt
```

`listen` defaults to UDP/443 when omitted. QUIC, MASQUE and multi-WAN paths use **one listener**, not one port per Client or WAN.

Before starting the service, run:

```bash
./bin/mqvpn-server validate --config /etc/mqvpn/server.yaml
sudo ./bin/mqvpn-server --config /etc/mqvpn/server.yaml
```

A Server instance requires a unique `name`, authenticated `server_name`, a TUN name/address, a peer authorization YAML and TLS identity material. The daemon creates or attaches its TUN and configures the interface's IP/CIDR, MTU and UP state; it does not create VRFs or firewall policy.

### Multiple isolated VPN instances

A single Server process can expose multiple instances under one UDP socket:

```yaml
instances:
  - name: site-a
    server_name: a.vpn.example.com
    tun: mq0
    address: 10.77.0.1/24
    peers: /etc/mqvpn/a-peers.yaml
    cert: /etc/mqvpn/tls/a.crt
    key: /etc/mqvpn/tls/a.key
    client_ca: /etc/mqvpn/tls/a-clients-ca.crt

  - name: site-b
    server_name: b.vpn.example.com
    tun: mq1
    address: 10.88.0.1/24
    peers: /etc/mqvpn/b-peers.yaml
    cert: /etc/mqvpn/tls/b.crt
    key: /etc/mqvpn/tls/b.key
    client_ca: /etc/mqvpn/tls/b-clients-ca.crt
```

Each DNS name must match the corresponding Server certificate DNS subjectAltName. TLS SNI and the HTTP authority determine the same instance; missing or unknown SNI is **not** routed to a default tenant when multiple instances are configured.

**Single-instance exception:** the Server may instead use an IP address as `server_name` if the Server certificate has the matching **IP subjectAltName**. This does not allow multiple unrelated tenants to share the missing-SNI path.

Overlapping private prefixes are possible across instances, but Linux needs separate routing tables/VRFs for overlapping FIB routes. See [Overlapping subnets with VRF](overlapping-subnets-vrf.md).

## Authorize peers and destination prefixes

The `peers` file is independent of the Server's own instance YAML:

```yaml
# /etc/mqvpn/peers.yaml
peers:
  - id: site-1
    certificate_sha256: "REPLACE_WITH_64_LOWERCASE_HEX_CHARACTERS"
    routes:
      - 10.77.0.2/32
      - 192.168.20.0/24

  - id: site-2
    certificate_sha256: "REPLACE_WITH_A_DIFFERENT_64_CHARACTER_SHA256"
    routes:
      - 10.77.0.3/32
      - 192.168.30.0/24
```

Obtain a Client certificate fingerprint:

```bash
openssl x509 -in client.crt -outform DER | sha256sum | cut -d' ' -f1
```

A trusted Client CA validates the certificate. The fingerprint must **also** match an explicitly authorized peer inside the selected tenant. `routes` are **P2MP destination ownership rules**: the Server forwards an inner packet to the corresponding authenticated Client session. They are *not* Linux FIB routes, source anti-spoofing rules or firewall ACLs.

For cross-site forwarding, the Server's Linux namespace needs IP forwarding and the correct kernel routes to the TUN. BGP/OSPF route learning is managed externally, for example by FRRouting. See [Five-site BGP and OSPF](five-site-routing.md).

## Optional: assign tunnel IPs automatically

Static addresses as in [the first-connection tutorial](getting-started.md) need no dynamic pool. If you want a peer to receive an address at session start, configure a matching Server `tunnel_pool` and authorize `dynamic_tunnel_ip`:

```yaml
# Within a Server instance (other required fields omitted):
address: 10.77.0.1/24
tunnel_pool: 10.77.0.0/24
```

```yaml
# In that instance's peer authorization YAML:
peers:
  - id: leased-site
    certificate_sha256: "REPLACE_WITH_THE_CLIENT_CERTIFICATE_FINGERPRINT"
    dynamic_tunnel_ip: true
    routes:
      - 192.168.20.0/24
```

The matching Client omits `address` or sets `address: auto`. Leases are session-scoped: they can change after reconnect and are not persisted across restarts. Host addresses reserved by static peers or the Server cannot be leased. A peer without `dynamic_tunnel_ip` cannot request a lease.

## Optional: advertise routes and DNS

The following options belong **inside** a Server instance. They are delivered after successful mTLS peer authorization:

```yaml
push_routes:
  - 192.168.20.0/24
  # - 0.0.0.0/0   # only after checking underlay protection / policy routes
push_dns:
  - 10.77.0.1
```

Clients accept authorized pushes by default but can opt out using `accept_routes`, `accept_dns` or `dns_routes` in their Client YAML. Route pushes install only Client-session-owned routes. The Client protects the actual Server underlay address so a pushed full-tunnel route does not recursively send VPN control traffic into the TUN; some multi-WAN/full-tunnel combinations are deliberately rejected without explicit source-policy routing.

DNS pushes use per-link `systemd-resolved` or `resolvconf` configuration and are restored at disconnect. Without a push, the resolver is not changed. See [Client configuration](client-config.md) for route, DNS and reconnect behavior.

## Optional: Server cluster HA

To run more than one Server backend, give each backend compatible tenant identity, peer certificate authorizations and tunnel routes. The Client can select backends in `active_standby` or fleet-wide `active_active`, or delegate TCP session selection to an external HAProxy. HA does **not** replicate Server sessions or Linux routing state. See [High availability](high-availability.md).

## Optional: multiple physical WANs

```yaml
listen: "0.0.0.0:8443"
wans:
  - interface: wan0
    ip: 192.0.2.1
  - interface: wan1
    ip: 198.51.100.1
```

The Server advertises authenticated additional QUIC path addresses through the negotiated MPQUIC extension. The Client must have reachable source/destination WAN pairs and appropriate Linux source-policy routes. Configure these **outside** mqvpn. See [Server multi-WAN](server-multiwan.md) and [Client WAN selection](client-config.md#wan-path-configuration-ordered-list).

The legacy `wan_interfaces` option is only for WAN-aware MTU discovery; do **not** combine it with `wans`.

## Other Server choices

| Setting | Use it when… | Details |
| --- | --- | --- |
| `path` | You need a custom CONNECT endpoint on a specific tenant | Defaults to `/.well-known/masque/ethernet/` and must match the Client |
| `mtu`, `max_frame` | You need an explicit TUN/frame budget | [MTU and MSS](mtu-mss.md) |
| `path_scheduler` | You prefer a connection-wide low-RTT MPQUIC scheduler | [Path scheduling](multipath-low-latency.md) |
| `tcp_fallback` | You want an opt-in TLS/TCP backup listener | [TCP fallback](tcp-fallback.md) |
| `tc` | You need embedded TCX MSS clamp or TUN statistics | [TC eBPF](tc-ebpf.md) |
| `xdp` | You need outer WAN UDP-port packet counters | [XDP](xdp-multi-instance.md) |

**Do not infer from configuration that mqvpn enforces firewall rules, configures LAN routing, installs BGP/OSPF, or offers AF_XDP zero-copy.** Those capabilities are external or not provided.

## Reload and observe

The Server periodically checks configuration/identity/peer files (default interval `2s`), or you can request a SIGHUP-based reload:

```bash
./bin/mqvpn-server reload --pid SERVER_PID
```

The target process logs whether its reload succeeded. The default CLI log format is text on stderr. Use `--log-format json` and `--log-level debug` for structured diagnostics. Replacing a shared listener, WAN address or TCP fallback listen socket may require a **process restart**; do not assume a reload migrates established QUIC paths.

Removing a peer authorization revokes the matching peer session; the Hub protects its ingress/egress boundary against retired sessions. Review [Operations and troubleshooting](operations.md) for reload, path and route verification.

## Production checklist

1. Install CA certificates and private keys with appropriate permissions; do not deploy the demo CA from `scripts/gen-dev-certs.sh`.
2. Review all authorized peer SHA-256 fingerprints and P2MP destination prefixes.
3. Configure Linux firewall, forwarding and routing according to the intended trust boundaries.
4. Validate YAML **before** starting; confirm the Server certificate SAN matches the Client's configured Server name.
5. Test UDP reachability, backup transport if enabled, MTU and reconnect behavior in the target network.
