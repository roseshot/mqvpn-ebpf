# Client daemon configuration

The standalone `mqvpn-client` accepts
`--config /etc/mqvpn/client.yaml`. YAML is parsed strictly:
unknown keys, duplicate keys, and non-YAML formats are rejected.
CLI flags override matching YAML fields.

## Required configuration

~~~yaml
server: tenant.vpn.example.com
ca: /etc/mqvpn/ca.pem
cert: /etc/mqvpn/client.pem
key: /etc/mqvpn/client.key
~~~

`server` is always the authenticated tenant DNS hostname, optionally
with a QUIC UDP port (`tenant.vpn.example.com:8443`). An URL scheme,
path, query, IP literal, and separate SNI field are not accepted.
`connect_ip` is the optional physical destination override without
changing the certificate-verified DNS identity.

The optional `path` is a canonical absolute MASQUE CONNECT path;
default `/.well-known/masque/ethernet/`. Server and Client must
agree on the exact path. The `url` / `server_name` alias fields
and `--url` / `--server-name` CLI flags are not part of the current
configuration and will fail validation.

## Tunnel IP and automatic behavior

When `address` is omitted or set to `auto`, Client requests an
authenticated server-assigned Tunnel IP at CONNECT. Server must
configure `tunnel_pool` and authorize the certificate fingerprint
with `dynamic_tunnel_ip: true`. An explicit `address: 10.77.0.2/24`
is a static Tunnel IP and disables address negotiation.

The TUN defaults to `mq0`; primary WAN source and MTU are selected
automatically, with `max_frame = MTU + 14`. QUIC/MPQUIC is preferred.
TCP fallback on initial handshake timeout requires the Server to enable
it; forced TCP uses primary WAN only. The TCX eBPF program is embedded
in the binaries and normally loads in `auto` mode with automatic
MSS clamp and counters.

Automatic reconnection is enabled by default, including after initial
dial failures, established QUIC/TCP session failures, and remote EOF.
The Client uses a 1, 2, 4, 8, 16, 30-second exponential retry delay
with a 30-second cap. A session running for at least one minute resets
the delay to one second. SIGINT/SIGTERM stops retries immediately.
Each attempt re-resolves the Server's IP and WAN, redoes mTLS and
dynamic Tunnel IP negotiation, and re-applies authenticated routes
after removing the previous session's managed routes. A Server-assigned
lease may change after reconnect. This does not migrate an existing
QUIC/TCP connection: every attempt starts a new authenticated session.

## Optional YAML fields

| Key | Purpose |
| --- | --- |
| `path` | Server-specific MASQUE CONNECT path |
| `address` | Static TUN CIDR or `auto` for Server lease |
| `accept_routes` | Apply authenticated `push_routes` (default true) |
| `reconnect` | Automatically reconnect on disconnect or dial failure (default true; false = one attempt) |
| `tun`, `mtu`, `max_frame` | TUN name and MTU/frame limits |
| `connect_ip` | Pin physical Server IP without changing TLS SNI |
| `source_ip`, `source_interface` | Primary WAN binding |
| `wan2_ip`, `wan2_interface` | MPQUIC secondary WAN |
| `transport`, `udp_dial_timeout`, `tcp_port` | Transport and fallback policy |
| `tc.mode`, `tc.object`, `tc.mss_clamp`, `tc.stats` | TCX tuning/ELF override |

The CLI forms use hyphens, for example `--server`, `--path`,
`--connect-ip`, `--accept-routes=false` and `--reconnect=false`.
Missing or invalid configuration and identity files are rejected before
entering the reconnect loop rather than silently retried.

## Server-pushed routes

When enabled, authenticated routes are installed on the Client's TUN
through Linux netlink. Client protects the actual Server public IP
with a WAN host route before inserting overlapping TUN routes. A
full-tunnel IPv4 `0.0.0.0/0` advertisement is installed as two
`/1` routes; IPv6 `::/0` similarly uses two `/1` routes.
Only daemon-owned routes are removed at session termination; existing
administrator routes are never replaced. If dual-WAN MPQUIC receives
a push that covers the Server public IP, Client rejects it instead
of redirecting an underlay path through the tunnel.

The program does not install firewall rules, VRFs, policy routing
rules, custom DNS or inner traffic filters. For unusual multi-WAN
routing, specify `source_interface` and optionally `source_ip`.
