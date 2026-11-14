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

`server` is the authenticated tenant DNS hostname, optionally
with a QUIC UDP port (`tenant.vpn.example.com:8443`). For a **single
Server instance only**, `server` may also be a literal IPv4 or IPv6
address with a matching Server certificate IP SAN. Go TLS omits SNI
for IP literals, and the single Server instance is selected without
SNI. With multiple instances, only DNS identities with SNI are
permitted. URL schemes, embedded paths, queries and separate SNI
fields are not accepted.
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
| `accept_dns` | Apply authenticated `push_dns` with systemd-resolved (default true; false opts out) |
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
administrator routes are never replaced. New Client-created TUNs are
deleted at session end; pre-existing TUNs regain their original IP
addresses, MTU and administrative UP/DOWN state. The Client does not
install system DNS settings; it does not modify or reset DNS on
disconnect. Cleanup failures stop retries instead of compounding stale
kernel state. If dual-WAN MPQUIC receives
a push that covers the Server public IP, Client rejects it instead
of redirecting an underlay path through the tunnel.

The program does not install firewall rules, VRFs, policy routing
rules, custom DNS or inner traffic filters. For unusual multi-WAN
routing, specify `source_interface` and optionally `source_ip`.

## Server-pushed DNS

A Server instance may advertise literal IP DNS servers after authenticated
HTTP/3 CONNECT or TCP Upgrade:

~~~yaml
# Server instance configuration (inside instances: [])
push_dns:
  - 10.77.0.1
  - fd77::53
~~~

The Client accepts pushed DNS by default. Set `accept_dns: false` or
`--accept-dns=false` to ignore the advertisement. The Server may
advertise up to eight IPv4/IPv6 unicast DNS addresses using the
`Mqvpn-DNS` response header. The authenticated Client validates them
before touching system resolver state.

On Linux, mqvpn configures only the session TUN through the
`systemd-resolved` D-Bus link API, with a route-only `~.` DNS domain so
these DNS servers are preferred for general name lookups. The Client
snapshots the TUN's existing DNS server details (including custom ports
and TLS names), domains and DNS default-route policy, and restores
them before the TUN is closed or another session starts. Network
changes by another manager are never blindly overwritten; if it cannot
restore safely, automatic reconnect stops.

`systemd-resolved` and its system D-Bus are required **only when pushed
DNS is accepted**. This feature does not edit `/etc/resolv.conf`, and does
not use shell commands or modify global/physical WAN DNS. The host must
already route queries through systemd-resolved (usually its stub resolver
or `nss-resolve`); a host using a foreign resolv.conf will not
automatically consume per-link settings. If the DNS server is not in
the VPN's connected TUN subnet, Server must also push a reachable
route via `push_routes` (or the client must already have one).
