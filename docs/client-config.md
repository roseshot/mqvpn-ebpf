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

## WAN path configuration (ordered list)

Client WANs are an **ordered list**, not a fixed pair. First entry is
the initial QUIC handshake path; remaining entries are attached with
`Conn.AddPath` and explicitly validated with `Probe`. To configure
four WANs:

~~~yaml
server: vpn.example.com:8443
connect_ip: 192.0.2.1
transport: quic
wans:
  - source_ip: 192.0.2.2
    interface: wan0
  - source_ip: 198.51.100.2
    interface: wan1
  - source_ip: 203.0.113.2
    interface: wan2
  - source_ip: 192.0.2.6
    interface: wan3
~~~

CLI equivalent:

~~~bash
mqvpn-client --server vpn.example.com:8443 --connect-ip 192.0.2.1 \
  --wan 192.0.2.2@wan0 \
  --wan 198.51.100.2@wan1 \
  --wan 203.0.113.2@wan2 \
  --wan 192.0.2.6@wan3
~~~

Repeat `--wan` for each interface. The CLI list replaces any YAML
`wans` list. Mixing a WAN list with legacy `source_ip` /
`source_interface` / `wan2_ip` / `wan2_interface` fields is rejected
rather than silently merging them. Single- and dual-WAN legacy flags
are still accepted and mapped to the common ordered representation.

**No fixed WAN maximum is imposed by mqvpn's configuration or loop.**
The current `github.com/qoke/mp-quic-go v0.3.1` dependency has an
independent internal maximum of **64 simultaneously active paths**.
The client requests the configured path count (and the Server advertises
the largest count supported by its QUIC library), but exceeding the
dependency limit cannot work without updating that library. Resource
limits and route/connection-ID limits may further restrict usable paths.
Never interpret an accepted configuration with more than 64 WANs as a
guarantee that all will connect.

All configured WAN interfaces must be physically and routably distinct.
Using source IPs and `SO_BINDTODEVICE` is not enough to create routing:
for same-destination multi-WAN links, add the required per-source policy
routing externally. mqvpn does not install or remove these Linux rules.
The TUN's automatic MTU considers **every validated WAN**, and the
TCP fallback remains intentionally single-WAN.

### Client paths to different Server WAN IPs

An ordered Client WAN list can target a different Server IP on each
path, still using **one authenticated MPQUIC connection**. Specify the
secondary destinations in YAML:

~~~yaml
wans:
  - source_ip: 192.0.2.2
    interface: wan0
    server_ip: 192.0.2.1
  - source_ip: 198.51.100.2
    interface: wan1
    server_ip: 198.51.100.1
  - source_ip: 203.0.113.2
    interface: wan2
    server_ip: 203.0.113.1
  - source_ip: 192.0.2.6
    interface: wan3
    server_ip: 192.0.2.5
~~~

Or use repeatable `--wan 198.51.100.2@wan1=198.51.100.1` for
additional interfaces. A first-path `server_ip` must match the
authenticated connection's `connect_ip` destination.

With `use_server_wans: true` (CLI: `--use-server-wans=true`) the
Client can discover missing secondary Server IPs from authenticated
MPQUIC `ADD_ADDRESS` announcements. For nontrivial topology,
explicit pairing is recommended so each link targets a reachable IP.

The multi-destination path transport uses source-bound UDP sockets
through `mp-quic-go MultiSocketManager`, not `SO_BINDTODEVICE` for
the secondary paths. Administrators must configure and verify Linux
source-policy routes to the desired interface for every Server IP;
mqvpn does not create those rules.

Server-side configuration and the four-WAN test are documented in
[Server multi-WAN](server-multiwan.md). The current `mp-quic-go v0.3.1` library
still caps active MPQUIC paths at **64**, independent of the unbounded
configuration list.

## High availability across Server backends

For two independent Server processes, set `ha.mode: active_standby` or `active_active` and list their physical IPs under `ha.backends`. Every backend uses the same authenticated `server` identity. Client-managed HA switches on reconnect and keeps **one** TUN/session at a time; active/active means **different Clients are distributed across the fleet**. Alternatively, use `ha.controller: haproxy` and a stable TCP VIP with `transport: tcp`. See [High availability](high-availability.md) for configuration, HAProxy examples, failback timing and limits.

## Optional YAML fields

| Key | Purpose |
| --- | --- |
| `path` | Server-specific MASQUE CONNECT path |
| `address` | Static TUN CIDR or `auto` for Server lease |
| `accept_routes` | Apply authenticated `push_routes` (default true) |
| `accept_dns` | Apply authenticated `push_dns` through a per-interface resolver (default true) |
| `dns_routes` | Automatically install DNS /32 IPv4 or /128 IPv6 TUN routes (default true) |
| `reconnect` | Automatically reconnect on disconnect or dial failure (default true; false = one attempt) |
| `tun`, `mtu`, `max_frame` | TUN name and MTU/frame limits |
| `connect_ip` | Pin physical Server IP without changing TLS SNI |
| `source_ip`, `source_interface` | Primary WAN binding |
| `wans` | Ordered list of MPQUIC WANs: `source_ip` and `interface` |
| `wan2_ip`, `wan2_interface` | Legacy secondary WAN parameters (still supported) |
| `use_server_wans` | Discover Server WAN IPs from authenticated MPQUIC ADD_ADDRESS announcements |
| `transport`, `udp_dial_timeout`, `tcp_port` | Transport and fallback policy |
| `tc.mode`, `tc.object`, `tc.mss_clamp`, `tc.stats` | TCX tuning/ELF override |

The CLI forms use hyphens, for example `--server`, `--path`,
`--connect-ip`, `--accept-routes=false`, `--dns-routes=false` and
`--reconnect=false`.
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
addresses, MTU and administrative UP/DOWN state. If the Server sends authenticated DNS settings and the Client accepts
them, the Client applies per-interface resolver settings through
`systemd-resolved` or `resolvconf`, restoring its own changes on
disconnect. Without an authenticated DNS push, system DNS is not changed.
Cleanup failures stop retries instead of compounding stale kernel state. If multi-WAN MPQUIC receives
a push that covers the Server public IP, Client rejects it instead
of redirecting an underlay path through the tunnel.

The program does not install firewall rules, VRFs, policy routing
rules, custom DNS or inner traffic filters. For unusual multi-WAN
routing, specify `source_interface` and optionally `source_ip`.

## Server-pushed DNS

A Server instance advertises up to eight validated literal IPv4/IPv6 DNS
addresses after an authenticated HTTP/3 CONNECT or TCP Upgrade:

~~~yaml
# Within the Server instance:
push_dns:
  - 10.77.0.1
  - fd77::53
~~~

The Client accepts DNS by default. Set `accept_dns: false` or
`--accept-dns=false` to ignore `Mqvpn-DNS`. The Client validates
these authenticated addresses before modifying the resolver.

Every accepted DNS IP also gets a dedicated VPN TUN route by default:
IPv4 `/32`, IPv6 `/128`. These host routes are independent of
`accept_routes`, share the VPN's underlay protection and session-owned
route rollback, and cannot override an existing host route to the VPN
Server's Underlay IP. Disable this behavior with `dns_routes: false`
or `--dns-routes=false` while continuing to accept pushed DNS. Normal
`push_routes` handling is unchanged.

On Linux, mqvpn first attempts `systemd-resolved`'s D-Bus link API:
it sets DNS on the TUN and adds the routing-only `~.` domain. At
disconnect, the previous per-link DNS server details, domains and DNS
default-route state are restored. Intervening modifications by another
network manager are not silently overwritten.

If systemd-resolved (or system D-Bus) is **unavailable**, Client uses
`resolvconf` (openresolv or the resolvconf package) to register DNS
for the VPN interface under a uniquely owned source. On disconnect,
it deregisters only that source, preserving other interfaces'
registrations. This fallback's priority and effective DNS order
depend on the installed resolver manager; `~.` routing is specific
to systemd-resolved.

Linux itself has no kernel per-interface DNS setting, so at least
one of systemd-resolved or resolvconf must be functional. The daemon
does not edit `/etc/resolv.conf` directly; resolvconf may manage it.
A DNS cleanup failure stops reconnect rather than stacking stale state.
