# Client daemon configuration

The standalone `mqvpn-client` accepts `--config /etc/mqvpn/client.yaml`.
The file is strictly parsed as YAML (unknown fields and duplicate keys are
rejected), with a single document. CLI options override the corresponding
YAML values; old CLI deployments continue to work.

## Minimal configuration

~~~yaml
server: tenant.vpn.example.com
# address: auto   # omitted = request a dynamic Tunnel IP from Server
ca: /etc/mqvpn/ca.pem
cert: /etc/mqvpn/client.pem
key: /etc/mqvpn/client.key
~~~

Run `mqvpn-client --config /etc/mqvpn/client.yaml`.
`server` accepts a hostname, hostname:port or HTTPS URL; a missing path
defaults to `/.well-known/masque/ethernet/` and port to 443.

The optional `address` is the **inner TUN host address with prefix**,
not the WAN source address. When omitted or set to `auto`, Client requests
a Server-assigned Tunnel IP only after successful mTLS CONNECT. The Server
must configure `tunnel_pool` and authorize this Peer with
`dynamic_tunnel_ip: true`. Older Servers cannot supply the response,
so the Client fails clearly before opening the TUN. For a dynamic lease
the client assigns its actual local TUN address as /32 (IPv4) or /128
(IPv6) and uses the advertised subnet as a peer unicast route. This
makes the subnet's first and last IPv4 addresses usable as ordinary
host destinations. An explicit static CIDR continues to work without
address negotiation. The `ca`, `cert` and `key` are required
mTLS files and are never silently created or skipped.

## Default behavior

- TUN device: `mq0`. Tunnel IP: authenticated Server lease by default;
  or a static CIDR from `address`.
- Primary WAN: chosen from the kernel route to the server's resolved IP
  (connected UDP probe; no packets sent and no Linux routes changed).
- MTU: automatic from selected WAN link; `max_frame = MTU + 14`.
- Transport: QUIC/MPQUIC, then authenticated TCP fallback on initial
  UDP handshake timeout only; UDP deadline 5s, fallback TCP port 443.
- TCX eBPF: embedded object, `mode: auto`, MSS clamp auto, stats enabled.
  A TCX load error in auto mode logs a warning and uses normal TUN.

## Optional keys

| Key | Purpose |
| --- | --- |
| `address` | Optional static TUN CIDR; omit or `auto` to request Server lease |
| `tun`, `mtu`, `max_frame` | TUN name and MTU override |
| `connect_ip` | Pin remote IP while retaining `server` TLS DNS identity |
| `server_name` | Explicit tenant DNS identity (IP URL compatibility) |
| `source_ip`, `source_interface` | Bind primary WAN address/interface |
| `wan2_ip`, `wan2_interface` | Explicit secondary MPQUIC WAN path |
| `transport`, `udp_dial_timeout`, `tcp_port` | Advanced fallback settings |
| `tc.mode`, `tc.object`, `tc.mss_clamp`, `tc.stats` | eBPF policy/ELF override |
| `url` | Full legacy HTTPS endpoint, mutually exclusive with `server` |

The corresponding CLI options use hyphens instead of underscores.
`--server` provides a short CLI alternative to the old full `--url`.
The existing `--url` path still works unchanged. If an IP literal is
used as the server host, an explicit authenticated DNS `server_name`
is mandatory; the daemon never disables TLS certificate verification.

The daemon does not install firewall rules, policy routes, VRFs or
forwarding rules. On hosts with multiple default routes or unusual
routing, explicitly set `source_interface` and if needed `source_ip`.
TCP fallback uses the primary WAN only.
