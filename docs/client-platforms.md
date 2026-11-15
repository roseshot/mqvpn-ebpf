# Cross-platform Client: incremental implementation boundary

**Current status:** The full `mqvpn-client` application is a **Linux-only**
executable. This phase makes the running Linux Client's operating-system
resource calls injectable behind one narrow `clientPlatform` interface, and
adds Windows/macOS/Android **compile-only** checks for the reusable packet
core. It does **not** ship or claim a working native Client on those systems.

## Reuse without copying the protocol implementation

The existing `internal/p2mp.ClientPumpWithFeatures` already consumes an
`io.ReadWriteCloser` for L3 packets. Reuse the same TLS 1.3 / mTLS,
QUIC/HTTP3/MASQUE, L3 codec, fragmentation, QoS, transport fallback,
authenticated route/DNS parsers, and reconnection semantics on all hosts.
Do not introduce an alternate VPN protocol or move Server eBPF, cluster
Raft, leases or HA authority into the Client.

The Linux Client now selects `linuxClientPlatform` and routes these
operations through the internal `clientPlatform` boundary:

| Client operation | Linux implementation | Native adapter responsibility |
| --- | --- | --- |
| UDP underlay, explicit source and primary WAN | `wan.Listen`, `wan.ResolveSource` | Open and bind/protect platform-owned underlay sockets |
| TCP fallback | `wan.DialTCP` | Preserve source/path selection and certificate verification |
| WAN MTU | `wan.SourceUnderlay` | Inspect actual selected physical network MTU |
| Server endpoint route protection | `routepush.ProtectServer` | Prevent the VPN route from capturing its own encrypted connection |
| Authenticated tunnel configuration | `openClientNetworkSession` | Create packet device; install routes/DNS; own and restore exactly the changes made |

The `OpenNetworkSession` resource stays alive through the packet pump;
its `Close` returns network cleanup failures to the reconnect supervisor.
The route guard outlives the device, as it did before refactoring. The
Linux-only TUN, DNS, netlink, optional TCX and source-socket code is still
used unchanged by `linuxClientPlatform`. The platform boundary must not
hide cleanup failures or silently bypass the authenticated Server route.

## Platform implementation order

| Target | First milestone | Native work required (not present) |
| --- | --- | --- |
| Windows x64 | One-WAN QUIC + Wintun L3 packet device | Wintun lifetime, route guard, DNS policy, service permissions, disconnect restoration |
| macOS arm64 | Single-host Network Extension packet tunnel | App/Packet Tunnel Provider host, entitlements, `NEPacketTunnelNetworkSettings`, route and DNS ownership |
| Android arm64 | One-network `VpnService` | Kotlin service and Go bridge, protected sockets, `VpnService.Builder` routes/DNS/MTU, VPN permission and background lifecycle |

The native Client must use the OS-managed VPN permission/configuration
model, not mutate system-wide network state from an unprivileged helper.
On Android every physical TCP/UDP socket must be excluded from the VPN
using `VpnService.protect` **before** connecting, including sockets
created by external transport libraries. Binding an Android `Network`
for Wi-Fi/cellular alone is not sufficient. In the current Client,
`quic.NewMultiSocketManager` creates additional underlay sockets
internally: this must also become platform-protectable before Android
multi-WAN or endpoint announcement can be enabled. Sticky VoIP uses the
same platform `ListenUDP` and is subject to the same safety rule.

Even when `github.com/qoke/mp-quic-go` cross-compiles, this is **not** proof
its socket binding, MPQUIC multipath, or mobile network switching works.
Those behaviors require device-level transport tests before enablement.

## Validation and future acceptance

The `client-core-cross` GitHub Actions job builds pure protocol and
packet-processing packages and the actual `mp-quic-go` and `http3` Go
libraries for `windows/amd64`, `darwin/arm64`, and `android/arm64`, and
**compiles but does not run** the portable `internal/p2mp` tests. The existing Linux tests, race detector,
eBPF/TUN and QUIC/multi-WAN network integration remain the regression gate.

Before promoting each platform to supported, add a native test environment
covering end-to-end authenticated QUIC, packet ingress/egress, IPv4/IPv6,
server endpoint route protection, DNS and route rollback, cancellation,
reconnect after partial cleanup, network transitions, and certificate/CRL
fail-closed behavior. Add TCP and multiple WANs only once single-path
lifecycle and socket protection have passed. Avoid enabling a platform
`GOOS` build target before its native adapter and host integration exist.

See [Linux runtime architecture](runtime-architecture.md) and
[Client configuration](client-config.md).
