# Cross-platform Client: incremental implementation boundary

**Current status:** `mqvpn-server` is **Linux-only**, by design.
`mqvpn-client` runs as a complete VPN on Linux. The Windows Client executable
can now be built, but deliberately refuses to connect until it has native
route/DNS/underlay protection. The Windows-only `internal/wintun` package
implements native L3 packet I/O backed by an operator-provided official
`wintun.dll`; it is **not wired to a usable VPN network session** yet.
macOS/Android support remains at shared protocol-core compilation only.
This does **not** ship a working native VPN Client on any non-Linux OS.

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

## Windows packet device increment

`internal/wintun.Open(name)` creates a Wintun adapter and starts an L3
ring with `Read`, `Write`, `Close` and an adapter LUID accessor. It
loads `wintun.dll` from the executable directory (an **absolute path**),
rather than from the current working directory or `PATH`. No Wintun
binary is bundled or silently downloaded. Obtain the signed, properly
licensed DLL through the [official Wintun distribution](https://www.wintun.net/);
driver installation and adapter creation may require administrator
privileges. Only the adapter created by this component is closed.

**The DLL and packet device are not sufficient for a safe VPN session.**
A production Windows `clientPlatform` still has to configure address/MTU,
add authenticated VPN routes and DNS, preserve a physical route to every
QUIC/TCP Server endpoint, and restore exactly its owned changes after
disconnect or partial failure. It must protect against Client traffic
recirculating into its own virtual adapter. Until that work and Windows
end-to-end packet tests are complete, the Windows executable returns a
native-platform-unavailable error *before opening any underlay socket*.

The GitHub Actions `windows-client` job builds the complete Windows
Client executable, compiles/tests the Wintun I/O component **without
requiring the DLL**, and checks refusal to establish an incomplete
Windows VPN session. The Server binary remains Linux-only and is
intentionally not cross-compiled for Windows.

## Platform implementation order

| Target | First milestone | Native work required (not present) |
| --- | --- | --- |
| Windows x64 | Wintun packet I/O and Windows Client binary compile (implemented, fail-closed) | Windows route guard, address/MTU, DNS policy, service permissions, packet-path integration, disconnect restoration |
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
