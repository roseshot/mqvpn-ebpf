# Source layout and Go package ownership

mqvpn is one Go module containing two commands. The `cmd/` directories
are thin entry points; implementation stays in narrowly scoped
`internal/` packages. The Linux Server never imports Client internals,
and Client never imports the Server.

```text
cmd/
  mqvpn-client/       Client executable (Linux; Windows binary is fail-closed)
  mqvpn-server/       Server executable (Linux only)
internal/
  client/             Client CLI, QUIC/TCP, multi-WAN, reconnect, platform adapter
  server/             Linux-only tenant routing, TLS authorization, hot reload, health
  session/            Shared MASQUE/SNI, framing, compression, addresses, scheduling
  p2mp/               L3 peer overlay, packet pumps, peer routing and queues
  l3/                 Packet encoding, decoding and fragmentation
  capsule/            TCP fallback DATAGRAM capsules
  qos/                Traffic classification and scheduling
  configfile/         Strict YAML loading and serialization
  cluster/            HA ownership/policy contracts; production consensus not wired
  mtu/                Pure Go MTU and frame budget planning
  tun/                TUN validation and Linux TUN device operations
  wan/                Linux underlay source selection and socket binding
  routepush/          Authenticated routes and Linux session-owned route updates
  dnspush/            Authenticated DNS and Linux DNS restoration
  tcebpf/             Linux TCX attach and MSS policy, bundled ELF
  xdp/                Linux statistics-only XDP, bundled ELF
  wintun/             Windows native L3 packet and unicast address primitives
  architecture/       Dependency and subprocess boundary regression tests
  logging/            Structured logging setup
bpf/                  TC/XDP C source
configs/              Deployable example configuration
docs/                 Operator and maintainer documentation
scripts/              Development tools
tests/integration/    Real Linux TUN, WAN, FRR and encrypted-traffic scenarios
```

## Dependency direction

- `client` imports `session` and platform-neutral protocol packages. Its
  platform-specific files own underlay sockets, TUN, routes and DNS. Client
  never depends on `server`, `xdp` or the HA control authority.
- `server` imports `session`, `p2mp` and Linux-specific network packages.
  Every Server source file is guarded for Linux. There is no non-Linux Server
  entry point or runtime.
- `session` implements **authenticated wire/session semantics** common to
  both ends. No Linux kernel TUN or cross-node ownership state is managed
  here. It may depend on narrow pure Go packet/MTU modules.
- `cluster` contains state machine contracts, not a mandatory dependency of
  the standalone Client.
- `p2mp`, `l3`, `capsule`, `qos` and `mtu` preserve distinct
  protocol/data-plane responsibilities instead of a giant shared package.
- `internal/logging` exclusively creates root slog Handlers, sets
  text/JSON format, minimum level, stderr destination and component fields.
  Both command entry points configure their root logger once and inject it
  into their runtime; business components retain `*slog.Logger` as a standard
  Go dependency and use `With` for structured contextual fields.
  `logging.Require` rejects a missing injected logger rather than opening
  an independent default Text/Info output path. No global slog defaults or
  extra logging facades are used.
- `internal/architecture` tests guard the no-subprocess rule, exclusive
  Handler construction, explicit logger injection and import boundaries.

## Naming conventions

Package names are short nouns for their responsibility, in lower case.
`client.Run` and `server.Run` avoid repetitive `RunClient`/
`RunServer` symbols. Local types use their package context
(`client.sessionOptions`, `server.Config`, `server.manager`).
Filename labels describe behavior (`session.go`, `reconnect.go`,
`handler_linux.go`, `network_linux.go`, `addresses.go`) and Go OS
build constraints are explicit. Test files live beside the package whose
behavior they verify; cross-endpoint behavior is tested as transport or
integration behavior, not by reaching into another package's unexported
functions.

Package ownership is explicit: this repository has no catch-all
`src/`, `pkg/`, `utils/` or `common/` subtree, and the Client, Server
and shared session code are maintained in their owning packages.

**Platform scope:** Server runs **only on Linux**. Client is operational
on Linux; Windows Wintun primitives exist but the Windows VPN session is
still fail-closed. macOS/Android retain portable Core compilation, and
need native packet tunnel adapters to become operational.

References: [Go module layout](https://go.dev/doc/modules/layout),
[Go package names](https://go.dev/blog/package-names), and
[Go code review naming guidance](https://go.dev/wiki/CodeReviewComments).
