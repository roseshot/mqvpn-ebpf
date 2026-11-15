# mqvpn-ebpf

**A Linux site-to-site VPN using encrypted MASQUE over Multipath QUIC.** It connects multiple authenticated sites through one server, with optional multi-WAN transport, traffic prioritization, and Linux eBPF helpers.

[简体中文](README.zh-CN.md) · [Documentation](docs/README.md) · [Get started](docs/getting-started.md) · [Troubleshooting](docs/operations.md)

## What does it do?

`mqvpn-server` creates an isolated point-to-multipoint (P2MP) VPN on a Linux TUN device. `mqvpn-client` connects using mutual TLS (mTLS). The server can host several independent VPN instances behind **one UDP listener**, selected by a verified DNS name (TLS SNI).

```text
                   One UDP/QUIC listener
                          |
                  mqvpn-server / mq0
                    10.77.0.1/24
                   /      |       \
            Site A     Site B     Site C
              mq0        mq0        mq0
         10.77.0.2   10.77.0.3   10.77.0.4
          1–8 WANs   1–8 WANs   1–8 WANs
```

The tunnel carries **IPv4 and IPv6 packets** in MASQUE CONNECT-ETHERNET DATAGRAMs. It is a **routed L3 VPN**: FRRouting or Linux can provide IP routes, but mqvpn does not configure OSPF/BGP for you or bridge Ethernet broadcasts between sites.

### At a glance

| Feature | What to expect |
| --- | --- |
| Encrypted transport | HTTP/3 over QUIC, TLS 1.3, mTLS certificate-chain validation, per-instance CN peer identity and optional CRL checks |
| Multi-WAN | Ordered, validated MPQUIC paths; `round_robin` or connection-wide `low_latency` scheduling |
| Server HA ingress | Optional local Server readiness probe; Keepalived UDP VIP failover or HAProxy TLS/TCP backend balancing, with no Client HA settings |
| QoS | Separate realtime, assured and best-effort queues (4:2:1 weighted service) |
| Sticky voice | Optional single-WAN QUIC companion for SIP/DSCP EF, with WAN failover |
| Routing | Per-peer allowed destination prefixes; optional server-pushed routes and DNS; external FRR for dynamic routing |
| Fallback | Optional TLS/TCP transport if the *initial* QUIC handshake times out |
| Linux integration | Managed TUN, optional embedded TCX MSS clamp, optional statistics-only XDP |

**Important limits:** Assured and best-effort traffic share the same MPQUIC connection-wide WAN scheduler; the QoS queue does not choose an independent WAN for each packet. Sticky voice is traffic-class affinity, **not per-call** path pinning. The XDP program does **not** implement AF_XDP zero-copy, and TCP fallback is single-WAN. See [QoS and path selection](docs/qos-queues.md) and [limitations](#limits-and-security).

## Try it in a Linux lab

You need **Linux**, **Go 1.27.4** (see `go.mod`), and `/dev/net/tun`. Building the Go binaries does not require Clang, libbpf, or CGO; the optional eBPF objects are already embedded.

```bash
make release
# Creates bin/mqvpn-server and bin/mqvpn-client
```

To verify a real encrypted server/client tunnel in **isolated Linux network namespaces**, install `iproute2`, `iputils-ping`, OpenSSL and Python 3, then run:

```bash
sudo bash tests/integration/overlay-netns.sh udp
```

This test needs root or the appropriate Linux network capabilities. It creates test-only interfaces, certificates and namespaces and cleans them up. It is **not** a production deployment.

For a two-host deployment, continue with the [step-by-step setup guide](docs/getting-started.md). It covers certificates, authorized peer identities, Server/Client YAML, validation, connection and a first ping. Use a trusted CA and protected keys in production—not the generated demo certificates.

## Find the right guide

| I want to… | Read |
| --- | --- |
| Set up my first server and client | [Get started](docs/getting-started.md) |
| Configure tenants, peer routes, leases, DNS or reload | [Server configuration](docs/server-config.md) |
| Configure a client or choose 1–8 WANs | [Client configuration](docs/client-config.md) and [Server WAN addresses](docs/server-multiwan.md) |
| Prioritize traffic or keep voice on one WAN | [QoS queues](docs/qos-queues.md) and [Sticky SIP/RTP](docs/voip-sticky.md) |
| Choose latency-aware MPQUIC or TCP fallback | [Path scheduling](docs/multipath-low-latency.md) and [TCP fallback](docs/tcp-fallback.md) |
| Run five-site BGP/OSPF tests | [Five-site routing lab](docs/five-site-routing.md) |
| Diagnose connectivity, MTU, TLS or route problems | [Operations and troubleshooting](docs/operations.md) |
| Understand internals or run other tests | [Documentation index](docs/README.md) |

## Build and validate

```bash
make release      # Build Linux server and client, CGO_ENABLED=0
make test         # Unit tests
make fmt-check    # Check Go formatting
make mod-check    # Check Go module integrity
```

After preparing an authorized Server configuration:

```bash
./bin/mqvpn-server validate --config /etc/mqvpn/server.yaml
sudo ./bin/mqvpn-server --config /etc/mqvpn/server.yaml
# On another host: sudo ./bin/mqvpn-client --config /etc/mqvpn/client.yaml
```

The client reconnects by default. Server and Client logs go to stderr; use `--log-level debug` or `--log-format json` when investigating a problem. The Server uses YAML; the Client accepts YAML and CLI overrides.

See [test coverage](docs/README.md#testing) for real TUN/WAN, encrypted packet capture, four-WAN, QoS, VoIP, and randomized five-site OSPF/BGP tests.

## Limits and security

- Every Client must pass tenant-isolated mTLS validation and match a configured Peer certificate CN/identity. A trusted CA alone does **not** grant VPN access. Optional CRLs enforce certificate revocation.
- Configure Linux forwarding, firewall rules, source-policy routing, VRFs and FRRouting **externally** when your topology needs them. Peer destination mapping is **not** a Linux kernel route.
- A Server can host multiple tenants on one UDP port only when each tenant has a distinct, certificate-verified SNI identity. A single instance may alternatively use a certificate-verified IP SAN.
- The default TUN MTU is selected from available WANs and capped at 1400; it does not guarantee a particular end-to-end path MTU.
- Automatic TLS/TCP fallback only follows an **initial QUIC handshake timeout**. It never silently downgrades after authentication failure.
- CI validates functionality in controlled Linux environments; it is not a throughput, MOS, zero-loss or production-security certification.

For configuration boundaries and operational caveats, use [the documentation index](docs/README.md) rather than copying example credentials into a real deployment.

## Project status and help

This repository builds two Go executables from `cmd/mqvpn-server` and `cmd/mqvpn-client` and keeps its Linux integration tests under `tests/integration`. The [GitHub Actions workflow](.github/workflows/go.yml) tests builds, race detection, eBPF, and encrypted multi-site forwarding on pull requests.

For an unexpected behavior, start with [Troubleshooting](docs/operations.md) and the [GitHub issue tracker](https://github.com/roseshot/mqvpn-ebpf/issues). Reports should include the version/commit, Linux kernel, relevant sanitized logs and reproduction steps; **never post private keys or TLS key logs**.
