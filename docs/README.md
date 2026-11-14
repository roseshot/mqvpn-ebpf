# Documentation

[Back to project README](../README.md) · [简体中文简介](../README.zh-CN.md)

**Start with a task, not a protocol specification.** If you are setting up mqvpn for the first time, follow [Get started](getting-started.md). If a working tunnel stopped passing traffic, use [Operations and troubleshooting](operations.md).

The guides follow the [Diátaxis](https://diataxis.fr/) idea of separating *learning*, *doing*, *looking up facts*, and *understanding why*. Existing deep-dive URLs remain in place.

## Learn: start with a working tunnel

| Guide | What you will achieve |
| --- | --- |
| [Get started](getting-started.md) | Build two binaries, create lab credentials, authorize a peer, connect two Linux hosts and send a first ping |
| [Architecture overview](runtime-architecture.md) | Understand the client/server, TUN, QUIC and Linux resource boundaries |

## Do: configure and operate

| Goal | Guide |
| --- | --- |
| Deploy a tenant, static peer routes, optional leases or DNS | [Server configuration](server-config.md) |
| Set up an authenticated Client, transport and ordered WAN paths | [Client configuration](client-config.md) |
| Expose many WAN addresses on one Server QUIC listener | [Server multi-WAN](server-multiwan.md) |
| Choose a connection-wide low-latency MPQUIC scheduler | [Low-latency path scheduling](multipath-low-latency.md) |
| Configure assured/realtime/best-effort service | [QoS and bounded queues](qos-queues.md) |
| Pin SIP/RTP traffic to one WAN with failover | [Sticky voice](voip-sticky.md) |
| Enable and understand a TCP backup connection | [TCP fallback](tcp-fallback.md) |
| Size TUN MTU / TCP MSS; diagnose fragmentation | [MTU/MSS sizing](mtu-mss.md) · [DATAGRAM fragmentation](fragmentation.md) |
| Use multiple overlapping tenant subnet spaces | [Linux VRF isolation](overlapping-subnets-vrf.md) |
| Configure Linux TCX or statistics-only XDP | [TC eBPF](tc-ebpf.md) · [XDP](xdp-multi-instance.md) |
| Find log messages, verify network paths and troubleshoot errors | [Operations and troubleshooting](operations.md) |

## Look up: protocol and implementation details

These pages are intended for maintainers and operators who already have a working deployment.

| Topic | Reference |
| --- | --- |
| TUN creation, cleanup and connected routes | [TUN lifecycle](tun-lifecycle.md) |
| Linux API boundaries and process policy | [Runtime architecture](runtime-architecture.md) |
| QUIC DATAGRAM budget and SIP receive metrics | [Adaptive DATAGRAM and VoIP diagnostics](adaptive-datagram-voip.md) |
| Compression and priority interactions | [Zstd and QoS](zstd-qos.md) |
| TCP fallback framing and security limits | [TLS/TCP wire contract](tcp-fallback.md) |
| Multi-instance XDP statistics | [XDP multi-instance](xdp-multi-instance.md) |

## Testing

The following tests use **real Linux namespaces, TUNs and QUIC** rather than only mocked packet streams. They require privileges and additional packages; CI installs those for you.

| Scenario | Guide and command |
| --- | --- |
| Basic authenticated UDP/TUN | [Overlay integration](overlay-tests.md): `sudo bash tests/integration/overlay-netns.sh udp` |
| Four WANs, shaping, VoIP and failover | [Overlay integration](overlay-tests.md) · [Sticky WAN verification](voip-sticky.md) |
| Five sites, randomized 1–8 WANs, BGP and OSPF | [Five-site FRRouting](five-site-routing.md) |
| Wire confidentiality and temporary diagnostic key logs | [Wire encryption verification](wire-encryption-tests.md) |

The project CI also runs regular Go tests, the race detector, format/module checks, Linux TUN checks and eBPF compilation. Test-only TLS key logs or demo CA keys **must not** be used in production.

## Reading conventions

- Code blocks labeled `bash` are shell commands; `yaml` examples contain configuration. Replace illustrative domains, IPs and paths with values for your environment.
- Documentation is explicit about whether an option is **default**, **opt-in**, **test-only**, or **not supported**.
- `routes` inside Server peer YAML decide **which authenticated QUIC session owns a destination**. Linux kernel routes and OSPF/BGP are a different layer.
- The quickest route to finding a problem is [the symptom table](operations.md#troubleshooting-by-symptom).

The content organization draws on the [Diátaxis documentation framework](https://diataxis.fr/), [GitHub's README guidance](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/about-readmes), and the [Google developer documentation style guide](https://developers.google.com/style/highlights).
