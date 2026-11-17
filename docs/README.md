# Documentation

[Project README](../README.md) · [简体中文项目简介](../README.zh-CN.md) · [Report an issue](https://github.com/roseshot/mqvpn-ebpf/issues)

Use this page to find the right guide. The [project README](../README.md) summarizes what mqvpn does; the pages below explain how to deploy, operate, test, and develop it. The Server runtime is Linux-only, while the Client protocol core is cross-platform; a complete native VPN Client currently runs on Linux. See [platform support](client-platforms.md) for each operating system's implementation status.

## Start here

| If you want to… | Start with |
| --- | --- |
| Establish your first authenticated tunnel | [Getting started](getting-started.md) |
| Configure a deployed Server or Client | [Server configuration](server-config.md) and [Client configuration](client-config.md) |
| Diagnose a tunnel, route, certificate, or WAN failure | [Operations and troubleshooting](operations.md) |
| Run the complete network integration suite | [Testing](#testing) |
| Find the relevant Go package | [Project layout](project-layout.md) and [Runtime architecture](runtime-architecture.md) |

## Deploy and operate

| Guide | Scope |
| --- | --- |
| [Getting started](getting-started.md) | Build binaries, create test credentials, authorize a Client peer, and verify a two-host TUN connection |
| [Server configuration](server-config.md) | Tenant instances, certificate CN authorization, peer destinations, CRLs, tunnel pools, pushed routes/DNS, and reload |
| [Client configuration](client-config.md) | Endpoint identity, ordered WANs, TUN, TLS credentials, reconnection, and optional route/DNS handling |
| [Server multi-WAN](server-multiwan.md) | Advertise multiple physical Server IPs on one shared QUIC listener |
| [High availability](high-availability.md) | Server-local readiness, VRRP/Keepalived UDP VIP failover, and HAProxy TLS/TCP ingress; deployment constraints |
| [Overlapping subnets and VRF](overlapping-subnets-vrf.md) | Isolate overlapping tenant networks using Linux routing tables and VRFs |
| [Operations and troubleshooting](operations.md) | Check live sessions, WAN reachability, kernel routes, FRR, logging, and safe reload |

## Transport, routing, and traffic policy

| Guide | Scope |
| --- | --- |
| [Low-latency multipath scheduling](multipath-low-latency.md) | Choose connection-wide `round_robin` or `low_latency` MPQUIC policy |
| [TCP fallback](tcp-fallback.md) | Optional initial-handshake fallback to single-WAN TLS/TCP and its security limits |
| [QoS queues](qos-queues.md) | Realtime, assured, and best-effort traffic classification and bounded queues |
| [Sticky voice](voip-sticky.md) | SIP/DSCP-EF single-WAN QUIC companion and failover |
| [MTU and TCP MSS](mtu-mss.md) | Calculate inner TUN frame budgets and MSS clamping |
| [DATAGRAM fragmentation](fragmentation.md) | Negotiated fragmentation, reassembly, and MPQUIC size limits |
| [Zstd and QoS](zstd-qos.md) | Negotiated compression and priority-packet handling |
| [Adaptive DATAGRAM and VoIP diagnostics](adaptive-datagram-voip.md) | QUIC datagram-size feedback and RTP/RTCP receive indicators |

## Linux data plane

| Guide | Scope |
| --- | --- |
| [TUN lifecycle](tun-lifecycle.md) | TUN setup, connected routes, cleanup, and ownership |
| [TC eBPF](tc-ebpf.md) | Embedded TCX programs, TCP MSS policy, and kernel requirements |
| [XDP multi-instance](xdp-multi-instance.md) | Statistics-only XDP attachment and interface metrics; no AF_XDP forwarding |

## High-availability control plane: design and local primitives

**Do not treat the following as a deployed HA cluster.** The current implementation provides Server-local readiness and deployment-level ingress failover. Production quorum replication, distributed policy/CRL reconciliation, fenced cross-Server admission, and live QUIC session takeover are **not implemented**.

| Design reference | Status and purpose |
| --- | --- |
| [HA cluster state synchronization](ha-cluster-state-sync.md) | Proposed N-node replication, ordering, fencing, and acceptance criteria |
| [ClusterStore contract](ha-cluster-store.md) | Backend-neutral store interface and separation of node-local and shared state; no production consensus backend |
| [Keyed lease state machine](ha-keyed-lease-state.md) | Local deterministic peer/IP lease transitions, not a distributed lease service |
| [Ownership fencing](ha-ownership-fence.md) | Local epoch verification primitive, not yet connected to P2MP admission |

See [HA deployment guidance](high-availability.md) for supported ingress patterns and [tracking issue #43](https://github.com/roseshot/mqvpn-ebpf/issues/43) for unfinished cluster work.

## Architecture and platform support

| Guide | Scope |
| --- | --- |
| [Runtime architecture](runtime-architecture.md) | Server/Client boundaries, authenticated sessions, and Linux resources |
| [Project layout](project-layout.md) | Source directories, Go package ownership, and dependency direction |
| [Client platforms](client-platforms.md) | Linux support, Windows Wintun primitives and fail-closed Client, and portable macOS/Android core |

## Testing

CI validates the Linux data plane and encrypted traffic with real namespaces, TUN devices, QUIC and FRRouting. From the **repository root** on a prepared, isolated Linux host with root privileges and the documented test dependencies:

```bash
sudo env WAN_SEED=20261115 bash tests/integration/scenario.sh
```

That **single integration entrypoint** runs kernel TCX/TUN checks, wire-encryption assertions, two-site WAN impairment and transport probes, then a shared five-site MPQUIC topology with concurrent BGP/OSPF and cross-Client TCP/UDP/VoIP traffic. `WAN_SEED` makes WAN selection reproducible. The two-site phases use separate namespaces because they require conflicting network conditions.

| Focused test guide | What it covers |
| --- | --- |
| [Overlay tests](overlay-tests.md) | Two-site QUIC/TUN, four WANs, failover, VXLAN, TCP/UDP, and SIP/RTP/RTCP |
| [Five-site FRRouting](five-site-routing.md) | Reproducible multi-WAN topology, BGP/OSPF route and adjacency checks, cross-site forwarding |
| [Wire encryption tests](wire-encryption-tests.md) | Ciphertext capture, validation of confidentiality, and explicitly test-only TLS key logging |

For unprivileged checks, run `make test` and `python3 scripts/check-doc-links.py` from the repository root. GitHub Actions additionally checks Go formatting, modules, race conditions, cross-platform compilation and eBPF ELF reproducibility. **Never use generated lab certificates or TLS key logs in production.**

## Reading notes

- **Peer destination ownership is not a kernel route.** A Server peer's YAML `routes` control which authenticated Client receives traffic; Linux FIB entries, IP forwarding, firewalls and OSPF/BGP are configured separately.
- **Separate implemented behavior from design.** Pages label optional features, local-only HA primitives, and not-yet-supported distributed capabilities explicitly.
- Commands and configuration examples assume an isolated Linux lab unless otherwise stated. Replace illustrative domains, IP addresses, paths and credentials before deployment.
