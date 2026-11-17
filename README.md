# mqvpn-ebpf

**A routed multi-site VPN with a cross-platform Client Core, a Linux Server, and authenticated MASQUE over Multipath QUIC (MPQUIC).**

[简体中文](README.zh-CN.md) · [Documentation](docs/README.md) · [Two-host setup](docs/getting-started.md) · [Troubleshooting](docs/operations.md)

`mqvpn-server` connects independently authenticated sites through Linux TUN devices. The `mqvpn-client` protocol and packet-processing core is portable across operating systems; native TUN, routing, DNS and underlay protection remain platform-specific. On Linux, the operational Client uses TLS 1.3 mutual authentication (mTLS) and carries IPv4/IPv6 over MASQUE CONNECT-ETHERNET, HTTP/3 and QUIC DATAGRAMs. Multiple isolated tenants share **one Server UDP listener**, selected through verified TLS SNI.

## Overview

~~~text
                    mqvpn-server (Linux)
                     one UDP/QUIC listener
                              |
                 +------------+------------+
                 |                         |
           Tenant A / mq0            Tenant B / mq1
            P2MP routing              P2MP routing
             /     \                       |
         Client A Client B              Client C
           mq0      mq0                  mq0
        (each Client can use validated MPQUIC WAN paths)
~~~

Each tenant owns a TUN and a peer-authorization map that selects the authenticated Client session for each destination prefix. **This is a routed L3 VPN, not an Ethernet bridge.** Kernel routes and optional FRRouting determine how packets reach the VPN; mqvpn does not configure OSPF, BGP, firewalls or VRFs.

## Capabilities and platform scope

| Area | Implemented behavior and boundary |
| --- | --- |
| Security and tenancy | TLS 1.3 mTLS; instance-local certificate checks, explicit Client certificate-CN/Peer authorization and optional CRLs; distinct SNI identities for multiple tenants |
| Transport | HTTP/3 over QUIC, ordered validated MPQUIC paths; connection-wide `round_robin` or `low_latency` scheduling |
| Routing | P2MP destination ownership, optional authenticated route/DNS pushes; Linux forwarding and FRR are external |
| QoS and voice | Realtime/assured/best-effort queues (4:2:1); optional separately authenticated single-WAN SIP/DSCP-EF sticky companion |
| TCP alternative | Optional single-WAN TLS/TCP, either explicitly selected or used after **initial** QUIC handshake timeout |
| Linux data plane | Managed TUN, optional embedded TCX MSS clamp and counters, optional statistics-only XDP |
| Server availability | Local readiness and external VRRP/Keepalived or HAProxy ingress patterns; **no deployed distributed peer/lease state or seamless QUIC takeover** |
| Platforms | **Server: Linux only. Client: fully operational on Linux.** Windows binary/Wintun components do not yet provide a working VPN session; macOS/Android only compile shared core |

mqvpn configuration has **no fixed 8-WAN limit**. The current MPQUIC dependency caps **simultaneously active paths at 64**; real underlay resources and policy routing can impose tighter limits. See [Client WAN configuration](docs/client-config.md).

## Quick start on Linux

Requirements: **Go 1.27.4** (see [go.mod](go.mod)), Linux `/dev/net/tun`, and network administration privileges for running the VPN. Go builds use `CGO_ENABLED=0` and bundled eBPF objects, so building the binaries does not require Clang or libbpf.

~~~bash
make release
# Produces bin/mqvpn-server and bin/mqvpn-client
~~~

For your **first deployment**, follow [the two-host guide](docs/getting-started.md) to generate *lab-only* certificates, authorize a Client CN and create the Server/Client YAML. Then:

~~~bash
# Linux Server
./bin/mqvpn-server validate --config /etc/mqvpn/server.yaml
sudo ./bin/mqvpn-server --config /etc/mqvpn/server.yaml

# Another Linux host
sudo ./bin/mqvpn-client --config /etc/mqvpn/client.yaml
~~~

Check `mq0` and traffic using `ip addr`, `ip route get` and `ping` as shown in the guide. The Client reconnects by default; a reconnect creates a new authenticated session rather than migrating an existing one.

## Find the right guide

| Goal | Where to read |
| --- | --- |
| Establish a first tunnel | [Getting started](docs/getting-started.md) |
| Configure tenants, TLS, Client addresses and routes | [Server configuration](docs/server-config.md) · [Client configuration](docs/client-config.md) |
| Configure WAN paths, VRFs or packet sizes | [Server multi-WAN](docs/server-multiwan.md) · [VRF isolation](docs/overlapping-subnets-vrf.md) · [MTU/MSS](docs/mtu-mss.md) |
| Choose scheduling, QoS, voice affinity or TCP backup | [MPQUIC scheduling](docs/multipath-low-latency.md) · [QoS](docs/qos-queues.md) · [Sticky voice](docs/voip-sticky.md) · [TCP fallback](docs/tcp-fallback.md) |
| Plan ingress failover or understand cluster limits | [Server HA](docs/high-availability.md) · [Cluster state design](docs/ha-cluster-state-sync.md) |
| Troubleshoot or explore internals | [Operations](docs/operations.md) · [Runtime architecture](docs/runtime-architecture.md) · [Source layout](docs/project-layout.md) |

**[Full documentation index](docs/README.md):** deployment, transport, Linux data plane, HA design, platform support and tests.

## Build and validate

From the repository root:

~~~bash
make release                           # Linux executables
make test                              # Go package tests
make fmt-check                         # Go formatting
make mod-check                         # Module integrity
python3 scripts/check-doc-links.py     # Markdown links and heading anchors
~~~

A basic authenticated tunnel can be tested in isolated Linux namespaces with root privileges, `iproute2`, `iputils-ping`, OpenSSL and Python 3:

~~~bash
sudo bash tests/integration/overlay-netns.sh udp
~~~

For the **complete reproducible Linux integration scenario**, first install the additional kernel/FRRouting, networking, `tshark` and Clang dependencies described under [Testing](docs/README.md#testing), then run:

~~~bash
sudo env WAN_SEED=20261115 bash tests/integration/scenario.sh
~~~

This single fail-fast entrypoint covers TUN/TCX, encrypted WAN captures, WAN impairments, TCP/UDP/VoIP and a persistent **five-site BGP+OSPF** topology. Isolated two-site fixtures exercise mutually incompatible impairment conditions. [GitHub Actions](.github/workflows/go.yml) also checks race detection, portable Client builds and eBPF object reproducibility.

## Limits and security

- A trusted CA **does not automatically authorize a Client**. The verified certificate identity must match tenant-specific Peer authorization; optional CRLs enforce revocation.
- Peer YAML `routes` map destinations to authenticated sessions; they are **not Linux kernel routes**. Administrators own forwarding, firewalls, policy routing, VRFs and FRR.
- QoS priority **does not select an independent WAN per class**. Sticky voice pins a traffic class, **not an individual call**, through a single-WAN companion.
- Automatic TCP fallback occurs only after an **initial QUIC handshake timeout**, never after authentication failure, and uses one WAN.
- Server-local health checks and external VIP/ingress failover do **not** provide shared IP leases, cross-Server ownership or seamless QUIC/TLS session takeover.
- Auto-selected TUN MTU is not an end-to-end path MTU guarantee. Validate transport size budgets and negotiated fragmentation for your paths.
- CI is a reproducible lab regression, **not** a throughput, voice-quality, zero-loss or production-security certification. Never deploy lab CA/private keys or test TLS traffic-secret logs.

## Project status and help

The entrypoints are `cmd/mqvpn-server` and `cmd/mqvpn-client`. Code is separated into Client, Linux Server and shared protocol/data-plane packages under `internal/`; see [project layout](docs/project-layout.md) and [platform support](docs/client-platforms.md).

Start with [symptom-based troubleshooting](docs/operations.md#troubleshooting-by-symptom), then file a [GitHub issue](https://github.com/roseshot/mqvpn-ebpf/issues) with the commit/version, Linux kernel, reproduction steps and **sanitized** logs. Never publish private keys, passwords, decrypted captures or TLS key logs.
