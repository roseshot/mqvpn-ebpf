# Linux runtime architecture and process policy

Production code is Go-only (`CGO_ENABLED=0`). The server and client do
not shell out to configure network interfaces, compute MTUs, or attach
eBPF. The permitted Linux interface operations are performed with Go
standard-library APIs and Go modules.

| Responsibility | Package / Go module | Execution model |
| --- | --- | --- |
| TUN naming, IP/MTU validation | `internal/tun/config.go` | Pure Go validation |
| TUN creation or attach | `internal/tun/device_linux.go` | `/dev/net/tun` + Linux `TUNSETIFF` ioctl |
| TUN IP/CIDR, MTU, UP, ready checks | `internal/tun/configure_linux.go` | `github.com/vishvananda/netlink` |
| WAN source IP/interface resolution | `internal/wan/socket_linux.go` | Go `net` |
| UDP/QUIC and TCP/TLS device pinning | `internal/wan/bind_linux.go` | Shared `SO_BINDTODEVICE` socket control |
| WAN MTU / route-table *inspection* | `internal/wan/mtu_linux.go` | Go `net` + `github.com/vishvananda/netlink` |
| TUN frame and path-MTU budget | `internal/mtu/plan.go` | Pure Go calculation |
| XDP attach and maps | `internal/xdp/dispatcher_linux.go` | `github.com/cilium/ebpf` |
| QUIC/HTTP3/MPQUIC | Go `github.com/qoke/mp-quic-go` | Pure Go networking |
| HTTP/1.1/TCP fallback capsules | `internal/capsule` | Pure Go framing |

The TUN driver creates or attaches the configured interface, sets
its IP/CIDR and MTU, brings it UP and checks readiness. The Linux kernel
adds the normal connected-prefix route as part of address configuration.
The daemon does not explicitly insert/delete custom routes, policy
rules, VRFs, multicast routes or firewall settings.

The `internal/architecture` test parses all production source files
under `internal`, `cmd/mqvpn-server` and `cmd/mqvpn-client` and fails
if an external-process API such as `os/exec`, `os.StartProcess` or
`syscall.Exec` is introduced. Development-only `_test.go` files,
build tooling and scripts are outside this production restriction.

**Development/build commands are allowed:** the existing
`scripts/gen-dev-certs.sh` invokes OpenSSL to create short-lived
development-only credentials; `make bpf` invokes Clang/LLVM to compile
the eBPF ELF. These commands run in the developer/CI environment,
not in the VPN runtime. There is no need to replace them with custom
Go certificate or eBPF compilers.

There is intentionally no new submodule: the repository's root
`go.mod` declares the Go dependencies. `internal` package boundaries
separate Linux device access, local WAN discovery, sizing policy and
the network transport rather than spawning commands or duplicating
Linux socket setup.
