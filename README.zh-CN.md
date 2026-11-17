# mqvpn-ebpf

**采用跨平台 Client Core 与 Linux Server 的多站点三层路由 VPN，基于双向认证的 MASQUE 和多路径 QUIC（MPQUIC）。**

[English](README.md) · [完整文档](docs/README.md) · [双主机入门](docs/getting-started.md) · [故障排查](docs/operations.md)

`mqvpn-server` 通过 Linux TUN 连接多个经过独立身份验证的站点。`mqvpn-client` 的协议与数据包处理核心可以跨平台复用，但 TUN、路由、DNS 和物理网络连接保护需要各操作系统的原生适配。当前完整运行的 Linux Client 通过 TLS 1.3 双向认证（mTLS）、MASQUE CONNECT-ETHERNET、HTTP/3 和 QUIC DATAGRAM 传输 IPv4/IPv6 数据包。一个 Server UDP 监听端口可以借助经过校验的 TLS SNI 承载多个相互隔离的 VPN 租户。

## 项目概览

~~~text
                  mqvpn-server (Linux)
                   一个 UDP/QUIC 监听端口
                             |
                +------------+------------+
                |                         |
          租户 A / mq0               租户 B / mq1
           P2MP 路由                  P2MP 路由
           /     \                         |
       Client A Client B                Client C
         mq0      mq0                    mq0
      （各 Client 可配置并验证多条 MPQUIC WAN 路径）
~~~

每个租户拥有独立 TUN，以及按目的网段选择已认证 Client 会话的授权转发表。**这是三层路由 VPN，不是二层以太网网桥。** Linux 内核路由及可选的 FRRouting 负责把数据送达 VPN；mqvpn 不会自动配置 OSPF、BGP、防火墙或 VRF。

## 功能与平台支持范围

| 能力 | 已实现行为与边界 |
| --- | --- |
| 安全与多租户 | TLS 1.3 mTLS、实例独立的证书验证、显式 Client 证书 CN/Peer 授权、可选 CRL；多租户使用独立 SNI 身份 |
| 传输与多 WAN | HTTP/3/QUIC、有序且经验证的 MPQUIC 路径；连接级 `round_robin` 或 `low_latency` 调度 |
| 路由 | P2MP 目的网段归属、可选的认证路由和 DNS 推送；Linux 转发及 FRR 由管理员配置 |
| QoS 与语音 | 实时、保障、尽力而为三级队列（4:2:1）；可选独立认证的单 WAN SIP/DSCP-EF Sticky 伴随连接 |
| TCP 备用 | 初次 QUIC 握手超时或显式选择 TCP 时，可以使用单 WAN TLS/TCP |
| Linux 数据面 | 自动管理 TUN、可选内置 TCX MSS 调整与统计、仅统计用途的 XDP |
| Server 可用性 | 本地就绪检查及外部 VRRP/Keepalived、HAProxy 接入方案；**尚无已部署的分布式 Peer/租约状态或无缝 QUIC 会话接管** |
| 平台 | **Server 仅支持 Linux；Client 在 Linux 上完整可用。** Windows 二进制与 Wintun 组件尚无法建立可用 VPN 会话；macOS/Android 仅编译共享 Core |

mqvpn 配置**没有固定的 8 WAN 上限**。当前 MPQUIC 依赖库最多支持 **64 条同时活跃路径**；底层网络资源和策略路由还可能施加更严格的限制。详见 [Client WAN 配置](docs/client-config.md)。

## Linux 快速开始

需要 **Go 1.27.4**（以 [go.mod](go.mod) 为准）、Linux `/dev/net/tun`，以及运行 VPN 时所需的网络管理权限。Go 构建使用 `CGO_ENABLED=0` 和内置 eBPF 对象，因此**只编译二进制程序无需 Clang 或 libbpf**。

~~~bash
make release
# 生成 bin/mqvpn-server 和 bin/mqvpn-client
~~~

**首次部署：** 先按[双主机教程](docs/getting-started.md)生成*仅供实验使用的*证书、授权 Client 证书 CN，并创建 Server/Client YAML。配置完成后：

~~~bash
# Linux Server
./bin/mqvpn-server validate --config /etc/mqvpn/server.yaml
sudo ./bin/mqvpn-server --config /etc/mqvpn/server.yaml

# 另一台 Linux 主机
sudo ./bin/mqvpn-client --config /etc/mqvpn/client.yaml
~~~

按教程使用 `ip addr`、`ip route get` 和 `ping` 检查 `mq0` 与隧道连通性。Client 默认自动重连，但重连会创建新的认证会话，不会迁移已建立的加密会话。

## 按任务查阅文档

| 任务 | 文档 |
| --- | --- |
| 建立第一个 VPN 隧道 | [双主机入门](docs/getting-started.md) |
| 配置租户、TLS、Client 地址及路由 | [Server 配置](docs/server-config.md) · [Client 配置](docs/client-config.md) |
| 配置 WAN、VRF 或数据包大小 | [Server 多 WAN](docs/server-multiwan.md) · [VRF 隔离](docs/overlapping-subnets-vrf.md) · [MTU/MSS](docs/mtu-mss.md) |
| 调整路径调度、QoS、语音亲和性或 TCP 备用 | [MPQUIC 调度](docs/multipath-low-latency.md) · [QoS](docs/qos-queues.md) · [Sticky VoIP](docs/voip-sticky.md) · [TCP 备用](docs/tcp-fallback.md) |
| 部署接入故障切换或了解集群设计限制 | [Server HA](docs/high-availability.md) · [集群状态设计](docs/ha-cluster-state-sync.md) |
| 排查故障或了解代码实现 | [运维排障](docs/operations.md) · [运行时架构](docs/runtime-architecture.md) · [项目目录](docs/project-layout.md) |

**[完整文档索引](docs/README.md)**：包含部署、传输、Linux 数据面、HA 设计、平台和测试专题。深入技术文档目前以英语为主。

## 构建与验证

从仓库根目录执行：

~~~bash
make release                           # 构建 Linux 程序
make test                              # Go 包测试
make fmt-check                         # Go 格式检查
make mod-check                         # Go 模块完整性检查
python3 scripts/check-doc-links.py     # Markdown 链接及标题锚点
~~~

在具备 root 权限及 `iproute2`、`iputils-ping`、OpenSSL、Python 3 的隔离 Linux 环境中，可先验证基本认证隧道：

~~~bash
sudo bash tests/integration/overlay-netns.sh udp
~~~

要运行**完整、可重现的 Linux 集成测试场景**，先按[测试文档](docs/README.md#testing)准备额外的内核/FRRouting、网络工具、`tshark` 和 Clang 等依赖，然后执行：

~~~bash
sudo env WAN_SEED=20261115 bash tests/integration/scenario.sh
~~~

这一统一入口失败即停止，覆盖 TUN/TCX、WAN 密文抓包、WAN 劣化、TCP/UDP/VoIP，以及**同一五站点拓扑中的 BGP+OSPF**。两站点专项测试使用各自的隔离环境，以验证不能在同一拓扑共存的故障条件。[GitHub Actions](.github/workflows/go.yml) 还验证竞态、跨平台 Client Core 编译和 eBPF 对象的可复现性。

## 限制与安全边界

- **仅由受信任 CA 签发证书不足以自动授权 Client。** 经过验证的证书身份必须匹配租户对应的 Peer 授权，可选 CRL 还可验证吊销。
- Peer YAML 中的 `routes` 是目的网段到已认证会话的映射，**不是 Linux 内核路由**；主机转发、防火墙、策略路由、VRF 和 FRR 由管理员负责。
- QoS 优先级**不会让每种流量类别自动选择独立 WAN**；Sticky VoIP 固定的是一个流量类别，**不是每通电话**，且使用单 WAN 伴随连接。
- **只有初次 QUIC 握手超时**才会自动触发 TCP 备用；认证失败不会静默降级，而且 TCP 备用仅使用一条 WAN。
- Server 本地健康检查与外部 VIP/接入故障切换**不提供**共享 IP 租约、跨 Server 会话归属仲裁或既有 QUIC/TLS 会话的无缝接管。
- 自动选择的 TUN MTU 不是端到端路径 MTU 保证，应根据实际网络验证封装预算与协商后的分片能力。
- CI 是可复现的实验室回归测试，**不是**生产吞吐、语音质量、零丢包或安全认证。不要部署实验 CA/私钥或测试 TLS 密钥日志。

## 项目状态与问题反馈

项目入口是 `cmd/mqvpn-server` 和 `cmd/mqvpn-client`；`internal/` 下按 Client、Linux Server、共享协议与数据面划分职责。详见[项目目录](docs/project-layout.md)与[平台支持状态](docs/client-platforms.md)。

遇到问题请先查看[按症状排障](docs/operations.md#troubleshooting-by-symptom)，再通过 [GitHub Issues](https://github.com/roseshot/mqvpn-ebpf/issues) 提供提交版本、Linux 内核、复现步骤与**脱敏日志**。不要公开私钥、密码、解密抓包或 TLS 密钥日志。
