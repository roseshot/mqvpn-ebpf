# mqvpn-ebpf

[English](README.md) · [文档导航](docs/README.md) · [部署教程](docs/getting-started.md)

**基于 Linux 的多站点加密 VPN。** 使用 MASQUE CONNECT-ETHERNET、HTTP/3、TLS 1.3 和多路径 QUIC（MPQUIC），通过一个 Server 把多个经过证书授权的站点连接起来。

项目由两个程序组成：`mqvpn-server` 和 `mqvpn-client`。数据通过 Linux TUN 设备传输，是**三层路由 VPN**，不是二层以太网交换机，也不会自动配置 BGP、OSPF 或防火墙。

## 项目能做什么？

| 能力 | 实际行为 |
| --- | --- |
| 加密与身份验证 | TLS 1.3 + 双向 TLS（mTLS）；Server 按证书 CN 映射已授权 Peer，可选使用 CRL 验证吊销 |
| 多租户 | 一个 UDP/QUIC 监听端口；通过校验过的 TLS SNI 选择相互隔离的 VPN 实例 |
| 多 WAN | 每个 Client 可配置多条有序 QUIC 路径；支持 `round_robin` 和连接级 `low_latency` 策略 |
| Server 高可用 | Server 本地健康检测、Keepalived/VRRP UDP VIP 主备、HAProxy TCP 主备或双活；Client 无需 HA 配置 |
| QoS | 实时、保障、尽力而为三级独立队列，按 4:2:1 加权调度 |
| VoIP | 可选的 SIP/DSCP EF 独立 Sticky WAN，支持故障切换 |
| 路由 | Server 按认证 Peer 的目的网段转发；支持推送路由、DNS，动态路由由外部 FRRouting 管理 |
| TCP 备用 | 仅初次 QUIC 握手超时时，可按配置转向 TLS/TCP；备用传输仅使用一条 WAN |
| Linux eBPF | 可选的 TCX MSS 调整与统计；XDP 当前只做统计，不提供 AF_XDP 零拷贝 |

**要注意：** QoS 的保障流量和普通流量共用 MPQUIC 连接；优先级影响本地队列调度，并不意味着每个 DSCP 等级都有独立 WAN。Sticky VoIP 按流量类别固定 WAN，不是每通电话各选一条。

## 从哪里开始？

第一次使用建议按以下顺序：

1. 阅读[双主机部署教程](docs/getting-started.md)，准备 Linux、证书和认证 Peer。
2. 使用 `make release` 构建 Server、Client。
3. 配置 Server 的 `server_name`、TUN 地址和 Peer 指纹，再运行 `mqvpn-server validate`。
4. 配置 Client，确保公网/内网物理地址可达，启动 VPN。
5. 用 `ip addr`、`ip route get` 和 `ping` 检验数据是否经过 TUN。

在 Linux 实验机上，也可以直接运行隔离的双站点测试：

```bash
make release
sudo bash tests/integration/overlay-netns.sh udp
```

需要 Go **1.27.4**（以 `go.mod` 为准）、`/dev/net/tun`、Linux 网络管理权限、`iproute2`、OpenSSL 和 Python 3。编译 Go 程序不需要 CGO，也不用在部署时安装 Clang。上述测试会使用临时证书和网络命名空间，**不能把测试证书作为生产环境凭据**。

## 常见任务与对应文档

| 想做的事 | 文档 |
| --- | --- |
| 完整搭建第一个 Server 和 Client | [入门教程](docs/getting-started.md) |
| 配置多租户、证书 CN、CRL、动态地址、路由及 DNS | [Server 配置](docs/server-config.md) |
| 配置 Client、认证、重连、WAN 列表 | [Client 配置](docs/client-config.md) |
| 在一条连接上使用多个 Server WAN IP | [Server 多 WAN](docs/server-multiwan.md) |
| 根据 DSCP 优化转发队列 | [QoS 分级队列](docs/qos-queues.md) |
| SIP/RTP 固定单 WAN 和失效切换 | [Sticky VoIP](docs/voip-sticky.md) |
| 测试五站点、随机 1–8 WAN、OSPF/BGP | [五站点路由测试](docs/five-site-routing.md) |
| 处理 MTU、路由、证书、网络连通性问题 | [运维与故障排查](docs/operations.md) |
| 查阅架构、其他测试与高级选项 | [完整文档目录](docs/README.md) |

现有的深入技术文档以英语编写；本页提供中文项目概览和操作入口。

## 构建、测试和运行

```bash
make release      # 构建 bin/mqvpn-server、bin/mqvpn-client
make test         # Go 单元测试
make fmt-check    # 检查 Go 格式
make mod-check    # 检查模块完整性

# 配置文件准备好后：
./bin/mqvpn-server validate --config /etc/mqvpn/server.yaml
sudo ./bin/mqvpn-server --config /etc/mqvpn/server.yaml
# 在另一个 Linux 主机运行：
sudo ./bin/mqvpn-client --config /etc/mqvpn/client.yaml
```

Server 采用 YAML；Client 既可以用 YAML，也可以通过命令行覆盖配置。Client 默认自动重连。日志输出到 stderr，可以增加 `--log-level debug` 或 `--log-format json` 观察故障。

## 安全边界

- 客户端必须通过实例的 mTLS 证书链校验、可选 CRL 检查，并与该实例配置的 CN/Peer 身份相匹配。仅有 CA 签名不足以自动获得网段访问权。
- Server Peer YAML 的 `routes` 是“目的前缀对应哪个认证会话”的映射，不是 Linux 系统路由表。
- 跨站点转发、Linux VRF、策略路由、防火墙和 OSPF/BGP 需要根据你的拓扑另行配置。
- 单一 UDP 端口下的多租户必须有独立 TLS SNI 身份；客户端连接必须校验证书域名或 IP SAN。
- 自动 TCP 备用不在认证失败时静默降级，也不提供运行中的无缝 QUIC/TCP 切换。
- CI 验证的是可重复的 Linux 实验拓扑，不能等同于生产网络的吞吐、音质、可靠性或安全认证。

如遇问题，先看[故障现象速查](docs/operations.md#troubleshooting-by-symptom)，再提交带有版本、Linux 内核、脱敏日志和复现步骤的 [GitHub Issue](https://github.com/roseshot/mqvpn-ebpf/issues)。请勿上传私钥、客户端凭据或 TLS 测试密钥日志。
