# TLS/TCP fallback for CONNECT-ETHERNET

[Documentation index](README.md) · [Transport, routing, and traffic policy](README.md#transport-routing-and-traffic-policy)

> **Document scope:** **Optional transport reference.** Forced TCP or an initial QUIC handshake timeout may use a separate single-WAN TLS/TCP connection; authentication failures never trigger a silent downgrade.

## On this page

- [Wire protocol](#wire-protocol)
- [Configuration](#configuration)
- [Limits / security](#limits--security)
- [Default TUN MTU on TCP](#default-tun-mtu-on-tcp)

## Wire protocol

The primary data path is HTTP/3 Extended CONNECT over Multipath QUIC on
**UDP/443**, with unreliable QUIC DATAGRAM frames.

The optional backup is CONNECT-ETHERNET over encrypted TCP using the
**HTTP/1.1 Upgrade** representation in
[draft-ietf-masque-connect-ethernet-18](https://datatracker.ietf.org/doc/html/draft-ietf-masque-connect-ethernet-18),
rather than the HTTP/2 Extended CONNECT variant.

TCP client requests:

~~~http
GET /.well-known/masque/ethernet/ HTTP/1.1
Host: customer-a.vpn.example.com
Connection: Upgrade
Upgrade: connect-ethernet
Capsule-Protocol: ?1
~~~

Success response:

~~~http
HTTP/1.1 101 Switching Protocols
Connection: Upgrade
Upgrade: connect-ethernet
Capsule-Protocol: ?1
~~~

After the blank line, both sides send RFC 9297 DATAGRAM Capsules:

    QUIC varint Capsule Type=0x00
    QUIC varint Capsule Length
    QUIC varint Context ID=0
    Synthetic Ethernet header + complete IPv4/IPv6 packet

Frames are unchanged by the fallback transport. RFC 9297 capsule framing
is not interchangeable with HTTP/3 QUIC DATAGRAM frames: the TCP stream
never sends HTTP/3 Quarter Stream ID bytes.

## Configuration

~~~yaml
# /etc/mqvpn/server.yaml
# UDP/443 is the default even if listen is omitted
tcp_fallback:
  enabled: true
  # listen: "0.0.0.0:443"  # TCP/443 default
instances:
  - name: customer-a
    server_name: customer-a.vpn.example.com
    tun: mq0
    address: 10.77.0.1/24
    mtu: 1100
    peers: /etc/mqvpn/peers-a.yaml
    cert: /etc/mqvpn/tls/a.crt
    key: /etc/mqvpn/tls/a.key
    client_ca: /etc/mqvpn/tls/a-clients.crt
~~~

Every TCP request negotiates TLS 1.3 ALPN "http/1.1". The **same live
SNI registry** as UDP selects the tenant TLS certificate and client CA.
Incoming HTTP Host and TLS SNI must match that tenant. The already-authenticated
client DER certificate fingerprint must be present in that instance's
Peer YAML; a different tenant is not silently selected.

~~~bash
# Default: attempt UDP first; only if initial UDP handshake times out
# connect to the same host/port over TCP.
mqvpn-client --transport auto --udp-dial-timeout 5s \
  --server customer-a.vpn.example.com \
  --wan 192.0.2.2@enp1s0 --tun mq0 --tun-address 10.77.0.2/24 \
  --ca /etc/mqvpn/a-ca.crt \
  --cert /etc/mqvpn/a-client.crt --key /etc/mqvpn/a-client.key

# Force TCP from the outset (single WAN).
mqvpn-client --transport tcp \
  --server customer-a.vpn.example.com \
  --connect-ip 198.51.100.10 \
  --wan 192.0.2.2@enp1s0 --tun mq0 --tun-address 10.77.0.2/24 \
  --ca /etc/mqvpn/a-ca.crt \
  --cert /etc/mqvpn/a-client.crt --key /etc/mqvpn/a-client.key
~~~

A server occupying TCP/443 cannot share that TCP socket with mqvpn's
fallback listener unless another application-level multiplexer is
provided. UDP/443 and TCP/443 are independent sockets and can both bind.

## Limits / security

- The TCP fallback is **opt-in on the server**; its address/listener
  lifecycle can be changed only by a daemon restart.
- Automatic fallback is **only** used if QUIC fails to complete its initial
  connection handshake before --udp-dial-timeout. No fallback occurs for
  TLS/CA/peer authentication failures, HTTP rejection, or application errors.
- There is no continuous UDP health probe, in-session TCP-to-UDP return,
  or seamless switching of an active session. Client reconnects by default
  after a failed or disconnected QUIC/TCP session, with 1s–30s
  exponential backoff. Each retry starts over with QUIC in `auto`
  mode and may use TCP only after a *new* initial QUIC handshake timeout.
  Set `reconnect: false` or `--reconnect=false` to disable retries.
- Only the primary WAN source/interface can be used by TCP. AF_XDP and
  MPQUIC dual-WAN scheduling remain UDP-only.
- Like other TCP-over-TCP tunnels, nested retransmissions and head-of-line
  blocking may significantly reduce latency and throughput under loss.
- Server and Client manage their named TUN IP/CIDR, MTU and UP state.
  When Client accepts a Server `push_routes` advertisement it also
  manages those authenticated routes plus an underlay-protecting host
  route. It does not add VRFs, policy routing rules, multicast entries
  or inner packet filters.
- CI exercises encrypted TLS/TCP fallback in real network namespaces with
  positive TLS-key-based wire decryption checks (`crypto-tcp`) as well as
  protocol unit tests. It does **not** establish hardware N200/I226
  throughput or production failover performance.

Specifications:
- CONNECT-ETHERNET draft-18: https://datatracker.ietf.org/doc/html/draft-ietf-masque-connect-ethernet-18
- RFC 9297 Capsule Protocol: https://www.rfc-editor.org/rfc/rfc9297


### Independent UDP/TCP port numbers

Client `--server hostname[:port]` selects the QUIC **UDP** port
(443 if omitted). The independent `--tcp-port` selects fallback
**TCP** port (443 by default, regardless of the UDP port). For example:

~~~bash
mqvpn-client --transport auto --udp-dial-timeout 5s \
  --server customer-a.vpn.example.com:54433 \
  --tcp-port 8443 \
  --wan 192.0.2.2@enp1s0 --tun mq0 --tun-address 10.77.0.2/24 \
  --ca /etc/mqvpn/a-ca.crt \
  --cert /etc/mqvpn/a-client.crt --key /etc/mqvpn/a-client.key
~~~

Here QUIC attempts UDP/54433; TCP fallback connects to TCP/8443,
with HTTP Host `customer-a.vpn.example.com:8443` and unchanged TLS SNI.
Configure matching Server `listen` and `tcp_fallback.listen` addresses.


## Default TUN MTU on TCP

When Client `--tun-mtu` and `--max-frame` are omitted, forced TCP
fallback calculates its initial TUN MTU from the actual local primary
WAN interface MTU, capped at 1400, and sets `max_frame=MTU+14`.
This uses the same automatic sizing planner as UDP/MPQUIC, even though
TCP can segment Capsules into stream bytes. TCP mode does not use WAN2.

## Related documentation

- [Client configuration](client-config.md)
- [Server configuration](server-config.md)
- [MTU/MSS sizing](mtu-mss.md)
