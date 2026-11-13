# TLS/TCP fallback for CONNECT-ETHERNET

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
  --url https://customer-a.vpn.example.com/.well-known/masque/ethernet/ \
  --source-interface enp1s0 --tun mq0 --tun-address 10.77.0.2/24 \
  --ca /etc/mqvpn/a-ca.crt \
  --cert /etc/mqvpn/a-client.crt --key /etc/mqvpn/a-client.key

# Force TCP from the outset (single WAN).
mqvpn-client --transport tcp \
  --url https://198.51.100.10/.well-known/masque/ethernet/ \
  --server-name customer-a.vpn.example.com \
  --source-interface enp1s0 --tun mq0 --tun-address 10.77.0.2/24 \
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
- There is currently no continuous UDP health probe, TCP-to-UDP automatic
  return, or seamless switching of an active client session. Site reconnection
  still requires restarting the Client on a session failure.
- Only the primary WAN source/interface can be used by TCP. AF_XDP and
  MPQUIC dual-WAN scheduling remain UDP-only.
- Like other TCP-over-TCP tunnels, nested retransmissions and head-of-line
  blocking may significantly reduce latency and throughput under loss.
- Server and Client manage only their named TUN IP/CIDR, MTU and UP
  state. Linux creates the normal connected-prefix route automatically;
  mqvpn does not explicitly add custom routes, VRFs, policy routing,
  kernel multicast entries or inner packet filters.
- No hardware N200/I226 failover benchmark or network namespace E2E tests
  have been run. CI includes unit-level TLS/HTTP Upgrade tests only.

Specifications:
- CONNECT-ETHERNET draft-18: https://datatracker.ietf.org/doc/html/draft-ietf-masque-connect-ethernet-18
- RFC 9297 Capsule Protocol: https://www.rfc-editor.org/rfc/rfc9297


### Independent UDP/TCP port numbers

Client `--url` selects the QUIC **UDP** port (443 if omitted).
The independent `--tcp-port` selects the fallback **TCP** port
(443 by default, regardless of the QUIC URL). For example:

~~~bash
mqvpn-client --transport auto --udp-dial-timeout 5s \
  --url https://customer-a.vpn.example.com:54433/.well-known/masque/ethernet/ \
  --tcp-port 8443 \
  --source-interface enp1s0 --tun mq0 --tun-address 10.77.0.2/24 \
  --ca /etc/mqvpn/a-ca.crt \
  --cert /etc/mqvpn/a-client.crt --key /etc/mqvpn/a-client.key
~~~

Here QUIC attempts UDP/54433; TCP fallback connects to TCP/8443,
with HTTP Host `customer-a.vpn.example.com:8443` and unchanged TLS SNI.
Configure matching Server `listen` and `tcp_fallback.listen` addresses.
