# Get started: connect two Linux sites

**Outcome:** An authenticated `mqvpn-client` connects to `mqvpn-server` over QUIC, creates a Linux TUN interface and can ping the Server's tunnel address.

This is a **lab setup on two Linux hosts**. It uses static tunnel addresses, one WAN, and test-only credentials to keep the path visible. You can add WANs, dynamic addresses and FRRouting after the first connection works.

## Before you start

You need:

- Two Linux hosts or VMs that can reach each other over UDP/8443; use root or the capabilities needed to manage TUN and routes. The Server can listen on another port if you update both configurations.
- Linux with `/dev/net/tun`; `iproute2`, OpenSSL and a Go toolchain matching `go.mod` (**Go 1.27.4**). Use different host namespaces or distinct physical machines so both sides can use a local `mq0`.
- An available, nonconflicting tunnel prefix. This example uses `10.77.0.0/24`, Server `.1` and Client `.2`. Use **your own non-overlapping range** for a real deployment.
- A hostname used as the Server's authenticated DNS identity, for example `vpn.example.test`. A lab can pin the actual server WAN IP with `connect_ip` so that the name does not have to resolve publicly.

> **Security:** `scripts/gen-dev-certs.sh` creates a short-lived test CA and private keys. Never copy these demo keys into production, publish them in a PR, or use them as persistent infrastructure credentials.

## Build the binaries

Run on both hosts after cloning the repository:

```bash
make release
./bin/mqvpn-client --help
./bin/mqvpn-server --help
```

This produces `bin/mqvpn-client` and `bin/mqvpn-server`. Building only the Go binaries does **not** require Clang or root access. Running TUN devices requires elevated Linux network privileges.

## Create a lab CA and certificates

On the **Server** host, from the repository root:

```bash
bash scripts/gen-dev-certs.sh "$PWD/demo-certs" vpn.example.test
openssl x509 -in demo-certs/server.crt -noout -text | grep -A2 "Subject Alternative Name"
openssl x509 -in demo-certs/client.crt -noout -subject
```

The Client certificate **CN** from the final command is `mqvpn-client`. This identity must match a Server-authorized Peer entry.

Copy **only** the appropriate test materials to the Client using a secure transfer: `ca.crt`, `client.crt` and `client.key`. Keep `ca.key` and `server.key` on the Server. Use paths readable by the daemon without relaxing private-key permissions.

## Configure the Server

Create `/etc/mqvpn/peers.yaml` on the **Server**:

```yaml
peers:
  - id: site-1
    certificate_cn: mqvpn-client
    routes:
      - 10.77.0.2/32
```

The Server first verifies mTLS against the configured Client CA and optional CRL, then maps the verified Client certificate CN to this instance's explicitly authorized Peer. Neither a trusted CA nor an arbitrary CN alone grants routes. The `routes` entry tells the Server's P2MP hub which authenticated session owns `10.77.0.2`. It is **not** a command to install a Linux route.

Create `/etc/mqvpn/server.yaml` (substitute your **absolute** certificate paths):

```yaml
listen: "0.0.0.0:8443"
instances:
  - name: lab
    server_name: vpn.example.test
    tun: mq0
    address: 10.77.0.1/24
    peers: /etc/mqvpn/peers.yaml
    cert: /absolute/path/demo-certs/server.crt
    key: /absolute/path/demo-certs/server.key
    client_ca: /absolute/path/demo-certs/ca.crt
```

Validate before opening any listener:

```bash
./bin/mqvpn-server validate --config /etc/mqvpn/server.yaml
sudo ./bin/mqvpn-server --config /etc/mqvpn/server.yaml
```

Keep the terminal running while you start the Client. Open UDP/8443 through the Server's firewall and any intervening network security policy.

## Connect the Client

Create `/etc/mqvpn/client.yaml` on the **Client**. Replace `198.51.100.10` with the **real Server WAN IP** and use the local absolute file paths:

```yaml
server: vpn.example.test:8443
connect_ip: 198.51.100.10
address: 10.77.0.2/24
ca: /absolute/path/demo-certs/ca.crt
cert: /absolute/path/demo-certs/client.crt
key: /absolute/path/demo-certs/client.key
```

`server` determines the Server's TLS certificate identity; `connect_ip` only chooses the physical destination. **Do not** replace the verified TLS name with an unrelated IP.

Start the Client:

```bash
sudo ./bin/mqvpn-client --config /etc/mqvpn/client.yaml
```

The Client reconnects automatically after a lost session by default. In this first example, omit optional WAN, XDP, VRF, compression and routing settings.

## Verify your first tunnel

On the **Client**:

```bash
ip addr show dev mq0
ip route get 10.77.0.1
ping -c 3 10.77.0.1
```

On the **Server**:

```bash
ip addr show dev mq0
ip route get 10.77.0.2
ping -c 3 10.77.0.2
```

The expected result is a configured `mq0` on both hosts and successful ICMP traffic through the authenticated QUIC tunnel. Stop the foreground daemons with Ctrl+C; the Client removes its session-owned TUN/routes when it exits. Existing administrator-owned routing objects are not supposed to be overwritten.

If you do not have two machines, the repository's privileged namespace integration test runs a temporary two-site environment instead:

```bash
sudo bash tests/integration/overlay-netns.sh udp
```

The namespace test requires installed networking tools and Python 3. It generates and removes test resources automatically.

## Where to go next

| Goal | Next guide |
| --- | --- |
| Add more clients, tenants or server-assigned tunnel addresses | [Server configuration](server-config.md) |
| Use two to eight physical WANs | [Client configuration](client-config.md) · [Server WAN addresses](server-multiwan.md) |
| Prefer low latency or apply QoS classes | [MPQUIC path scheduling](multipath-low-latency.md) · [QoS queues](qos-queues.md) |
| Give SIP and EF-marked media a sticky WAN | [Sticky voice](voip-sticky.md) |
| Let FRRouting advertise remote networks | [Five-site OSPF/BGP integration](five-site-routing.md) |
| Resolve a connection or routing failure | [Operations and troubleshooting](operations.md) |

For production, replace the lab CA and keys with your PKI, audit your firewall and source-routing policies, and test recovery and packet-size behavior on your actual underlay.
