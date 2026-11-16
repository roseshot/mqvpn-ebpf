# Verify TUN confidentiality on the physical WAN

[Documentation index](README.md) · [Testing](README.md#testing)

> **Document scope:** **Security regression guide.** Compare inner TUN plaintext to captured physical WAN ciphertext and use isolated, permission-limited test TLS secrets as a positive decrypt control.

The `crypto-wan4` and `crypto-tcp` integration scenarios exercise real,
authenticated mqvpn Server/Client binaries in Linux network namespaces.
They capture inner **TUN plaintext** and outer **WAN transport traffic**,
then verify both negative and positive controls.

## On this page

- [Requirements](#requirements)
- [Automated assertions](#automated-assertions)
- [Limitations](#limitations)

## Requirements

Linux root / CAP_NET_ADMIN, `/dev/net/tun`, `iproute2`,
`iputils-ping`, OpenSSL, Python 3, `tcpdump` and `tshark`
(Wireshark CLI). From the repository root:

```bash
make release
sudo bash tests/integration/overlay-netns.sh crypto-wan4
sudo bash tests/integration/overlay-netns.sh crypto-tcp
```

The first test runs **4 independent Client WANs to 4 distinct Server
WAN IPs** over one mTLS MPQUIC/HTTP/3 connection; the second forces
the **single-WAN TLS 1.3 / TCP fallback** with HTTP/1.1 CONNECT-ETHERNET
Upgrade, without relying on UDP.

## Automated assertions

1. The Server and Client `mq0` TUN PCAPs both contain the exact
   `MQVPN_CANARY_001` marker and noncompressible SHAKE-256-derived data;
   a UDP request/echo is checked byte for byte in both directions,
   for 160 × 1200-byte datagrams per test direction.
2. Both sides of *every* physical WAN are captured from before the
   Client handshake through the last test packet. **No WAN PCAP**
   may contain the marker or an inner `10.77.0.x` IP source/destination.
   The parser requires real WAN IPv4/UDP 8443 (QUIC) or WAN IPv4/TCP 8443
   packets and, respectively, 1-RTT-style QUIC short headers or TLS 1.3
   application-data records on each captured interface.
3. An explicitly enabled, private file with **TLS 1.3 application
   traffic secrets** is written *only* for this test. The test validates
   `0600` permissions, then calls `tshark` with
   `-o tls.keylog_file:<path>` to confirm that the correct secrets
   decrypt the QUIC DATAGRAM canary or HTTP/1.1 Upgrade request.
4. GitHub Actions performs these checks automatically before the
   WAN/transport probes and combined five-site BGP+OSPF phase of the
   same unified integration scenario.

## Limitations

A missing plaintext marker on the WAN **alone** is not a cryptographic
proof: a different framing, compression, or failed capture can also
hide it. That is why the test includes the TUN positive control,
actual WAN packet/frame validation, traffic integrity checks and
a **positive decryption test** with the test-only TLS secrets. This
verifies the tested traffic and the correct TLS transport operation,
not the absence of all possible implementation vulnerabilities.

QUIC/TLS encrypts the inner VPN content; outer source/destination IP,
UDP/TCP ports, packet lengths and timing remain visible. This test
does not claim traffic-analysis resistance or peer anonymity.

**Do not enable TLS key logging on production VPN connections.**
The diagnostic flag is deliberately named `--test-tls-keylog-file` and
requires the environment variable:

```text
MQVPN_UNSAFE_TEST_KEYLOG=I_ACKNOWLEDGE_TLS_SECRETS
```

The file must be a new absolute path and is created exclusively at
mode `0600`. It gives holders of the file and matching PCAPs the
ability to decrypt the entire captured VPN session. The integration
runner creates its own private `mktemp -d` directory, never uploads
PCAPs or TLS secrets as CI artifacts, and erases the directory and
terminates captures during trap cleanup, including on failures.

If a test fails, inspect GitHub Actions text logs for the failing
capture or protocol check. Avoid uploading TLS secret files,
decrypted PCAPs or real user VPN traffic into issue reports.

## Related documentation

- [Overlay integration tests](overlay-tests.md)
- [TLS/TCP fallback protocol](tcp-fallback.md)
- [Complete test scenario](five-site-routing.md)
