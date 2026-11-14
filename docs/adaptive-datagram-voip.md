# Adaptive DATAGRAM budget and SIP/RTP diagnostics

## QUIC DATAGRAM size feedback

The `frag-v1` extension initially uses a **1024-byte application payload
budget**. This is intentionally below the typical QUIC minimum packet-size
baseline; it is not a measured path MTU. Starting with this revision, the
Client and Server respond to an actual `quic.DatagramTooLargeError` from
`github.com/qoke/mp-quic-go`.

When the QUIC library rejects a packet due to size, the sender uses the
reported maximum QUIC payload less **64 bytes of HTTP/3/framing headroom**
to reduce its **session-local** application fragmentation budget. It then
re-encodes the original frame with a fresh fragment ID and retries at most
twice. If the path limit is too small to support a 160-byte application
fragment, or 16 fragment pieces cannot carry the original frame, the
frame is dropped. A transport error unrelated to packet size never
triggers retransmission.

This is **shrink-only feedback**, not a complete PMTU discovery
implementation: the library does not expose a per-path PMTU through the
`http3.Stream` used by mqvpn; a DATAGRAM accepted into the QUIC send
queue may still be dropped later on a different MPQUIC path. Budget
reductions are logged by both endpoints. There is no optimistic
increase, no background probing, no ACK-based delivery guarantee, and
no IP fragmentation.

Old peers without `frag-v1` still use the original unfragmented
CONNECT-ETHERNET frame format. A non-negotiated connection does not
retry using the private fragment extension.

## DSCP EF VoIP receive indicators

The Client and P2MP Server keep bounded in-memory receive-side
counters for inner IPv4 and IPv6 **UDP packets marked DSCP EF (46)**:

- RTP packet count, sequence gap events, estimated missing sequence
  numbers, and late/duplicate packet count
- RTCP Sender/Receiver Report count, report block count, latest report
  fraction lost and cumulative lost, and latest jitter in RTP clock ticks

Per-session SSRC/flow state is capped at 128 entries; old flows are
evicted. Stats are logged at session teardown; the Server exposes
`Hub.PeerVoIPStats()` for future local diagnostics or metrics export.
No packet data or audio payloads are saved or logged.

Important limits: RTP sequence gaps are **not confirmed packet loss**
because packets may be reordered, and rollovers, long silence periods
and stream restarts can distort the gap estimate. RTCP report loss
is the receiver's report, while RTCP jitter units are **RTP timestamps**
and require the stream clock rate to convert to milliseconds. The
monitor intentionally does not parse SIP/SDP, unmarked RTP, encrypted
SRTP payloads for codec information, or IPv6 extension-header chains.
It parses RTP/RTCP cleartext headers inside the authenticated VPN
payload; SRTP headers are normally visible. Misclassified or spoofed
DSCP EF packets can affect counters but never routing or authorization.

## SIP deployment

Mark media RTP/RTCP with DSCP EF (46) on the PBX, SBC, or IP phone.
Keep SIP 5060/5061 on the existing priority queue. To interpret the
metrics, compare the receiver-reported RTCP loss and jitter with RTP
sequence gaps under bulk transfer and after MPQUIC path switching.

The improvement does not supersede route PMTU discovery, packet pacing,
or WAN QoS. For real deployment, test with G.711/Opus calls and
asymmetric 1500/1492/1420 MTU paths and track receiver loss, jitter,
audio gaps, and CPU overhead before relying on performance claims.
