# Zstd DATAGRAM compression and SIP/RTP priority

The VPN keeps CONNECT-ETHERNET over authenticated QUIC/HTTP/3 (and the
HTTP/1.1/TLS Capsule fallback). eBPF programs are unchanged.

## Capability negotiation and compatibility

The Client sends `Mqvpn-Compression: zstd-v1` in the authenticated CONNECT
request. A supporting Server echoes exactly `zstd-v1` in its successful
response. Compression is active only after that echo. Missing reply means
legacy uncompressed CONNECT-ETHERNET: old Servers and Clients still work.
Unknown compression replies are rejected.

The feature applies in both QUIC and TCP fallback. A compressed frame uses
the synthetic Ethernet envelope with experimental EtherType 0x88B5. Its
payload is a 2-byte network-order original IP length followed by one
independently encoded Zstandard frame. The MASQUE Context ID remains 0.
This EtherType is used only on the synthetic frame after negotiation, never
on physical Ethernet.

The receiver rejects compressed frames when unnegotiated, rejects decoded
frames exceeding max_frame, limits decoder memory, validates the declared
decompressed size, and re-validates the inner IP packet. Decoding is stateless
across packets: losing one DATAGRAM never corrupts subsequent ones.

Only non-priority inner IP packets >=512 bytes are considered for compression,
and the result must save at least 16 bytes after the two-byte length field.
SIP signalling and DSCP EF traffic bypass compression. Compression is done
independently per packet and is not a replacement for PMTU discovery or
DATAGRAM fragmentation. A TUN MTU of 1500 is **not guaranteed** to cross a
1500-byte WAN PMTU without application-layer fragmentation; this change does
not implement fragmentation/reassembly.

## Packet priority

The built-in conservative priority class covers:

- Inner IPv4 or IPv6 packets marked DSCP EF (46), suitable for RTP/RTCP
- SIP signalling on TCP or UDP ports 5060/5061
- All other packets remain normal priority

There is no speculative RTP payload inspection, because RTP uses SDP-
negotiated dynamic ports; configure the phone, SBC or PBX to mark RTP with
DSCP EF. As with all DSCP-based priority classification, untrusted peers
could claim high priority. Apply policing or marking at your trust boundary
if needed. Classification never denies traffic or provides an IP ACL.

Both Client and Server senders use per-session bounded priority (64)
and normal (192) queues. Each sender favors priority traffic but gives
normal traffic an opportunity after four priority packets, so bulk traffic
cannot be starved indefinitely. A saturated queue drops new DATAGRAMs
instead of blocking the TUN reader. Prioritization reduces local
head-of-line queuing; it cannot override QUIC pacing, congestion control,
WAN bottleneck queues or the TCP fallback's inherent head-of-line blocking.

## Operational checks

Check with G.711/Opus SIP calls under concurrent bulk transfer, in both
directions and when MPQUIC changes WAN paths. Measure RTP jitter, loss,
RTCP reports and late-packet drops, not merely throughput. A downstream
switch/router may still need its own DSCP policy; inner DSCP does not
automatically change the outer QUIC UDP socket's DSCP.

Security: compressing attacker-controlled and sensitive plaintext in a
shared secret-bearing context may create a size side channel. Only stateless
per-packet frames are used here; assess application confidentiality needs
before enabling compression for sensitive workloads.
