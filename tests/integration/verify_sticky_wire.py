#!/usr/bin/env python3
"""Verify that the pinned realtime QUIC connection never rotates WANs.

The established mTLS realtime companion has its own ephemeral UDP source
port. Compare both sides of every WAN to prove that this exact connection
uses only its pinned interface before and after intentional WAN0 loss.
Bulk MPQUIC packets still use the other WANs and different UDP ports.
"""
import pathlib
import re
import struct
import sys

from verify_wire_crypto import ip_payload, pcap_packets


def session_ports(text):
    sessions = {}
    for line in text.splitlines():
        if "sticky realtime established" not in line:
            continue
        index = re.search(r"\bwan_index=(\d+)\b", line)
        local = re.search(r"\blocal=\S+:(\d+)\b", line)
        if index and local:
            sessions[int(index.group(1)) - 1] = int(local.group(1))
    return sessions


def traffic(path):
    linktype, packets = pcap_packets(path)
    result = []
    for raw in packets:
        packet = ip_payload(linktype, raw)
        if packet is None:
            continue
        proto, src, dst, payload = packet
        if proto != 17 or len(payload) < 8:
            continue
        sport, dport = struct.unpack_from("!HH", payload)
        if sport != 8443 and dport != 8443:
            continue
        result.append((sport, dport))
    if len(result) < 10:
        raise AssertionError(f"{path}: too few UDP/8443 packets to test real path usage")
    return result


def verify(root):
    ports = session_ports((root / "client.log").read_text())
    if 0 not in ports or 1 not in ports:
        raise AssertionError(f"expected sticky WAN0 then WAN1 failover, got {ports}")
    if ports[0] == ports[1]:
        raise AssertionError("sticky realtime transport reused the same source port on WAN failover")

    packets = {(side, index): traffic(root / f"{side}-wan{index}.pcap")
               for side in ("server", "client") for index in range(4)}
    for expected_wan, port in sorted(ports.items()):
        matched = 0
        for index in range(4):
            client_count = sum(sport == port and dport == 8443
                               for sport, dport in packets["client", index])
            server_count = sum(sport == 8443 and dport == port
                               for sport, dport in packets["server", index])
            if index == expected_wan:
                if client_count < 60 or server_count < 60:
                    raise AssertionError(
                        f"sticky WAN{index} port {port} insufficient full-duplex QUIC packets: "
                        f"client={client_count}, server={server_count}")
                matched = client_count + server_count
            elif client_count or server_count:
                raise AssertionError(
                    f"STICKY VIOLATION: realtime port {port} leaked from WAN{expected_wan} "
                    f"to WAN{index}, client={client_count}, server={server_count}")
        print(f"PASS sticky single-WAN source port={port} WAN{expected_wan}: "
              f"{matched} bidirectional encrypted transport packets", flush=True)

    # The general-purpose MPQUIC connection must retain independent
    # service on all the remaining WAN links, rather than accidentally
    # pinning the whole tunnel to WAN0.
    for index in (1, 2, 3):
        bulk = sum(sport not in ports.values() and dport == 8443
                   for sport, dport in packets["client", index])
        if bulk < 30:
            raise AssertionError(f"WAN{index} bulk MPQUIC still underused: {bulk} packets")
        print(f"PASS WAN{index} bulk MPQUIC remains distributed: {bulk} packets", flush=True)
    print("PASS sticky RTP/EF path affinity and controlled WAN0 -> WAN1 failover", flush=True)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: verify_sticky_wire.py PCAP_DIRECTORY")
    verify(pathlib.Path(sys.argv[1]))
