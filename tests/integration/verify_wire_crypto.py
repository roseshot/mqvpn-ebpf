#!/usr/bin/env python3
"""Offline wire-encryption checks for isolated Linux namespace E2E PCAPs.

Checks the *positive* control (inner payload really present in TUN),
the negative control (none of the underlay packets contains the
distinctive canary), per-WAN QUIC/TLS traffic and Wireshark test-key
decryption. No permanent artifacts or production secrets are retained.
"""
import argparse
import pathlib
import re
import struct
import subprocess
import sys

CANARY = b"MQVPN_CANARY_001"


def pcap_packets(path):
    data = path.read_bytes()
    if len(data) < 24:
        raise AssertionError(f"{path}: no PCAP header")
    magics = {
        b"\xd4\xc3\xb2\xa1": "<",
        b"\xa1\xb2\xc3\xd4": ">",
        b"\x4d\x3c\xb2\xa1": "<",
        b"\xa1\xb2\x3c\x4d": ">",
    }
    order = magics.get(data[:4])
    if order is None:
        raise AssertionError(f"{path}: unsupported PCAP magic {data[:4].hex()}")
    linktype = struct.unpack_from(order + "I", data, 20)[0] & 0xFFFF
    frames = []
    offset = 24
    while offset < len(data):
        if offset + 16 > len(data):
            raise AssertionError(f"{path}: truncated PCAP record")
        _, _, length, wire_length = struct.unpack_from(order + "IIII", data, offset)
        offset += 16
        if length > wire_length or length > 65536 or offset + length > len(data):
            raise AssertionError(f"{path}: corrupt PCAP packet length")
        frames.append(data[offset:offset + length])
        offset += length
    if not frames:
        raise AssertionError(f"{path}: empty packet capture")
    return linktype, frames


def ip_payload(linktype, frame):
    if linktype == 1:  # Ethernet
        if len(frame) < 14:
            return None
        ether_type = struct.unpack_from("!H", frame, 12)[0]
        offset = 14
        while ether_type in (0x8100, 0x88a8) and len(frame) >= offset + 4:
            ether_type = struct.unpack_from("!H", frame, offset + 2)[0]
            offset += 4
        if ether_type != 0x0800:
            return None
    elif linktype in (12, 101):  # RAW IPv4/IP
        offset = 0
    elif linktype == 113:  # Linux SLL
        if len(frame) < 16 or struct.unpack_from("!H", frame, 14)[0] != 0x0800:
            return None
        offset = 16
    elif linktype == 276:  # Linux SLL2
        if len(frame) < 20 or struct.unpack_from("!H", frame, 0)[0] != 0x0800:
            return None
        offset = 20
    else:
        raise AssertionError(f"unsupported PCAP linktype {linktype}")
    if len(frame) < offset + 20 or frame[offset] >> 4 != 4:
        return None
    ihl = (frame[offset] & 15) * 4
    if ihl < 20 or len(frame) < offset + ihl:
        return None
    proto = frame[offset + 9]
    src, dst = frame[offset + 12:offset + 16], frame[offset + 16:offset + 20]
    return proto, src, dst, frame[offset + ihl:]


def underlay_frames(path, mode):
    linktype, packets = pcap_packets(path)
    candidates = []
    for packet in packets:
        if CANARY in packet:
            raise AssertionError(f"PLAINTEXT LEAK: {path} contains known inner canary")
        decoded = ip_payload(linktype, packet)
        if decoded is None:
            continue
        proto, src, dst, payload = decoded
        if src[:2] == b"\x0a\x4d" or dst[:2] == b"\x0a\x4d":
            raise AssertionError(f"{path}: saw inner TUN address on physical WAN")
        want_proto = 17 if mode == "quic" else 6
        if proto != want_proto or len(payload) < 9:
            continue
        source_port, target_port = struct.unpack_from("!HH", payload)
        if source_port != 8443 and target_port != 8443:
            continue
        off = 8 if mode == "quic" else ((payload[12] >> 4) * 4 if len(payload) >= 20 else 99)
        if len(payload) <= off:
            continue
        candidates.append(payload[off:])
    if len(candidates) < 12:
        raise AssertionError(f"{path}: only {len(candidates)} actual {mode} WAN payloads")
    if mode == "quic":
        short = sum((packet[0] & 0xC0) == 0x40 for packet in candidates)
        if short < 6:
            raise AssertionError(f"{path}: no sustained encrypted QUIC 1-RTT short-header traffic")
        print(f"PASS {path.name}: {len(candidates)} QUIC UDP payloads, {short} 1-RTT headers; no TUN plaintext", flush=True)
    else:
        tls_app = sum(packet.startswith(b"\x17\x03\x03") for packet in candidates)
        if tls_app < 2:
            raise AssertionError(f"{path}: missing TLS application-data records")
        print(f"PASS {path.name}: {len(candidates)} TCP payloads, {tls_app} TLS application records; no TUN plaintext", flush=True)


def key_log(path):
    content = path.read_text(encoding="ascii")
    for name in ("CLIENT_TRAFFIC_SECRET_0", "SERVER_TRAFFIC_SECRET_0"):
        if not re.search(r"(?m)^" + name + r" [0-9a-fA-F]+ [0-9a-fA-F]+$", content):
            raise AssertionError(f"test-only TLS key log lacks {name}")
    if path.stat().st_mode & 0o077:
        raise AssertionError("TLS key log accessible by group/other")
    print("PASS: private mode-0600 test-only TLS 1.3 application traffic secrets captured", flush=True)


def decrypt_with_tshark(mode, capture, keypath):
    args = ["tshark", "-r", str(capture),
            "-o", "tls.keylog_file:" + str(keypath)]
    if mode == "quic":
        args += ["-d", "udp.port==8443,quic",
                 "-Y", "quic.dg", "-T", "fields", "-e", "quic.dg"]
    else:
        args += ["-d", "tcp.port==8443,tls",
                 "-Y", 'http.request.method == "GET"',
                 "-T", "fields", "-e", "http.request.method"]
    result = subprocess.run(args, capture_output=True, text=True, timeout=80, check=False)
    if result.returncode != 0:
        raise AssertionError(f"tshark test-key decryption failed: {result.stderr[-700:]}")
    if mode == "quic":
        compact = re.sub(r"[^0-9a-f]", "", result.stdout.lower())
        if CANARY.hex() not in compact:
            raise AssertionError("test key did not reveal the known canary in decrypted QUIC DATAGRAM frames")
        print("PASS: Wireshark using temporary TLS traffic secrets decrypted QUIC DATAGRAM canary", flush=True)
    else:
        if "GET" not in result.stdout:
            raise AssertionError("test key failed to decrypt the authenticated TLS/HTTP Upgrade request")
        print("PASS: Wireshark using temporary TLS traffic secrets decrypted the HTTP/1.1 Upgrade request", flush=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("quic", "tcp"))
    parser.add_argument("directory", type=pathlib.Path)
    parser.add_argument("--wan-count", type=int, required=True)
    args = parser.parse_args()
    base = args.directory
    for side in ("server", "client"):
        path = base / (side + "-mq0.pcap")
        _, packets = pcap_packets(path)
        observed = sum(CANARY in packet for packet in packets)
        if observed < 10:
            raise AssertionError(f"{path}: TUN positive control missing ({observed} known canaries)")
        print(f"PASS {side} TUN: {observed} authenticated plaintext canary packets seen", flush=True)
        for index in range(args.wan_count):
            underlay_frames(base / f"{side}-wan{index}.pcap", args.mode)
    secret = base / "tls.keys"
    key_log(secret)
    # Initial handshake is captured on wan0 before the Client starts,
    # allowing the dissector to discover CIDs and use the test keys.
    decrypt_with_tshark(args.mode, base / "client-wan0.pcap", secret)
    print(f"PASS end-to-end {args.mode.upper()} confidentiality wire test on {args.wan_count} WAN(s)", flush=True)


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"FAIL wire crypto: {exc}", file=sys.stderr, flush=True)
        raise
