#!/usr/bin/env python3
"""Send/echo high-entropy canary payloads across a *real* mqvpn TUN.

Every packet has a distinctive plaintext marker followed by pseudorandom
material, avoiding a false success caused by compression hiding repeated
ping patterns. No third-party Python modules are required.
"""
import hashlib
import socket
import struct
import sys

MARKER = b"MQVPN_CANARY_001"
PORT = 34931
COUNT = 160
SIZE = 1200


def payload(index):
    header = MARKER + struct.pack("!I", index)
    tail = hashlib.shake_256(b"wire-crypto-" + header).digest(SIZE - len(header))
    return header + tail


def run(role, local, remote, ready_file):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind((local, PORT if role == "listen" else 0))
        sock.settimeout(9)
        if role == "listen":
            with open(ready_file, "w", encoding="ascii") as handle:
                handle.write("READY\n")
        for index in range(COUNT):
            if role == "listen":
                received, source = sock.recvfrom(2048)
                if source[0] != remote or received != payload(index):
                    raise AssertionError(f"wire canary packet #{index} corrupted at listener")
                sock.sendto(received, source)
            else:
                original = payload(index)
                sock.sendto(original, (remote, PORT))
                echoed, source = sock.recvfrom(2048)
                if source[0] != remote or echoed != original:
                    raise AssertionError(f"wire canary packet #{index} corrupted at initiator")
    print(f"PASS wire canary {role}: {COUNT} * {SIZE} bytes, authenticated full-duplex echo", flush=True)


if __name__ == "__main__":
    if len(sys.argv) != 5 or sys.argv[1] not in ("listen", "send"):
        raise SystemExit("usage: wire_crypto_probe.py listen|send LOCAL_IP REMOTE_IP MARKER_PATH")
    run(*sys.argv[1:])
