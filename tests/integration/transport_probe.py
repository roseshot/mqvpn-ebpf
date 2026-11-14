#!/usr/bin/env python3
"""Synthetic TCP, UDP and SIP/RTP/RTCP probes for actual mqvpn TUN namespaces.

Run only from tests/integration/overlay-netns.sh.  No third-party packages,
external SIP services or fake QUIC devices are involved.
"""
import hashlib
import os
import socket
import struct
import sys
import threading
import time

TCP_PORT = 34010
UDP_PORT = 34011
SIP_PORT = 5060
RTP_PORT = 40000
RTCP_PORT = 40001
RTP_COUNT = 100
RTP_PERIOD = 0.020  # G.711 PCMU: 160 audio samples every 20 ms at 8 kHz
RTP_PAYLOAD = 160
DSCP_EF = 46
SOCKET_TIMEOUT = 10.0


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def ready(path):
    # Write only after *all* listening sockets are bound, and use a fresh
    # marker file for each independent namespace test case.
    with open(path, "w", encoding="ascii") as file:
        file.write("READY\n")


def sha_payload(label, length):
    return hashlib.shake_256(label.encode("ascii")).digest(length)


def receive_exact(conn, length):
    out = bytearray()
    while len(out) < length:
        block = conn.recv(min(16384, length - len(out)))
        require(block, f"TCP closed with {length - len(out)} bytes missing")
        out.extend(block)
    return bytes(out)


def probe_tcp(role, local, peer, marker):
    expected = sha_payload("mqvpn-tcp-256KiB", 256 * 1024)
    if role == "listen":
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind((local, TCP_PORT))
            listener.listen(1)
            listener.settimeout(SOCKET_TIMEOUT)
            ready(marker)
            with listener.accept()[0] as conn:
                conn.settimeout(SOCKET_TIMEOUT)
                require(receive_exact(conn, len(expected)) == expected,
                        "TCP request integrity mismatch")
                conn.sendall(expected)
    else:
        with socket.create_connection((peer, TCP_PORT), SOCKET_TIMEOUT,
                                      source_address=(local, 0)) as conn:
            conn.settimeout(SOCKET_TIMEOUT)
            conn.sendall(expected)
            require(receive_exact(conn, len(expected)) == expected,
                    "TCP echo integrity mismatch")
    print(f"PASS TCP {role}: 256 KiB each direction, SHAKE256 integrity", flush=True)


UDP_SIZES = (64, 512, 1200, 1472, 64, 512, 1200, 1472)


def udp_data(index, length):
    require(length >= 4, "invalid probe size")
    return struct.pack("!HH", index, length) + sha_payload(
        f"mqvpn-udp-{index}-{length}", length - 4)


def probe_udp(role, local, peer, marker):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind((local, UDP_PORT if role == "listen" else 0))
        sock.settimeout(SOCKET_TIMEOUT)
        if role == "listen":
            ready(marker)
            for index, length in enumerate(UDP_SIZES):
                received, address = sock.recvfrom(2048)
                require(address[0] == peer, "UDP packet came from unexpected host")
                require(received == udp_data(index, length),
                        f"UDP payload {index} integrity or ordering mismatch")
                sock.sendto(received, address)
        else:
            for index, length in enumerate(UDP_SIZES):
                payload = udp_data(index, length)
                sock.sendto(payload, (peer, UDP_PORT))
                received, address = sock.recvfrom(2048)
                require(address[0] == peer and received == payload,
                        f"UDP echo {index} failed (size={length})")
    print(f"PASS UDP {role}: {len(UDP_SIZES)} datagrams, sizes={UDP_SIZES}, "
          "including 1472-byte UDP payload / 1500-byte inner IPv4", flush=True)


def voice_socket(local, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((local, port))
    sock.settimeout(SOCKET_TIMEOUT)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_TOS, DSCP_EF << 2)
    # The UDP payload must keep its EF marking through the authenticated TUN.
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_RECVTOS, 1)
    return sock


def get_voice_packet(sock, size):
    data, ancillary, _, address = sock.recvmsg(size, 128)
    tos = next((values[0] for level, kind, values in ancillary
                if level == socket.IPPROTO_IP and kind == socket.IP_TOS
                and len(values) >= 1), None)
    require(tos is not None and tos >> 2 == DSCP_EF,
            f"RTP/RTCP DSCP EF was not preserved (TOS={tos})")
    return data, address


def sip_dialogue(sock, role, local, peer, verb, cseq):
    call_id = "mqvpn-voip-ci-1"
    if role == "send":
        sdp = ("v=0\r\no=- 1 1 IN IP4 " + local +
               "\r\ns=CI G711\r\nc=IN IP4 " + local +
               f"\r\nt=0 0\r\nm=audio {RTP_PORT} RTP/AVP 0"
               "\r\na=rtpmap:0 PCMU/8000\r\n") if verb == "INVITE" else ""
        message = (
            f"{verb} sip:test@{peer} SIP/2.0\r\n"
            f"Via: SIP/2.0/UDP {local}:5062;branch=z9hG4bK{cseq}\r\n"
            f"From: <sip:ci@{local}>;tag=ci\r\n"
            f"To: <sip:test@{peer}>\r\n"
            f"Call-ID: {call_id}\r\n"
            f"CSeq: {cseq} {verb}\r\n"
            f"Content-Type: application/sdp\r\n"
            f"Content-Length: {len(sdp)}\r\n\r\n{sdp}"
        ).encode("ascii")
        sock.sendto(message, (peer, SIP_PORT))
        response, addr = sock.recvfrom(4096)
        require(addr[0] == peer and response.startswith(b"SIP/2.0 200 OK")
                and f"CSeq: {cseq} {verb}".encode("ascii") in response,
                f"unexpected SIP {verb} response: {response[:160]!r}")
    else:
        request, addr = sock.recvfrom(4096)
        require(addr[0] == peer and
                request.startswith(f"{verb} ".encode("ascii")) and
                f"CSeq: {cseq} {verb}".encode("ascii") in request and
                b"Call-ID: mqvpn-voip-ci-1" in request,
                f"invalid SIP {verb} request: {request[:160]!r}")
        if verb == "INVITE":
            require(b"RTP/AVP 0" in request and
                    f"m=audio {RTP_PORT}".encode("ascii") in request,
                    "missing G.711 / PCMU SDP offer")
        reply = (f"SIP/2.0 200 OK\r\nCSeq: {cseq} {verb}\r\n"
                 f"Call-ID: {call_id}\r\nContent-Length: 0\r\n\r\n")
        sock.sendto(reply.encode("ascii"), addr)


def send_rtp(sock, peer, ssrc, errors):
    try:
        deadline = time.monotonic() + 0.050
        for seq in range(RTP_COUNT):
            sleep = deadline - time.monotonic()
            if sleep > 0:
                time.sleep(sleep)
            # RFC3550 RTP v2, payload type 0 (PCMU), timestamps in 8kHz ticks.
            header = struct.pack("!BBHII", 0x80, 0, seq,
                                 seq * RTP_PAYLOAD, ssrc)
            payload = bytes([seq & 0xff]) * RTP_PAYLOAD
            sock.sendto(header + payload, (peer, RTP_PORT))
            deadline += RTP_PERIOD
    except Exception as exc:
        errors.append(exc)


def receive_rtp(sock, peer, expected_ssrc):
    sequences = []
    arrival = []
    jitter = 0.0
    previous_transit = None
    for _ in range(RTP_COUNT):
        packet, addr = get_voice_packet(sock, 2048)
        require(addr[0] == peer, "RTP came from unexpected IP")
        require(len(packet) == 12 + RTP_PAYLOAD and
                packet[0] == 0x80 and (packet[1] & 0x7f) == 0,
                "RTP v2 PCMU header or 20ms payload incorrect")
        _, _, seq, timestamp, ssrc = struct.unpack("!BBHII", packet[:12])
        require(ssrc == expected_ssrc and timestamp == seq * RTP_PAYLOAD
                and packet[12:] == bytes([seq & 0xff]) * RTP_PAYLOAD,
                "RTP timestamp, SSRC or payload integrity mismatch")
        now = time.monotonic()
        transit = now * 8000.0 - timestamp
        if previous_transit is not None:
            delta = abs(transit - previous_transit)
            jitter += (delta - jitter) / 16
        previous_transit = transit
        sequences.append(seq)
        arrival.append(now)
    require(sorted(sequences) == list(range(RTP_COUNT)),
            f"RTP packet loss, duplication or invalid sequence: {sequences}")
    # Keep tolerance wide enough for CI's shared virtual CPU. This is a
    # functional smoke test, NOT a real-world voice MOS/SLA certificate.
    max_gap_ms = max((b - a) * 1000 for a, b in zip(arrival, arrival[1:]))
    jitter_ms = jitter / 8.0
    require(max_gap_ms <= 200 and jitter_ms <= 80,
            f"RTP pacing disrupted: gap={max_gap_ms:.1f}ms jitter={jitter_ms:.1f}ms")
    return jitter_ms, max_gap_ms, sum(b < a for a, b in zip(sequences, sequences[1:]))


def rtcp_rr(local_ssrc, remote_ssrc, jitter_ticks):
    # RTCP Receiver Report: 1 report block, 0 packet loss, 100 packets.
    return (struct.pack("!BBHI", 0x81, 201, 7, local_ssrc) +
            struct.pack("!IB3sIIII", remote_ssrc, 0, b"\x00\x00\x00",
                        RTP_COUNT - 1, jitter_ticks, 0, 0))


def exchange_voice(rtp, rtcp, peer, local_ssrc, remote_ssrc):
    errors = []
    worker = threading.Thread(target=send_rtp,
                              args=(rtp, peer, local_ssrc, errors), daemon=True)
    worker.start()
    try:
        jitter, max_gap, reordered = receive_rtp(rtp, peer, remote_ssrc)
    finally:
        worker.join(timeout=SOCKET_TIMEOUT)
    require(not worker.is_alive() and not errors,
            f"RTP sender failed: {errors}")
    rtcp.sendto(rtcp_rr(local_ssrc, remote_ssrc, round(jitter * 8)),
                (peer, RTCP_PORT))
    report, addr = get_voice_packet(rtcp, 512)
    require(addr[0] == peer and len(report) == 32 and
            report[:2] == b"\x81\xc9" and
            struct.unpack_from("!I", report, 4)[0] == remote_ssrc and
            struct.unpack_from("!I", report, 8)[0] == local_ssrc,
            "RTCP receiver report not received or malformed")
    print(f"RTP {RTP_COUNT}/{RTP_COUNT} packets, 0% loss, "
          f"jitter={jitter:.2f}ms, max-gap={max_gap:.2f}ms, "
          f"reordered={reordered}; RTCP RR received", flush=True)


def probe_voip(role, local, peer, marker):
    local_ssrc = 0x11111111 if role == "listen" else 0x22222222
    remote_ssrc = 0x22222222 if role == "listen" else 0x11111111
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sip, \
         voice_socket(local, RTP_PORT) as rtp, \
         voice_socket(local, RTCP_PORT) as rtcp:
        sip.bind((local, SIP_PORT if role == "listen" else 0))
        sip.settimeout(SOCKET_TIMEOUT)
        if role == "listen":
            ready(marker)
        for method, cseq in (("REGISTER", 1), ("INVITE", 2)):
            sip_dialogue(sip, role, local, peer, method, cseq)
        exchange_voice(rtp, rtcp, peer, local_ssrc, remote_ssrc)
        sip_dialogue(sip, role, local, peer, "BYE", 3)
    print(f"PASS SIP/RTP/RTCP {role}: REGISTER / INVITE / BYE, "
          "full-duplex G.711 PCMU 20ms packets, DSCP EF, no RTP loss",
          flush=True)


def main():
    require(len(sys.argv) == 6, "usage: probe.py listen|send tcp|udp|voip local peer marker")
    _, role, proto, local, peer, marker = sys.argv
    require(role in ("listen", "send") and proto in ("tcp", "udp", "voip"),
            "unsupported role or protocol")
    {"tcp": probe_tcp, "udp": probe_udp, "voip": probe_voip}[proto](
        role, local, peer, marker)


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(f"FAIL: {error}", file=sys.stderr, flush=True)
        raise
