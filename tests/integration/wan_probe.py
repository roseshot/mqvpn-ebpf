#!/usr/bin/env python3
"""Loss-tolerant SIP/RTP/RTCP quality probe for real, netem-impaired VPN TUNs.

Two network namespaces run this script as listener and initiator. No PBX,
third-party Python dependencies, or synthetic tunnel implementation is used.
The application simulates the SIP transaction and G.711 RTP wire format, not
audio playback. Statistics are observational; RFC 3550 jitter is an estimate.
"""

import json
import socket
import struct
import sys
import threading
import time

from transport_probe import (
    DSCP_EF, RTP_PAYLOAD, RTP_PERIOD, RTP_PORT, RTCP_PORT, SIP_PORT,
    get_voice_packet, ready, require, voice_socket,
)

PACKETS = 250
MEDIA_SECONDS = PACKETS * RTP_PERIOD
SOCKET_WINDOW = 12.0
PROFILES = {
    # Smoke-test ceilings, not voice quality service-level agreements.
    "regional": {"loss": 25.0, "jitter_ms": 150.0, "gap_ms": 1200.0},
    "poor": {"loss": 40.0, "jitter_ms": 260.0, "gap_ms": 2000.0},
}


def invite(local, peer):
    sdp = ("v=0\r\no=- 1 1 IN IP4 " + local +
           "\r\ns=netem RTP test\r\nc=IN IP4 " + local +
           "\r\nt=0 0\r\nm=audio 40000 RTP/AVP 0\r\n"
           "a=rtpmap:0 PCMU/8000\r\n")
    return (
        f"INVITE sip:ci@{peer} SIP/2.0\r\n"
        f"Via: SIP/2.0/UDP {local}:5062;branch=z9hG4bKnetem\r\n"
        f"From: <sip:ci@{local}>;tag=ci\r\n"
        f"To: <sip:ci@{peer}>\r\n"
        f"Call-ID: mqvpn-netem-ci-1\r\n"
        f"CSeq: 1 INVITE\r\n"
        "Content-Type: application/sdp\r\n"
        f"Content-Length: {len(sdp)}\r\n\r\n{sdp}"
    ).encode("ascii")


OK_INVITE = (b"SIP/2.0 200 OK\r\nCSeq: 1 INVITE\r\n"
             b"Call-ID: mqvpn-netem-ci-1\r\nContent-Length: 0\r\n\r\n")
ACK = (b"ACK sip:ci SIP/2.0\r\nCSeq: 1 ACK\r\n"
       b"Call-ID: mqvpn-netem-ci-1\r\nContent-Length: 0\r\n\r\n")
BYE = (b"BYE sip:ci SIP/2.0\r\nCSeq: 2 BYE\r\n"
       b"Call-ID: mqvpn-netem-ci-1\r\nContent-Length: 0\r\n\r\n")
OK_BYE = (b"SIP/2.0 200 OK\r\nCSeq: 2 BYE\r\n"
          b"Call-ID: mqvpn-netem-ci-1\r\nContent-Length: 0\r\n\r\n")


def sip_start(sock, role, local, peer):
    target = (peer, SIP_PORT)
    if role == "send":
        request = invite(local, peer)
        for attempt in range(12):
            sock.sendto(request, target)
            sock.settimeout(0.8)
            try:
                reply, addr = sock.recvfrom(4096)
            except socket.timeout:
                continue
            if addr[0] == peer and reply.startswith(OK_INVITE[:18]) and (
                    b"CSeq: 1 INVITE" in reply):
                # UDP SIP ACKs may be lost; send a short redundant train.
                for _ in range(3):
                    sock.sendto(ACK, target)
                    time.sleep(0.07)
                return attempt
        raise AssertionError("SIP INVITE failed after 12 bounded UDP retries")

    deadline = time.monotonic() + SOCKET_WINDOW
    invited = False
    invite_count = 0
    while time.monotonic() < deadline:
        sock.settimeout(min(0.4, max(0.01, deadline - time.monotonic())))
        try:
            message, addr = sock.recvfrom(4096)
        except socket.timeout:
            continue
        require(addr[0] == peer, "SIP INVITE/ACK unexpected sender")
        if message.startswith(b"INVITE "):
            require(b"Call-ID: mqvpn-netem-ci-1" in message and
                    b"m=audio 40000 RTP/AVP 0" in message and
                    b"PCMU/8000" in message, "invalid netem SIP SDP")
            invited = True
            invite_count += 1
            sock.sendto(OK_INVITE, addr)
        elif invited and message.startswith(b"ACK "):
            return invite_count - 1
    raise AssertionError("SIP INVITE/ACK did not complete over impaired WAN")


def sip_end(sock, role, peer):
    target = (peer, SIP_PORT)
    if role == "send":
        for _ in range(12):
            sock.sendto(BYE, target)
            sock.settimeout(0.7)
            try:
                response, addr = sock.recvfrom(4096)
            except socket.timeout:
                continue
            if addr[0] == peer and response.startswith(b"SIP/2.0 200 OK") and (
                    b"CSeq: 2 BYE" in response):
                return
        raise AssertionError("SIP BYE did not complete over impaired WAN")

    deadline = time.monotonic() + SOCKET_WINDOW
    while time.monotonic() < deadline:
        sock.settimeout(min(0.5, max(0.01, deadline - time.monotonic())))
        try:
            request, addr = sock.recvfrom(4096)
        except socket.timeout:
            continue
        require(addr[0] == peer, "SIP BYE unexpected sender")
        if request.startswith(b"BYE ") and b"CSeq: 2 BYE" in request:
            # Any one of the redundant responses can survive packet loss.
            for _ in range(5):
                sock.sendto(OK_BYE, addr)
                time.sleep(0.06)
            return
        if request.startswith(b"INVITE "):
            sock.sendto(OK_INVITE, addr)
    raise AssertionError("SIP BYE not received over impaired WAN")


def send_media(sock, peer, ssrc, errors):
    try:
        start = time.monotonic() + 0.15
        for seq in range(PACKETS):
            pause = start + seq * RTP_PERIOD - time.monotonic()
            if pause > 0:
                time.sleep(pause)
            header = struct.pack("!BBHII", 0x80, 0, seq,
                                 seq * RTP_PAYLOAD, ssrc)
            sock.sendto(header + bytes([seq & 255]) * RTP_PAYLOAD,
                        (peer, RTP_PORT))
    except Exception as exc:
        errors.append(str(exc))


def receive_media(sock, peer, remote_ssrc):
    # Unlike the no-loss integration probe, *never* wait for all 250
    # packets. A dropped RTP frame is a measurement, not a deadlock.
    end = time.monotonic() + MEDIA_SECONDS + 1.7
    seen = set()
    highest = -1
    duplicates = reordered = 0
    jitter_ticks = 0.0
    last_transit = None
    last_arrival = None
    largest_gap_ms = 0.0
    while time.monotonic() < end:
        sock.settimeout(min(0.20, max(0.01, end - time.monotonic())))
        try:
            data, addr = get_voice_packet(sock, 2048)
        except socket.timeout:
            continue
        require(addr[0] == peer, "RTP unexpected source IP")
        require(len(data) == 12 + RTP_PAYLOAD and
                data[0] == 0x80 and (data[1] & 127) == 0,
                "RTP v2/PCMU frame invalid")
        _, _, seq, timestamp, ssrc = struct.unpack("!BBHII", data[:12])
        require(ssrc == remote_ssrc and seq < PACKETS and
                timestamp == seq * RTP_PAYLOAD and
                data[12:] == bytes([seq & 255]) * RTP_PAYLOAD,
                "RTP sequence, SSRC, timestamp or audio payload corrupted")
        if seq in seen:
            duplicates += 1
            continue
        if seq < highest:
            reordered += 1
        highest = max(highest, seq)
        seen.add(seq)
        arrival = time.monotonic()
        if last_arrival is not None:
            largest_gap_ms = max(largest_gap_ms,
                                 (arrival - last_arrival) * 1000)
        last_arrival = arrival
        transit = arrival * 8000.0 - timestamp
        if last_transit is not None:
            jitter_ticks += (abs(transit - last_transit) - jitter_ticks) / 16
        last_transit = transit
    missed = PACKETS - len(seen)
    return {
        "expected": PACKETS,
        "received": len(seen),
        "missing": missed,
        "loss_percent": 100.0 * missed / PACKETS,
        "reordered": reordered,
        "duplicate": duplicates,
        "jitter_ms": jitter_ticks / 8.0,
        "max_gap_ms": largest_gap_ms,
    }


def report(local_ssrc, remote_ssrc, stats):
    fraction = round(256.0 * stats["missing"] / PACKETS)
    missing = stats["missing"]
    return (struct.pack("!BBHI", 0x81, 201, 7, local_ssrc) +
            struct.pack("!IB3sIIII", remote_ssrc, min(fraction, 255),
                        missing.to_bytes(3, "big"), PACKETS - 1,
                        round(stats["jitter_ms"] * 8), 0, 0))


def rtcp_exchange(sock, peer, local_ssrc, remote_ssrc, stats):
    payload = report(local_ssrc, remote_ssrc, stats)
    for _ in range(5):
        sock.sendto(payload, (peer, RTCP_PORT))
        time.sleep(0.08)
    deadline = time.monotonic() + 2.5
    while time.monotonic() < deadline:
        sock.settimeout(min(0.4, max(0.01, deadline - time.monotonic())))
        try:
            data, addr = get_voice_packet(sock, 512)
        except socket.timeout:
            continue
        if (addr[0] == peer and len(data) == 32 and
                data[:2] == b"\x81\xc9" and
                struct.unpack_from("!I", data, 4)[0] == remote_ssrc and
                struct.unpack_from("!I", data, 8)[0] == local_ssrc):
            return {"fraction_lost": data[12], "jitter_ticks": struct.unpack_from("!I", data, 20)[0]}
    raise AssertionError("RTCP RR not received after 5 lossy-netem transmissions")


def run(role, local, peer, marker, profile):
    thresholds = PROFILES[profile]
    local_ssrc = 0x11111111 if role == "listen" else 0x22222222
    remote_ssrc = 0x22222222 if role == "listen" else 0x11111111
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sip, \
         voice_socket(local, RTP_PORT) as rtp, \
         voice_socket(local, RTCP_PORT) as rtcp:
        sip.bind((local, SIP_PORT if role == "listen" else 0))
        if role == "listen":
            ready(marker)
        retransmits = sip_start(sip, role, local, peer)
        errors = []
        sender = threading.Thread(target=send_media,
                                  args=(rtp, peer, local_ssrc, errors),
                                  daemon=True)
        sender.start()
        stats = receive_media(rtp, peer, remote_ssrc)
        sender.join(timeout=2)
        require(not sender.is_alive() and not errors,
                f"RTP sender failed: {errors}")
        response = rtcp_exchange(rtcp, peer, local_ssrc, remote_ssrc, stats)
        sip_end(sip, role, peer)
    stats.update({"profile": profile, "role": role,
                  "sip_invite_retries": retransmits,
                  "rtcp_report": response})
    print("WAN_QOE_JSON=" + json.dumps(stats, sort_keys=True), flush=True)
    require(stats["received"] > 0, "all media packets lost")
    require(stats["loss_percent"] <= thresholds["loss"],
            f"RTP receive loss too high: {stats['loss_percent']}%")
    require(stats["jitter_ms"] <= thresholds["jitter_ms"],
            f"RTP receive jitter too high: {stats['jitter_ms']:.1f} ms")
    require(stats["max_gap_ms"] <= thresholds["gap_ms"],
            f"RTP interarrival gap too high: {stats['max_gap_ms']:.1f} ms")
    print(f"PASS WAN {profile} {role}: SIP INVITE/ACK/BYE, "
          f"RTP {stats['received']}/{PACKETS}, "
          f"loss={stats['loss_percent']:.1f}%, "
          f"jitter={stats['jitter_ms']:.2f}ms, "
          f"reordered={stats['reordered']}, "
          "DSCP EF and RTCP RR", flush=True)


if __name__ == "__main__":
    try:
        require(len(sys.argv) == 6,
                "usage: wan_probe.py listen|send local peer marker regional|poor")
        _, role, local, peer, marker, profile = sys.argv
        require(role in ("listen", "send") and profile in PROFILES,
                "bad WAN test role/profile")
        run(role, local, peer, marker, profile)
    except Exception as exc:
        print(f"FAIL WAN probe: {exc}", file=sys.stderr, flush=True)
        raise
