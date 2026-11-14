// Package qos implements priority classification and SIP/RTP observability.
package qos

import (
	"encoding/binary"
	"net/netip"
	"sync"
	"time"
)

const maxVoIPStreams = 128

// VoIPStats contains receive-side indicators for DSCP EF-marked RTP and RTCP.
// Sequence gaps are NOT confirmed losses: reordered packets may arrive later.
// RTCP jitter is expressed in RTP clock ticks, not milliseconds (the codec
// sampling rate is unavailable without the SIP/SDP signalling context).
type VoIPStats struct {
	RTPPackets           uint64
	RTCPPackets          uint64
	RTPSequenceGapEvents uint64
	EstimatedMissing     uint64
	LateOrDuplicate      uint64
	RTCPReportBlocks     uint64
	LatestFractionLost   uint8
	LatestCumulativeLost int32
	LatestJitterTicks    uint32
}

type voipFlow struct {
	lastSeq  uint16
	lastSeen time.Time
}

type voipKey struct {
	src, dst netip.Addr
	sport    uint16
	dport    uint16
	ssrc     uint32
}

// VoIPMonitor safely collects metrics from a live authenticated VPN session.
// It only inspects inner IPv4/IPv6 UDP packets marked DSCP EF (46) and keeps
// at most 128 SSRC/5-tuple states. Packets are never blocked or rewritten.
type VoIPMonitor struct {
	mu    sync.Mutex
	flows map[voipKey]*voipFlow
	stats VoIPStats
}

func (m *VoIPMonitor) Snapshot() VoIPStats {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.stats
}

func evictOldestFlow(flows map[voipKey]*voipFlow) {
	var oldest voipKey
	var seen time.Time
	for key, flow := range flows {
		if seen.IsZero() || flow.lastSeen.Before(seen) {
			oldest, seen = key, flow.lastSeen
		}
	}
	if !seen.IsZero() {
		delete(flows, oldest)
	}
}

// voiceUDPPayload extracts a DSCP EF-marked, non-fragmented UDP packet.
// IPv6 extension-header chains are intentionally not guessed or parsed.
func voiceUDPPayload(packet []byte) (src, dst netip.Addr, sport, dport uint16, payload []byte, ok bool) {
	if len(packet) < 1 {
		return
	}
	var start int
	switch packet[0] >> 4 {
	case 4:
		if len(packet) < 20 || packet[0]&0x0f < 5 {
			return
		}
		start = int(packet[0]&0x0f) * 4
		if len(packet) < start+8 || int(binary.BigEndian.Uint16(packet[2:4])) != len(packet) ||
			packet[1]>>2 != 46 || packet[9] != 17 ||
			binary.BigEndian.Uint16(packet[6:8])&0x3fff != 0 {
			return
		}
		var a, b [4]byte
		copy(a[:], packet[12:16])
		copy(b[:], packet[16:20])
		src, dst = netip.AddrFrom4(a), netip.AddrFrom4(b)
	case 6:
		if len(packet) < 48 || int(binary.BigEndian.Uint16(packet[4:6]))+40 != len(packet) ||
			packet[6] != 17 {
			return
		}
		tc := (packet[0]&0x0f)<<4 | packet[1]>>4
		if tc>>2 != 46 {
			return
		}
		start = 40
		var a, b [16]byte
		copy(a[:], packet[8:24])
		copy(b[:], packet[24:40])
		src, dst = netip.AddrFrom16(a), netip.AddrFrom16(b)
	default:
		return
	}
	udp := packet[start:]
	udpLen := int(binary.BigEndian.Uint16(udp[4:6]))
	if udpLen < 8 || udpLen > len(udp) {
		return
	}
	sport = binary.BigEndian.Uint16(udp[:2])
	dport = binary.BigEndian.Uint16(udp[2:4])
	payload = udp[8:udpLen]
	return src, dst, sport, dport, payload, true
}

func (m *VoIPMonitor) Observe(packet []byte) {
	src, dst, sport, dport, data, ok := voiceUDPPayload(packet)
	if !ok || len(data) < 8 || data[0]>>6 != 2 {
		return
	}
	// RTCP RR/SR carry the endpoint-reported loss and RFC 3550 jitter.
	// Only treat 200/201 as RTCP when the full declared RTCP packet fits.
	if data[1] == 200 || data[1] == 201 {
		packetLen := (int(binary.BigEndian.Uint16(data[2:4])) + 1) * 4
		reportOffset := 8
		if data[1] == 200 {
			reportOffset = 28
		}
		reports := int(data[0] & 0x1f)
		if packetLen >= reportOffset+reports*24 && packetLen <= len(data) {
			m.mu.Lock()
			m.stats.RTCPPackets++
			for i := 0; i < reports; i++ {
				block := data[reportOffset+i*24:]
				lost := int32(block[5])<<16 | int32(block[6])<<8 | int32(block[7])
				if lost&0x800000 != 0 {
					lost |= ^int32(0xffffff)
				}
				m.stats.RTCPReportBlocks++
				m.stats.LatestFractionLost = block[4]
				m.stats.LatestCumulativeLost = lost
				m.stats.LatestJitterTicks = binary.BigEndian.Uint32(block[12:16])
			}
			m.mu.Unlock()
			return
		}
	}
	if len(data) < 12+int(data[0]&0x0f)*4 {
		return
	}
	// Don't misinterpret malformed RTCP lookalikes as RTP.
	if data[1] >= 200 && data[1] <= 211 {
		return
	}
	seq := binary.BigEndian.Uint16(data[2:4])
	key := voipKey{
		src: src, dst: dst, sport: sport, dport: dport,
		ssrc: binary.BigEndian.Uint32(data[8:12]),
	}
	now := time.Now()
	m.mu.Lock()
	defer m.mu.Unlock()
	m.stats.RTPPackets++
	if m.flows == nil {
		m.flows = make(map[voipKey]*voipFlow)
	}
	flow := m.flows[key]
	if flow == nil {
		if len(m.flows) >= maxVoIPStreams {
			evictOldestFlow(m.flows)
		}
		m.flows[key] = &voipFlow{lastSeq: seq, lastSeen: now}
		return
	}
	delta := int16(seq - flow.lastSeq)
	if delta > 1 {
		m.stats.RTPSequenceGapEvents++
		m.stats.EstimatedMissing += uint64(delta - 1)
	}
	if delta <= 0 {
		m.stats.LateOrDuplicate++
	} else {
		flow.lastSeq = seq
	}
	flow.lastSeen = now
}
