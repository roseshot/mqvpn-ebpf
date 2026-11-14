// Package qos provides conservative classification and fair high-priority
// DATAGRAM scheduling. No traffic is denied based on packet contents.
package qos

import "context"

const (
	// EF (Expedited Forwarding) is commonly applied to VoIP RTP by the PBX.
	dscpEF = 46
	// Bound realtime bursts so signalling and bulk transfers still progress.
	maxPriorityBurst = 4
)

// Priority returns true for DSCP EF packets and the usual SIP signalling
// ports. RTP uses dynamic negotiated ports, so it must be DSCP-marked by
// the phone/PBX or a network QoS policy. We deliberately do not guess RTP
// from arbitrary UDP payloads or blindly prioritize a wide ephemeral range.
func Priority(pkt []byte) bool {
	if len(pkt) < 1 {
		return false
	}
	var proto byte
	var offset int
	switch pkt[0] >> 4 {
	case 4:
		if len(pkt) < 20 || pkt[0]&0x0f < 5 {
			return false
		}
		offset = int(pkt[0]&0x0f) * 4
		if len(pkt) < offset || len(pkt) != int(pkt[2])<<8|int(pkt[3]) {
			return false
		}
		if pkt[1]>>2 == dscpEF {
			return true
		}
		// No transport headers exist in non-first fragments.
		if (uint16(pkt[6])<<8|uint16(pkt[7]))&0x1fff != 0 {
			return false
		}
		proto = pkt[9]
	case 6:
		if len(pkt) < 40 || len(pkt)-40 != int(pkt[4])<<8|int(pkt[5]) {
			return false
		}
		trafficClass := (pkt[0]&0x0f)<<4 | pkt[1]>>4
		if trafficClass>>2 == dscpEF {
			return true
		}
		// Follow the IPv6 extension chain so unmarked SIP with Hop-by-Hop,
		// Routing, Destination Options, Fragment or AH headers remains
		// pinned to the realtime WAN. Never infer ports from a non-initial
		// fragment or from malformed/truncated extension headers.
		var ok bool
		proto, offset, ok = ipv6Transport(pkt)
		if !ok {
			return false
		}
	default:
		return false
	}
	if (proto != 6 && proto != 17) || len(pkt) < offset+4 {
		return false
	}
	src := uint16(pkt[offset])<<8 | uint16(pkt[offset+1])
	dst := uint16(pkt[offset+2])<<8 | uint16(pkt[offset+3])
	return src == 5060 || dst == 5060 || src == 5061 || dst == 5061
}

// Next prefers priority DATAGRAMs while permitting normal traffic at least
// once every maxPriorityBurst priority selections whenever it is queued.
// The channels are bounded and never closed; ctx cancels the consumer.
func Next(ctx context.Context, priority, normal <-chan []byte, burst *int) ([]byte, bool) {
	if ctx.Err() != nil {
		return nil, false
	}
	if *burst >= maxPriorityBurst {
		select {
		case p := <-normal:
			*burst = 0
			return p, true
		default:
		}
	}
	select {
	case p := <-priority:
		*burst++
		return p, true
	default:
	}
	select {
	case p := <-normal:
		*burst = 0
		return p, true
	default:
	}
	select {
	case <-ctx.Done():
		return nil, false
	case p := <-priority:
		*burst++
		return p, true
	case p := <-normal:
		*burst = 0
		return p, true
	}
}

// ipv6Transport locates the transport header without allocating or reading
// beyond the IPv6 payload. At most 16 extension headers are walked so
// maliciously long chains cannot monopolize the QoS classifier. ESP and
// unknown next-header values are left to the caller (and are never SIP).
func ipv6Transport(pkt []byte) (proto byte, offset int, ok bool) {
	proto, offset = pkt[6], 40
	for headers := 0; headers < 16; headers++ {
		switch proto {
		case 0, 43, 60: // Hop-by-Hop, Routing, Destination Options
			if len(pkt)-offset < 2 {
				return 0, 0, false
			}
			size := (int(pkt[offset+1]) + 1) * 8
			if size > len(pkt)-offset {
				return 0, 0, false
			}
			proto = pkt[offset]
			offset += size
		case 44: // Fragment: only fragment offset 0 contains transport ports
			if len(pkt)-offset < 8 {
				return 0, 0, false
			}
			if pkt[offset+2] != 0 || pkt[offset+3]&0xf8 != 0 {
				return 0, 0, false
			}
			proto = pkt[offset]
			offset += 8
		case 51: // Authentication Header: size in four-byte words minus 2
			if len(pkt)-offset < 2 {
				return 0, 0, false
			}
			size := (int(pkt[offset+1]) + 2) * 4
			if size < 12 || size > len(pkt)-offset {
				return 0, 0, false
			}
			proto = pkt[offset]
			offset += size
		default:
			return proto, offset, true
		}
	}
	return 0, 0, false
}
