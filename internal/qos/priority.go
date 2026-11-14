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

// Class separates interactive realtime traffic, assured delivery, and bulk.
// Only Realtime is eligible for the single-WAN sticky QUIC companion.
// Assured never changes the existing connection-wide MPQUIC path scheduler.
type Class uint8

const (
	BestEffort Class = iota
	Assured
	Realtime
)

// Classify respects caller-supplied IPv4/IPv6 DSCP without trusting
// malformed IP headers. SIP/EF is strict realtime; AF1x–AF4x, CS5,
// CS6 and CS7 share an assured bulk-MPQUIC queue.
func Classify(pkt []byte) Class {
	if Priority(pkt) {
		return Realtime
	}
	if len(pkt) == 0 {
		return BestEffort
	}
	var dscp byte
	switch pkt[0] >> 4 {
	case 4:
		if len(pkt) < 20 || pkt[0]&0x0f < 5 ||
			len(pkt) < int(pkt[0]&0x0f)*4 ||
			len(pkt) != int(pkt[2])<<8|int(pkt[3]) {
			return BestEffort
		}
		dscp = pkt[1] >> 2
	case 6:
		if len(pkt) < 40 || len(pkt) != 40+(int(pkt[4])<<8|int(pkt[5])) {
			return BestEffort
		}
		dscp = (((pkt[0] & 0x0f) << 4) | pkt[1]>>4) >> 2
	default:
		return BestEffort
	}
	switch dscp {
	case 10, 12, 14, 18, 20, 22, 26, 28, 30, 34, 36, 38, 40, 48, 56:
		return Assured
	default:
		return BestEffort
	}
}

// Weighted schedule bounds the service gap for every continuously queued
// class: four realtime, two assured, one best-effort packet per seven
// selections. Unused slots are immediately borrowed by active queues.
var qosSchedule = [...]Class{Realtime, Realtime, Assured, Realtime, Assured, Realtime, BestEffort}

// NextTier uses a cyclic, bounded weighted service order. No lane can
// monopolize the sender while the other lanes are backlogged. A return
// value of false indicates cancellation; channels remain open for lifetime.
func NextTier(ctx context.Context, realtime, assured, bestEffort <-chan []byte, cursor *int) ([]byte, bool) {
	if ctx.Err() != nil {
		return nil, false
	}
	for i := 0; i < len(qosSchedule); i++ {
		idx := (*cursor + i) % len(qosSchedule)
		var queue <-chan []byte
		switch qosSchedule[idx] {
		case Realtime:
			queue = realtime
		case Assured:
			queue = assured
		default:
			queue = bestEffort
		}
		select {
		case pkt := <-queue:
			*cursor = (idx + 1) % len(qosSchedule)
			return pkt, true
		default:
		}
	}
	select {
	case <-ctx.Done():
		return nil, false
	case pkt := <-realtime:
		*cursor = 1
		return pkt, true
	case pkt := <-assured:
		*cursor = 3
		return pkt, true
	case pkt := <-bestEffort:
		*cursor = 0
		return pkt, true
	}
}
