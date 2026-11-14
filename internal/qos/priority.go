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
        proto, offset = pkt[6], 40
        // Extension-header parsing is unnecessary for SIP classification.
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
