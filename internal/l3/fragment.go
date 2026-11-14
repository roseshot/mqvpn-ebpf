package l3

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

// FramingVersion identifies a private, authenticated CONNECT-ETHERNET
// extension. Older peers must never receive its synthetic EtherType.
const FramingVersion = "frag-v1"

// FragmentPayloadBudget is deliberately below the minimum 1200-byte QUIC
// packet size, leaving room for HTTP/3, QUIC, UDP and outer IP headers.
// It is a conservative cap, NOT a path MTU discovery result.
const FragmentPayloadBudget = 1024

const (
	fragmentEtherType uint16 = 0x88b6
	fragmentHeaderSize       = 12 // packet ID (4), full frame length (4), offset (4)
	fragmentEnvelopeSize     = 1 + EthernetLen + fragmentHeaderSize
	fragmentTimeout          = 2 * time.Second
	maxPendingFragments      = 32
	maxBufferedFragments     = 2 << 20
	maxFragmentsPerPacket    = 16
)

var ErrInvalidFragment = errors.New("invalid VPN DATAGRAM fragment")

// Fragmenter is sender-goroutine local; a separate instance per authenticated
// tunnel means fragment IDs cannot collide between unrelated sessions.
type Fragmenter struct {
	Enabled bool
	nextID  uint32
}

// Split fragments the encoded CONNECT-ETHERNET payload, which may already
// contain a stateless zstd-v1 frame. No fragmentation happens without explicit
// protocol negotiation. Partial transport sends are handled by the caller.
func (f *Fragmenter) Split(frame []byte) ([][]byte, error) {
	if !f.Enabled || len(frame) <= FragmentPayloadBudget {
		return [][]byte{frame}, nil
	}
	if len(frame) < 1+EthernetLen+20 || frame[0] != ContextIDZero || len(frame) > 65536 {
		return nil, ErrInvalidFragment
	}
	chunkSize := FragmentPayloadBudget - fragmentEnvelopeSize
	count := (len(frame) + chunkSize - 1) / chunkSize
	if count > maxFragmentsPerPacket {
		return nil, fmt.Errorf("%w: too many fragments (%d)", ErrInvalidFragment, count)
	}
	f.nextID++
	id := f.nextID
	out := make([][]byte, 0, count)
	for offset := 0; offset < len(frame); offset += chunkSize {
		end := min(offset+chunkSize, len(frame))
		frag := make([]byte, fragmentEnvelopeSize+end-offset)
		frag[0] = ContextIDZero
		copy(frag[1:7], outerDst[:])
		copy(frag[7:13], outerSrc[:])
		binary.BigEndian.PutUint16(frag[13:15], fragmentEtherType)
		binary.BigEndian.PutUint32(frag[15:19], id)
		binary.BigEndian.PutUint32(frag[19:23], uint32(len(frame)))
		binary.BigEndian.PutUint32(frag[23:27], uint32(offset))
		copy(frag[27:], frame[offset:end])
		out = append(out, frag)
	}
	return out, nil
}

type partialFrame struct {
	created  time.Time
	total    int
	received int
	chunks   map[uint32][]byte
}

// Reassembler is receive-goroutine local and must never be shared between
// authenticated sessions. It bounds outstanding frames, retained bytes,
// individual frame sizes and expiry, and tolerates out-of-order arrival.
type Reassembler struct {
	Enabled  bool
	MaxFrame int // Ethernet + inner IP, excluding the 1-byte Context ID.
	partials map[uint32]*partialFrame
	buffered int
}

func (r *Reassembler) remove(id uint32) {
	if p, ok := r.partials[id]; ok {
		r.buffered -= p.received
		delete(r.partials, id)
	}
}

func (r *Reassembler) expire(now time.Time) {
	for id, p := range r.partials {
		if now.Sub(p.created) >= fragmentTimeout {
			r.remove(id)
		}
	}
}

func (r *Reassembler) evictOldest() {
	var oldestID uint32
	var oldest time.Time
	for id, p := range r.partials {
		if oldest.IsZero() || p.created.Before(oldest) {
			oldestID, oldest = id, p.created
		}
	}
	if !oldest.IsZero() {
		r.remove(oldestID)
	}
}

// Accept returns (complete frame, true, nil) only when the whole original
// CONNECT-ETHERNET frame is available. Incomplete fragments return (nil,
// false, nil). Malformed, overlapping or unnegotiated frames are rejected.
func (r *Reassembler) Accept(payload []byte) ([]byte, bool, error) {
	if len(payload) < 1+EthernetLen || payload[0] != ContextIDZero {
		return nil, false, ErrInvalidFragment
	}
	if binary.BigEndian.Uint16(payload[13:15]) != fragmentEtherType {
		// Let the standard Codec verify ordinary IP/zstd frame semantics.
		return payload, true, nil
	}
	if !r.Enabled {
		return nil, false, fmt.Errorf("%w: unnegotiated fragmentation", ErrInvalidFragment)
	}
	if len(payload) <= fragmentEnvelopeSize {
		return nil, false, ErrInvalidFragment
	}
	id := binary.BigEndian.Uint32(payload[15:19])
	total := int(binary.BigEndian.Uint32(payload[19:23]))
	offset := int(binary.BigEndian.Uint32(payload[23:27]))
	data := payload[fragmentEnvelopeSize:]
	if len(payload) > FragmentPayloadBudget ||
		total < 1+EthernetLen+20 || total > 65536 ||
		r.MaxFrame < 64 || total > r.MaxFrame+1 ||
		offset >= total || len(data) > total-offset {
		return nil, false, ErrInvalidFragment
	}
	if r.partials == nil {
		r.partials = make(map[uint32]*partialFrame)
	}
	now := time.Now()
	r.expire(now)
	p := r.partials[id]
	if p != nil && p.total != total {
		r.remove(id)
		return nil, false, fmt.Errorf("%w: conflicting total size", ErrInvalidFragment)
	}
	if p == nil {
		for len(r.partials) >= maxPendingFragments {
			r.evictOldest()
		}
		p = &partialFrame{created: now, total: total, chunks: make(map[uint32][]byte)}
		r.partials[id] = p
	}
	// Prevent overlapping fragments from replacing already trusted bytes.
	// Exact duplicates are harmless on reordered MPQUIC paths.
	for begin, chunk := range p.chunks {
		start := int(begin)
		if start == offset && bytes.Equal(chunk, data) {
			return nil, false, nil
		}
		if offset < start+len(chunk) && start < offset+len(data) {
			r.remove(id)
			return nil, false, fmt.Errorf("%w: overlapping ranges", ErrInvalidFragment)
		}
	}
	for r.buffered+len(data) > maxBufferedFragments {
		r.evictOldest()
		if r.partials[id] == nil {
			return nil, false, fmt.Errorf("%w: fragment memory limit", ErrInvalidFragment)
		}
	}
	p.chunks[uint32(offset)] = append([]byte(nil), data...)
	p.received += len(data)
	r.buffered += len(data)
	if p.received < p.total {
		return nil, false, nil
	}
	complete := make([]byte, total)
	for offset := 0; offset < total; {
		piece := p.chunks[uint32(offset)]
		if len(piece) == 0 {
			r.remove(id)
			return nil, false, fmt.Errorf("%w: missing bytes", ErrInvalidFragment)
		}
		copy(complete[offset:], piece)
		offset += len(piece)
	}
	r.remove(id)
	return complete, true, nil
}
