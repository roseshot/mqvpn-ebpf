package l3

import (
	"encoding/binary"
	"errors"
	"fmt"
	"sync"

	"github.com/klauspost/compress/zstd"
)

// Experimental EtherType, only used inside the synthetic Ethernet envelope
// after authenticated HTTP negotiation of Mqvpn-Compression: zstd-v1.
// This is NOT advertised on a physical Ethernet interface.
const zstdEtherType = 0x88b5

const (
	minCompressBytes = 512
	minSavingsBytes  = 16
	maxDecodedMemory = 1 << 20
)

// Codec is scoped to an authenticated VPN session. Stateless zstd frames
// (no cross-packet dictionary) prevent reordering and losses from affecting
// subsequent packets. Plain CONNECT-ETHERNET frames remain interoperable.
type Codec struct {
	Compression bool
	MaxFrame    int // Ethernet header + original inner IP packet
}

var encoders sync.Pool
var decoders sync.Pool

func zstdEncode(pkt []byte) ([]byte, error) {
	raw := encoders.Get()
	var encoder *zstd.Encoder
	if raw == nil {
		var err error
		encoder, err = zstd.NewWriter(nil,
			zstd.WithEncoderLevel(zstd.SpeedFastest),
			zstd.WithEncoderConcurrency(1))
		if err != nil {
			return nil, err
		}
	} else {
		encoder = raw.(*zstd.Encoder)
	}
	defer encoders.Put(encoder)
	return encoder.EncodeAll(pkt, nil), nil
}

func zstdDecode(data []byte) ([]byte, error) {
	raw := decoders.Get()
	var decoder *zstd.Decoder
	if raw == nil {
		var err error
		decoder, err = zstd.NewReader(nil,
			zstd.WithDecoderConcurrency(1),
			zstd.WithDecoderMaxMemory(maxDecodedMemory))
		if err != nil {
			return nil, err
		}
	} else {
		decoder = raw.(*zstd.Decoder)
	}
	defer decoders.Put(decoder)
	return decoder.DecodeAll(data, nil)
}

// Wrap selects compression only when explicitly negotiated, outside the
// low-latency priority class, and after a meaningful per-packet saving.
// Uncompressible or encrypted IP payloads retain the ordinary frame format.
func (c Codec) Wrap(pkt []byte, priority bool) ([]byte, error) {
	if !c.Compression || priority || len(pkt) < minCompressBytes {
		return Wrap(pkt)
	}
	if _, _, _, err := Inspect(pkt); err != nil {
		return nil, err
	}
	compressed, err := zstdEncode(pkt)
	if err != nil {
		return nil, fmt.Errorf("zstd encode: %w", err)
	}
	// The new format adds a 2-byte uncompressed-length field.
	if len(compressed)+2+minSavingsBytes >= len(pkt) {
		return Wrap(pkt)
	}
	frame := make([]byte, 1+EthernetLen+2+len(compressed))
	frame[0] = ContextIDZero
	copy(frame[1:7], outerDst[:])
	copy(frame[7:13], outerSrc[:])
	binary.BigEndian.PutUint16(frame[13:15], zstdEtherType)
	binary.BigEndian.PutUint16(frame[15:17], uint16(len(pkt)))
	copy(frame[17:], compressed)
	return frame, nil
}

// Unwrap accepts the standard IP frame on all connections, and additionally
// accepts zstd-v1 frames only after authenticated capability negotiation.
// Reject excessive decoded sizes and verify the restored inner IP header.
func (c Codec) Unwrap(payload []byte) ([]byte, error) {
	if len(payload) < 1+EthernetLen || payload[0] != ContextIDZero {
		return nil, errors.New("invalid CONNECT-ETHERNET context")
	}
	if binary.BigEndian.Uint16(payload[13:15]) != zstdEtherType {
		pkt, err := Unwrap(payload)
		if err != nil {
			return nil, err
		}
		if c.MaxFrame > 0 && len(pkt)+EthernetLen > c.MaxFrame {
			return nil, errors.New("IP packet exceeds configured max_frame")
		}
		return pkt, nil
	}
	if !c.Compression {
		return nil, errors.New("compressed packet without negotiated zstd-v1")
	}
	if len(payload) < 18 {
		return nil, errors.New("short zstd-v1 frame")
	}
	decodedLen := int(binary.BigEndian.Uint16(payload[15:17]))
	if decodedLen < 20 || (c.MaxFrame > 0 && decodedLen+EthernetLen > c.MaxFrame) {
		return nil, errors.New("zstd-v1 decoded IP length exceeds limit")
	}
	pkt, err := zstdDecode(payload[17:])
	if err != nil {
		return nil, fmt.Errorf("zstd decode: %w", err)
	}
	if len(pkt) != decodedLen {
		return nil, errors.New("zstd-v1 decoded length mismatch")
	}
	if _, _, _, err := Inspect(pkt); err != nil {
		return nil, err
	}
	return pkt, nil
}
