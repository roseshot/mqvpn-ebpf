package ethernet

import "errors"

const (
	// MinFrameSize excludes the FCS; TAP delivers complete L2 frames without FCS.
	MinFrameSize = 14
	ContextEthernet byte = 0 // QUIC varint encoding of CONNECT-ETHERNET Context ID 0.
)

var (
	ErrInvalidFrame = errors.New("ethernet frame shorter than 14 bytes")
	ErrUnsupportedContext = errors.New("unsupported CONNECT-ETHERNET context ID")
)

// Encode returns the HTTP Datagram payload (not the HTTP/3 quarter stream ID).
// The HTTP/3 library adds the quarter stream ID before the QUIC DATAGRAM is sent.
func Encode(frame []byte) ([]byte, error) {
	if len(frame) < MinFrameSize {
		return nil, ErrInvalidFrame
	}
	p := make([]byte, len(frame)+1)
	p[0] = ContextEthernet
	copy(p[1:], frame)
	return p, nil
}

// Decode returns the Ethernet frame without FCS. A nonzero or malformed
// context ID is not silently treated as Ethernet data.
func Decode(payload []byte) ([]byte, error) {
	if len(payload) == 0 || payload[0] != ContextEthernet {
		return nil, ErrUnsupportedContext
	}
	if len(payload)-1 < MinFrameSize {
		return nil, ErrInvalidFrame
	}
	return payload[1:], nil
}
