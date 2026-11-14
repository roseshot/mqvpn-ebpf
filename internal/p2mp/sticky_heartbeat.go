package p2mp

// StickyHeartbeatMarker is a private, authenticated realtime companion
// control datagram. Its nonzero context ID cannot be confused with a
// CONNECT-ETHERNET application frame, whose context ID is always zero.
// It is never forwarded into the Linux TUN.
const (
	StickyHeartbeatMarker byte = 0xfe
	StickyHeartbeatSize        = 9
)

func IsStickyHeartbeat(payload []byte) bool {
	return len(payload) == StickyHeartbeatSize && payload[0] == StickyHeartbeatMarker
}
