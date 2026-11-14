package p2mp

import (
	"context"
	"errors"

	quic "github.com/qoke/mp-quic-go"
	"github.com/roseshot/mqvpn-ebpf/internal/l3"
)

const (
	// HTTP/3 adds the quarter-stream ID and QUIC DATAGRAM framing. Leave
	// headroom because QUIC reports a transport payload limit, not an
	// application CONNECT-ETHERNET payload limit.
	datagramSizeHeadroom = 64
	maxSizeRetries       = 2
)

// sendEncodedFrame adapts to a QUIC DATAGRAM size rejection. This is
// opportunistic transport feedback, NOT per-WAN-path PMTU discovery.
// The fragmenter and stream belong to the same session sender goroutine.
//
// If any fragment was already accepted by QUIC before a later fragment
// became too large (for example after MPQUIC path changes), restarting
// with a fresh fragment ID leaves the old incomplete assembly to expire.
func sendEncodedFrame(ctx context.Context, stream Stream, fragmenter *l3.Fragmenter, frame []byte) (sent, reductions int, err error) {
	for attempt := 0; attempt <= maxSizeRetries; attempt++ {
		if err := ctx.Err(); err != nil {
			return sent, reductions, err
		}
		parts, err := fragmenter.Split(frame)
		if err != nil {
			return sent, reductions, err
		}
		var failed error
		for _, part := range parts {
			if err := ctx.Err(); err != nil {
				return sent, reductions, err
			}
			if err := stream.SendDatagram(part); err != nil {
				failed = err
				break
			}
			sent++
		}
		if failed == nil {
			return sent, reductions, nil
		}

		// Only a typed size error can justify an adaptive retry.
		// General transport errors and peer disconnects never trigger
		// repeated sends of the same IP packet.
		var tooLarge *quic.DatagramTooLargeError
		if attempt == maxSizeRetries || !fragmenter.Enabled || !errors.As(failed, &tooLarge) {
			return sent, reductions, failed
		}
		if tooLarge.MaxDatagramPayloadSize <= datagramSizeHeadroom ||
			!fragmenter.ReduceBudget(int(tooLarge.MaxDatagramPayloadSize)-datagramSizeHeadroom) {
			return sent, reductions, failed
		}
		reductions++
	}
	return sent, reductions, errors.New("exhausted DATAGRAM payload-size retries")
}
