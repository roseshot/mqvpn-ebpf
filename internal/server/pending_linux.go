//go:build linux

package server

import (
	"context"

	"github.com/roseshot/mqvpn-ebpf/internal/p2mp"
)

// pendingHTTP3Stream permits authorization and duplicate-session checks
// before committing HTTP 200. HTTPStreamer.HTTPStream() flushes headers
// immediately, so it must only be invoked after all successful response
// headers (Capsule-Protocol, tunnel address, routes, DNS, framing) are set.
type pendingHTTP3Stream struct {
	ctx    context.Context
	ready  chan struct{}
	stream p2mp.Stream
}

func (s *pendingHTTP3Stream) release(stream p2mp.Stream) {
	s.stream = stream
	close(s.ready)
}

func (s *pendingHTTP3Stream) SendDatagram(payload []byte) error {
	select {
	case <-s.ready:
		return s.stream.SendDatagram(payload)
	case <-s.ctx.Done():
		return s.ctx.Err()
	}
}

func (s *pendingHTTP3Stream) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	select {
	case <-s.ready:
		return s.stream.ReceiveDatagram(ctx)
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-s.ctx.Done():
		return nil, s.ctx.Err()
	}
}
