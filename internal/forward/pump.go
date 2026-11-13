package forward

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync/atomic"

	"github.com/roseshot/mqvpn-ebpf/internal/ethernet"
)

// DatagramStream is implemented by http3.Stream and http3.RequestStream.
// Its payload begins at the CONNECT-ETHERNET Context ID; http3 itself
// handles the Quarter Stream ID and QUIC DATAGRAM frame.
type DatagramStream interface {
	SendDatagram([]byte) error
	ReceiveDatagram(context.Context) ([]byte, error)
}

type Counters struct {
	TXFrames atomic.Uint64
	RXFrames atomic.Uint64
	TXDrops  atomic.Uint64
	RXDrops  atomic.Uint64
	TXBytes  atomic.Uint64
	RXBytes  atomic.Uint64
}

type Snapshot struct {
	TXFrames, RXFrames, TXDrops, RXDrops, TXBytes, RXBytes uint64
}

func (c *Counters) Snapshot() Snapshot {
	return Snapshot{c.TXFrames.Load(), c.RXFrames.Load(), c.TXDrops.Load(), c.RXDrops.Load(), c.TXBytes.Load(), c.RXBytes.Load()}
}

// Run bridges TAP and a CONNECT-ETHERNET HTTP/3 request stream.
// It closes tap on termination to unblock a pending Read.
func Run(ctx context.Context, device io.ReadWriteCloser, stream DatagramStream, maxFrame int, c *Counters, logger *slog.Logger) error {
	if maxFrame < ethernet.MinFrameSize || maxFrame > 65535 {
		return errors.New("invalid max-frame (must be 14..65535)")
	}
	if c == nil { c = &Counters{} }
	if logger == nil { logger = slog.Default() }
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	errs := make(chan error, 2)
	go func() {
		buf := make([]byte, 65535)
		for {
			n, err := device.Read(buf)
			if err != nil { errs <- err; return }
			if n < ethernet.MinFrameSize || n > maxFrame {
				c.TXDrops.Add(1)
				continue
			}
			payload, err := ethernet.Encode(buf[:n])
			if err != nil { c.TXDrops.Add(1); continue }
			if err := stream.SendDatagram(payload); err != nil {
				// QUIC DATAGRAM is intentionally unreliable. A PMTU or
				// congestion rejection drops this frame, never fragments it.
				c.TXDrops.Add(1)
				logger.Debug("drop outbound Ethernet frame", "error", err, "bytes", n)
				continue
			}
			c.TXFrames.Add(1)
			c.TXBytes.Add(uint64(n))
		}
	}()
	go func() {
		for {
			payload, err := stream.ReceiveDatagram(ctx)
			if err != nil { errs <- err; return }
			frame, err := ethernet.Decode(payload)
			if err != nil || len(frame) > maxFrame {
				c.RXDrops.Add(1)
				continue
			}
			n, err := device.Write(frame)
			if err != nil { errs <- err; return }
			if n != len(frame) {
				errs <- fmt.Errorf("short TAP write: %d of %d", n, len(frame))
				return
			}
			c.RXFrames.Add(1)
			c.RXBytes.Add(uint64(n))
		}
	}()

	var result error
	select {
	case <-ctx.Done():
		result = ctx.Err()
	case result = <-errs:
	}
	cancel()
	_ = device.Close()
	if errors.Is(result, context.Canceled) || errors.Is(result, io.EOF) {
		return nil
	}
	return result
}
