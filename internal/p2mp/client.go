package p2mp

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"

	"github.com/roseshot/mqvpn-ebpf/internal/l3"
)

// ClientPump transports every valid IP packet read from the TUN. It does not
// inspect ports, multicast groups, IP source addresses, mDNS, or packet rate.
// Linux (not mqvpn) decides which traffic to send to the TUN.
func ClientPump(ctx context.Context, device io.ReadWriteCloser, stream Stream, maxFrame int, logger *slog.Logger) error {
	if maxFrame < 64 || maxFrame > 65535 {
		return fmt.Errorf("invalid maxFrame %d", maxFrame)
	}
	if logger == nil {
		logger = slog.Default()
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	ends := make(chan error, 2)
	go func() {
		buf := make([]byte, 65535)
		for {
			n, err := device.Read(buf)
			if err != nil {
				ends <- err
				return
			}
			if n+l3.EthernetLen > maxFrame {
				continue
			}
			payload, err := l3.Wrap(buf[:n])
			if err != nil {
				continue
			}
			if err := stream.SendDatagram(payload); err != nil {
				// A QUIC DATAGRAM can be dropped due to path MTU or congestion.
				logger.Debug("client QUIC DATAGRAM rejected", "error", err)
			}
		}
	}()
	go func() {
		for {
			payload, err := stream.ReceiveDatagram(ctx)
			if err != nil {
				ends <- err
				return
			}
			pkt, err := l3.Unwrap(payload)
			if err != nil || len(pkt)+l3.EthernetLen > maxFrame {
				continue
			}
			n, err := device.Write(pkt)
			if err != nil {
				ends <- err
				return
			}
			if n != len(pkt) {
				ends <- fmt.Errorf("short TUN write: %d / %d", n, len(pkt))
				return
			}
		}
	}()
	var result error
	select {
	case <-ctx.Done():
		result = ctx.Err()
	case result = <-ends:
	}
	cancel()
	// Closing TUN stops a blocked kernel Read. Always wait for both pump
	// goroutines before returning to the reconnect supervisor; otherwise
	// the previous session could still touch an interface being restored.
	closeErr := device.Close()
	<-ends
	if errors.Is(result, context.Canceled) || errors.Is(result, io.EOF) {
		result = nil
	}
	return errors.Join(result, closeErr)
}
