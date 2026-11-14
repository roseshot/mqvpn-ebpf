package p2mp

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"

	"github.com/roseshot/mqvpn-ebpf/internal/l3"
	"github.com/roseshot/mqvpn-ebpf/internal/logging"
	"github.com/roseshot/mqvpn-ebpf/internal/qos"
)

// realtimeDatagramSender is supplied by the opt-in dual-session QUIC
// transport. It sends classified realtime frames on the single-WAN
// companion connection, never on the round-robin bulk connection.
type realtimeDatagramSender interface {
	SendRealtimeDatagram([]byte) error
}

type realtimeSendStream struct {
	Stream
	sender realtimeDatagramSender
}

func (r realtimeSendStream) SendDatagram(data []byte) error {
	return r.sender.SendRealtimeDatagram(data)
}

// ClientPump retains the legacy frame format for callers that did not
// negotiate the optional zstd-v1 capability.
func ClientPump(ctx context.Context, device io.ReadWriteCloser, stream Stream, maxFrame int, logger *slog.Logger) error {
	return ClientPumpWithFeatures(ctx, device, stream, maxFrame, false, false, logger)
}

// ClientPumpWithCompression forwards all valid IP traffic without imposing
// port- or DSCP-based ACLs. RTP marked DSCP EF and SIP signalling use a
// bounded priority queue, and are never compressed.
func ClientPumpWithCompression(ctx context.Context, device io.ReadWriteCloser, stream Stream, maxFrame int, compression bool, logger *slog.Logger) error {
	return ClientPumpWithFeatures(ctx, device, stream, maxFrame, compression, false, logger)
}

// ClientPumpWithFeatures uses negotiated Zstd and fragmentation without
// changing legacy call sites or the SIP/RTP priority policy.
func ClientPumpWithFeatures(ctx context.Context, device io.ReadWriteCloser, stream Stream, maxFrame int, compression, fragmentation bool, logger *slog.Logger) error {
	if maxFrame < 64 || maxFrame > 65535 {
		return fmt.Errorf("invalid maxFrame %d", maxFrame)
	}
	logger = logging.Ensure(logger)
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	codec := l3.Codec{Compression: compression, MaxFrame: maxFrame}
	fragmenter := &l3.Fragmenter{Enabled: fragmentation}
	reassembler := &l3.Reassembler{Enabled: fragmentation, MaxFrame: maxFrame}
	voice := &qos.VoIPMonitor{}
	urgent, normal := make(chan []byte, 64), make(chan []byte, 192)
	ends := make(chan error, 3)
	var workers sync.WaitGroup
	workers.Add(3)
	realtime, hasRealtime := stream.(interface {
		ReceiveRealtimeDatagram(context.Context) ([]byte, error)
	})
	if hasRealtime {
		workers.Add(1)
	}
	var writeMu sync.Mutex

	go func() {
		defer workers.Done()
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
			pkt := buf[:n]
			if _, _, _, err := l3.Inspect(pkt); err != nil {
				continue
			}
			priority := qos.Priority(pkt)
			// The TUN read buffer is reused, so queued packets own a copy.
			copyPkt := append([]byte(nil), pkt...)
			queue := normal
			if priority {
				queue = urgent
			}
			// Slow peers must not create an unbounded buffer or block
			// the reader behind bulk traffic.
			select {
			case <-ctx.Done():
				return
			case queue <- copyPkt:
			default:
				logger.DebugContext(ctx, "client DATAGRAM priority queue full", "priority", priority)
			}
		}
	}()

	go func() {
		defer workers.Done()
		burst := 0
		for {
			pkt, ok := qos.Next(ctx, urgent, normal, &burst)
			if !ok || ctx.Err() != nil {
				return
			}
			payload, err := codec.Wrap(pkt, qos.Priority(pkt))
			if err != nil {
				continue
			}
			out := stream
			if qos.Priority(pkt) {
				if sticky, ok := stream.(realtimeDatagramSender); ok {
					out = realtimeSendStream{Stream: stream, sender: sticky}
				}
			}
			_, reductions, err := sendEncodedFrame(ctx, out, fragmenter, payload)
			if reductions > 0 {
				logger.InfoContext(ctx, "client DATAGRAM size budget reduced",
					"budget", fragmenter.Budget(), "reductions", reductions)
			}
			if err != nil {
				logger.DebugContext(ctx, "client QUIC DATAGRAM rejected", "error", err)
			}
		}
	}()

	go func() {
		defer workers.Done()
		for {
			payload, err := stream.ReceiveDatagram(ctx)
			if err != nil {
				ends <- err
				return
			}
			frame, complete, err := reassembler.Accept(payload)
			if err != nil || !complete {
				continue
			}
			pkt, err := codec.Unwrap(frame)
			if err != nil {
				continue
			}
			writeMu.Lock()
			n, err := device.Write(pkt)
			writeMu.Unlock()
			if err != nil {
				ends <- err
				return
			}
			if n != len(pkt) {
				ends <- fmt.Errorf("short TUN write: %d / %d", n, len(pkt))
				return
			}
			voice.Observe(pkt)
		}
	}()

	// Realtime companion frames use a separate fragment-ID namespace.
	// Both receivers synchronize writes to the same Linux TUN and share
	// the threadsafe VoIP monitor, but never merge partial fragments.
	if hasRealtime {
		go func() {
			defer workers.Done()
			stickyReassembler := &l3.Reassembler{Enabled: fragmentation, MaxFrame: maxFrame}
			for {
				frame, err := realtime.ReceiveRealtimeDatagram(ctx)
				if err != nil {
					return
				}
				payload, complete, err := stickyReassembler.Accept(frame)
				if err != nil || !complete {
					continue
				}
				pkt, err := codec.Unwrap(payload)
				if err != nil {
					continue
				}
				writeMu.Lock()
				n, err := device.Write(pkt)
				writeMu.Unlock()
				if err != nil || n != len(pkt) {
					ends <- fmt.Errorf("realtime TUN write: %w (len %d/%d)", err, n, len(pkt))
					return
				}
				voice.Observe(pkt)
			}
		}()
	}

	var result error
	select {
	case <-ctx.Done():
		result = ctx.Err()
	case result = <-ends:
	}
	cancel()
	// Close TUN before joining all workers; a stale reader must never
	// access the device after the next reconnect attempt starts.
	closeErr := device.Close()
	workers.Wait()
	if stats := voice.Snapshot(); stats.RTPPackets > 0 || stats.RTCPPackets > 0 {
		logger.Info("client VoIP receive summary", "stats", stats)
	}
	if errors.Is(result, context.Canceled) || errors.Is(result, io.EOF) {
		result = nil
	}
	return errors.Join(result, closeErr)
}
