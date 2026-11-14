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

// ClientPump retains the legacy frame format for callers that did not
// negotiate the optional zstd-v1 capability.
func ClientPump(ctx context.Context, device io.ReadWriteCloser, stream Stream, maxFrame int, logger *slog.Logger) error {
    return ClientPumpWithCompression(ctx, device, stream, maxFrame, false, logger)
}

// ClientPumpWithCompression forwards all valid IP traffic without imposing
// port- or DSCP-based ACLs. RTP marked DSCP EF and SIP signalling use a
// bounded priority queue, and are never compressed.
func ClientPumpWithCompression(ctx context.Context, device io.ReadWriteCloser, stream Stream, maxFrame int, compression bool, logger *slog.Logger) error {
    if maxFrame < 64 || maxFrame > 65535 {
        return fmt.Errorf("invalid maxFrame %d", maxFrame)
    }
    logger = logging.Ensure(logger)
    ctx, cancel := context.WithCancel(ctx)
    defer cancel()
    codec := l3.Codec{Compression: compression, MaxFrame: maxFrame}
    urgent, normal := make(chan []byte, 64), make(chan []byte, 192)
    ends := make(chan error, 3)
    var workers sync.WaitGroup
    workers.Add(3)

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
            if priority { queue = urgent }
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
            if !ok || ctx.Err() != nil { return }
            payload, err := codec.Wrap(pkt, qos.Priority(pkt))
            if err != nil { continue }
            if err := stream.SendDatagram(payload); err != nil {
                // QUIC DATAGRAM has no retransmission guarantee.
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
            pkt, err := codec.Unwrap(payload)
            if err != nil { continue }
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
    // Close TUN before joining all workers; a stale reader must never
    // access the device after the next reconnect attempt starts.
    closeErr := device.Close()
    workers.Wait()
    if errors.Is(result, context.Canceled) || errors.Is(result, io.EOF) {
        result = nil
    }
    return errors.Join(result, closeErr)
}
