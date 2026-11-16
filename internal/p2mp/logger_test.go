package p2mp

import (
	"io"
	"log/slog"
)

// discardTestLogger is an explicit dependency of packet-pump tests.
// Production P2MP code never constructs an output handler or fallback logger.
func discardTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}
