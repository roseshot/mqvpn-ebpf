//go:build linux

package server

import (
	"io"
	"log/slog"
)

func discardServerTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}
