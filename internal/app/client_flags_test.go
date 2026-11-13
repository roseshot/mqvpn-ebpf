package app

import (
	"context"
	"io"
	"log/slog"
	"testing"
)

func TestNoDeprecatedClientWANFlags(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	for _, flag := range []string{"--wan1", "--wan2", "--wan1-ip", "--wan1-interface", "--wan2-iface"} {
		if err := RunClient(context.Background(), []string{flag, "192.0.2.10"}, logger); err == nil {
			t.Fatalf("deprecated client flag %s accepted", flag)
		}
	}
}
