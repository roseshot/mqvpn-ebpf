//go:build windows

package app

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
)

func TestWindowsClientFailsClosedBeforeAnyNetworkResources(t *testing.T) {
	if err := clientPlatformPreflight(); !errors.Is(err, errNativeClientUnavailable) {
		t.Fatalf("unexpected native preflight result: %v", err)
	}
	err := RunClient(context.Background(), []string{"--server", "vpn.example.invalid", "--transport", "quic"}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if !errors.Is(err, errNativeClientUnavailable) {
		t.Fatalf("Windows must not dial without native route/DNS and underlay protection: %v", err)
	}
	if !strings.Contains(err.Error(), "Wintun") {
		t.Fatalf("Windows unsupported error should identify pending network requirements: %v", err)
	}
}
