package app

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"testing"
)

func TestClientRequiresExplicitTUNAddressBeforeNetworking(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	for _, tc := range []struct {
		args  []string
		match string
	}{
		{[]string{"--tun", "mq0", "--tun-address", "auto", "--wan", "192.0.2.1@wan0"}, "server"},
		{[]string{"--tun", "mq0", "--tun-address", "0.0.0.0/24", "--wan", "192.0.2.1@wan0"}, "unicast"},
		{[]string{"--tun", "mq0", "--tun-address", "fd77::2/64", "--tun-mtu", "1100", "--wan", "192.0.2.1@wan0"}, "MTU"},
		{[]string{"--tun", "mq0", "--tun-address", "10.77.0.2/24", "--tun-mtu", "1200", "--max-frame", "1160", "--wan", "192.0.2.1@wan0"}, "max-frame"},
	} {
		err := RunClient(context.Background(), tc.args, logger)
		if err == nil || !strings.Contains(err.Error(), tc.match) {
			t.Fatalf("args %v: got %v; expected %q", tc.args, err, tc.match)
		}
	}
}

func TestClientRejectsInvalidTCModeBeforeDial(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	err := RunClient(context.Background(), []string{
		"--tun", "mq0", "--tun-address", "10.77.0.2/24",
		"--tc-mode", "unsupported", "--wan", "192.0.2.2@wan0",
	}, logger)
	if err == nil || !strings.Contains(err.Error(), "TC eBPF") {
		t.Fatalf("expected invalid TC eBPF mode error: %v", err)
	}
}

func TestClientReconnectValidationFailsBeforeDial(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	for _, args := range [][]string{
		{"--server", "vpn.example.com", "--reconnect", "--tc-mode", "invalid"},
		{"--server", "not-a-host", "--reconnect=false"},
	} {
		if err := RunClient(context.Background(), args, logger); err == nil {
			t.Fatalf("invalid configuration started reconnect loop: %v", args)
		}
	}
}
