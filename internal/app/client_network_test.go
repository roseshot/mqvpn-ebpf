package app

import (
	"errors"
	"fmt"
	"testing"

	"github.com/roseshot/mqvpn-ebpf/internal/dnspush"
	"github.com/roseshot/mqvpn-ebpf/internal/tun"
)

func TestClassifyClientCleanupErrors(t *testing.T) {
	transient := errors.New("dial temporarily unavailable")
	if got := classifyClientCleanup(nil); got != nil {
		t.Fatalf("nil cleanup error changed: %v", got)
	}
	for _, cause := range []error{tun.ErrCleanup, dnspush.ErrCleanup} {
		got := classifyClientCleanup(fmt.Errorf("restore failed: %w", cause))
		if !errors.Is(got, errUnsafeReconnect) || !errors.Is(got, cause) {
			t.Fatalf("unsafe cleanup not propagated: %v", got)
		}
	}
	got := classifyClientCleanup(transient)
	if !errors.Is(got, transient) || errors.Is(got, errUnsafeReconnect) {
		t.Fatalf("ordinary transient failure classified as unsafe: %v", got)
	}
}
