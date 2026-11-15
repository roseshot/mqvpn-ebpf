package cluster

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
)

func TestNodeLocalProbesDoNotRequireSharedStore(t *testing.T) {
	var calls atomic.Int32
	probes := []LocalProbe{
		{Name: "quic-listener", Check: func(context.Context) error {
			calls.Add(1)
			return nil
		}},
		{Name: "tun-mq0", Check: func(context.Context) error {
			calls.Add(1)
			return nil
		}},
		{Name: "wan-0", Check: func(context.Context) error {
			calls.Add(1)
			return nil
		}},
		{Name: "local-fib", Check: func(context.Context) error {
			calls.Add(1)
			return nil
		}},
	}
	if err := CheckNodeLocal(context.Background(), probes); err != nil {
		t.Fatalf("healthy node-local resources rejected: %v", err)
	}
	if got := calls.Load(); got != int32(len(probes)) {
		t.Fatalf("read %d probes, expected %d", got, len(probes))
	}
	// No Store is configured or involved, and no other node's status is read.
}

func TestNodeLocalProbesFailClosedIndependently(t *testing.T) {
	failed := errors.New("local interface down")
	var afterward atomic.Bool
	probes := []LocalProbe{
		{Name: "wan-0", Check: func(context.Context) error {
			return failed
		}},
		{Name: "tun-mq0", Check: func(context.Context) error {
			afterward.Store(true)
			return nil
		}},
	}
	err := CheckNodeLocal(context.Background(), probes)
	if !errors.Is(err, ErrNotReady) || !errors.Is(err, failed) || afterward.Load() {
		t.Fatalf("failed local WAN check did not fail closed: %v", err)
	}
	for _, bad := range [][]LocalProbe{
		nil,
		{{Name: "missing-handler"}},
		{{Name: "", Check: func(context.Context) error { return nil }}},
		{
			{Name: "tun", Check: func(context.Context) error { return nil }},
			{Name: "tun", Check: func(context.Context) error { return nil }},
		},
	} {
		if err := CheckNodeLocal(context.Background(), bad); !errors.Is(err, ErrNotReady) {
			t.Fatalf("invalid local probes accepted: %+v, err=%v", bad, err)
		}
	}
}

func TestNodeLocalProbesHonorCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var ran atomic.Bool
	err := CheckNodeLocal(ctx, []LocalProbe{{Name: "tun", Check: func(context.Context) error {
		ran.Store(true)
		return nil
	}}})
	if !errors.Is(err, context.Canceled) || ran.Load() {
		t.Fatalf("cancelled local probe ran: %v", err)
	}
}
