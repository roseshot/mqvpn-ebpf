//go:build linux

package server

import (
	"testing"

	quic "github.com/qoke/mp-quic-go"
	vpnwire "github.com/roseshot/mqvpn-ebpf/internal/session"
)

func TestServerPathSchedulerConfigurationValidation(t *testing.T) {
	cfg := Config{
		Listen:        "0.0.0.0:8443",
		PathScheduler: vpnwire.SchedulerLowLatency,
		Instances:     []Instance{sampleInstance("lab", "vpn.example.test", "mq0")},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("valid low-latency Server policy: %v", err)
	}
	if cfg.PathScheduler != vpnwire.SchedulerLowLatency {
		t.Fatalf("Server scheduler changed unexpectedly: %q", cfg.PathScheduler)
	}
	cfg.PathScheduler = "random"
	if err := cfg.Validate(); err == nil {
		t.Fatal("invalid Server scheduler accepted")
	}
}

func TestSharedHTTP3ServerSchedulerPolicy(t *testing.T) {
	srv := newSharedHTTP3ServerWithScheduler(newMux(), vpnwire.SchedulerLowLatency)
	if srv.QUICConfig == nil || srv.QUICConfig.MultipathControllerFactory == nil {
		t.Fatal("missing connection-local scheduling policy factory")
	}
	ctl := srv.QUICConfig.MultipathControllerFactory()
	defaultCtl, ok := ctl.(*quic.DefaultMultipathController)
	if !ok {
		t.Fatalf("unexpected MPQUIC controller %T", ctl)
	}
	if _, ok := defaultCtl.GetScheduler().(*quic.LowLatencyScheduler); !ok {
		t.Fatalf("Server low-latency policy not installed: %T", defaultCtl.GetScheduler())
	}
	ctl2 := srv.QUICConfig.MultipathControllerFactory()
	if ctl == ctl2 {
		t.Fatal("independent connections share mutable path state")
	}
	legacy := newSharedHTTP3Server(newMux())
	ctl3, ok := legacy.QUICConfig.MultipathControllerFactory().(*quic.DefaultMultipathController)
	if !ok {
		t.Fatal("legacy QUIC controller missing")
	}
	if _, ok := ctl3.GetScheduler().(*quic.RoundRobinScheduler); !ok {
		t.Fatalf("legacy Round Robin scheduler changed: %T", ctl3.GetScheduler())
	}
}
