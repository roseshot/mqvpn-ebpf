package session

import (
	"testing"
	"time"

	quic "github.com/qoke/mp-quic-go"
)

func TestPathSchedulerValidationAndCompatibility(t *testing.T) {
	for _, tc := range []struct {
		value string
		want  string
	}{
		{"", SchedulerRoundRobin},
		{SchedulerRoundRobin, SchedulerRoundRobin},
		{SchedulerLowLatency, SchedulerLowLatency},
	} {
		got, err := NormalizePathScheduler(tc.value)
		if err != nil || got != tc.want {
			t.Errorf("policy %q: got %q, err %v, want %q", tc.value, got, err, tc.want)
		}
	}
	for _, invalid := range []string{"min_rtt", "random", "ROUND_ROBIN", "low-latency"} {
		if _, err := NormalizePathScheduler(invalid); err == nil {
			t.Errorf("invalid scheduler %q accepted", invalid)
		}
	}
}

func TestLowLatencySchedulerPrefersFastHealthyPathAndFailsOver(t *testing.T) {
	s := NewPathScheduler(SchedulerLowLatency)
	paths := []quic.SchedulerPathInfo{
		{PathID: 1, SendingAllowed: true, SmoothedRTT: 150 * time.Millisecond},
		{PathID: 2, SendingAllowed: true, SmoothedRTT: 20 * time.Millisecond},
		{PathID: 3, SendingAllowed: true, SmoothedRTT: 70 * time.Millisecond},
		{PathID: 4, SendingAllowed: true, SmoothedRTT: 240 * time.Millisecond},
	}
	for i := 0; i < 16; i++ {
		selected := s.SelectPath(paths, false)
		if selected == nil || selected.PathID != 2 {
			t.Fatalf("expected fast WAN path 2, got %+v", selected)
		}
		s.UpdateQuota(selected.PathID, 1200)
	}
	paths[1].PotentiallyFailed = true
	if got := s.SelectPath(paths, false); got == nil || got.PathID != 3 {
		t.Fatalf("expected WAN3 after low-latency WAN2 failure, got %+v", got)
	}
	paths[1].PotentiallyFailed = false
	paths[1].SendingAllowed = false
	if got := s.SelectPath(paths, false); got == nil || got.PathID != 3 {
		t.Fatalf("expected backup WAN3 when fast WAN2 congestion limited, got %+v", got)
	}
	paths[1].SendingAllowed = true
	if got := s.SelectPath(paths, false); got == nil || got.PathID != 2 {
		t.Fatalf("expected fastest WAN to recover, got %+v", got)
	}
}

func TestServerPathSchedulerConfigurationValidation(t *testing.T) {
	cfg := ServerConfig{
		Listen:        "0.0.0.0:8443",
		PathScheduler: SchedulerLowLatency,
		Instances:     []ServerInstance{sampleInstance("lab", "vpn.example.test", "mq0")},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("valid low-latency Server policy: %v", err)
	}
	if cfg.PathScheduler != SchedulerLowLatency {
		t.Fatalf("Server scheduler changed unexpectedly: %q", cfg.PathScheduler)
	}
	cfg.PathScheduler = "random"
	if err := cfg.Validate(); err == nil {
		t.Fatal("invalid Server scheduler accepted")
	}
}

func TestSharedHTTP3ServerSchedulerPolicy(t *testing.T) {
	srv := newSharedHTTP3ServerWithScheduler(newServerMux(), SchedulerLowLatency)
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
	legacy := newSharedHTTP3Server(newServerMux())
	ctl3, ok := legacy.QUICConfig.MultipathControllerFactory().(*quic.DefaultMultipathController)
	if !ok {
		t.Fatal("legacy QUIC controller missing")
	}
	if _, ok := ctl3.GetScheduler().(*quic.RoundRobinScheduler); !ok {
		t.Fatalf("legacy Round Robin scheduler changed: %T", ctl3.GetScheduler())
	}
}
