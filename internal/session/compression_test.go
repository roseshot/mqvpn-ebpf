package session

import "testing"

func TestCompressionCPUAllowed(t *testing.T) {
	cases := []struct {
		name             string
		cpus, gomaxprocs int
		throughputMiB    float64
		want             bool
	}{
		{name: "single core", cpus: 1, gomaxprocs: 1, throughputMiB: 500, want: false},
		{name: "dual core", cpus: 2, gomaxprocs: 2, throughputMiB: 500, want: false},
		{name: "CPU quota", cpus: 16, gomaxprocs: 2, throughputMiB: 500, want: false},
		{name: "slow quad core", cpus: 4, gomaxprocs: 4, throughputMiB: 45, want: false},
		{name: "threshold boundary", cpus: 4, gomaxprocs: 4, throughputMiB: minCompressionMiBPerSec, want: true},
		{name: "fast quad core", cpus: 4, gomaxprocs: 4, throughputMiB: 200, want: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := compressionCPUAllowed(tc.cpus, tc.gomaxprocs, tc.throughputMiB); got != tc.want {
				t.Fatalf("compressionCPUAllowed(%d,%d,%.1f)=%t want %t",
					tc.cpus, tc.gomaxprocs, tc.throughputMiB, got, tc.want)
			}
		})
	}
}

func TestCompressionNegotiation(t *testing.T) {
	cases := []struct {
		response   string
		advertised bool
		enabled    bool
		errorWant  bool
	}{
		{response: "", advertised: false},
		{response: "", advertised: true},
		{response: CompressionZstd, advertised: true, enabled: true},
		{response: CompressionZstd, advertised: false, errorWant: true},
		{response: "unknown", advertised: true, errorWant: true},
	}
	for _, tc := range cases {
		got, err := NegotiatedCompression(tc.response, tc.advertised)
		if got != tc.enabled || (err != nil) != tc.errorWant {
			t.Fatalf("NegotiatedCompression(%q,%v)=(%v,%v), expected enabled=%v error=%v",
				tc.response, tc.advertised, got, err, tc.enabled, tc.errorWant)
		}
	}
}
