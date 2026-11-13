//go:build linux

package tap

import (
	"strings"
	"testing"
)

func TestTunnelConfigValidation(t *testing.T) {
	cases := []struct{ name, cidr string; mtu, maxFrame int; want string }{
		{"", "10.77.0.1/30", 1100, 1160, "name"},
		{"mq0", "", 1100, 1160, "--tunnel-ip"},
		{"mq0", "invalid", 1100, 1160, "invalid tunnel CIDR"},
		{"mq0", "10.77.0.1/30", 1100, 1113, "--max-frame"},
		{"mq0", "fd77::1/64", 1100, 1160, "IPv6 tunnel"},
	}
	for _, tt := range cases {
		err := Configure(tt.name, tt.cidr, tt.mtu, tt.maxFrame)
		if err == nil || !strings.Contains(err.Error(), tt.want) {
			t.Fatalf("Configure(%q, %q, %d, %d) = %v; want %q", tt.name, tt.cidr, tt.mtu, tt.maxFrame, err, tt.want)
		}
	}
}
