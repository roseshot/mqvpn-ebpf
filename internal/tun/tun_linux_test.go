//go:build linux

package tun

import (
	"strings"
	"testing"
)

func TestValidate(t *testing.T) {
	for _, tt := range []struct{ name,cidr string; mtu,max int; msg string }{
		{"mq0", "10.77.0.1/24", 1100, 1160, ""},
		{"mq0", "fd42::1/64", 1280, 1400, ""},
		{"", "10.77.0.1/24", 1100, 1160, "name"},
		{"mq0", "10.77.0.1", 1100, 1160, "CIDR"},
		{"mq0", "10.77.0.1/24", 1100, 1113, "exceeds"},
		{"mq0", "fd42::1/64", 1100, 1160, "IPv6"},
	} {
		err := Validate(tt.name,tt.cidr,tt.mtu,tt.max)
		if tt.msg == "" && err != nil { t.Fatalf("unexpected: %v",err) }
		if tt.msg != "" && (err == nil || !strings.Contains(err.Error(),tt.msg)) {
			t.Fatalf("want %s got %v",tt.msg,err)
		}
	}
}
