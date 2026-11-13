//go:build linux

package tap

import "testing"

func TestValidateName(t *testing.T) {
	for _, s := range []string{"mq0", "vpn.12", "tap-test"} {
		if err := validateName(s); err != nil { t.Fatalf("%q: %v", s, err) }
	}
	for _, s := range []string{"", "bad name", "abcdefghijklmnop", "a/b"} {
		if err := validateName(s); err == nil { t.Fatalf("%q should fail", s) }
	}
}
