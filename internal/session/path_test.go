package session

import "testing"

func TestMASQUEPathValidation(t *testing.T) {
	if err := ValidateMASQUEPath(DefaultPath); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"vpn", "//vpn", "/vpn//endpoint", "/vpn/../admin", "/vpn/./admin", "/vpn?x=1", "/vpn#frag", "/vpn%2Fadmin", "/vpn\\admin", "/vpn\r\nX: injected", "/vpn path"} {
		if err := ValidateMASQUEPath(path); err == nil {
			t.Fatalf("accepted unsafe path %q", path)
		}
	}
}
