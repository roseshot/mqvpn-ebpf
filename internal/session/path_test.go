package session

import "testing"

func TestMasquePathDefaultAndOverride(t *testing.T) {
	for _, tc := range []struct{ path, want string }{
		{"", DefaultPath},
		{"/connect/custom", "/connect/custom"},
		{"/tenant/vpn/", "/tenant/vpn/"},
	} {
		e, err := planClientEndpoint("tenant.example.com", tc.path, "")
		if err != nil {
			t.Fatal(err)
		}
		if e.requestURL != "https://tenant.example.com:443"+tc.want {
			t.Fatalf("path %q: %+v", tc.path, e)
		}
	}
	if err := ValidateMASQUEPath(DefaultPath); err != nil {
		t.Fatal(err)
	}
}
func TestMasquePathRejectsAmbiguity(t *testing.T) {
	for _, path := range []string{"vpn", "//vpn", "/vpn//endpoint", "/vpn/../admin", "/vpn/./admin", "/vpn?x=1", "/vpn#frag", "/vpn%2Fadmin", "/vpn\\admin", "/vpn\r\nX: injected", "/vpn path"} {
		if err := ValidateMASQUEPath(path); err == nil {
			t.Fatalf("accepted unsafe path %q", path)
		}
		if _, err := planClientEndpoint("tenant.example.com", path, ""); err == nil {
			t.Fatalf("client accepted unsafe path %q", path)
		}
	}
}
