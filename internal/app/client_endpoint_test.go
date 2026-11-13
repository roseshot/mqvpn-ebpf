package app

import (
	"net/url"
	"strings"
	"testing"
)

const clientPath = "/.well-known/masque/ethernet/"

func TestClientEndpointDomainDirect(t *testing.T) {
	got, err := planClientEndpoint("https://customer-a.vpn.example.com:4433"+clientPath, "", "")
	if err != nil { t.Fatal(err) }
	if got.dialAddress != "customer-a.vpn.example.com:4433" ||
		got.serverName != "customer-a.vpn.example.com" ||
		got.requestURL != "https://customer-a.vpn.example.com:4433"+clientPath {
		t.Fatalf("unexpected domain plan %+v", got)
	}
}

func TestClientEndpointIPWithTenantDomain(t *testing.T) {
	for _, tc := range []struct{
		rawURL, name, dial string
	}{
		{"https://198.51.100.10:4433"+clientPath, "customer-a.vpn.example.com", "198.51.100.10:4433"},
		{"https://[2001:db8::10]:4433"+clientPath, "customer-b.vpn.example.com", "[2001:db8::10]:4433"},
	} {
		got, err := planClientEndpoint(tc.rawURL, "", tc.name)
		if err != nil { t.Fatal(err) }
		if got.dialAddress != tc.dial || got.serverName != tc.name {
			t.Fatalf("unexpected IP plan %+v", got)
		}
		parsed, err := url.Parse(got.requestURL)
		if err != nil || parsed.Hostname() != tc.name || parsed.Port() != "4433" {
			t.Fatalf("CONNECT authority must be tenant DNS name: %+v %v", got, err)
		}
	}
}

func TestClientEndpointDomainWithPinnedIP(t *testing.T) {
	for _, ip := range []string{"198.51.100.20", "2001:db8::20"} {
		got, err := planClientEndpoint("https://vpn.example.com:4433"+clientPath, ip, "tenant.example.com")
		if err != nil { t.Fatal(err) }
		parsed, err := url.Parse(got.requestURL)
		if err != nil || parsed.Hostname() != "tenant.example.com" || got.serverName != "tenant.example.com" {
			t.Fatalf("tenant request mismatched SNI: %+v %v", got, err)
		}
		if !strings.Contains(got.dialAddress, ip) {
			t.Fatalf("explicit IP override not used: %+v", got)
		}
	}
}

func TestClientEndpointRejectUnsafeOrAmbiguousTarget(t *testing.T) {
	for _, tc := range []struct{rawURL, ip, name string}{
		{"https://198.51.100.10:4433"+clientPath, "", ""}, // no SNI
		{"https://198.51.100.10:4433"+clientPath, "198.51.100.20", "tenant.example.com"},
		{"https://vpn.example.com:4433"+clientPath, "not-an-ip", ""},
		{"https://vpn.example.com:4433"+clientPath, "0.0.0.0", ""},
		{"https://vpn.example.com:4433"+clientPath, "224.0.0.1", ""},
		{"https://vpn.example.com:4433"+clientPath, "", "198.51.100.1"},
		{"https://vpn.example.com:4433"+clientPath, "", "*.vpn.example.com"},
		{"http://vpn.example.com:4433"+clientPath, "", ""},
		{"https://vpn.example.com:bad"+clientPath, "", ""},
		{"https://vpn.example.com:4433"+clientPath+"?unknown=yes", "", ""},
		{"https://vpn.example.com:4433", "", ""},
	} {
		if _, err := planClientEndpoint(tc.rawURL, tc.ip, tc.name); err == nil {
			t.Fatalf("unsafe endpoint accepted %+v", tc)
		}
	}
}
