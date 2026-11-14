//go:build linux

package dnspush

import (
	"errors"
	"net/netip"
	"reflect"
	"strings"
	"testing"
)

type fakeResolver struct {
	state  linkState
	calls  []string
	fail   string
	closed int
}

func (f *fakeResolver) Read() (linkState, error) {
	f.calls = append(f.calls, "read")
	if f.fail == "read" {
		return linkState{}, errors.New("read error")
	}
	return cloneState(f.state), nil
}
func cloneState(s linkState) linkState {
	s.DNS = append([]dnsRecord(nil), s.DNS...)
	for i := range s.DNS {
		s.DNS[i].Address = append([]byte(nil), s.DNS[i].Address...)
	}
	s.Domains = append([]domainRecord(nil), s.Domains...)
	return s
}
func (f *fakeResolver) SetDNS(v []dnsRecord) error {
	f.calls = append(f.calls, "dns")
	if f.fail == "dns" {
		return errors.New("set DNS error")
	}
	f.state.DNS = cloneState(linkState{DNS: v}).DNS
	return nil
}
func (f *fakeResolver) SetDomains(v []domainRecord) error {
	f.calls = append(f.calls, "domains")
	if f.fail == "domains" {
		return errors.New("set domains error")
	}
	f.state.Domains = append([]domainRecord(nil), v...)
	return nil
}
func (f *fakeResolver) SetDefaultRoute(v bool) error {
	f.calls = append(f.calls, "default")
	if f.fail == "default" {
		return errors.New("set default error")
	}
	f.state.DefaultRoute = v
	return nil
}
func (f *fakeResolver) Close() error { f.closed++; f.calls = append(f.calls, "close"); return nil }

func TestResolverSessionApplyRollbackRestoresPriorLinkState(t *testing.T) {
	initial := linkState{
		DNS:          []dnsRecord{{Family: 2, Address: []byte{192, 0, 2, 53}, Port: 853, Name: "dns.example.test"}},
		Domains:      []domainRecord{{Domain: "corp.example.test", RoutingOnly: false}},
		DefaultRoute: false,
	}
	f := &fakeResolver{state: cloneState(initial)}
	lease, err := applyWithBackend(f, []netip.Addr{netip.MustParseAddr("10.77.0.1"), netip.MustParseAddr("fd77::53")})
	if err != nil {
		t.Fatal(err)
	}
	if len(f.state.DNS) != 2 || !domainsEqual(f.state.Domains, []domainRecord{{Domain: "corp.example.test"}, {Domain: ".", RoutingOnly: true}}) || !f.state.DefaultRoute {
		t.Fatalf("VPN DNS not applied: %+v", f.state)
	}
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
	if f.closed != 1 || !reflect.DeepEqual(f.state, initial) {
		t.Fatalf("original systemd-resolved link settings not restored: %+v", f.state)
	}
}
func TestResolverRejectsInterveningNetworkManagerChanges(t *testing.T) {
	f := &fakeResolver{}
	lease, err := applyWithBackend(f, []netip.Addr{netip.MustParseAddr("10.77.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	f.state.DNS = []dnsRecord{{Family: 2, Address: []byte{8, 8, 8, 8}, Port: 53}}
	err = lease.Close()
	if !errors.Is(err, ErrCleanup) {
		t.Fatalf("external DNS changes not detected: %v", err)
	}
	if f.state.DNS[0].Address[0] != 8 || f.closed != 1 {
		t.Fatal("overwrote newer DNS configuration")
	}
}
func TestResolverPartialSetupRollback(t *testing.T) {
	for _, stage := range []string{"dns", "domains", "default", "read"} {
		f := &fakeResolver{fail: stage}
		_, err := applyWithBackend(f, []netip.Addr{netip.MustParseAddr("10.77.0.1")})
		if err == nil || f.closed != 1 {
			t.Fatalf("stage %s did not close after failure: %v", stage, err)
		}
		if stage == "read" || stage == "dns" || stage == "domains" || stage == "default" {
			if stage == "dns" || stage == "domains" || stage == "default" {
				if !errors.Is(err, ErrCleanup) {
					t.Fatalf("stage %s did not flag failed rollback: %v", stage, err)
				}
			}
		}
	}
}
func TestResolverDefaultAndRootRoutingDomain(t *testing.T) {
	if got := addRootDomain([]domainRecord{{Domain: ".", RoutingOnly: true}}); len(got) != 1 {
		t.Fatal("root routing domain duplicated")
	}
	if got := toRecords([]netip.Addr{netip.MustParseAddr("fd77::1")}); len(got) != 1 || got[0].Family != 10 || got[0].Port != 53 || len(got[0].Address) != 16 {
		t.Fatalf("IPv6 DNS record invalid %+v", got)
	}
	if !strings.Contains(ErrCleanup.Error(), "DNS") {
		t.Fatal("expected DNS cleanup category")
	}
}
