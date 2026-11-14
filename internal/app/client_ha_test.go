package app

import (
	"context"
	"crypto/x509"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestPlanClientHAValidModesAndFixedTLSIdentity(t *testing.T) {
	for _, mode := range []string{"active_active", "active_standby", "active/active", "active-standby"} {
		p, err := planClientHA("vpn.example.com:8443", "/connect/", "", &clientHAConfig{
			Mode: mode, Backends: []string{"192.0.2.10", "198.51.100.10", "2001:db8::10"},
		})
		if err != nil {
			t.Fatalf("HA mode %q: %v", mode, err)
		}
		if p.controller != clientHANative || len(p.endpoints) != 3 {
			t.Fatalf("unexpected HA plan: %+v", p)
		}
		for i, endpoint := range p.endpoints {
			if endpoint.serverName != "vpn.example.com" ||
				endpoint.requestURL != "https://vpn.example.com:8443/connect/" ||
				!strings.Contains(endpoint.dialAddress, []string{"192.0.2.10", "198.51.100.10", "2001:db8::10"}[i]) {
				t.Fatalf("backend %d changed authenticated tenant identity: %+v", i, endpoint)
			}
		}
	}
	external, err := planClientHA("vpn.example.com:8443", "", "192.0.2.5", &clientHAConfig{
		Mode: "active_active", Controller: "haproxy",
	})
	if err != nil || external.controller != clientHAExternal ||
		len(external.endpoints) != 1 || !strings.Contains(external.endpoints[0].dialAddress, "192.0.2.5") {
		t.Fatalf("external HA endpoint invalid: %+v %v", external, err)
	}
	if plan, err := planClientHA("vpn.example.com", "", "", nil); plan != nil || err != nil {
		t.Fatalf("unconfigured HA must preserve existing client behavior: %+v %v", plan, err)
	}
}

func TestPlanClientHARejectsUnsafeConfigurations(t *testing.T) {
	for _, tc := range []struct {
		name string
		pin  string
		cfg  clientHAConfig
	}{
		{"missing mode", "", clientHAConfig{Backends: []string{"192.0.2.1", "192.0.2.2"}}},
		{"unknown mode", "", clientHAConfig{Mode: "random", Backends: []string{"192.0.2.1", "192.0.2.2"}}},
		{"unknown controller", "", clientHAConfig{Mode: "active_active", Controller: "unknown"}},
		{"one backend", "", clientHAConfig{Mode: "active_active", Backends: []string{"192.0.2.1"}}},
		{"no backend", "", clientHAConfig{Mode: "active_standby"}},
		{"duplicate backend", "", clientHAConfig{Mode: "active_standby", Backends: []string{"192.0.2.1", "192.0.2.1"}}},
		{"duplicate mapped IPv4", "", clientHAConfig{Mode: "active_active", Backends: []string{"192.0.2.1", "::ffff:192.0.2.1"}}},
		{"hostname backend", "", clientHAConfig{Mode: "active_active", Backends: []string{"node.example.com", "192.0.2.1"}}},
		{"multicast backend", "", clientHAConfig{Mode: "active_active", Backends: []string{"192.0.2.1", "224.0.0.1"}}},
		{"link-local backend", "", clientHAConfig{Mode: "active_active", Backends: []string{"192.0.2.1", "fe80::1"}}},
		{"IP zone backend", "", clientHAConfig{Mode: "active_active", Backends: []string{"192.0.2.1", "fe80::1%eth0"}}},
		{"two control planes", "192.0.2.5", clientHAConfig{Mode: "active_active", Backends: []string{"192.0.2.1", "192.0.2.2"}}},
		{"external plus backend list", "", clientHAConfig{Mode: "active_standby", Controller: "external", Backends: []string{"192.0.2.1"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if p, err := planClientHA("vpn.example.com", "", tc.pin, &tc.cfg); err == nil {
				t.Fatalf("invalid HA configuration accepted: %+v", p)
			}
		})
	}
}

func testHAPlan(t *testing.T, mode string) *clientHAPlan {
	t.Helper()
	p, err := planClientHA("vpn.example.com", "", "", &clientHAConfig{
		Mode: mode, Backends: []string{"192.0.2.1", "192.0.2.2", "192.0.2.3"},
	})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestHAActiveStandbyFailureRotationAndFailback(t *testing.T) {
	s := newClientHASelector(testHAPlan(t, "active_standby"), []byte("client"))
	var got []int
	for _, step := range []struct {
		err      error
		lifetime time.Duration
	}{
		{errors.New("primary unreachable"), time.Millisecond},
		{errors.New("standby unreachable"), time.Millisecond},
		{errors.New("last standby unavailable"), time.Millisecond},
		{errors.New("primary failed"), time.Millisecond},
		{nil, time.Second}, // graceful standby close: next attempt prefers primary
	} {
		index, _ := s.selected()
		got = append(got, index)
		s.complete(index, step.err, step.lifetime)
	}
	if !reflect.DeepEqual(got, []int{0, 1, 2, 0, 1}) {
		t.Fatalf("failover sequence = %v", got)
	}
	if index, _ := s.selected(); index != 0 {
		t.Fatalf("standby did not prefer primary on clean reconnect: %d", index)
	}
	// A healthy standby is never preempted. On its next disconnect a
	// sustained session resets accumulated preference to the primary.
	s.index = 2
	s.complete(2, errors.New("post-hour-long disconnect"), time.Hour)
	if index, _ := s.selected(); index != 0 {
		t.Fatalf("stable standby did not reset preference to primary: %d", index)
	}
	// A primary that ran for hours and then failed must switch immediately
	// to a standby, rather than retrying the same dead primary first.
	s.complete(0, errors.New("long-running primary just died"), 2*time.Hour)
	if index, _ := s.selected(); index != 1 {
		t.Fatalf("lost long-running primary retried rather than failing over: %d", index)
	}
}

func TestHAActiveActiveStableClientDistribution(t *testing.T) {
	plan := testHAPlan(t, "active_active")
	initial := newClientHASelector(plan, []byte("site-1-cert"))
	initialAgain := newClientHASelector(plan, []byte("site-1-cert"))
	if initial.index != initialAgain.index {
		t.Fatalf("active/active identity hash is not deterministic")
	}
	distinct := map[int]bool{}
	for i := 0; i < 100; i++ {
		s := newClientHASelector(plan, []byte{byte(i)})
		distinct[s.index] = true
	}
	if len(distinct) != 3 {
		t.Fatalf("active/active did not distribute independent client identities: %+v", distinct)
	}
	prev, _ := initial.selected()
	initial.complete(prev, errors.New("backend lost"), time.Millisecond)
	if current, _ := initial.selected(); current != (prev+1)%3 {
		t.Fatalf("active/active did not move after disconnect: previous=%d current=%d", prev, current)
	}
}

func TestHAAutonomousSupervisorSerializesAndStopsOnCancellation(t *testing.T) {
	plan := testHAPlan(t, "active_standby")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	attempts, active := 0, 0
	visited := []string{}
	err := runClientHASupervisorWithWait(ctx, plan, []byte("test cert"), silentReconnectLogger(),
		func(_ context.Context, endpoint clientEndpoint) error {
			if active != 0 {
				t.Fatal("overlapping TUN or QUIC sessions")
			}
			active++
			attempts++
			visited = append(visited, endpoint.dialAddress)
			active-- // runClientSession guarantees cleanup before returning
			if attempts == 4 {
				cancel()
			}
			return errors.New("backend transport lost")
		},
		func(context.Context, time.Duration) error {
			if active != 0 {
				t.Fatal("retry started before session cleanup")
			}
			return nil
		},
	)
	if !errors.Is(err, context.Canceled) || attempts != 4 {
		t.Fatalf("unexpected HA shutdown: %v, %d attempts", err, attempts)
	}
	if want := []string{"192.0.2.1:443", "192.0.2.2:443", "192.0.2.3:443", "192.0.2.1:443"}; !reflect.DeepEqual(visited, want) {
		t.Fatalf("unexpected HA failover order: %v", visited)
	}
}

func TestHAFailClosedOnPeerDenialAndTLSIdentityErrors(t *testing.T) {
	for _, failure := range []error{
		errClientPeerDenied,
		x509.HostnameError{Host: "wrong.example.com"},
		x509.UnknownAuthorityError{},
	} {
		attempts, waits := 0, 0
		err := runClientHASupervisorWithWait(context.Background(),
			testHAPlan(t, "active_active"), []byte("identity"),
			silentReconnectLogger(),
			func(context.Context, clientEndpoint) error {
				attempts++
				return failure
			},
			func(context.Context, time.Duration) error {
				waits++
				return nil
			},
		)
		if !errors.Is(err, errHAFatal) || !errors.Is(err, failure) && failure == errClientPeerDenied ||
			attempts != 1 || waits != 0 {
			t.Fatalf("auth failure rotated or retried: %v attempts=%d waits=%d", err, attempts, waits)
		}
	}
}

func TestHAUnsafeCleanupMustNotRotateToNextBackend(t *testing.T) {
	attempts, waits := 0, 0
	err := runClientHASupervisorWithWait(context.Background(), testHAPlan(t, "active_standby"),
		[]byte("site"), silentReconnectLogger(),
		func(context.Context, clientEndpoint) error {
			attempts++
			return errors.Join(errUnsafeReconnect, errors.New("route restoration failed"))
		},
		func(context.Context, time.Duration) error {
			waits++
			return nil
		},
	)
	if !errors.Is(err, errUnsafeReconnect) || attempts != 1 || waits != 0 {
		t.Fatalf("unsafe cleanup rotated: err=%v attempts=%d waits=%d", err, attempts, waits)
	}
}

func TestHAExternalControllerDoesNotPickMultipleBackends(t *testing.T) {
	plan, err := planClientHA("vpn.example.com", "", "", &clientHAConfig{
		Mode: "active_active", Controller: "external",
	})
	if err != nil {
		t.Fatal(err)
	}
	s := newClientHASelector(plan, []byte("client"))
	for range 20 {
		index, endpoint := s.selected()
		if index != 0 || endpoint.dialAddress != "vpn.example.com:443" {
			t.Fatalf("external controller unexpectedly switched backend: %d %+v", index, endpoint)
		}
		s.complete(index, errors.New("HAProxy endpoint unreachable"), time.Second)
	}
}
