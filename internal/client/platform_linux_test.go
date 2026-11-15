//go:build linux

package client

import (
	"context"
	"net"
	"testing"
)

type recordingClientPlatform struct {
	linuxPlatform
	called bool
}

func (p *recordingClientPlatform) ResolveSource(_, _ string, _ *net.UDPAddr) (net.IP, error) {
	p.called = true
	return net.IPv4(192, 0, 2, 12), nil
}

func TestClientPlatformSelectionDoesNotBypassInjectedAdapter(t *testing.T) {
	custom := &recordingClientPlatform{}
	got := platformForClient(custom)
	if got != custom {
		t.Fatal("Client replaced the injected platform with the Linux default")
	}
	ip, err := got.ResolveSource("", "", &net.UDPAddr{})
	if err != nil || !ip.Equal(net.IPv4(192, 0, 2, 12)) || !custom.called {
		t.Fatalf("Client did not call injected underlay adapter: %v %v", ip, err)
	}
	if _, ok := platformForClient(nil).(linuxPlatform); !ok {
		t.Fatal("standalone Client must retain its existing Linux adapter by default")
	}
}

func TestLinuxClientPlatformPreservesLocalSocketAndRouteOwnership(t *testing.T) {
	if _, err := net.InterfaceByName("lo"); err != nil {
		t.Skipf("Linux loopback is unavailable: %v", err)
	}
	p := platformForClient(nil)
	remote := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9443}
	source, err := p.ResolveSource("127.0.0.1", "", remote)
	if err != nil {
		t.Fatal(err)
	}
	conn, bound, err := p.ListenUDP(context.Background(), "127.0.0.1", "", remote)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if !bound.Equal(source) || !conn.LocalAddr().(*net.UDPAddr).IP.Equal(source) {
		t.Fatalf("Linux UDP adapter bound source=%s, expected=%s", bound, source)
	}
	underlay, err := p.SourceUnderlay(bound, "lo")
	if err != nil || underlay.MTU <= 0 {
		t.Fatalf("Linux underlay inspection failed: %+v %v", underlay, err)
	}
	// With no pushed routes, the Linux guard must not change any route.
	guard, err := p.ProtectServer(remote.IP, bound, "", "mq0", nil, false)
	if err != nil || guard == nil {
		t.Fatalf("create empty route guard: %v", err)
	}
	if err := guard.Close(); err != nil {
		t.Fatalf("close empty route guard: %v", err)
	}
}
