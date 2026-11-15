package cluster

import (
	"net/netip"
	"testing"
	"time"
)

func TestLeaseMembershipGenerationMustBeRefreshedBeforeDataplaneUse(t *testing.T) {
	now := time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)
	s := leaseMachine(t, 3)
	f := testFence(t, "server-0")
	if err := f.SetMembers("cluster-1", 1, members(3)); err != nil {
		t.Fatal(err)
	}
	peer := leasePeer("client")
	ip := netip.MustParseAddr("10.77.0.7")
	first, err := s.Claim(peer, "server-0", ip, 0, now.Add(5*time.Second), now)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Apply(first, now); err != nil {
		t.Fatal(err)
	}
	if !f.Allowed(peer, first.Epoch, ip, now) {
		t.Fatal("current membership lease was not authorized")
	}
	// Expanding N is a committed membership change; the old lease must
	// not be used until its record is committed against that generation.
	if err := s.SetMembers(2, members(5)); err != nil {
		t.Fatal(err)
	}
	if err := f.SetMembers("cluster-1", 2, members(5)); err != nil {
		t.Fatal(err)
	}
	if f.Allowed(peer, first.Epoch, ip, now.Add(time.Second)) {
		t.Fatal("lease issued under stale membership remains authorized")
	}
	if f.WithAuthorized(peer, first.Epoch, ip, now.Add(time.Second), func() {
		t.Fatal("stale lease executed a final dataplane action")
	}) {
		t.Fatal("stale membership allowed final action")
	}
	renewed, err := s.Renew(peer, "server-0", ip, first.Epoch,
		now.Add(7*time.Second), now.Add(time.Second))
	if err != nil || renewed.MembershipRevision != 2 {
		t.Fatalf("renewal did not acquire current membership revision: %+v %v", renewed, err)
	}
	if err := f.Apply(renewed, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if !f.Allowed(peer, renewed.Epoch, ip, now.Add(time.Second)) {
		t.Fatal("freshly revalidated owner was denied")
	}
}

func TestLeaseAndFenceRejectBroadcastIP(t *testing.T) {
	now := time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)
	ip := netip.MustParseAddr("255.255.255.255")
	s := leaseMachine(t, 3)
	peer := leasePeer("broadcast")
	if _, err := s.Claim(peer, "server-0", ip, 0, now.Add(5*time.Second), now); err == nil {
		t.Fatal("lease allocator accepted IPv4 broadcast IP")
	}
	f := testFence(t, "server-0")
	if err := f.SetMembers("cluster-1", 1, members(3)); err != nil {
		t.Fatal(err)
	}
	record := sampleRecord("server-0", 1, 1, now.Add(5*time.Second))
	record.TunnelIP = ip
	if err := f.Apply(record, now); err == nil {
		t.Fatal("local ownership fence accepted broadcast tunnel IP")
	}
}
