package cluster

import (
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func leaseMachine(t *testing.T, n int) *LeaseStateMachine {
	t.Helper()
	s, err := NewLeaseStateMachine("cluster-1", 30*time.Second, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetMembers(1, members(n)); err != nil {
		t.Fatal(err)
	}
	return s
}

func leasePeer(id string) Peer {
	return Peer{Tenant: "tenant-a", ID: id}
}

func TestLeaseIndependentNAndAtomicIPUniqueness(t *testing.T) {
	now := time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)
	ip := netip.MustParseAddr("10.77.0.2")
	for _, n := range []int{2, 3, 5, 8} {
		t.Run(fmt.Sprintf("N-%d", n), func(t *testing.T) {
			s := leaseMachine(t, n)
			var winners atomic.Int32
			var wg sync.WaitGroup
			for i := 0; i < 48; i++ {
				wg.Add(1)
				go func(i int) {
					defer wg.Done()
					peer := leasePeer(fmt.Sprintf("client-%d", i))
					owner := fmt.Sprintf("server-%d", i%n)
					_, err := s.Claim(peer, owner, ip, 0, now.Add(10*time.Second), now)
					if err == nil {
						winners.Add(1)
					} else if !errors.Is(err, ErrConflict) {
						t.Errorf("unexpected concurrent claim: %v", err)
					}
				}(i)
			}
			wg.Wait()
			if winners.Load() != 1 {
				t.Fatalf("one IP allocated to %d distinct peers", winners.Load())
			}
			if err := s.SetMembers(1, members(n)); err != nil {
				t.Fatalf("identical membership replay failed: %v", err)
			}
		})
	}
}

func TestLeaseNoImplicitExpiredTakeoverOrIPReuse(t *testing.T) {
	now := time.Now()
	s := leaseMachine(t, 3)
	ip := netip.MustParseAddr("10.77.0.2")
	a, b := leasePeer("a"), leasePeer("b")
	first, err := s.Claim(a, "server-0", ip, 0, now.Add(5*time.Second), now)
	if err != nil {
		t.Fatal(err)
	}
	expired := now.Add(6 * time.Second)
	if _, err := s.Claim(b, "server-1", ip, 0, expired.Add(time.Second), expired); !errors.Is(err, ErrConflict) {
		t.Fatalf("expired owner leaked IP without tombstone: %v", err)
	}
	if _, err := s.Claim(a, "server-1", ip, 1, expired.Add(time.Second), expired); !errors.Is(err, ErrConflict) {
		t.Fatalf("expired owner silently transferred: %v", err)
	}
	tombstone, err := s.Revoke(a, first.Epoch, expired)
	if err != nil || tombstone.Epoch != 2 || tombstone.OwnerNode != "" ||
		tombstone.TunnelIP.IsValid() || !tombstone.ValidUntil.IsZero() {
		t.Fatalf("incorrect fenced tombstone: %+v %v", tombstone, err)
	}
	if _, err := s.Claim(b, "server-1", ip, 0, expired.Add(time.Second), expired); !errors.Is(err, ErrConflict) {
		t.Fatalf("fencing grace bypassed by other peer: %v", err)
	}
	if _, err := s.Claim(a, "server-1", ip, tombstone.Epoch, expired.Add(time.Second), expired); !errors.Is(err, ErrConflict) {
		t.Fatalf("fencing grace bypassed by same peer: %v", err)
	}
	at := first.ValidUntil.Add(3 * time.Second)
	if _, err := s.Claim(b, "server-1", ip, 0, at.Add(4*time.Second), at); err != nil {
		t.Fatalf("fenced IP could not be reassigned after grace: %v", err)
	}
	if _, err := s.Claim(a, "server-2", ip, tombstone.Epoch, at.Add(5*time.Second), at); !errors.Is(err, ErrConflict) {
		t.Fatalf("same tenant IP duplication accepted: %v", err)
	}
}

func TestLeaseRenewConflictAndTombstoneReplay(t *testing.T) {
	now := time.Now()
	s := leaseMachine(t, 5)
	peer := leasePeer("client")
	ip := netip.MustParseAddr("10.77.0.2")
	initial, err := s.Claim(peer, "server-0", ip, 0, now.Add(5*time.Second), now)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		owner string
		ip    netip.Addr
		epoch uint64
		until time.Time
		at    time.Time
	}{
		{"server-1", ip, 1, now.Add(7 * time.Second), now.Add(time.Second)},
		{"server-0", ip, 0, now.Add(7 * time.Second), now.Add(time.Second)},
		{"server-0", netip.MustParseAddr("10.77.0.3"), 1, now.Add(7 * time.Second), now.Add(time.Second)},
		{"server-0", ip, 1, now.Add(4 * time.Second), now.Add(time.Second)},
		{"server-0", ip, 1, now.Add(7 * time.Second), now.Add(5 * time.Second)},
	} {
		if _, err := s.Renew(peer, tc.owner, tc.ip, tc.epoch, tc.until, tc.at); !errors.Is(err, ErrConflict) {
			t.Fatalf("stale/wrong-owner renewal accepted: %+v, %v", tc, err)
		}
	}
	renewed, err := s.Renew(peer, "server-0", ip, 1, now.Add(8*time.Second), now.Add(time.Second))
	if err != nil || !renewed.ValidUntil.Equal(now.Add(8*time.Second)) {
		t.Fatalf("valid renewal failed: %+v %v", renewed, err)
	}
	if _, err := s.Revoke(peer, 0, now.Add(2*time.Second)); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale revoke accepted: %v", err)
	}
	fenced, err := s.Revoke(peer, renewed.Epoch, now.Add(2*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Revoke(peer, renewed.Epoch, now.Add(3*time.Second)); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate tombstone accepted: %v", err)
	}
	if _, err := s.Renew(peer, initial.OwnerNode, ip, 1, now.Add(15*time.Second), now.Add(3*time.Second)); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale renewal after fence accepted: %v", err)
	}
	at := renewed.ValidUntil.Add(3 * time.Second)
	next, err := s.Claim(peer, "server-1", ip, fenced.Epoch, at.Add(5*time.Second), at)
	if err != nil || next.Epoch != 3 || next.OwnerNode != "server-1" {
		t.Fatalf("fenced handoff failed: %+v %v", next, err)
	}
}

func TestLeaseNNodeMembershipRemovalRequiresDrain(t *testing.T) {
	now := time.Now()
	s := leaseMachine(t, 3)
	peer := leasePeer("client")
	ip := netip.MustParseAddr("10.77.0.9")
	first, err := s.Claim(peer, "server-0", ip, 0, now.Add(5*time.Second), now)
	if err != nil {
		t.Fatal(err)
	}
	nextMembers := []string{"server-1", "server-2", "server-3", "server-4"}
	if err := s.SetMembers(2, nextMembers); !errors.Is(err, ErrConflict) {
		t.Fatalf("membership removed a live owner without drain: %v", err)
	}
	if _, err := s.Revoke(peer, first.Epoch, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := s.SetMembers(2, nextMembers); err != nil {
		t.Fatalf("drained owner could not be removed: %v", err)
	}
	if err := s.SetMembers(2, []string{"server-1", "server-2"}); !errors.Is(err, ErrConflict) {
		t.Fatalf("same revision conflicting membership accepted: %v", err)
	}
	if err := s.SetMembers(1, members(3)); !errors.Is(err, ErrConflict) {
		t.Fatalf("membership revision rollback accepted: %v", err)
	}
	at := first.ValidUntil.Add(3 * time.Second)
	reclaimed, err := s.Claim(peer, "server-4", ip, 2, at.Add(time.Second), at)
	if err != nil || reclaimed.MembershipRevision != 2 || reclaimed.Epoch != 3 {
		t.Fatalf("new node did not receive current generation and epoch: %+v %v", reclaimed, err)
	}
	if err := s.SetMembers(3, []string{"server-0", "server-1", "server-2", "server-3"}); !errors.Is(err, ErrConflict) {
		t.Fatalf("rejoin attempted to remove newly active owner without drain: %v", err)
	}
}

func TestLeaseFencingCompleteAcrossNodeLocalGuards(t *testing.T) {
	now := time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)
	s := leaseMachine(t, 5)
	a := testFence(t, "server-0")
	b := testFence(t, "server-3")
	for _, f := range []*Fence{a, b} {
		if err := f.SetMembers("cluster-1", 1, members(5)); err != nil {
			t.Fatal(err)
		}
	}
	peer, ip := leasePeer("client"), netip.MustParseAddr("10.77.0.2")
	initial, err := s.Claim(peer, "server-0", ip, 0, now.Add(5*time.Second), now)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range []*Fence{a, b} {
		if err := f.Apply(initial, now); err != nil {
			t.Fatal(err)
		}
	}
	if !a.Allowed(peer, initial.Epoch, ip, now) || b.Allowed(peer, initial.Epoch, ip, now) {
		t.Fatal("initial record not isolated to the owner")
	}
	tomb, err := s.Revoke(peer, initial.Epoch, now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range []*Fence{a, b} {
		if err := f.Apply(tomb, now.Add(time.Second)); err != nil {
			t.Fatal(err)
		}
	}
	if a.Allowed(peer, initial.Epoch, ip, now.Add(time.Second)) {
		t.Fatal("fenced node still authorized")
	}
	at := initial.ValidUntil.Add(3 * time.Second)
	next, err := s.Claim(peer, "server-3", ip, tomb.Epoch, at.Add(8*time.Second), at)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range []*Fence{a, b} {
		if err := f.Apply(next, at); err != nil {
			t.Fatal(err)
		}
	}
	if a.Allowed(peer, next.Epoch, ip, at) || !b.Allowed(peer, next.Epoch, ip, at) {
		t.Fatal("transfer did not fence old node and authorize new owner")
	}
	// An isolated node that never observes the tombstone must still be
	// denied once the old lease expires. Grace elapses before new grant.
	isolated := testFence(t, "server-0")
	if err := isolated.SetMembers("cluster-1", 1, members(5)); err != nil {
		t.Fatal(err)
	}
	if err := isolated.Apply(initial, now); err != nil {
		t.Fatal(err)
	}
	if isolated.Allowed(peer, initial.Epoch, ip, at) {
		t.Fatal("isolated old owner outlived its old TTL")
	}
}

func TestLeaseTenantOverlapAndInvalidCommands(t *testing.T) {
	now := time.Now()
	s := leaseMachine(t, 3)
	ip := netip.MustParseAddr("10.77.0.2")
	if _, err := s.Claim(leasePeer("client-1"), "server-0", ip, 0, now.Add(5*time.Second), now); err != nil {
		t.Fatal(err)
	}
	otherTenant := Peer{Tenant: "tenant-b", ID: "client-1"}
	if _, err := s.Claim(otherTenant, "server-1", ip, 0, now.Add(5*time.Second), now); err != nil {
		t.Fatalf("different tenants should be able to overlap private IPs: %v", err)
	}
	for _, tc := range []struct {
		peer  Peer
		owner string
		ip    netip.Addr
	}{
		{leasePeer("client-2"), "server-9", netip.MustParseAddr("10.77.0.4")},
		{Peer{Tenant: "", ID: "client"}, "server-0", netip.MustParseAddr("10.77.0.4")},
		{leasePeer("client-2"), "server-0", netip.MustParseAddr("224.0.0.1")},
		{leasePeer("client-2"), "server-0", netip.MustParseAddr("127.0.0.1")},
		{leasePeer("client-2"), "server-0", netip.Addr{}},
	} {
		if _, err := s.Claim(tc.peer, tc.owner, tc.ip, 0, now.Add(time.Second), now); err == nil {
			t.Fatalf("invalid claim accepted: %+v", tc)
		}
	}
	if _, err := s.Claim(leasePeer("client-3"), "server-0", netip.MustParseAddr("10.77.0.4"), 0, now.Add(time.Hour), now); !errors.Is(err, ErrInvalid) {
		t.Fatalf("lease beyond maxTTL accepted: %v", err)
	}
	if _, err := s.Claim(leasePeer("client-3"), "server-0", netip.MustParseAddr("10.77.0.4"), 0, now.Add(5*time.Second), now.Add(-time.Second)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("nonmonotonic committed timestamp accepted: %v", err)
	}
	if _, err := NewLeaseStateMachine("", time.Second, time.Second); err == nil {
		t.Fatal("missing cluster ID accepted")
	}
	if _, err := NewLeaseStateMachine("cluster-1", 0, time.Second); err == nil {
		t.Fatal("invalid maxTTL accepted")
	}
	if _, err := NewLeaseStateMachine("cluster-1", 5*time.Second, 0); err == nil {
		t.Fatal("zero fencing grace accepted")
	}
}
