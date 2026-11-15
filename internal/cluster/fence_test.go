package cluster

import (
	"fmt"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func sampleRecord(node string, epoch, revision uint64, expires time.Time) Record {
	return Record{
		ClusterID: "cluster-1",
		Peer:      Peer{Tenant: "tenant-1", ID: "client-1"},
		OwnerNode: node, Epoch: epoch, MembershipRevision: revision,
		TunnelIP: netip.MustParseAddr("10.77.0.2"), ValidUntil: expires,
	}
}

func testFence(t *testing.T, local string) *Fence {
	t.Helper()
	f, err := NewFence("cluster-1", local, 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func members(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf("server-%d", i)
	}
	return out
}

func TestMembershipAnyNAndMonotonicRevision(t *testing.T) {
	for _, n := range []int{2, 3, 5, 8} {
		t.Run(fmt.Sprintf("N-%d", n), func(t *testing.T) {
			f := testFence(t, "server-0")
			nodes := members(n)
			if err := f.SetMembers("cluster-1", 10, nodes); err != nil {
				t.Fatal(err)
			}
			if err := f.SetMembers("cluster-1", 10, append([]string(nil), nodes...)); err != nil {
				t.Fatalf("idempotent replay rejected: %v", err)
			}
			if f.Revision() != 10 {
				t.Fatalf("revision=%d, want 10", f.Revision())
			}
			if err := f.SetMembers("cluster-1", 10, members(n+1)); err == nil {
				t.Fatal("conflicting members at the same revision accepted")
			}
			if err := f.SetMembers("cluster-1", 9, nodes); err == nil {
				t.Fatal("membership rollback accepted")
			}
			if err := f.SetMembers("cluster-1", 11, members(n+1)); err != nil {
				t.Fatalf("N-node scale-out rejected: %v", err)
			}
		})
	}
}

func TestRejectInvalidMembershipAndIdentities(t *testing.T) {
	for _, tc := range []struct {
		cluster, local string
		ttl            time.Duration
	}{
		{"", "server-0", time.Second},
		{"cluster-1", "bad node", time.Second},
		{"cluster-1", "server-0", 0},
		{"cluster-1", "server-0", 3 * time.Minute},
	} {
		if _, err := NewFence(tc.cluster, tc.local, tc.ttl); err == nil {
			t.Fatalf("unsafe cluster setup accepted: %+v", tc)
		}
	}
	f := testFence(t, "server-0")
	for _, tc := range []struct {
		rev   uint64
		nodes []string
	}{
		{0, members(3)},
		{1, nil},
		{1, []string{"server-0"}},
		{1, []string{"server-0", "server-0"}},
		{1, []string{"server-0", "bad node"}},
		{1, []string{"server-0", "server-\x00"}},
	} {
		if err := f.SetMembers("cluster-1", tc.rev, tc.nodes); err == nil {
			t.Fatalf("invalid members accepted: %+v", tc)
		}
	}
	if err := f.SetMembers("cluster-1", 1, members(3)); err != nil {
		t.Fatal(err)
	}
}

func TestFenceTransferRenewalAndReplay(t *testing.T) {
	now := time.Date(2026, 11, 15, 0, 0, 0, 0, time.UTC)
	f := testFence(t, "server-0")
	if err := f.SetMembers("cluster-1", 1, members(3)); err != nil {
		t.Fatal(err)
	}
	original := sampleRecord("server-0", 1, 1, now.Add(10*time.Second))
	if err := f.Apply(original, now); err != nil {
		t.Fatal(err)
	}
	if !f.Allowed(original.Peer, 1, original.TunnelIP, now) {
		t.Fatal("local owner must be allowed while lease is live")
	}
	if f.Allowed(original.Peer, 2, original.TunnelIP, now) ||
		f.Allowed(original.Peer, 1, netip.MustParseAddr("10.77.0.3"), now) ||
		f.Allowed(original.Peer, 1, original.TunnelIP, now.Add(10*time.Second)) {
		t.Fatal("wrong epoch, IP or expired lease accepted")
	}
	renew := original
	renew.ValidUntil = now.Add(15 * time.Second)
	if err := f.Apply(renew, now.Add(time.Second)); err != nil {
		t.Fatalf("same-epoch extension rejected: %v", err)
	}
	if err := f.Apply(original, now.Add(2*time.Second)); err == nil {
		t.Fatal("replayed old expiry accepted")
	}
	transfer := sampleRecord("server-1", 2, 1, now.Add(20*time.Second))
	if err := f.Apply(transfer, now); err == nil {
		t.Fatal("cross-node transfer without fencing accepted")
	}
	readdress := sampleRecord("server-0", 2, 1, now.Add(20*time.Second))
	readdress.TunnelIP = netip.MustParseAddr("10.77.0.9")
	if err := f.Apply(readdress, now); err == nil {
		t.Fatal("address reassignment without fencing accepted")
	}
	fence := Record{ClusterID: "cluster-1", Peer: original.Peer, Epoch: 2, MembershipRevision: 1}
	if err := f.Apply(fence, now); err != nil {
		t.Fatal(err)
	}
	if f.Allowed(original.Peer, 1, original.TunnelIP, now) {
		t.Fatal("fenced lease stayed authorized")
	}
	if err := f.Apply(renew, now); err == nil {
		t.Fatal("late owner replay after fence accepted")
	}
	if err := f.Apply(transfer, now); err == nil {
		t.Fatal("same epoch as fence allowed ownership resurrection")
	}
	transfer.Epoch = 3
	if err := f.Apply(transfer, now); err != nil {
		t.Fatalf("new fenced owner rejected: %v", err)
	}
	if f.Allowed(original.Peer, 3, transfer.TunnelIP, now) {
		t.Fatal("old Server authorized traffic belonging to new owner")
	}
}

func TestRemoveAndRejoinNeedsNewEpoch(t *testing.T) {
	now := time.Now()
	f := testFence(t, "server-0")
	if err := f.SetMembers("cluster-1", 1, []string{"server-0", "server-1", "server-2"}); err != nil {
		t.Fatal(err)
	}
	first := sampleRecord("server-0", 42, 1, now.Add(20*time.Second))
	if err := f.Apply(first, now); err != nil {
		t.Fatal(err)
	}
	if err := f.SetMembers("cluster-1", 2, []string{"server-1", "server-2", "server-3"}); err != nil {
		t.Fatal(err)
	}
	if f.Allowed(first.Peer, 42, first.TunnelIP, now) {
		t.Fatal("removed member still owns an active session")
	}
	if err := f.SetMembers("cluster-1", 3, []string{"server-0", "server-1", "server-2"}); err != nil {
		t.Fatal(err)
	}
	if f.Allowed(first.Peer, 42, first.TunnelIP, now) {
		t.Fatal("rejoining node resurrected its old lease")
	}
	first.MembershipRevision = 3
	if err := f.Apply(first, now); err == nil {
		t.Fatal("old epoch accepted after rejoin")
	}
	first.Epoch = 43
	if err := f.Apply(first, now); err != nil {
		t.Fatalf("new epoch after membership fencing rejected: %v", err)
	}
	if !f.Allowed(first.Peer, 43, first.TunnelIP, now) {
		t.Fatal("valid new epoch not authorized")
	}
}

func TestIPLeaseCannotBeReusedWithoutFence(t *testing.T) {
	now := time.Now()
	f := testFence(t, "server-0")
	if err := f.SetMembers("cluster-1", 1, members(5)); err != nil {
		t.Fatal(err)
	}
	first := sampleRecord("server-0", 1, 1, now.Add(time.Second))
	if err := f.Apply(first, now); err != nil {
		t.Fatal(err)
	}
	second := sampleRecord("server-1", 1, 1, now.Add(10*time.Second))
	second.Peer.ID = "client-2"
	if err := f.Apply(second, now.Add(2*time.Second)); err == nil {
		t.Fatal("IP reuse accepted without explicit tombstone even after expiry")
	}
	if err := f.Apply(Record{ClusterID: "cluster-1", Peer: first.Peer, Epoch: 2, MembershipRevision: 1}, now.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := f.Apply(second, now.Add(2*time.Second)); err != nil {
		t.Fatalf("IP reuse after fencing rejected: %v", err)
	}
	otherTenant := second
	otherTenant.Peer.Tenant = "tenant-2"
	if err := f.Apply(otherTenant, now.Add(2*time.Second)); err != nil {
		t.Fatalf("overlapping subnets across isolated tenants rejected: %v", err)
	}
}

func TestCrossClusterRecordsAlwaysRejected(t *testing.T) {
	now := time.Now()
	f := testFence(t, "server-0")
	if err := f.SetMembers("other-cluster", 1, members(3)); err == nil {
		t.Fatal("foreign cluster membership was accepted")
	}
	if f.Revision() != 0 {
		t.Fatal("foreign membership changed local revision")
	}
	if err := f.SetMembers("cluster-1", 1, members(3)); err != nil {
		t.Fatal(err)
	}
	record := sampleRecord("server-0", 1, 1, now.Add(10*time.Second))
	record.ClusterID = "other-cluster"
	if err := f.Apply(record, now); err == nil {
		t.Fatal("foreign cluster owner was accepted")
	}
	if f.Allowed(record.Peer, 1, record.TunnelIP, now) {
		t.Fatal("foreign cluster record authorized the local node")
	}
}

func TestRejectStaleMembershipAndMalformedRecords(t *testing.T) {
	now := time.Now()
	f := testFence(t, "server-0")
	one := sampleRecord("server-0", 1, 1, now.Add(time.Second))
	if err := f.Apply(one, now); err == nil {
		t.Fatal("record accepted before trusted membership")
	}
	if err := f.SetMembers("cluster-1", 2, members(3)); err != nil {
		t.Fatal(err)
	}
	cases := []Record{
		one,
		sampleRecord("server-4", 1, 2, now.Add(time.Second)),
		sampleRecord("server-0", 0, 2, now.Add(time.Second)),
		sampleRecord("server-0", 1, 2, now.Add(-time.Second)),
		sampleRecord("server-0", 1, 2, now.Add(time.Hour)),
		sampleRecord("server-0", 1, 2, now.Add(time.Second)),
		sampleRecord("server-0", 1, 2, now.Add(time.Second)),
	}
	cases[5].TunnelIP = netip.MustParseAddr("224.0.0.1")
	cases[6].Peer.Tenant = "tenant with spaces"
	for i, record := range cases {
		if err := f.Apply(record, now); err == nil {
			t.Fatalf("invalid owner record %d accepted: %+v", i, record)
		}
	}
	if err := f.Apply(Record{
		ClusterID: "cluster-1",
		Peer:      Peer{Tenant: "tenant-1", ID: "client-1"},
		Epoch:     1, MembershipRevision: 2, TunnelIP: netip.MustParseAddr("10.77.0.2"),
	}, now); err == nil {
		t.Fatal("tombstone containing an IP accepted")
	}
}

// Parallel arrivals to one local checker cannot grant the same peer's epoch
// to multiple owners. This is NOT a substitute for cross-process quorum CAS.
func TestConcurrentFiveNodeEpochConflict(t *testing.T) {
	now := time.Now()
	f := testFence(t, "server-0")
	if err := f.SetMembers("cluster-1", 1, members(5)); err != nil {
		t.Fatal(err)
	}
	var successes atomic.Int32
	var wg sync.WaitGroup
	for _, node := range members(5) {
		wg.Add(1)
		go func(node string) {
			defer wg.Done()
			rec := sampleRecord(node, 1, 1, now.Add(5*time.Second))
			if err := f.Apply(rec, now); err == nil {
				successes.Add(1)
			}
		}(node)
	}
	wg.Wait()
	if successes.Load() != 1 {
		t.Fatalf("one local epoch granted to %d concurrent owners", successes.Load())
	}
}
