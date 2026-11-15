package cluster

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type countingControlStore struct {
	Store
	reads atomic.Int32
}

func (s *countingControlStore) Read(ctx context.Context, clusterID string) (ControlSnapshot, error) {
	s.reads.Add(1)
	return s.Store.Read(ctx, clusterID)
}

type fixedControlStore struct {
	snapshot ControlSnapshot
}

func (s fixedControlStore) Read(context.Context, string) (ControlSnapshot, error) {
	return copyControl(s.snapshot), nil
}

func (s fixedControlStore) CompareAndSwap(context.Context, string, uint64, ControlSnapshot) (ControlSnapshot, error) {
	return ControlSnapshot{}, ErrInvalid
}

func TestLocalControlViewDoesNotCallStoreOnEveryReadinessCheck(t *testing.T) {
	now := time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)
	base, applied := readyFixture(t, 5, "server-2")
	store := &countingControlStore{Store: base}
	view, err := NewLocalControlView(5 * time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err := view.Refresh(context.Background(), store, applied.ClusterID, now); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 100; i++ {
		if err := view.CheckAppliedLocal(applied, now.Add(time.Duration(i)*time.Millisecond)); err != nil {
			t.Fatalf("locally observed readiness rejected: %v", err)
		}
	}
	if got := store.reads.Load(); got != 1 {
		t.Fatalf("local checks did %d quorum reads, want exactly one background refresh", got)
	}
	if err := view.CheckAppliedLocal(applied, now.Add(5*time.Second)); !errors.Is(err, ErrNotReady) {
		t.Fatalf("expired quorum observation incorrectly accepted: %v", err)
	}
	if err := view.CheckAppliedLocal(applied, now.Add(-time.Second)); !errors.Is(err, ErrNotReady) {
		t.Fatalf("clock rollback incorrectly accepted: %v", err)
	}
}

func TestLocalControlViewQuorumFailureInvalidatesButLocalProbesStillWork(t *testing.T) {
	now := time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)
	store, applied := readyFixture(t, 3, "server-0")
	view, err := NewLocalControlView(time.Second)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := view.Refresh(ctx, store, applied.ClusterID, now); err != nil {
		t.Fatal(err)
	}
	store.SetAvailable(false)
	// Local status checks do not require cluster reachability.
	if err := CheckNodeLocal(ctx, []LocalProbe{{
		Name: "tun", Check: func(context.Context) error { return nil },
	}}); err != nil {
		t.Fatalf("local node status required quorum: %v", err)
	}
	// The cached control observation remains advisory for a bounded interval
	// until the refresh worker detects failure; it cannot grant IP leases.
	if err := view.CheckAppliedLocal(applied, now.Add(100*time.Millisecond)); err != nil {
		t.Fatalf("bounded cached control view rejected: %v", err)
	}
	if err := CheckApplied(ctx, store, applied); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("strict admission did not detect quorum failure: %v", err)
	}
	if err := view.Refresh(ctx, store, applied.ClusterID, now.Add(200*time.Millisecond)); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("refresh failure was not reported: %v", err)
	}
	if err := view.CheckAppliedLocal(applied, now.Add(300*time.Millisecond)); !errors.Is(err, ErrNotReady) {
		t.Fatalf("failed refresh left view available: %v", err)
	}
	store.SetAvailable(true)
	if err := view.Refresh(ctx, store, applied.ClusterID, now.Add(400*time.Millisecond)); err != nil {
		t.Fatalf("quorum recovery failed: %v", err)
	}
	if err := view.CheckAppliedLocal(applied, now.Add(500*time.Millisecond)); err != nil {
		t.Fatalf("recovered locally observed state rejected: %v", err)
	}
}

func TestLocalControlViewRefreshDetectsRevocationAndMembershipChanges(t *testing.T) {
	now := time.Now()
	ctx := context.Background()
	store, applied := readyFixture(t, 5, "server-4")
	view, err := NewLocalControlView(5 * time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err := view.Refresh(ctx, store, applied.ClusterID, now); err != nil {
		t.Fatal(err)
	}
	before, err := store.Read(ctx, applied.ClusterID)
	if err != nil {
		t.Fatal(err)
	}
	next := copyControl(before)
	next.Revision++
	next.Policy.Revision++
	next.Policy.Digest = digestB
	next.Policy.CRLDigest = digestC
	next.MembershipRevision++
	next.Members = []string{"server-0", "server-1", "server-2", "server-3", "server-5"}
	if _, err := store.CompareAndSwap(ctx, applied.ClusterID, before.Revision, next); err != nil {
		t.Fatal(err)
	}
	if err := view.Refresh(ctx, store, applied.ClusterID, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := view.CheckAppliedLocal(applied, now.Add(time.Second)); !errors.Is(err, ErrNotReady) {
		t.Fatalf("old policy and member accepted: %v", err)
	}
	applied.MembershipRevision = next.MembershipRevision
	applied.Policy = next.Policy
	if err := view.CheckAppliedLocal(applied, now.Add(time.Second)); !errors.Is(err, ErrNotReady) {
		t.Fatalf("removed node accepted: %v", err)
	}
	applied.NodeID = "server-5"
	if err := view.CheckAppliedLocal(applied, now.Add(time.Second)); err != nil {
		t.Fatalf("new node with current applied state rejected: %v", err)
	}
}

func TestLocalControlViewRejectsRollbackEvenAfterInvalidation(t *testing.T) {
	now := time.Now()
	ctx := context.Background()
	old := controlFixture(3)
	next := copyControl(old)
	next.Revision = 2
	next.Policy.Revision = 2
	next.Policy.Digest = digestB
	view, err := NewLocalControlView(10 * time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err := view.Refresh(ctx, fixedControlStore{snapshot: next}, next.ClusterID, now); err != nil {
		t.Fatal(err)
	}
	view.Invalidate()
	if err := view.Refresh(ctx, fixedControlStore{snapshot: old}, old.ClusterID, now.Add(time.Second)); !errors.Is(err, ErrNotReady) {
		t.Fatalf("rollback accepted after invalidate: %v", err)
	}
	applied := AppliedState{
		ClusterID: old.ClusterID, NodeID: "server-0",
		MembershipRevision: 1, Policy: old.Policy,
	}
	if err := view.CheckAppliedLocal(applied, now.Add(2*time.Second)); !errors.Is(err, ErrNotReady) {
		t.Fatalf("stale view revived after rollback: %v", err)
	}
	if err := view.Refresh(ctx, fixedControlStore{snapshot: next}, next.ClusterID, now.Add(3*time.Second)); err != nil {
		t.Fatalf("valid next revision could not recover: %v", err)
	}
}

func TestLocalControlViewConcurrentRefreshAndRead(t *testing.T) {
	now := time.Now()
	store, applied := readyFixture(t, 8, "server-7")
	view, err := NewLocalControlView(5 * time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err := view.Refresh(context.Background(), store, applied.ClusterID, now); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				if err := view.CheckAppliedLocal(applied, now.Add(time.Second)); err != nil {
					t.Errorf("unexpected concurrent not-ready: %v", err)
					return
				}
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for j := 0; j < 50; j++ {
			if err := view.Refresh(context.Background(), store, applied.ClusterID, now.Add(time.Second)); err != nil {
				t.Errorf("concurrent refresh: %v", err)
				return
			}
		}
	}()
	wg.Wait()
}

func TestLocalControlViewRejectsMissingAndInvalidArguments(t *testing.T) {
	if _, err := NewLocalControlView(0); err == nil {
		t.Fatal("zero expiration accepted")
	}
	if _, err := NewLocalControlView(time.Minute); err == nil {
		t.Fatal("unbounded expiration accepted")
	}
	view, err := NewLocalControlView(time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err := view.CheckAppliedLocal(AppliedState{}, time.Now()); !errors.Is(err, ErrNotReady) {
		t.Fatalf("uninitialized local view accepted: %v", err)
	}
	if err := view.Refresh(context.Background(), nil, "cluster-1", time.Now()); !errors.Is(err, ErrNotReady) {
		t.Fatalf("nil store accepted: %v", err)
	}
	if err := view.Refresh(context.Background(), fixedControlStore{snapshot: ControlSnapshot{}}, "cluster-1", time.Now()); !errors.Is(err, ErrNotReady) {
		t.Fatalf("malformed committed snapshot accepted: %v", err)
	}
}
