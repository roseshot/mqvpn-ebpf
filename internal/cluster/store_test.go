package cluster

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
)

const digestA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
const digestB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
const digestC = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"

func controlFixture(n int) ControlSnapshot {
	return ControlSnapshot{
		ClusterID:          "cluster-1",
		Revision:           1,
		MembershipRevision: 1,
		Members:            members(n),
		Policy: PolicyReference{
			Revision: 1, Digest: digestA, CRLDigest: digestB,
		},
	}
}

func mustBootstrap(t *testing.T, s Store, n int) ControlSnapshot {
	t.Helper()
	value, err := s.CompareAndSwap(context.Background(), "cluster-1", 0, controlFixture(n))
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func TestControlStoreSupportsArbitraryServerNAndIndependentQuorum(t *testing.T) {
	for _, n := range []int{2, 3, 5, 8, 17} {
		t.Run(fmt.Sprintf("N-%d", n), func(t *testing.T) {
			store := NewMemoryStore()
			initial := mustBootstrap(t, store, n)
			if len(initial.Members) != n || initial.Revision != 1 {
				t.Fatalf("snapshot %+v", initial)
			}
			next := copyControl(initial)
			next.Revision = 2
			next.MembershipRevision = 2
			next.Members = members(n + 1)
			actual, err := store.CompareAndSwap(context.Background(), "cluster-1", initial.Revision, next)
			if err != nil || len(actual.Members) != n+1 {
				t.Fatalf("N-node scale-out failed: %+v %v", actual, err)
			}
			next = copyControl(actual)
			next.Revision = 3
			next.MembershipRevision = 3
			next.Members = members(n)
			if _, err := store.CompareAndSwap(context.Background(), "cluster-1", actual.Revision, next); err != nil {
				t.Fatalf("N-node drain/remove failed: %v", err)
			}
		})
	}
}

func TestControlStorePolicyAndCRLAtomicRevision(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	current := mustBootstrap(t, store, 5)
	next := copyControl(current)
	next.Revision++
	next.Policy.Revision++
	next.Policy.Digest = digestB
	next.Policy.CRLDigest = digestC
	committed, err := store.CompareAndSwap(ctx, "cluster-1", current.Revision, next)
	if err != nil {
		t.Fatal(err)
	}
	if committed.Policy.Revision != 2 || committed.Policy.Digest != digestB ||
		committed.Policy.CRLDigest != digestC || committed.Revision != 2 {
		t.Fatalf("policy and CRL must commit atomically: %+v", committed)
	}
	loaded, err := store.Read(ctx, "cluster-1")
	if err != nil || loaded.Policy != committed.Policy {
		t.Fatalf("read did not observe entire commit: %+v %v", loaded, err)
	}
	if _, err := store.CompareAndSwap(ctx, "cluster-1", 1, next); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale CAS should conflict: %v", err)
	}
}

func TestControlStoreRejectsRollbackAndUnversionedChanges(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	orig := mustBootstrap(t, store, 3)
	for _, tc := range []struct {
		name string
		edit func(*ControlSnapshot)
	}{
		{"same global revision", func(s *ControlSnapshot) { s.Revision = 1 }},
		{"skipped global revision", func(s *ControlSnapshot) { s.Revision = 3 }},
		{"membership without bump", func(s *ControlSnapshot) { s.Members = members(5) }},
		{"duplicate server", func(s *ControlSnapshot) { s.Members = []string{"server-0", "server-0"} }},
		{"single server", func(s *ControlSnapshot) { s.Members = members(1) }},
		{"policy without bump", func(s *ControlSnapshot) { s.Policy.Digest = digestB }},
		{"CRL without bump", func(s *ControlSnapshot) { s.Policy.CRLDigest = digestC }},
		{"invalid policy digest", func(s *ControlSnapshot) { s.Policy.Revision++; s.Policy.Digest = "not-a-digest" }},
		{"uppercase digest", func(s *ControlSnapshot) { s.Policy.Revision++; s.Policy.Digest = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" }},
		{"invalid CRL digest", func(s *ControlSnapshot) { s.Policy.Revision++; s.Policy.CRLDigest = "bad" }},
		{"rollback membership", func(s *ControlSnapshot) { s.MembershipRevision = 0 }},
		{"rollback policy", func(s *ControlSnapshot) { s.Policy.Revision = 0 }},
		{"wrong cluster", func(s *ControlSnapshot) { s.ClusterID = "other-cluster" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			next := copyControl(orig)
			next.Revision = 2
			tc.edit(&next)
			if _, err := store.CompareAndSwap(ctx, "cluster-1", 1, next); err == nil {
				t.Fatal("invalid control transition accepted")
			}
			current, err := store.Read(ctx, "cluster-1")
			if err != nil || current.Revision != 1 {
				t.Fatalf("invalid write corrupted committed state: %+v %v", current, err)
			}
		})
	}
}

func TestControlStoreBootstrapRequiresValidGeneration(t *testing.T) {
	ctx := context.Background()
	for _, mutate := range []func(*ControlSnapshot){
		func(s *ControlSnapshot) { s.Revision = 2 },
		func(s *ControlSnapshot) { s.MembershipRevision = 2 },
		func(s *ControlSnapshot) { s.Policy.Revision = 2 },
		func(s *ControlSnapshot) { s.Members = nil },
		func(s *ControlSnapshot) { s.ClusterID = "" },
	} {
		store := NewMemoryStore()
		next := controlFixture(3)
		mutate(&next)
		if _, err := store.CompareAndSwap(ctx, next.ClusterID, 0, next); err == nil {
			t.Fatal("invalid bootstrap accepted")
		}
	}
	store := NewMemoryStore()
	if _, err := store.Read(ctx, "cluster-1"); !errors.Is(err, ErrMissing) {
		t.Fatalf("missing cluster should fail closed: %v", err)
	}
	if _, err := store.CompareAndSwap(ctx, "cluster-1", 10, controlFixture(3)); !errors.Is(err, ErrConflict) {
		t.Fatalf("wrong bootstrap CAS should fail: %v", err)
	}
}

func TestControlStoreQuorumOutageFailClosedAndRecovery(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	old := mustBootstrap(t, store, 3)
	store.SetAvailable(false)
	if _, err := store.Read(ctx, "cluster-1"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("read accepted without quorum: %v", err)
	}
	next := copyControl(old)
	next.Revision++
	next.Policy.Revision++
	next.Policy.Digest = digestC
	if _, err := store.CompareAndSwap(ctx, "cluster-1", 1, next); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("write accepted without quorum: %v", err)
	}
	store.SetAvailable(true)
	loaded, err := store.Read(ctx, "cluster-1")
	if err != nil || loaded.Revision != 1 {
		t.Fatalf("unavailable write should not persist: %+v %v", loaded, err)
	}
	if _, err := store.CompareAndSwap(ctx, "cluster-1", 1, next); err != nil {
		t.Fatalf("recovery failed: %v", err)
	}
}

func TestControlStoreCopiesSlicesAndIsolatesClusters(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	initial := controlFixture(3)
	committed, err := store.CompareAndSwap(ctx, "cluster-1", 0, initial)
	if err != nil {
		t.Fatal(err)
	}
	initial.Members[0] = "mutated-input"
	committed.Members[1] = "mutated-output"
	loaded, err := store.Read(ctx, "cluster-1")
	if err != nil {
		t.Fatal(err)
	}
	loaded.Members[2] = "mutated-read"
	reloaded, err := store.Read(ctx, "cluster-1")
	if err != nil {
		t.Fatal(err)
	}
	for i, node := range members(3) {
		if reloaded.Members[i] != node {
			t.Fatalf("committed member %d corrupted: %q", i, reloaded.Members[i])
		}
	}
	second := controlFixture(2)
	second.ClusterID = "cluster-2"
	if _, err := store.CompareAndSwap(ctx, "cluster-2", 0, second); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Read(ctx, "cluster-2"); err != nil {
		t.Fatal(err)
	}
}

func TestControlStoreCancellationAndConcurrentCAS(t *testing.T) {
	store := NewMemoryStore()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := store.Read(ctx, "cluster-1"); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled read accepted: %v", err)
	}
	if _, err := store.CompareAndSwap(ctx, "cluster-1", 0, controlFixture(3)); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled write accepted: %v", err)
	}
	orig := mustBootstrap(t, store, 5)
	var wg sync.WaitGroup
	var success atomic.Int32
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			next := copyControl(orig)
			next.Revision = 2
			next.Policy.Revision = 2
			if i%2 == 0 {
				next.Policy.Digest = digestB
			} else {
				next.Policy.Digest = digestC
			}
			_, err := store.CompareAndSwap(context.Background(), "cluster-1", 1, next)
			if err == nil {
				success.Add(1)
			} else if !errors.Is(err, ErrConflict) {
				t.Errorf("concurrent CAS unexpectedly failed: %v", err)
			}
		}(i)
	}
	wg.Wait()
	if success.Load() != 1 {
		t.Fatalf("one atomic revision should have exactly one winner, got %d", success.Load())
	}
	final, err := store.Read(context.Background(), "cluster-1")
	if err != nil || final.Revision != 2 {
		t.Fatalf("bad concurrent CAS final state: %+v %v", final, err)
	}
}
