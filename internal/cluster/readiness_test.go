package cluster

import (
	"context"
	"errors"
	"testing"
)

func readyFixture(t *testing.T, n int, node string) (*MemoryStore, AppliedState) {
	t.Helper()
	store := NewMemoryStore()
	committed := mustBootstrap(t, store, n)
	return store, AppliedState{
		ClusterID: committed.ClusterID,
		NodeID: node,
		MembershipRevision: committed.MembershipRevision,
		Policy: committed.Policy,
	}
}

func TestCheckAppliedRequiresExactQuorumPolicyAndCRL(t *testing.T) {
	ctx := context.Background()
	store, applied := readyFixture(t, 5, "server-2")
	if err := CheckApplied(ctx, store, applied); err != nil {
		t.Fatalf("fully applied member rejected: %v", err)
	}
	store.SetAvailable(false)
	if err := CheckApplied(ctx, store, applied); !errors.Is(err, ErrNotReady) || !errors.Is(err, ErrUnavailable) {
		t.Fatalf("quorum unavailable did not fail closed: %v", err)
	}
	store.SetAvailable(true)
	before, err := store.Read(ctx, "cluster-1")
	if err != nil {
		t.Fatal(err)
	}
	next := copyControl(before)
	next.Revision++
	next.Policy.Revision++
	next.Policy.CRLDigest = digestC
	next.Policy.Digest = digestB
	if _, err := store.CompareAndSwap(ctx, "cluster-1", before.Revision, next); err != nil {
		t.Fatal(err)
	}
	if err := CheckApplied(ctx, store, applied); !errors.Is(err, ErrNotReady) {
		t.Fatalf("stale CRL passed readiness: %v", err)
	}
	applied.Policy = next.Policy
	if err := CheckApplied(ctx, store, applied); err != nil {
		t.Fatalf("current applied policy rejected: %v", err)
	}
}

func TestCheckAppliedRejectsMembershipDriftAndRemovedNode(t *testing.T) {
	ctx := context.Background()
	store, applied := readyFixture(t, 3, "server-2")
	before, err := store.Read(ctx, "cluster-1")
	if err != nil {
		t.Fatal(err)
	}
	next := copyControl(before)
	next.Revision++
	next.MembershipRevision++
	next.Members = []string{"server-0", "server-1", "server-3"}
	if _, err := store.CompareAndSwap(ctx, "cluster-1", before.Revision, next); err != nil {
		t.Fatal(err)
	}
	if err := CheckApplied(ctx, store, applied); !errors.Is(err, ErrNotReady) {
		t.Fatalf("stale membership should fail closed: %v", err)
	}
	applied.MembershipRevision = next.MembershipRevision
	if err := CheckApplied(ctx, store, applied); !errors.Is(err, ErrNotReady) {
		t.Fatalf("removed node incorrectly ready: %v", err)
	}
	applied.NodeID = "server-3"
	if err := CheckApplied(ctx, store, applied); err != nil {
		t.Fatalf("newly admitted node with current applied generation rejected: %v", err)
	}
}

func TestCheckAppliedRejectsMissingInvalidAndCanceled(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	applied := AppliedState{
		ClusterID: "cluster-1", NodeID: "server-0",
		MembershipRevision: 1,
		Policy: PolicyReference{Revision: 1, Digest: digestA, CRLDigest: digestB},
	}
	if err := CheckApplied(ctx, store, applied); !errors.Is(err, ErrMissing) {
		t.Fatalf("uninitialized cluster accepted: %v", err)
	}
	if err := CheckApplied(ctx, nil, applied); !errors.Is(err, ErrNotReady) {
		t.Fatalf("nil store accepted: %v", err)
	}
	if err := CheckApplied(ctx, store, AppliedState{}); !errors.Is(err, ErrNotReady) {
		t.Fatalf("empty local applied state accepted: %v", err)
	}
	mustBootstrap(t, store, 3)
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if err := CheckApplied(canceled, store, applied); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled readiness check should fail closed: %v", err)
	}
	applied.Policy.Digest = "invalid"
	if err := CheckApplied(ctx, store, applied); !errors.Is(err, ErrNotReady) {
		t.Fatalf("unverified policy digest accepted: %v", err)
	}
}
