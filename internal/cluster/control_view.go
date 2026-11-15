package cluster

import (
	"context"
	"fmt"
	"maps"
	"sync"
	"time"
)

// LocalControlView is a bounded-age observation of committed control state.
// A background reconciler may Refresh it from a quorum-backed Store; HTTP
// health handlers and local status checks never read that Store themselves.
//
// This view is advisory for local readiness only. It is NOT a distributed
// fencing token, an address allocation authority or a substitute for fresh
// quorum confirmation of a security-critical admission/revocation decision.
type LocalControlView struct {
	mu          sync.RWMutex
	maxAge      time.Duration
	committed   ControlSnapshot
	refreshedAt time.Time
	valid       bool
}

func NewLocalControlView(maxAge time.Duration) (*LocalControlView, error) {
	if maxAge <= 0 || maxAge > 30*time.Second {
		return nil, fmt.Errorf("%w: local control view maximum age must be between 1ns and 30s", ErrInvalid)
	}
	return &LocalControlView{maxAge: maxAge}, nil
}

// Invalidate immediately removes readiness after a known quorum, trust,
// watch, or policy-reconciliation failure. Previously observed data MUST NOT
// continue to authorize new distributed ownership changes.
func (v *LocalControlView) Invalidate() {
	if v == nil {
		return
	}
	v.mu.Lock()
	v.valid = false
	v.mu.Unlock()
}

// Refresh is called by a background control-plane worker, never by a local
// health HTTP handler. It requires one linearizable Read from a real quorum
// backend; the test MemoryStore is not safe for multi-process deployment.
// Failed reads, stale observations or contradictory revisions fail closed.
func (v *LocalControlView) Refresh(ctx context.Context, store Store, clusterID string, at time.Time) error {
	if v == nil {
		return fmt.Errorf("%w: missing local control view", ErrNotReady)
	}
	if store == nil || !validID(clusterID) || at.IsZero() {
		v.Invalidate()
		return fmt.Errorf("%w: invalid control refresh arguments", ErrNotReady)
	}
	committed, err := store.Read(ctx, clusterID)
	if err != nil {
		v.Invalidate()
		return fmt.Errorf("%w: fresh quorum observation: %w", ErrNotReady, err)
	}
	if committed.ClusterID != clusterID || committed.Revision == 0 ||
		committed.MembershipRevision == 0 || committed.Policy.Revision == 0 ||
		!validDigest(committed.Policy.Digest) ||
		(committed.Policy.CRLDigest != "" && !validDigest(committed.Policy.CRLDigest)) {
		v.Invalidate()
		return fmt.Errorf("%w: malformed committed control snapshot", ErrNotReady)
	}
	newMembers, err := memberSet(committed.Members)
	if err != nil {
		v.Invalidate()
		return fmt.Errorf("%w: malformed committed members: %v", ErrNotReady, err)
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.valid {
		old := v.committed
		oldMembers, _ := memberSet(old.Members)
		if at.Before(v.refreshedAt) || committed.ClusterID != old.ClusterID ||
			committed.Revision < old.Revision ||
			committed.MembershipRevision < old.MembershipRevision ||
			committed.Policy.Revision < old.Policy.Revision ||
			(committed.MembershipRevision == old.MembershipRevision &&
				!maps.Equal(newMembers, oldMembers)) ||
			(committed.Policy.Revision == old.Policy.Revision &&
				committed.Policy != old.Policy) ||
			(committed.Revision == old.Revision &&
				(committed.MembershipRevision != old.MembershipRevision ||
					committed.Policy != old.Policy ||
					!maps.Equal(newMembers, oldMembers))) {
			v.valid = false
			return fmt.Errorf("%w: stale or contradictory committed observation", ErrNotReady)
		}
	}
	v.committed = copyControl(committed)
	v.refreshedAt = at
	v.valid = true
	return nil
}

// CheckAppliedLocal compares locally measured/applied state against the last
// bounded-age committed observation using only process memory. It performs
// NO network or Store call. If background refresh stops, it fails closed once
// the maximum age passes. This cannot guarantee instantaneous CRL revocation:
// strict new-session admission still requires an authoritative fencing/quorum
// decision, such as CheckApplied plus a valid committed peer lease.
func (v *LocalControlView) CheckAppliedLocal(applied AppliedState, now time.Time) error {
	if v == nil {
		return fmt.Errorf("%w: missing local control view", ErrNotReady)
	}
	v.mu.RLock()
	defer v.mu.RUnlock()
	if !v.valid || now.Before(v.refreshedAt) || now.Sub(v.refreshedAt) >= v.maxAge {
		return fmt.Errorf("%w: committed observation unavailable or stale", ErrNotReady)
	}
	return checkAppliedSnapshot(v.committed, applied)
}
