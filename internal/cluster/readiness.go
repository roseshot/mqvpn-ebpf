package cluster

import (
	"context"
	"errors"
	"fmt"
)

// ErrNotReady means a node has not yet applied the currently committed
// authenticated membership and policy/CRL manifest.
var ErrNotReady = errors.New("cluster control state not applied")

// AppliedState must be produced by a trusted Server-side reconciler only
// AFTER it validates and atomically activates the exact policy/CRL bytes.
// It is never a claim from a Client, a live socket, or an arbitrary YAML field.
type AppliedState struct {
	ClusterID          string
	NodeID             string
	MembershipRevision uint64
	Policy             PolicyReference
}

// CheckApplied performs a fresh linearizable quorum read and returns success
// only if this node is a current member and has applied the exact current
// membership, policy, CA and CRL generations. On quorum loss, stale state,
// uninitialized store or cancellation it fails closed. It does not check
// the P2MP peer-owner lease, FIB convergence or the QUIC listener.
func CheckApplied(ctx context.Context, store Store, applied AppliedState) error {
	if store == nil || !validID(applied.ClusterID) || !validID(applied.NodeID) ||
		applied.MembershipRevision == 0 || applied.Policy.Revision == 0 ||
		!validDigest(applied.Policy.Digest) ||
		(applied.Policy.CRLDigest != "" && !validDigest(applied.Policy.CRLDigest)) {
		return fmt.Errorf("%w: missing verified local policy or node identity", ErrNotReady)
	}
	committed, err := store.Read(ctx, applied.ClusterID)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrNotReady, err)
	}
	if committed.ClusterID != applied.ClusterID ||
		committed.MembershipRevision != applied.MembershipRevision ||
		committed.Policy != applied.Policy {
		return fmt.Errorf("%w: committed membership or policy/CRL revision differs", ErrNotReady)
	}
	for _, node := range committed.Members {
		if node == applied.NodeID {
			return nil
		}
	}
	return fmt.Errorf("%w: Server is not a current member", ErrNotReady)
}
